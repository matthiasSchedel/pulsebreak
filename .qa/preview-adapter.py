#!/usr/bin/env python3
"""Prepare an exact-head, isolated local preview for repository-owned QA."""

from __future__ import annotations

import argparse
import contextlib
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


REPO = pathlib.Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{40}$")
LIFETIME_SECONDS = 30 * 60


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=REPO, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def exact_clean_head(head: str) -> None:
    if not SHA.fullmatch(head):
        raise ValueError("--head must be a full lowercase commit SHA")
    if git("rev-parse", "HEAD").lower() != head:
        raise ValueError("checkout does not match --head")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("checkout is not clean")


def state_path(head: str) -> pathlib.Path:
    return pathlib.Path(tempfile.gettempdir()) / f"pulsebreak-pages-preview-{head}.json"


def marker_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/.__pulsebreak_qa_head"


def preview_responds(port: int, head: str) -> bool:
    try:
        with urllib.request.urlopen(marker_url(port), timeout=1.5) as response:
            return response.status == 200 and response.read().decode().strip() == head
    except (OSError, UnicodeError):
        return False


def read_state(head: str) -> dict[str, object] | None:
    try:
        state = json.loads(state_path(head).read_text())
        if (
            state.get("head") == head
            and state.get("repo") == str(REPO)
            and isinstance(state.get("pid"), int)
            and isinstance(state.get("port"), int)
        ):
            os.kill(int(state["pid"]), 0)
            if preview_responds(int(state["port"]), head):
                return state
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError, ValueError):
        pass
    return None


def choose_port(head: str) -> int:
    start = 43_000 + (int(head[:6], 16) % 1_000)
    for offset in range(80):
        port = 43_000 + ((start - 43_000 + offset) % 1_000)
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError("no isolated local preview port is available")


def stage_site(head: str) -> pathlib.Path:
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"pulsebreak-pages-{head[:12]}-"))
    slot = root / "site"
    slot.mkdir()
    for relative in git("ls-files").splitlines():
        if relative.startswith((".github/", ".qa/")):
            continue
        source = REPO / relative
        target = slot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    if not (slot / "index.html").is_file():
        raise RuntimeError("staged preview lacks index.html")
    return slot


def start_slot(head: str) -> dict[str, object]:
    existing = read_state(head)
    if existing:
        return existing
    slot = stage_site(head)
    port = choose_port(head)
    process = subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--serve", str(slot), str(port), head],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    for _ in range(80):
        if preview_responds(port, head):
            state = {"head": head, "repo": str(REPO), "pid": process.pid, "port": port, "slot": str(slot)}
            state_path(head).write_text(json.dumps(state, sort_keys=True) + "\n")
            os.chmod(state_path(head), 0o600)
            return state
        if process.poll() is not None:
            break
        time.sleep(0.1)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    raise RuntimeError("isolated local preview did not become ready")


class Handler(http.server.SimpleHTTPRequestHandler):
    head_sha = ""

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/.__pulsebreak_qa_head":
            body = (self.head_sha + "\n").encode()
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def serve(directory: pathlib.Path, port: int, head: str) -> None:
    if not directory.is_dir() or not SHA.fullmatch(head):
        raise ValueError("invalid preview server arguments")
    handler = lambda *args, **kwargs: Handler(*args, directory=str(directory), **kwargs)  # noqa: E731
    Handler.head_sha = head
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    timer = threading.Timer(LIFETIME_SECONDS, server.shutdown)
    timer.daemon = True
    timer.start()
    try:
        server.serve_forever()
    finally:
        timer.cancel()
        server.server_close()


def adapter(argv: list[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--mode", choices=("qa", "card"), required=True)
    parser.add_argument("--format", choices=("json",), required=True)
    args = parser.parse_args(argv)
    if not args.pr.isdigit():
        raise ValueError("--pr must be numeric")
    head = args.head.lower()
    exact_clean_head(head)
    slot = start_slot(head)
    preview_url = f"http://127.0.0.1:{slot['port']}/"
    automation = {"schema": "qa-automation/v1", "command": ["python3", ".qa/verify-public-artifact.py"]}
    card = {
        "schema": "preview-card/v1",
        "head_sha": head,
        "preview_url": preview_url,
        "card_markdown": "\n".join((
            f"**What to test — Gate 1 · #{args.pr} (Pulsebreak public listing)**",
            preview_url,
            f"Summary: Verify the generated game, support, and privacy routes at exact head {head}.",
            "No account or external service is required.",
            "1. Open the game route → the title screen loads with no failed local asset request.",
            "2. Open Support and Privacy → both pages render, link back to the game, and state the shipped contact/data practices.",
            "3. Reload each route → relative assets remain reachable and no cross-origin runtime dependency appears.",
        )),
        "required_flows": [{"id": "public-listing-routes", "visual_required": False, "automation": automation}],
        "artifacts": [],
    }
    print(json.dumps(card, sort_keys=True, separators=(",", ":")))


def main() -> int:
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--serve":
            serve(pathlib.Path(sys.argv[2]).resolve(), int(sys.argv[3]), sys.argv[4].lower())
        else:
            adapter(sys.argv[1:])
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"preview-adapter: {error}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
