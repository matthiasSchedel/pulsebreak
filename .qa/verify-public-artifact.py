#!/usr/bin/env python3
"""Verify the generated Pulsebreak public artifact and its legal routes."""

from __future__ import annotations

import argparse
import contextlib
import functools
from html.parser import HTMLParser
import http.server
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request


SHA = re.compile(r"^[0-9a-f]{40}$")


class References(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key in {"href", "src"} and value:
                self.values.append((tag, value))


def fetch(url: str) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "Pulsebreak-QA/1"})
    with urllib.request.urlopen(request, timeout=8) as response:
        return response.status, response.read(), response.headers.get_content_type()


def verify(base_url: str, head: str) -> dict[str, object]:
    base = base_url.rstrip("/") + "/"
    expected_origin = urllib.parse.urlsplit(base)
    checked: dict[str, dict[str, object]] = {}
    failures: list[str] = []
    queue = ["", "support/", "privacy/", "icon.svg", "manifest.webmanifest", ".__pulsebreak_qa_head"]
    seen: set[str] = set()
    while queue:
        relative = queue.pop(0)
        url = urllib.parse.urljoin(base, relative)
        if url in seen:
            continue
        seen.add(url)
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme, parsed.netloc) != (expected_origin.scheme, expected_origin.netloc):
            failures.append(f"cross-origin runtime reference: {url}")
            continue
        try:
            status, body, content_type = fetch(url)
        except (OSError, urllib.error.URLError) as error:
            failures.append(f"request failed: {relative or '/'} ({type(error).__name__})")
            continue
        checked[relative or "/"] = {"status": status, "bytes": len(body), "content_type": content_type}
        if status != 200 or not body:
            failures.append(f"unexpected response: {relative or '/'} status={status} bytes={len(body)}")
            continue
        if relative == ".__pulsebreak_qa_head" and body.decode(errors="replace").strip() != head:
            failures.append("preview head marker mismatch")
        if content_type == "text/html":
            parser = References()
            parser.feed(body.decode("utf-8"))
            for tag, reference in parser.values:
                if reference.startswith(("#", "mailto:", "tel:", "data:")):
                    continue
                target = urllib.parse.urljoin(url, reference)
                target_parts = urllib.parse.urlsplit(target)
                if (target_parts.scheme, target_parts.netloc) != (expected_origin.scheme, expected_origin.netloc):
                    if tag != "a":
                        failures.append(f"cross-origin runtime reference: {reference}")
                    continue
                target_relative = target_parts.path.lstrip("/")
                if target_relative and target_relative not in seen:
                    queue.append(target_relative)

    root_text = fetch(base)[1].decode("utf-8", errors="replace")
    support_text = fetch(urllib.parse.urljoin(base, "support/"))[1].decode("utf-8", errors="replace")
    privacy_text = fetch(urllib.parse.urljoin(base, "privacy/"))[1].decode("utf-8", errors="replace")
    if "Pulsebreak" not in root_text or 'rel="icon"' not in root_text:
        failures.append("root title or favicon declaration missing")
    if "matze.schedel@gmail.com" not in support_text:
        failures.append("support contact missing")
    if "does not collect" not in privacy_text:
        failures.append("privacy no-collection statement missing")
    if failures:
        raise AssertionError("; ".join(sorted(set(failures))))
    return {"head": head, "base_url": base, "checked": checked, "cross_origin_dependencies": []}


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return


def ci_preview(repo: pathlib.Path, head: str) -> tuple[http.server.ThreadingHTTPServer, str]:
    handler = functools.partial(QuietHandler, directory=str(repo))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    original = QuietHandler.do_GET

    def with_marker(self: QuietHandler) -> None:
        if self.path.split("?", 1)[0] == "/.__pulsebreak_qa_head":
            body = (head + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        original(self)

    QuietHandler.do_GET = with_marker
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--head")
    args = parser.parse_args()
    try:
        if args.ci:
            repo = pathlib.Path(args.repo or ".").resolve(strict=True)
            head = (args.head or "").lower()
            if not SHA.fullmatch(head):
                raise ValueError("--head must be a full lowercase SHA")
            current = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout.strip().lower()
            if current != head:
                raise ValueError("CI checkout is not the requested head")
            server, preview_url = ci_preview(repo, head)
            artifact_dir = pathlib.Path(tempfile.mkdtemp(prefix="pulsebreak-pages-ci-"))
        else:
            preview_url = os.environ.get("QA_PREVIEW_URL", "")
            head = os.environ.get("QA_EXACT_HEAD", "").lower()
            artifact_dir = pathlib.Path(os.environ.get("QA_ARTIFACT_DIR", ""))
            server = None
            if not preview_url.startswith("http://127.0.0.1:") or not SHA.fullmatch(head):
                raise ValueError("QA environment is not exact-head local-slot input")
            artifact_dir.resolve().mkdir(parents=True, exist_ok=True)
        try:
            assertions = verify(preview_url, head)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
        artifact = artifact_dir / "public-listing-routes.json"
        artifact.write_text(json.dumps(assertions, indent=2, sort_keys=True) + "\n")
        result = {
            "schema": "qa-journey-result/v1",
            "status": "PASS",
            "head_sha": head,
            "artifacts": [{"type": "assertion", "path": str(artifact.resolve())}],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (AssertionError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"verify-public-artifact: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
