#!/usr/bin/env python3
"""Verify the generated Pulsebreak public artifact and its legal routes."""

from __future__ import annotations

import argparse
import base64
import contextlib
import functools
from html.parser import HTMLParser
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable


SHA = re.compile(r"^[0-9a-f]{40}$")
CSS_URL = re.compile(r"url\(\s*([\"']?)([^\"')]+?)\1\s*\)", re.IGNORECASE)
SOURCE_MAPPING_DIRECTIVE = re.compile(rb"(?i)sourceMappingURL\s*[:=]")
JS_REFERENCE_PATTERNS = (
    ("runtime", re.compile(r"\b(?:fetch|importScripts|import|sendBeacon|register)\s*\(\s*([\"'`])([^\"'`]+)\1")),
    ("module", re.compile(r"\bdefine\s*\(\s*\[\s*([\"'`])([^\"'`]+)\1")),
    ("runtime", re.compile(r"\bnew\s+URL\s*\(\s*([\"'`])([^\"'`]+)\1")),
    ("runtime", re.compile(r"\b(?:src|href|url)\s*:\s*([\"'`])([^\"'`]+)\1")),
)
MANIFEST_KEYS = {
    # Core manifest URLs plus URL-bearing members of the current Web App
    # Manifest extensions. These values all control a fetch, navigation,
    # handler, or scope and therefore must remain inside the published graph.
    "id", "scope", "service_worker", "serviceworker", "src", "start_url", "url",
    "action", "origin", "new_note_url",
}
ROUTES = ("support/", "privacy/", "")
ROUTE_TITLES = {"": "Pulsebreak", "support/": "Support", "privacy/": "Privacy"}

# A bounded post-load async contract: every route remains under observation for
# two seconds after load, covering deferred application and worker behavior
# without leaving CI with an unbounded browser session.
RUNTIME_OBSERVATION_CONTRACT = "bounded-post-load-async-window-v1"
RUNTIME_OBSERVATION_WINDOW_SECONDS = 2.0
OFFLINE_RELOAD_CONTRACT = "installed-cache-storage-offline-reload-v1"
OFFLINE_RELOAD_TIMEOUT_SECONDS = 8.0
CDP_CONNECT_TIMEOUT_SECONDS = 20.0
CDP_COMMAND_TIMEOUT_SECONDS = 20.0
CDP_CACHE_STORAGE_DEADLINE_SECONDS = 30.0
CDP_COMMAND_RETRY_ATTEMPTS = 2
CDP_TARGET_DISCOVERY_TIMEOUT_SECONDS = 30.0
CDP_TARGET_POLL_SECONDS = 0.1

# These scripts bootstrap the worker itself. They are fetched by the browser
# during worker installation and are intentionally excluded from the offline
# application graph; every other discovered public resource must be precached.
WORKER_BOOTSTRAP_INVARIANT = "sw.js and workbox-*.js are install-time worker bootstrap files"


def is_worker_bootstrap(path: str) -> bool:
    return path == "sw.js" or (path.startswith("workbox-") and path.endswith(".js"))


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


def same_origin(url: str, origin: urllib.parse.SplitResult) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)


def ignorable_reference(reference: str) -> bool:
    return reference.startswith(("#", "mailto:", "tel:", "data:", "blob:"))


def reference_boundary_error(reference: str, tag: str) -> str | None:
    """Return an error for a non-relative runtime/PWA reference.

    External navigation anchors remain valid links. Every other public graph
    edge must be relative so the Pages artifact cannot silently escape its
    loopback origin or bypass the offline graph.
    """
    parsed = urllib.parse.urlsplit(reference)
    if tag == "a" and (reference.startswith("//") or parsed.scheme in {"http", "https"}):
        return None
    if reference.startswith("/") or reference.startswith("//") or parsed.scheme:
        return f"non-relative {tag} reference: {reference}"
    return None


def manifest_reference_boundary_error(reference: str) -> str | None:
    """Manifest-controlled URLs must name local relative artifact resources."""
    if reference.startswith("#"):
        return f"non-relative manifest reference: {reference}"
    return reference_boundary_error(reference, "manifest")


def artifact_path(relative: str) -> str:
    """Map a fetched route to the published file covered by precache."""
    path = relative.strip("/")
    if not path:
        return "index.html"
    if relative.endswith("/"):
        return f"{path}/index.html"
    return path


def browser_resource_path(url: str, origin: urllib.parse.SplitResult) -> str | None:
    """Normalize a successful same-origin browser response to its artifact path."""
    if not same_origin(url, origin):
        return None
    path = urllib.parse.urlsplit(url).path.lstrip("/")
    normalized = artifact_path(path)
    if normalized == ".__pulsebreak_qa_head" or is_worker_bootstrap(normalized):
        return None
    return normalized


def tracked_public_tree_failures(repo: pathlib.Path) -> list[str]:
    """Reject maps/directives anywhere in the tracked published tree."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        return [f"cannot enumerate tracked public tree: {type(error).__name__}"]
    failures: list[str] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", errors="surrogateescape")
        # QA and workflow sources are not shipped by the Pages artifact.
        if relative.startswith((".qa/", ".github/")):
            continue
        if relative.lower().endswith(".map"):
            failures.append(f"published source map is forbidden: {relative}")
        path = repo / pathlib.PurePosixPath(relative)
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                failures.append(f"published tree entry is not a regular file: {relative}")
                continue
            body = path.read_bytes()
        except OSError as error:
            failures.append(f"published tree entry unreadable: {relative} ({type(error).__name__})")
            continue
        if SOURCE_MAPPING_DIRECTIVE.search(body):
            failures.append(f"published sourceMappingURL directive is forbidden: {relative}")
    return failures


def manifest_references(value: object, key: str = "") -> list[str]:
    references: list[str] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            references.extend(manifest_references(child, child_key))
    elif isinstance(value, list):
        for child in value:
            references.extend(manifest_references(child, key))
    elif isinstance(value, str) and key in MANIFEST_KEYS:
        references.append(value)
    return references


def javascript_references(text: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for kind, pattern in JS_REFERENCE_PATTERNS:
        values.extend((kind, match.group(2)) for match in pattern.finditer(text))
    return values


def css_references(text: str) -> list[str]:
    return [match.group(2).strip() for match in CSS_URL.finditer(text)]


def javascript_tokens(text: str) -> list[tuple[str, str]]:
    """Tokenize enough JavaScript to isolate executable precache call data.

    Strings are opaque, while line and block comments are discarded before
    token matching. This prevents entry-shaped comment text from becoming an
    effective Workbox precache entry without downloading a parser dependency.
    """
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if character in "'\"`":
            quote = character
            index += 1
            value: list[str] = []
            while index < length:
                character = text[index]
                if character == quote:
                    index += 1
                    break
                if character == "\\" and index + 1 < length:
                    index += 1
                    escaped = text[index]
                    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
                    if escaped == "u" and index + 4 < length:
                        digits = text[index + 1:index + 5]
                        if re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                            value.append(chr(int(digits, 16)))
                            index += 5
                            continue
                    value.append(escapes.get(escaped, escaped))
                    index += 1
                    continue
                value.append(character)
                index += 1
            tokens.append(("string", "".join(value)))
            continue
        if character.isalpha() or character in "_$":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            tokens.append(("identifier", text[index:end]))
            index = end
            continue
        if character.isdigit():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "._"):
                end += 1
            tokens.append(("number", text[index:end]))
            index = end
            continue
        tokens.append(("punctuation", character))
        index += 1
    return tokens


def matching_token(tokens: list[tuple[str, str]], start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        value = tokens[index][1]
        if value == opening:
            depth += 1
        elif value == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def object_properties(tokens: list[tuple[str, str]], start: int, end: int) -> dict[str, tuple[str, str]]:
    properties: dict[str, tuple[str, str]] = {}
    depth = 0
    index = start + 1
    while index < end:
        kind, value = tokens[index]
        if depth == 0 and kind in {"identifier", "string"} and index + 2 < end and tokens[index + 1][1] == ":":
            properties[value] = tokens[index + 2]
        if value in "[{(":
            depth += 1
        elif value in "]})":
            depth = max(0, depth - 1)
        index += 1
    return properties


def precache_entries(text: str) -> list[tuple[str, str | None]]:
    """Extract one deterministic executable precacheAndRoute array.

    Workbox call selection is intentionally fail-closed. Static tokenization
    cannot prove JavaScript reachability, so multiple calls, malformed calls,
    and calls under control-flow operators are ambiguous and rejected. The
    browser-side Cache Storage and offline probes below remain the effective
    completeness authority.
    """
    tokens = javascript_tokens(text)
    candidates: list[list[tuple[str, str | None]]] = []
    ambiguous = False
    for index in range(len(tokens) - 2):
        if tokens[index] != ("identifier", "precacheAndRoute") or tokens[index + 1][1] != "(":
            continue
        array_start = index + 2
        if tokens[array_start][1] != "[":
            ambiguous = True
            continue
        array_end = matching_token(tokens, array_start, "[", "]")
        if array_end is None:
            ambiguous = True
            continue
        entries: list[tuple[str, str | None]] = []
        cursor = array_start + 1
        while cursor < array_end:
            if tokens[cursor][1] != "{":
                cursor += 1
                continue
            object_end = matching_token(tokens, cursor, "{", "}")
            if object_end is None or object_end > array_end:
                ambiguous = True
                break
            properties = object_properties(tokens, cursor, object_end)
            url = properties.get("url")
            revision = properties.get("revision")
            if url and url[0] == "string":
                revision_value = revision[1] if revision and revision[0] == "string" else None
                entries.append((url[1], revision_value))
            cursor = object_end + 1
        candidates.append(entries)

        # Find the nearest lexical block and its header. If the call is
        # guarded by if/else/switch/loop/catch or a short-circuit/ternary
        # expression, static analysis cannot establish that this is the
        # installed Workbox call, so fail closed.
        stack: list[tuple[str, int]] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        for token_index in range(index):
            value = tokens[token_index][1]
            if value in "([{":
                stack.append((value, token_index))
            elif value in pairs:
                for stack_index in range(len(stack) - 1, -1, -1):
                    if stack[stack_index][0] == pairs[value]:
                        del stack[stack_index:]
                        break
        block_start = max(
            (token_index for opening, token_index in stack if opening == "{"),
            default=-1,
        )
        statement_start = block_start + 1
        for token_index in range(statement_start, index):
            if tokens[token_index][1] == ";":
                statement_start = token_index + 1
        for token_index in range(statement_start, index):
            value = tokens[token_index][1]
            if value in {"if", "else", "switch", "for", "while", "catch", "?"}:
                ambiguous = True
            if value in {"&", "|"} and token_index + 1 < index and tokens[token_index + 1][1] == value:
                ambiguous = True
        header_start = block_start - 1
        while header_start >= 0 and tokens[header_start][1] not in {";", "{", "}"}:
            if tokens[header_start][1] in {"if", "else", "switch", "for", "while", "catch"}:
                ambiguous = True
            header_start -= 1
    if ambiguous or len(candidates) != 1:
        return []
    return candidates[0]


def verify(base_url: str, head: str, repo: pathlib.Path | None = None) -> dict[str, object]:
    base = base_url.rstrip("/") + "/"
    expected_origin = urllib.parse.urlsplit(base)
    checked: dict[str, dict[str, object]] = {}
    failures: list[str] = []
    if repo is not None:
        failures.extend(tracked_public_tree_failures(repo.resolve(strict=True)))
    queue = ["", "support/", "privacy/", "icon.svg", "manifest.webmanifest", ".__pulsebreak_qa_head"]
    seen: set[str] = set()
    while queue:
        relative = queue.pop(0)
        url = urllib.parse.urljoin(base, relative)
        if url in seen:
            continue
        seen.add(url)
        if not same_origin(url, expected_origin):
            failures.append(f"cross-origin runtime reference: {url}")
            continue
        try:
            status, body, content_type = fetch(url)
        except (OSError, urllib.error.URLError) as error:
            failures.append(f"request failed: {relative or '/'} ({type(error).__name__})")
            continue
        checked[relative or "/"] = {"status": status, "bytes": len(body), "content_type": content_type}
        if status >= 400 or not body:
            failures.append(f"unexpected response: {relative or '/'} status={status} bytes={len(body)}")
            continue
        if relative == ".__pulsebreak_qa_head" and body.decode(errors="replace").strip() != head:
            failures.append("preview head marker mismatch")

        references: list[tuple[str, str]] = []
        decoded = body.decode("utf-8", errors="replace")
        if content_type == "text/html":
            parser = References()
            parser.feed(decoded)
            references.extend(parser.values)
        elif content_type == "text/css":
            references.extend(("css", reference) for reference in css_references(decoded))
        elif content_type in {"text/javascript", "application/javascript", "application/x-javascript"}:
            references.extend(javascript_references(decoded))
        elif content_type in {"application/manifest+json", "application/json"}:
            if relative == "manifest.webmanifest":
                try:
                    manifest = json.loads(decoded)
                except json.JSONDecodeError as error:
                    failures.append(f"manifest is not valid JSON: {error}")
                else:
                    references.extend(("manifest", reference) for reference in manifest_references(manifest))

        for tag, reference in references:
            if tag != "manifest" and ignorable_reference(reference):
                continue
            boundary_error = manifest_reference_boundary_error(reference) if tag == "manifest" else reference_boundary_error(reference, tag)
            if boundary_error:
                failures.append(boundary_error)
                continue
            resolved_reference = reference
            if tag == "module" and reference == "exports":
                continue
            if tag == "module" and reference.startswith(("./", "../")) and not pathlib.PurePosixPath(reference).suffix:
                resolved_reference += ".js"
            target = urllib.parse.urljoin(url, resolved_reference)
            if not same_origin(target, expected_origin):
                if tag != "a":
                    failures.append(f"cross-origin runtime reference: {reference}")
                continue
            target_parts = urllib.parse.urlsplit(target)
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
    try:
        _sw_status, sw_body, _sw_type = fetch(urllib.parse.urljoin(base, "sw.js"))
        entries = precache_entries(sw_body.decode("utf-8", errors="replace"))
    except (OSError, urllib.error.URLError):
        entries = []
    if not entries:
        failures.append("service-worker precache manifest missing")
    else:
        precached_paths: set[str] = set()
        for reference, revision in entries:
            boundary_error = reference_boundary_error(reference, "precache")
            if boundary_error:
                failures.append(boundary_error)
                continue
            target = urllib.parse.urljoin(base, reference)
            if not same_origin(target, expected_origin):
                failures.append(f"cross-origin precache reference: {reference}")
                continue
            target_parts = urllib.parse.urlsplit(target)
            target_relative = artifact_path(target_parts.path.lstrip("/"))
            precached_paths.add(target_relative)
            try:
                status, body, _content_type = fetch(target)
            except (OSError, urllib.error.URLError) as error:
                failures.append(f"precache request failed: {reference} ({type(error).__name__})")
                continue
            if status != 200 or not body:
                failures.append(f"precache response invalid: {reference} status={status} bytes={len(body)}")
            if revision and hashlib.md5(body).hexdigest() != revision:
                failures.append(f"precache revision mismatch: {reference}")
        offline_required_paths = {
            artifact_path(path)
            for path in checked
            if path != ".__pulsebreak_qa_head" and not is_worker_bootstrap(path)
        }
        missing_paths = sorted(offline_required_paths - precached_paths)
        for path in missing_paths:
            failures.append(f"service-worker precache misses offline graph resource: {path}")
        if "index.html" not in precached_paths:
            failures.append("service-worker precache lacks index.html navigation fallback")
    if failures:
        raise AssertionError("; ".join(sorted(set(failures))))
    return {
        "head": head,
        "base_url": base,
        "checked": checked,
        "offline_graph": sorted(
            artifact_path(path)
            for path in checked
            if path != ".__pulsebreak_qa_head" and not is_worker_bootstrap(path)
        ),
        "precache_paths": sorted(precached_paths),
        "worker_bootstrap_invariant": WORKER_BOOTSTRAP_INVARIANT,
        "cross_origin_dependencies": [],
    }


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


class CDPConnection:
    """Small dependency-free WebSocket client for the Chromium DevTools Protocol."""

    def __init__(self, websocket_url: str) -> None:
        parsed = urllib.parse.urlsplit(websocket_url)
        if parsed.scheme != "ws" or not parsed.hostname or not parsed.port:
            raise RuntimeError("Chromium returned an invalid CDP WebSocket URL")
        self.socket = socket.create_connection(
            (parsed.hostname, parsed.port), timeout=CDP_CONNECT_TIMEOUT_SECONDS
        )
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.socket.sendall(request)
        response = b""
        handshake_deadline = time.monotonic() + CDP_CONNECT_TIMEOUT_SECONDS
        while b"\r\n\r\n" not in response:
            remaining = handshake_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Chromium CDP handshake timed out")
            self.socket.settimeout(remaining)
            try:
                chunk = self.socket.recv(4096)
            except socket.timeout as error:
                raise RuntimeError("Chromium CDP handshake timed out") from error
            if not chunk:
                raise RuntimeError("Chromium closed the CDP handshake")
            response += chunk
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError("Chromium rejected the CDP WebSocket handshake")
        self.next_id = 0
        self.event_handler = None
        self.pending: dict[int, dict[str, object]] = {}

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.close()

    def _send_frame(self, payload: bytes, opcode: int = 1) -> None:
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length < 65536:
            header = bytes((0x80 | opcode, 0x80 | 126)) + length.to_bytes(2, "big")
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + length.to_bytes(8, "big")
        mask = os.urandom(4)
        self.socket.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))

    def _receive_frame(self) -> tuple[bool, int, bytes]:
        header = self._read_exact(2)
        first, second = header
        length = second & 0x7F
        if length == 126:
            length = int.from_bytes(self._read_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._read_exact(8), "big")
        mask = self._read_exact(4) if second & 0x80 else None
        payload = self._read_exact(length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return bool(first & 0x80), first & 0x0F, payload

    def _read_exact(self, length: int) -> bytes:
        result = b""
        while len(result) < length:
            chunk = self.socket.recv(length - len(result))
            if not chunk:
                raise RuntimeError("Chromium closed the CDP connection")
            result += chunk
        return result

    def receive(self) -> dict[str, object]:
        fragments: list[bytes] = []
        while True:
            final, opcode, payload = self._receive_frame()
            if opcode == 9:
                self._send_frame(payload, opcode=10)
                continue
            if opcode == 8:
                raise RuntimeError("Chromium closed the CDP connection")
            if opcode == 1:
                fragments = [payload]
            elif opcode == 0:
                fragments.append(payload)
            else:
                continue
            if final:
                return json.loads(b"".join(fragments).decode("utf-8"))

    def command(
        self,
        method: str,
        params: dict[str, object] | None = None,
        session_id: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, object]:
        self.next_id += 1
        command_id = self.next_id
        command: dict[str, object] = {"id": command_id, "method": method, "params": params or {}}
        if session_id:
            command["sessionId"] = session_id
        command_deadline = time.monotonic() + (timeout or CDP_COMMAND_TIMEOUT_SECONDS)
        previous_timeout = self.socket.gettimeout()
        try:
            self.socket.settimeout(max(0.05, command_deadline - time.monotonic()))
            self._send_frame(json.dumps(command).encode())
            while True:
                pending = self.pending.pop(command_id, None)
                if pending is not None:
                    message = pending
                else:
                    remaining = command_deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(f"CDP {method} command {command_id} timed out")
                    self.socket.settimeout(max(0.05, remaining))
                    try:
                        message = self.receive()
                    except socket.timeout as error:
                        raise RuntimeError(f"CDP {method} command {command_id} timed out") from error
                if message.get("id") == command_id:
                    if "error" in message:
                        raise RuntimeError(f"CDP {method} failed: {message['error']}")
                    return message
                message_id = message.get("id")
                if isinstance(message_id, int):
                    self.pending[message_id] = message
                    continue
                if self.event_handler:
                    self.event_handler(message)
        finally:
            self.socket.settimeout(previous_timeout)


class RuntimeProbe:
    def __init__(self, origin: urllib.parse.SplitResult) -> None:
        self.origin = origin
        self.current_route = ""
        self.request_urls: dict[str, str] = {}
        self.observed_resources: set[str] = set()
        self.route: dict[str, object] = {}
        self.routes: list[dict[str, object]] = []

    def begin_route(self, route: str) -> None:
        self.current_route = route
        self.route = {
            "route": "/" if not route else f"/{route}",
            "document_status": None,
            "failed_requests": [],
            "console_errors": [],
            "page_errors": [],
            "log_errors": [],
            "cross_origin_requests": [],
            "same_origin_resources": [],
        }

    def _add(self, key: str, value: str) -> None:
        values = self.route.setdefault(key, [])
        if value not in values:
            values.append(value)

    def observe(self, message: dict[str, object]) -> None:
        method = message.get("method")
        params = message.get("params") or {}
        if method == "Network.requestWillBeSent":
            request_id = str(params.get("requestId", ""))
            request = params.get("request") or {}
            url = str(request.get("url", ""))
            self.request_urls[request_id] = url
            if url and not same_origin(url, self.origin):
                self._add("cross_origin_requests", url)
        elif method == "Network.responseReceived":
            response = params.get("response") or {}
            url = str(response.get("url", ""))
            status = int(response.get("status", 0) or 0)
            if status >= 400:
                self._add("failed_requests", f"{url} status={status}")
            if 200 <= status < 400:
                resource_path = browser_resource_path(url, self.origin)
                if resource_path:
                    self._add("same_origin_resources", resource_path)
                    self.observed_resources.add(resource_path)
            if params.get("type") == "Document":
                self.route["document_status"] = status
        elif method == "Network.loadingFailed":
            request_id = str(params.get("requestId", ""))
            self._add("failed_requests", f"{self.request_urls.get(request_id, request_id)}: {params.get('errorText', 'failed')}")
        elif method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails") or {}
            exception = details.get("exception") or {}
            self._add("page_errors", str(exception.get("description") or details.get("text") or "runtime exception"))
        elif method == "Runtime.consoleAPICalled":
            if params.get("type") in {"error", "assert"}:
                self._add("console_errors", str(params.get("type")))
        elif method == "Log.entryAdded":
            entry = params.get("entry") or {}
            if entry.get("level") == "error":
                self._add("log_errors", str(entry.get("text") or "browser log error"))

    def finish_route(self) -> None:
        self.routes.append(self.route)


def chrome_binary() -> str:
    candidates = []
    if os.environ.get("CHROME_BIN"):
        candidates.append(os.environ["CHROME_BIN"])
    candidates.extend((
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ))
    for candidate in candidates:
        path = shutil.which(candidate) if "/" not in candidate else candidate
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise RuntimeError("installed Chromium executable not found")


def browser_json(port: int, path: str, timeout: float = 2.0) -> object:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as response:
        return json.loads(response.read().decode())


def discover_page_target(
    port: int,
    process: subprocess.Popen[bytes],
    *,
    timeout: float = CDP_TARGET_DISCOVERY_TIMEOUT_SECONDS,
    poll_interval: float = CDP_TARGET_POLL_SECONDS,
    reader: Callable[[int, str], object] = browser_json,
) -> dict[str, object]:
    """Find a page target under a bounded, retrying startup deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Chromium exited before exposing a page target")
        try:
            targets = reader(port, "/json/list")
        except (OSError, ValueError, urllib.error.URLError):
            targets = []
        for candidate in targets if isinstance(targets, list) else []:
            if candidate.get("type") == "page" and candidate.get("webSocketDebuggerUrl"):
                return candidate
        remaining = deadline - time.monotonic()
        if remaining > 0 and poll_interval > 0:
            time.sleep(min(poll_interval, remaining))
    raise RuntimeError(
        f"Chromium did not expose a page target within {timeout:.1f}s"
    )


def cdp_command_with_retry(
    connection: CDPConnection,
    method: str,
    params: dict[str, object] | None = None,
    *,
    session_id: str | None = None,
    attempts: int = CDP_COMMAND_RETRY_ATTEMPTS,
    deadline_seconds: float = CDP_CACHE_STORAGE_DEADLINE_SECONDS,
) -> dict[str, object]:
    """Retry only bounded CDP timeouts while preserving command identity."""
    deadline = time.monotonic() + deadline_seconds
    last_error: Exception | None = None
    for attempt in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return connection.command(
                method,
                params,
                session_id=session_id,
                timeout=min(CDP_COMMAND_TIMEOUT_SECONDS, remaining),
            )
        except (RuntimeError, socket.timeout) as error:
            last_error = error
            if "timed out" not in str(error).lower() or attempt + 1 >= attempts:
                raise
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"CDP {method} retry deadline expired")


def browser_cache_storage(connection: CDPConnection, origin: urllib.parse.SplitResult) -> dict[str, object]:
    """Read the installed service worker's Cache Storage through the page.

    The static Workbox array is only a declaration. Cache Storage is the
    browser-observed effective installation, so a declared entry that was
    unreachable or conditionally skipped cannot satisfy completeness.
    """
    expression = """(async()=>{
      const entries=[];
      for (const name of await caches.keys()) {
        const cache=await caches.open(name);
        for (const request of await cache.keys()) entries.push({name,url:request.url});
      }
      return entries;
    })()"""
    evaluation = cdp_command_with_retry(
        connection,
        "Runtime.evaluate",
        {"expression": expression, "awaitPromise": True, "returnByValue": True},
        deadline_seconds=CDP_CACHE_STORAGE_DEADLINE_SECONDS,
    )
    result = (evaluation.get("result") or {}).get("result") or {}
    if "exceptionDetails" in evaluation.get("result", {}):
        raise RuntimeError("Cache Storage evaluation failed")
    entries = result.get("value")
    if not isinstance(entries, list):
        raise RuntimeError("Cache Storage returned no enumerable entries")
    paths: set[str] = set()
    foreign: set[str] = set()
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Cache Storage returned an ambiguous entry")
        name = str(entry.get("name", ""))
        url = str(entry.get("url", ""))
        names.add(name)
        parsed = urllib.parse.urlsplit(url)
        if not same_origin(url, origin):
            foreign.add(url)
            continue
        paths.add(artifact_path(parsed.path.lstrip("/")))
    return {"cache_names": sorted(names), "paths": sorted(paths), "foreign_urls": sorted(foreign)}


def run_browser(base_url: str, precache_paths: set[str] | None = None) -> dict[str, object]:
    origin = urllib.parse.urlsplit(base_url.rstrip("/") + "/")
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    browser_port = port_socket.getsockname()[1]
    port_socket.close()
    profile = pathlib.Path(tempfile.mkdtemp(prefix="pulsebreak-pages-chrome-"))
    process: subprocess.Popen[bytes] | None = None
    connection: CDPConnection | None = None
    try:
        process = subprocess.Popen(
            [
                chrome_binary(), "--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-component-update",
                "--disable-default-apps", "--disable-extensions", "--disable-sync",
                f"--user-data-dir={profile}", "--remote-debugging-address=127.0.0.1",
                f"--remote-debugging-port={browser_port}", "about:blank",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        target = discover_page_target(browser_port, process)
        connection = CDPConnection(str(target["webSocketDebuggerUrl"]))
        probe = RuntimeProbe(origin)
        active_probe = probe
        offline_mode = False

        attached_workers: set[str] = set()

        def observe(message: dict[str, object]) -> None:
            active_probe.observe(message)
            if message.get("method") != "Target.attachedToTarget":
                return
            params = message.get("params") or {}
            target_info = params.get("targetInfo") or {}
            if target_info.get("type") != "service_worker":
                return
            session_id = str(params.get("sessionId", ""))
            if not session_id or session_id in attached_workers:
                return
            attached_workers.add(session_id)
            connection.command("Runtime.enable", session_id=session_id)
            connection.command("Log.enable", session_id=session_id)
            connection.command("Network.enable", session_id=session_id)
            connection.command("Runtime.runIfWaitingForDebugger", session_id=session_id)
            if offline_mode:
                connection.command(
                    "Network.emulateNetworkConditions",
                    {"offline": True, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1},
                    session_id=session_id,
                )

        connection.event_handler = observe
        connection.command("Network.enable")
        connection.command("Runtime.enable")
        connection.command("Log.enable")
        connection.command("Page.enable")
        connection.command(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True},
        )

        def receive_until(deadline: float, load: bool = False) -> bool:
            loaded = False
            while time.monotonic() < deadline:
                connection.socket.settimeout(max(0.05, min(0.25, deadline - time.monotonic())))
                try:
                    message = connection.receive()
                except socket.timeout:
                    continue
                observe(message)
                if message.get("method") == "Page.loadEventFired":
                    loaded = True
                    if load:
                        return True
            return loaded

        def emulate_network(offline: bool) -> None:
            params = {
                "offline": offline,
                "latency": 0,
                "downloadThroughput": -1,
                "uploadThroughput": -1,
            }
            connection.command("Network.emulateNetworkConditions", params)
            for session_id in tuple(attached_workers):
                with contextlib.suppress(RuntimeError):
                    connection.command("Network.emulateNetworkConditions", params, session_id=session_id)

        for route in ROUTES:
            probe.begin_route(route)
            target_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", route)
            navigation = connection.command("Page.navigate", {"url": target_url})
            if (navigation.get("result") or {}).get("errorText"):
                probe._add("failed_requests", str((navigation.get("result") or {}).get("errorText")))
            if not receive_until(time.monotonic() + 15, load=True):
                probe._add("page_errors", "load event timeout")
            receive_until(time.monotonic() + RUNTIME_OBSERVATION_WINDOW_SECONDS)
            evaluation = connection.command("Runtime.evaluate", {"expression": "document.title", "returnByValue": True})
            result = (evaluation.get("result") or {}).get("result") or {}
            if "exceptionDetails" in evaluation.get("result", {}):
                probe._add("page_errors", "document.title evaluation failed")
            title = result.get("value")
            probe.route["title"] = title
            expected_title = ROUTE_TITLES[route]
            if not isinstance(title, str) or expected_title not in title:
                probe._add("page_errors", f"unexpected document title: {title!r}")
            probe.finish_route()

        cache_storage: dict[str, object] = {"cache_names": [], "paths": [], "foreign_urls": []}
        offline_routes: list[dict[str, object]] = []
        if precache_paths is not None:
            cache_storage = browser_cache_storage(connection, origin)
            foreign_urls = [str(url) for url in cache_storage.get("foreign_urls", [])]
            if foreign_urls:
                raise AssertionError("service-worker Cache Storage contains cross-origin entries: " + ", ".join(foreign_urls))
            cached_paths = {str(path) for path in cache_storage.get("paths", [])}
            missing_cached_paths = sorted(precache_paths - cached_paths)
            if missing_cached_paths:
                raise AssertionError(
                    "installed service-worker Cache Storage misses declared precache resources: "
                    + ", ".join(missing_cached_paths)
                )

            offline_probe = RuntimeProbe(origin)
            active_probe = offline_probe
            offline_mode = True
            try:
                emulate_network(True)
                for route in ROUTES:
                    offline_probe.begin_route(route)
                    target_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", route)
                    navigation = connection.command("Page.navigate", {"url": target_url})
                    if (navigation.get("result") or {}).get("errorText"):
                        offline_probe._add("failed_requests", str((navigation.get("result") or {}).get("errorText")))
                    loaded = receive_until(time.monotonic() + OFFLINE_RELOAD_TIMEOUT_SECONDS, load=True)
                    if not loaded:
                        offline_probe._add("page_errors", "offline reload timeout")
                    offline_probe.finish_route()
            finally:
                emulate_network(False)
                offline_mode = False
                active_probe = probe
            for route in offline_probe.routes:
                offline_routes.append({
                    "route": route["route"],
                    "document_status": route.get("document_status"),
                    "loaded": not any(route.get(key) for key in ("failed_requests", "page_errors", "console_errors", "log_errors", "cross_origin_requests")),
                })
                if route.get("document_status") != 200:
                    raise AssertionError(f"offline reload {route['route']} status={route.get('document_status')}")
                for key in ("failed_requests", "console_errors", "page_errors", "log_errors", "cross_origin_requests"):
                    if route.get(key):
                        raise AssertionError(f"offline reload {route['route']} {key}: {route[key]}")

        errors: list[str] = []
        for route in probe.routes:
            route_name = str(route["route"])
            if route.get("document_status") != 200:
                errors.append(f"{route_name} document status={route.get('document_status')}")
            for key in ("failed_requests", "console_errors", "page_errors", "log_errors", "cross_origin_requests"):
                for detail in route.get(key, []):
                    errors.append(f"{route_name} {key}: {detail}")
        if errors:
            raise AssertionError("; ".join(errors))
        observed_offline_resources = sorted(probe.observed_resources)
        if precache_paths is not None:
            missing_runtime_resources = sorted(set(observed_offline_resources) - precache_paths)
            if missing_runtime_resources:
                raise AssertionError(
                    "browser-observed same-origin resources missing from service-worker precache: "
                    + ", ".join(missing_runtime_resources)
                )
        return {
            "engine": pathlib.Path(chrome_binary()).name,
            "origin": f"{origin.scheme}://{origin.netloc}",
            "observation_contract": RUNTIME_OBSERVATION_CONTRACT,
            "observation_window_seconds": RUNTIME_OBSERVATION_WINDOW_SECONDS,
            "observed_offline_resources": observed_offline_resources,
            "cache_storage": cache_storage,
            "offline_reload_contract": OFFLINE_RELOAD_CONTRACT if precache_paths is not None else None,
            "offline_routes": offline_routes,
            "routes": probe.routes,
            "status": "PASS",
        }
    finally:
        if connection:
            connection.close()
        if process is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
        shutil.rmtree(profile, ignore_errors=True)


def merge_browser_offline_graph(
    assertions: dict[str, object], browser: dict[str, object]
) -> dict[str, object]:
    """Union successful browser resources into the required offline graph."""
    observed_resources = {str(path) for path in browser.get("observed_offline_resources", [])}
    precache_paths = {str(path) for path in assertions.get("precache_paths", [])}
    missing_runtime_resources = sorted(observed_resources - precache_paths)
    if missing_runtime_resources:
        raise AssertionError(
            "browser-observed same-origin resources missing from service-worker precache: "
            + ", ".join(missing_runtime_resources)
        )
    assertions["offline_graph"] = sorted(
        {str(path) for path in assertions.get("offline_graph", [])} | observed_resources
    )
    return assertions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--head")
    args = parser.parse_args()
    try:
        repo: pathlib.Path | None = None
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
            configured_repo = os.environ.get("QA_REPO", ".")
            repo = pathlib.Path(configured_repo).resolve(strict=True)
            artifact_dir.resolve().mkdir(parents=True, exist_ok=True)
        try:
            assertions = verify(preview_url, head, repo)
            precache_paths = {str(path) for path in assertions.get("precache_paths", [])}
            browser = run_browser(preview_url, precache_paths)
            merge_browser_offline_graph(assertions, browser)
            assertions["browser"] = browser
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
    except (AssertionError, OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"verify-public-artifact: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
