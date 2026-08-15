#!/usr/bin/env python3
"""Focused hostile fixtures for the public Pages QA boundaries."""

from __future__ import annotations

import functools
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADAPTER = load("pulsebreak_preview_adapter", ROOT / ".qa/preview-adapter.py")
VERIFY = load("pulsebreak_public_verifier", ROOT / ".qa/verify-public-artifact.py")


class MarkerServer:
    def __init__(self, directory: pathlib.Path, head: str) -> None:
        class Handler(VERIFY.QuietHandler):
            def do_GET(request_handler):  # noqa: N802
                if request_handler.path.split("?", 1)[0] == "/.__pulsebreak_qa_head":
                    body = (head + "\n").encode()
                    request_handler.send_response(200)
                    request_handler.send_header("Content-Type", "text/plain; charset=utf-8")
                    request_handler.send_header("Content-Length", str(len(body)))
                    request_handler.end_headers()
                    request_handler.wfile.write(body)
                    return
                super(Handler, request_handler).do_GET()

        handler = functools.partial(Handler, directory=str(directory))
        self.server = VERIFY.http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def write_fixture(
    root: pathlib.Path,
    app: str,
    css: str = "body { color: white; }",
    manifest_icon: str = "./icon.svg",
    sw: str | None = None,
) -> None:
    (root / "support").mkdir(parents=True)
    (root / "privacy").mkdir(parents=True)
    (root / "index.html").write_text(
        '<!doctype html><html><head><link rel="icon" href="./icon.svg">'
        '<link rel="stylesheet" href="./style.css"><link rel="manifest" href="./manifest.webmanifest">'
        '<script src="./app.js"></script><script src="./registerSW.js"></script>'
        '<title>Pulsebreak</title></head><body>fixture</body></html>\n'
    )
    (root / "support/index.html").write_text(
        '<link rel="icon" href="../icon.svg"><title>Pulsebreak Support</title>'
        "matze.schedel@gmail.com\n"
    )
    (root / "privacy/index.html").write_text(
        '<link rel="icon" href="../icon.svg"><title>Pulsebreak Privacy Policy</title>'
        "does not collect\n"
    )
    (root / "icon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1 1'></svg>\n")
    (root / "style.css").write_text(css)
    (root / "manifest.webmanifest").write_text(
        '{"name":"Pulsebreak","start_url":"./","scope":"./","icons":[{"src":"'
        + manifest_icon
        + '"}]}\n'
    )
    (root / "app.js").write_text(app)
    (root / "registerSW.js").write_text("navigator.serviceWorker.register('./sw.js');\n")
    if sw is None:
        sw = (
            'const precacheAndRoute=entries=>{'
            'const cacheName="fixture-precache";'
            'self.addEventListener("install",event=>event.waitUntil('
            'caches.open(cacheName).then(cache=>cache.addAll(entries.map(entry=>new URL(entry.url,self.location).href)))'
            '.then(()=>self.skipWaiting())));'
            'self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));'
            'self.addEventListener("fetch",event=>event.respondWith((async()=>{'
            'const requestURL=new URL(event.request.url);'
            'const candidates=[event.request];'
            'if(requestURL.pathname.endsWith("/"))candidates.push(new Request(new URL(requestURL.pathname+"index.html",requestURL)));'
            'const cache=await caches.open(cacheName);'
            'for(const request of candidates){const hit=await cache.match(request);if(hit)return hit;}'
            'return fetch(event.request);})()));};precacheAndRoute(['
            '{url:"registerSW.js",revision:null},'
            '{url:"manifest.webmanifest",revision:null},'
            '{url:"index.html",revision:null},'
            '{url:"icon.svg",revision:null},'
            '{url:"support/index.html",revision:null},'
            '{url:"privacy/index.html",revision:null},'
            '{url:"style.css",revision:null},'
            '{url:"app.js",revision:null}]);'
        )
    (root / "sw.js").write_text(sw)
    (root / "workbox.js").write_text("\n")


def track_fixture(root: pathlib.Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)


def add_precache_entry(root: pathlib.Path, path: str) -> None:
    sw = (root / "sw.js").read_text()
    (root / "sw.js").write_text(sw.replace("]);", f',{{url:"{path}",revision:null}}]);'))


FULL_FIXTURE_PRECACHE = (
    '{url:"registerSW.js",revision:null},'
    '{url:"manifest.webmanifest",revision:null},'
    '{url:"index.html",revision:null},'
    '{url:"icon.svg",revision:null},'
    '{url:"support/index.html",revision:null},'
    '{url:"privacy/index.html",revision:null},'
    '{url:"style.css",revision:null},'
    '{url:"app.js",revision:null}'
)


def fixture_precache_worker(body: str) -> str:
    return f"const precacheAndRoute=()=>{{}};{body}"


class QABoundaryTests(unittest.TestCase):
    def test_cdp_target_discovery_retries_delayed_page_target(self) -> None:
        class RunningProcess:
            def poll(self) -> None:
                return None

        calls = 0

        def delayed_reader(_port: int, _path: str) -> list[dict[str, str]]:
            nonlocal calls
            calls += 1
            if calls < 3:
                return []
            return [{"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/page"}]

        target = VERIFY.discover_page_target(
            1234,
            RunningProcess(),
            timeout=0.1,
            poll_interval=0,
            reader=delayed_reader,
        )
        self.assertEqual(target["type"], "page")
        self.assertEqual(calls, 3)

    def test_cdp_runtime_evaluate_retries_delayed_response(self) -> None:
        class DelayedEvaluate:
            def __init__(self) -> None:
                self.calls = 0

            def command(self, _method: str, _params: dict[str, object], **_kwargs: object) -> dict[str, object]:
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("CDP Runtime.evaluate command 1 timed out")
                return {
                    "result": {
                        "result": {
                            "value": [{
                                "name": "fixture-cache",
                                "url": "http://127.0.0.1:1234/index.html",
                            }]
                        }
                    }
                }

        connection = DelayedEvaluate()
        cache = VERIFY.browser_cache_storage(
            connection,
            VERIFY.urllib.parse.urlsplit("http://127.0.0.1:1234/"),
        )
        self.assertEqual(connection.calls, 2)
        self.assertEqual(cache["paths"], ["index.html"])

    def test_current_production_artifact_passes_static_and_browser(self) -> None:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            stdout=subprocess.PIPE, text=True,
        ).stdout.strip()
        server = MarkerServer(ROOT, head)
        try:
            static = VERIFY.verify(server.url, head, ROOT)
            browser = VERIFY.run_browser(server.url, set(static["precache_paths"]))
            self.assertEqual(browser["status"], "PASS")
            self.assertTrue(browser["offline_routes"])
        finally:
            server.close()

    def test_staging_rejects_tracked_symlink_and_stages_regular_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-symlink-fixture-") as temporary:
            repo = pathlib.Path(temporary)
            (repo / "index.html").write_text("regular fixture\n")
            (repo / "outside.txt").write_text("sentinel\n")
            (repo / "leak.txt").symlink_to(repo / "outside.txt")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "add", "index.html", "outside.txt", "leak.txt"], cwd=repo, check=True)
            previous = ADAPTER.REPO
            ADAPTER.REPO = repo.resolve()
            try:
                with self.assertRaises(RuntimeError):
                    ADAPTER.stage_site("a" * 40)
                subprocess.run(["git", "rm", "-q", "--cached", "leak.txt"], cwd=repo, check=True)
                (repo / "leak.txt").unlink()
                staged = ADAPTER.stage_site("a" * 40)
                try:
                    self.assertEqual((staged / "index.html").read_text(), "regular fixture\n")
                    self.assertFalse((staged / "leak.txt").exists())
                finally:
                    shutil.rmtree(staged.parent)
            finally:
                ADAPTER.REPO = previous

    def test_preview_namespace_isolated_by_repository_and_head(self) -> None:
        previous = ADAPTER.REPO
        try:
            ADAPTER.REPO = pathlib.Path("/tmp/pulsebreak-repo-a").resolve()
            first_state = ADAPTER.state_path("a" * 40)
            first_seed = ADAPTER.state_namespace("a" * 40)
            ADAPTER.REPO = pathlib.Path("/tmp/pulsebreak-repo-b").resolve()
            second_state = ADAPTER.state_path("a" * 40)
            second_seed = ADAPTER.state_namespace("a" * 40)
            self.assertNotEqual(first_state, second_state)
            self.assertNotEqual(first_seed, second_seed)
        finally:
            ADAPTER.REPO = previous

    def test_static_graph_rejects_javascript_css_manifest_and_service_worker_origins(self) -> None:
        hostile_cases = (
            ("fetch('https://tracker.invalid/pixel');", "body { background: white; }", "./icon.svg", "const precacheAndRoute=()=>{};precacheAndRoute([{url:\"index.html\",revision:null}]);"),
            ("void 0;", "body { background: url('https://tracker.invalid/pixel'); }", "./icon.svg", "const precacheAndRoute=()=>{};precacheAndRoute([{url:\"index.html\",revision:null}]);"),
            ("void 0;", "body { color: white; }", "https://tracker.invalid/icon.svg", "const precacheAndRoute=()=>{};precacheAndRoute([{url:\"index.html\",revision:null}]);"),
            ("void 0;", "body { color: white; }", "./icon.svg", "importScripts('https://tracker.invalid/sw.js');"),
        )
        for app, css, icon, sw in hostile_cases:
            with self.subTest(app=app, css=css, icon=icon, sw=sw), tempfile.TemporaryDirectory(prefix="pulsebreak-static-hostile-") as temporary:
                root = pathlib.Path(temporary)
                write_fixture(root, app, css, icon, sw)
                server = MarkerServer(root, "a" * 40)
                try:
                    with self.assertRaises(AssertionError):
                        VERIFY.verify(server.url, "a" * 40)
                finally:
                    server.close()

    def test_static_graph_rejects_source_mapping_directive_and_orphan_map(self) -> None:
        hostile_cases = (
            ("directive", "//# sourceMappingURL=app.js.map\n"),
            ("orphan", "void 0;\n"),
        )
        for label, app in hostile_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="pulsebreak-source-map-hostile-") as temporary:
                root = pathlib.Path(temporary)
                write_fixture(root, app)
                (root / "app.js.map").write_text("{\"version\":3,\"sources\":[]}")
                track_fixture(root)
                server = MarkerServer(root, "a" * 40)
                try:
                    with self.assertRaises(AssertionError):
                        VERIFY.verify(server.url, "a" * 40, root)
                finally:
                    server.close()

    def test_static_graph_rejects_root_absolute_pwa_and_runtime_references(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-root-absolute-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "void 0;")
            (root / "index.html").write_text(
                (root / "index.html").read_text()
                .replace("./icon.svg", "/icon.svg")
                .replace("./style.css", "/style.css")
                .replace("./manifest.webmanifest", "/manifest.webmanifest")
                .replace("./app.js", "/app.js")
                .replace("./registerSW.js", "/registerSW.js")
            )
            (root / "manifest.webmanifest").write_text(
                (root / "manifest.webmanifest").read_text()
                .replace("./", "/")
                .replace("./icon.svg", "/icon.svg")
            )
            (root / "registerSW.js").write_text(
                "navigator.serviceWorker.register('/sw.js');\n"
            )
            (root / "sw.js").write_text(
                (root / "sw.js").read_text().replace('url:"', 'url:"/')
            )
            server = MarkerServer(root, "a" * 40)
            try:
                with self.assertRaises(AssertionError):
                    VERIFY.verify(server.url, "a" * 40)
            finally:
                server.close()

    def test_static_graph_rejects_incomplete_offline_precache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-precache-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(
                root,
                "void 0;",
                sw='const precacheAndRoute=()=>{};precacheAndRoute([{url:"index.html",revision:null}]);',
            )
            server = MarkerServer(root, "a" * 40)
            try:
                with self.assertRaises(AssertionError):
                    VERIFY.verify(server.url, "a" * 40)
            finally:
                server.close()

    def test_static_graph_rejects_comment_decoy_precache_entries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-precache-comment-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(
                root,
                "void 0;",
                sw=(
                    'const precacheAndRoute=()=>{};'
                    'precacheAndRoute([{url:"index.html",revision:null}]);'
                    '/* {url:"registerSW.js",revision:null},'
                    '{url:"manifest.webmanifest",revision:null},'
                    '{url:"icon.svg",revision:null},'
                    '{url:"support/index.html",revision:null},'
                    '{url:"privacy/index.html",revision:null},'
                    '{url:"style.css",revision:null},'
                    '{url:"app.js",revision:null} */'
                ),
            )
            server = MarkerServer(root, "a" * 40)
            try:
                with self.assertRaises(AssertionError):
                    VERIFY.verify(server.url, "a" * 40)
            finally:
                server.close()

    def test_static_graph_rejects_ambiguous_workbox_call_shapes(self) -> None:
        hostile_workers = (
            (
                "if(false)",
                fixture_precache_worker(
                    f'if(false){{precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);}}'
                    'precacheAndRoute([{url:"index.html",revision:null}]);'
                ),
            ),
            (
                "reordered multiple",
                fixture_precache_worker(
                    f'precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);'
                    'precacheAndRoute([{url:"index.html",revision:null}]);'
                ),
            ),
            (
                "short circuit",
                fixture_precache_worker(
                    f'false&&precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);'
                ),
            ),
            (
                "only conditional",
                fixture_precache_worker(
                    f'if(false){{precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);}}'
                ),
            ),
            (
                "ternary sibling",
                fixture_precache_worker(
                    f'condition?precacheAndRoute([{FULL_FIXTURE_PRECACHE}]):precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);'
                ),
            ),
        )
        for label, sw in hostile_workers:
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="pulsebreak-precache-ambiguous-hostile-") as temporary:
                root = pathlib.Path(temporary)
                write_fixture(root, "void 0;", sw=sw)
                server = MarkerServer(root, "a" * 40)
                try:
                    with self.assertRaises(AssertionError):
                        VERIFY.verify(server.url, "a" * 40)
                finally:
                    server.close()

    def test_browser_rejects_declared_precache_absent_from_installed_cache(self) -> None:
        partial_worker = (
            'const precacheAndRoute=entries=>{'
            'self.addEventListener("install",event=>event.waitUntil('
            'caches.open("partial").then(cache=>cache.addAll(entries.slice(0,1).map(entry=>new URL(entry.url,self.location).href)))'
            '.then(()=>self.skipWaiting())));'
            'self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));'
            '};'
            f'precacheAndRoute([{FULL_FIXTURE_PRECACHE}]);'
        )
        with tempfile.TemporaryDirectory(prefix="pulsebreak-cache-storage-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "void 0;", sw=partial_worker)
            track_fixture(root)
            server = MarkerServer(root, "a" * 40)
            try:
                static = VERIFY.verify(server.url, "a" * 40, root)
                with self.assertRaisesRegex(AssertionError, "Cache Storage"):
                    VERIFY.run_browser(server.url, set(static["precache_paths"]))
            finally:
                server.close()

    def test_static_graph_rejects_nonrelative_manifest_controls(self) -> None:
        hostile_cases = (
            ("start_url", "data:text/html,pulsebreak"),
            ("start_url", "blob:https://tracker.invalid/pulsebreak"),
            ("start_url", "//tracker.invalid/pulsebreak"),
            ("start_url", "https://tracker.invalid/pulsebreak"),
            ("start_url", "/support/"),
            ("icons", "data:image/svg+xml,pulsebreak"),
        )
        for field, value in hostile_cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory(prefix="pulsebreak-manifest-hostile-") as temporary:
                root = pathlib.Path(temporary)
                write_fixture(root, "void 0;")
                manifest = {
                    "name": "Pulsebreak",
                    "start_url": "./",
                    "scope": "./",
                    "icons": [{"src": "./icon.svg"}],
                }
                if field == "icons":
                    manifest["icons"][0]["src"] = value
                else:
                    manifest[field] = value
                (root / "manifest.webmanifest").write_text(json.dumps(manifest) + "\n")
                server = MarkerServer(root, "a" * 40)
                try:
                    with self.assertRaises(AssertionError):
                        VERIFY.verify(server.url, "a" * 40)
                finally:
                    server.close()

    def test_static_graph_rejects_modern_manifest_url_controls(self) -> None:
        hostile_cases = (
            ("share_target.action", {"share_target": {"action": "data:text/plain,share"}}),
            ("share_target.action root", {"share_target": {"action": "/share/"}}),
            ("share_target.action cross-origin", {"share_target": {"action": "https://tracker.invalid/share"}}),
            ("file_handlers action", {"file_handlers": [{"action": "//tracker.invalid/open"}]}),
            ("file_handlers data action", {"file_handlers": [{"action": "data:text/plain,open"}]}),
            ("scope_extensions origin", {"scope_extensions": [{"origin": "https://tracker.invalid"}]}),
            ("shortcuts url", {"shortcuts": [{"url": "/support/"}]}),
            ("protocol handler url", {"protocol_handlers": [{"url": "https://tracker.invalid/?url=%s"}]}),
            ("note taking URL", {"note_taking": {"new_note_url": "blob:https://tracker.invalid/note"}}),
        )
        for label, additions in hostile_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="pulsebreak-manifest-controls-hostile-") as temporary:
                root = pathlib.Path(temporary)
                write_fixture(root, "void 0;")
                manifest = {
                    "name": "Pulsebreak",
                    "start_url": "./",
                    "scope": "./",
                    "icons": [{"src": "./icon.svg"}],
                }
                manifest.update(additions)
                (root / "manifest.webmanifest").write_text(json.dumps(manifest) + "\n")
                server = MarkerServer(root, "a" * 40)
                try:
                    with self.assertRaises(AssertionError):
                        VERIFY.verify(server.url, "a" * 40)
                finally:
                    server.close()

    def test_static_graph_accepts_valid_modern_manifest_url_controls(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-manifest-controls-positive-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "void 0;")
            (root / "share/index.html").parent.mkdir()
            (root / "share/index.html").write_text("share\n")
            (root / "open/index.html").parent.mkdir()
            (root / "open/index.html").write_text("open\n")
            (root / "handle").write_text("handle\n")
            (root / "new/index.html").parent.mkdir()
            (root / "new/index.html").write_text("new\n")
            (root / "manifest.webmanifest").write_text(json.dumps({
                "name": "Pulsebreak",
                "start_url": "./",
                "scope": "./",
                "id": "./",
                "icons": [{"src": "./icon.svg"}],
                "screenshots": [{"src": "./icon.svg"}],
                "shortcuts": [{"url": "./support/"}],
                "share_target": {"action": "./share/"},
                "file_handlers": [{"action": "./open/"}],
                "scope_extensions": [{"origin": "./"}],
                "protocol_handlers": [{"url": "./handle?url=%s"}],
                "note_taking": {"new_note_url": "./new/"},
                "tab_strip": {"new_tab_button": {"url": "./support/"}},
            }) + "\n")
            for path in ("share/index.html", "open/index.html", "handle", "new/index.html"):
                add_precache_entry(root, path)
            server = MarkerServer(root, "a" * 40)
            try:
                assertions = VERIFY.verify(server.url, "a" * 40)
                self.assertIn("share/index.html", assertions["offline_graph"])
                self.assertIn("open/index.html", assertions["offline_graph"])
            finally:
                server.close()

    def test_browser_rejects_loaded_runtime_exception(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "throw new Error('fixture runtime failure');\n")
            server = MarkerServer(root, "a" * 40)
            try:
                VERIFY.verify(server.url, "a" * 40)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url)
            finally:
                server.close()

    def test_browser_rejects_dynamic_cross_origin_fetch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-origin-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "fetch(new Request(location.protocol + '//tracker.invalid/pixel'));\n")
            server = MarkerServer(root, "a" * 40)
            try:
                VERIFY.verify(server.url, "a" * 40)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url)
            finally:
                server.close()

    def test_browser_rejects_delayed_runtime_exception(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-delayed-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "setTimeout(() => { throw new Error('delayed fixture failure'); }, 1200);\n")
            server = MarkerServer(root, "a" * 40)
            try:
                VERIFY.verify(server.url, "a" * 40)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url)
            finally:
                server.close()

    def test_browser_rejects_delayed_computed_cross_origin_fetch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-delayed-origin-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(
                root,
                "setTimeout(() => fetch(new Request(location.protocol + '//tracker.invalid/pixel')), 1200);\n",
            )
            server = MarkerServer(root, "a" * 40)
            try:
                VERIFY.verify(server.url, "a" * 40)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url)
            finally:
                server.close()

    def test_browser_rejects_delayed_same_origin_resource_missing_precache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-offline-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(
                root,
                "setTimeout(() => fetch(new Request(location.protocol + '//' + location.host + '/late.json')), 1200);\n",
            )
            (root / "late.json").write_text('{"late":true}\n')
            track_fixture(root)
            server = MarkerServer(root, "a" * 40)
            try:
                static = VERIFY.verify(server.url, "a" * 40, root)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url, set(static["precache_paths"]))
            finally:
                server.close()

    def test_browser_accepts_delayed_same_origin_resource_in_precache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-runtime-offline-positive-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(
                root,
                "setTimeout(() => fetch(new Request(location.protocol + '//' + location.host + '/late.json')), 1200);\n",
            )
            (root / "late.json").write_text('{"late":true}\n')
            add_precache_entry(root, "late.json")
            track_fixture(root)
            server = MarkerServer(root, "a" * 40)
            try:
                static = VERIFY.verify(server.url, "a" * 40, root)
                browser = VERIFY.run_browser(server.url, set(static["precache_paths"]))
                VERIFY.merge_browser_offline_graph(static, browser)
                self.assertIn("late.json", browser["observed_offline_resources"])
                self.assertIn("late.json", static["offline_graph"])
            finally:
                server.close()

    def test_browser_rejects_service_worker_runtime_exception(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulsebreak-worker-hostile-") as temporary:
            root = pathlib.Path(temporary)
            write_fixture(root, "void 0;\n")
            (root / "sw.js").write_text(
                (root / "sw.js").read_text()
                + "self.addEventListener('install',()=>{throw new Error('worker failure')});\n"
            )
            server = MarkerServer(root, "a" * 40)
            try:
                VERIFY.verify(server.url, "a" * 40)
                with self.assertRaises(AssertionError):
                    VERIFY.run_browser(server.url)
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
