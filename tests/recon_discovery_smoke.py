"""Verify bounded Recon extraction against disposable loopback fixtures only.

Run: python tests/recon_discovery_smoke.py [directory containing sniper]
"""

import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def eventually(operation, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for isolated Recon fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    types = {
        "javascript": "application/javascript", "text-javascript": "text/javascript",
        "ecmascript": "application/ecmascript", "text-ecmascript": "text/ecmascript",
        "mixed-ecmascript": "APPLICATION/ECMASCRIPT; charset=UTF-8",
        "parameter-javascript": "text/javascript; charset=utf-8", "legacy-javascript": "application/x-javascript",
        "missing.js": None, "unsupported.js": "application/octet-stream",
    }
    cases = {name: (False, name != "unsupported.js") for name in types}
    cases.update({"tags-before": (False, True), "tags-exact": (False, False), "tags-after": (True, False)})
    requested = []
    slow_started, release_slow = threading.Event(), threading.Event()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requested.append(self.path)
            content_type, body = "text/plain", b""
            if self.path.startswith("/case/"):
                name = self.path.removeprefix("/case/")
                content_type = "text/html"
                if name in types:
                    body = f'<script src="/script/{name}"></script>'.encode()
                else:
                    count = 4999 if name == "tags-before" else 5000
                    body = b"<span></span>" * count
                    if name != "tags-exact":
                        body += f'<a href="/found/{name}">link</a>'.encode()
            elif self.path.startswith("/script/"):
                name = self.path.removeprefix("/script/")
                content_type = types[name]
                body = f'fetch("/found/{name}")'.encode()
            elif self.path == "/slow":
                slow_started.set()
                release_slow.wait(10)
                content_type, body = "text/html", b'<a href="/after-stop">late</a>'
            self.send_response(200)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    temporary = tempfile.TemporaryDirectory(prefix="sniper-recon-discovery-")
    try:
        data = Path(temporary.name)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        env.pop("SNIPER_API_ADDR", None)
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
            env.pop(key, None)
        suffix = ".exe" if os.name == "nt" else ""
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                state = json.loads((data / "runtime-state.json").read_text())
                return state if state["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        runtime = eventually(ready)
        ui = "http://" + runtime["ui_addr"]

        def api(path, payload=None):
            request = urllib.request.Request(ui + path, data=None if payload is None else json.dumps(payload).encode(),
                                             headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        sid = api("/api/settings")["active_session"]["id"]
        with opener.open(ui + "/recon.js", timeout=10) as response:
            assert response.read() == (Path(__file__).resolve().parents[1] / "web/recon.js").read_bytes(), "Embedded Recon UI differs from tested source"

        def start(path):
            return api("/api/recon/jobs", {"session_id": sid, "target_url": origin + path,
                       "sources": ["crawler"], "max_requests": 8, "max_depth": 3, "max_endpoints": 5000})

        def completed(job):
            snapshot = api("/api/recon?session_id=" + sid)
            current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
            return (current, snapshot) if current["status"] != "running" else None

        failures, results = [], []
        for name, (clipped, found) in cases.items():
            before = api("/api/recon?session_id=" + sid)
            offset = len(requested)
            job = start("/case/" + name)
            job, snapshot = eventually(lambda: completed(job))
            source = job["sources"][0]
            paths = requested[offset:]
            endpoints = snapshot["endpoints"]
            checks = {
                "completed": job["status"] == "completed" and source["status"] == "completed",
                "truncation": source["truncated"] == clipped,
                "endpoint": any(item["url"] == origin + "/found/" + name for item in endpoints) == found,
                "requests": source["requests"] == len(paths),
                "discovered": source["discovered"] == len(endpoints) - len(before["endpoints"]),
                "static_only": ("/found/" + name in paths) == (name == "tags-before"),
                "bounded_warning": any("Collection was bounded" in warning for warning in source["warnings"]) == clipped,
                "extraction_warning": any("extraction limit" in warning for warning in source["warnings"]) == clipped,
            }
            failed = [key for key, passed in checks.items() if not passed]
            failures.extend(f"{name}: {key}" for key in failed)
            results.append({"case": name, "checks": checks, "job": job, "requested_paths": paths, "snapshot": snapshot})
            print(json.dumps({"case": name, "requests": source["requests"], "discovered": source["discovered"],
                              "truncated": source["truncated"], "failed": failed}), flush=True)

        job = start("/slow")
        assert slow_started.wait(5), "Slow fixture was not requested"
        stopped = api("/api/recon/jobs/" + job["id"] + "/stop", {"session_id": sid})
        assert stopped["stopped"]
        current, _ = eventually(lambda: completed(job))
        assert current["status"] == "cancelled", current
        release_slow.set()
        next_job = start("/after-cancel")
        current, snapshot = eventually(lambda: completed(next_job))
        assert current["status"] == "completed"
        assert "/after-stop" not in requested
        assert not any(item["url"] == origin + "/after-stop" for item in snapshot["endpoints"])
        print("Cancellation discards late work and permits a fresh completed job.", flush=True)
        if output := os.environ.get("SNIPER_RECON_SMOKE_RESULTS"):
            Path(output).write_text(json.dumps(results, indent=2) + "\n")
        assert not failures, "; ".join(failures)
        print(f"All {len(cases)} extraction fixtures and cancellation passed.", flush=True)
    finally:
        release_slow.set()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
