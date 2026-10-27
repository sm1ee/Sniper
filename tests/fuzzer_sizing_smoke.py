"""Check Fuzzer's mode-specific request-size admission with a loopback fixture.

Run: python3 tests/fuzzer_sizing_smoke.py [directory containing sniper]
Uses a temporary data directory. The oversized-template case must be rejected
by planning; it does not exercise the separate last-moment send guard directly.
"""

import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for the isolated Fuzzer sizing fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    received, received_lock = [], threading.Lock()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            # No test expects a large request. Refuse it without reading or
            # retaining its body if the admission regression ever returns.
            if size > 128 * 1024:
                with received_lock:
                    received.append((self.path, size, "oversized"))
                self.send_error(413)
                return
            body = self.rfile.read(size)
            with received_lock:
                received.append((self.path, len(body), hashlib.sha256(body).hexdigest()))
            reply = b"synthetic sizing response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            try:
                self.wfile.write(reply)
            except (BrokenPipeError, ConnectionResetError):
                pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    temporary = tempfile.TemporaryDirectory(prefix="sniper-fuzzer-sizing-")
    try:
        data_dir = Path(temporary.name)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data_dir), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)
        suffix = ".exe" if os.name == "nt" else ""
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=flags)

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                runtime = json.loads((data_dir / "runtime-state.json").read_text())
                return runtime if runtime["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        ui = "http://" + eventually(ready)["ui_addr"]

        def api(path, body=None, expected=200):
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(ui + path, data=data,
                                             headers={"Content-Type": "application/json"})
            try:
                with opener.open(request, timeout=20) as response:
                    status, raw = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, raw = error.code, error.read()
            assert status == expected, (path, status, raw[:300].decode(errors="replace"))
            return json.loads(raw) if expected == 200 else raw.decode()

        session_id = api("/api/settings")["active_session"]["id"]

        def start(body, payload, mode, path, expected=200):
            return api("/api/fuzzer/attacks", {
                "session_id": session_id,
                "template": {"scheme": "http", "host": f"127.0.0.1:{upstream.server_port}",
                             "method": "POST", "path": path, "headers": [],
                             "body": body, "body_encoding": "utf8", "preview_truncated": False},
                "payloads": [payload], "attack_type": mode, "url_encode": False,
                "concurrency": 1,
            }, expected)

        def finished(identifier):
            value = api(f"/api/fuzzer/attacks/{identifier}?session_id={session_id}")
            return value if not value.get("running", False) else None

        payload = "x" * (64 * 1024)
        started = start("$payload$" * 65, payload, "sniper", "/selected")
        assert started["planned"] == 65 and started["marker_count"] == 65, started
        completed = eventually(lambda: finished(started["id"]))
        assert not completed.get("stopped", False) and completed["status"] == "completed"
        results = completed["results"]
        assert len(results) == 65 and [row["position"] for row in results] == list(range(65))
        assert all(row["status"] == 200 and row.get("transaction_id") for row in results)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with received_lock:
            assert received == [("/selected", len(payload), digest)] * 65, received
        print("Sniper admitted 65 selected-position requests; each sent exactly one 64KiB payload.", flush=True)

        for body, value, mode, path in (
            ("$payload$" * 65, payload, "battering_ram", "/all-over-limit"),
            ("$payload$§" + "o" * (4 * 1024 * 1024) + "§", "x", "sniper", "/original-over-limit"),
        ):
            error = start(body, value, mode, path, expected=400)
            assert "4194304" in error and "limit" in error, error
            assert [row["id"] for row in api(f"/api/fuzzer/attacks?session_id={session_id}")] == [started["id"]]
        with received_lock:
            assert len(received) == 65, received
        print("All-position expansion and oversized preserved originals were rejected before any fixture request.", flush=True)

        control = start("$payload$§old§", "ok", "battering_ram", "/control")
        control = eventually(lambda: finished(control["id"]))
        assert control["planned"] == 1 and len(control["results"]) == 1
        assert control["results"][0]["status"] == 200
        with received_lock:
            assert received == [("/selected", len(payload), digest)] * 65 + [
                ("/control", 4, hashlib.sha256(b"okok").hexdigest())
            ], received
        print("A subsequent explicit Battering ram control sent once with both positions filled; rejected attacks sent nothing.", flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
