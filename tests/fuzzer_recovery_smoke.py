"""Verify Fuzzer checkpoints through an abrupt isolated runtime restart.

Run: python3 tests/fuzzer_recovery_smoke.py [directory containing sniper]
Only a temporary session and a loopback HTTP fixture are used.
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
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for the isolated Fuzzer fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    waiting, release = threading.Event(), threading.Event()
    requests, request_lock = [], threading.Lock()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with request_lock:
                requests.append(self.path)
            if self.path == "/waiting":
                waiting.set()
                release.wait(30)
            body = b"synthetic fuzzer response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    temporary = tempfile.TemporaryDirectory(prefix="sniper-fuzzer-recovery-")
    try:
        data_dir = Path(temporary.name)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data_dir), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)

        def launch():
            suffix = ".exe" if os.name == "nt" else ""
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            return subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=flags)

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                runtime = json.loads((data_dir / "runtime-state.json").read_text())
                return runtime if runtime["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        process = launch()
        ui = "http://" + eventually(ready)["ui_addr"]

        def api(path, body=None):
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(ui + path, data=data,
                                             headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        session_id = api("/api/settings")["active_session"]["id"]

        def start(payloads):
            return api("/api/fuzzer/attacks", {
                "session_id": session_id,
                "template": {"scheme": "http", "host": f"127.0.0.1:{upstream.server_port}",
                             "method": "GET", "path": "/$payload$", "headers": [],
                             "body": "", "body_encoding": "utf8", "preview_truncated": False},
                "payloads": payloads, "attack_type": "battering_ram", "url_encode": True,
                "concurrency": 1,
            })

        def attack(identifier):
            return api(f"/api/fuzzer/attacks/{identifier}?session_id={session_id}")

        started = start(["completed", "waiting", "never"])
        assert waiting.wait(5), "The second local request did not start"

        def checkpoint():
            try:
                saved = json.loads((data_dir / "sessions" / session_id / "state.json").read_text())
                result = next((item for item in saved["fuzzer_attacks"] if item["id"] == started["id"]), None)
                return result if result and len(result["results"]) == 1 else None
            except (OSError, ValueError, KeyError):
                return None

        saved = eventually(checkpoint)
        assert saved["stopped"] and not saved.get("running", False), saved
        assert attack(started["id"])["running"], "The checkpoint stopped the live worker"
        process.kill()  # No graceful shutdown or final save can rescue the result.
        process.wait(timeout=5)
        process = launch()
        ui = "http://" + eventually(ready)["ui_addr"]
        recovered = attack(started["id"])
        assert recovered["stopped"] and not recovered.get("running", False), recovered
        assert recovered["planned"] == 3 and len(recovered["results"]) == 1, recovered
        result = recovered["results"][0]
        assert result["payload"] == "completed" and result["status"] == 200, result
        transaction = api(f'/api/transactions/{result["transaction_id"]}?session_id={session_id}')
        assert transaction["path"] == "/completed"
        assert "synthetic fuzzer response" in transaction["response"]["body_preview"]
        with request_lock:
            assert requests == ["/completed", "/waiting"], requests
        print("Abrupt process restart retained the completed result and readable transaction without resuming the attack.", flush=True)

        fresh = start(["fresh"])
        def fresh_finished():
            value = attack(fresh["id"])
            return value if not value.get("running", False) else None

        finished = eventually(fresh_finished)
        assert len(finished["results"]) == 1 and finished["results"][0]["status"] == 200, finished
        with request_lock:
            assert requests == ["/completed", "/waiting", "/fresh"], requests
        print("A fresh explicit attack ran after recovery; no old payload was resent.", flush=True)
    finally:
        release.set()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
