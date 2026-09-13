"""Exercise built executables against an isolated local upstream, including restart.

Run: python tests/runtime_smoke.py [directory containing the release binaries]
"""

import concurrent.futures
import http.client
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


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("synthetic:" + self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def eventually(operation, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        threading.Event().wait(0.05)
    raise AssertionError("Timed out waiting for the isolated runtime")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    child = None
    with tempfile.TemporaryDirectory(prefix="sniper-smoke-") as temporary:
        # Exercise non-ASCII names and spaces without touching the user's session.
        data = Path(temporary) / "space \uD55C\uAE00"
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", RUST_LOG="off")
        env.pop("SNIPER_API_ADDR", None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def start():
            process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=flags)

            def ready():
                assert process.poll() is None, "Headless runtime exited before becoming ready"
                try:
                    snapshot = json.loads((data / "runtime-state.json").read_text(encoding="utf-8"))
                    if snapshot["pid"] != process.pid:
                        return None
                    with opener.open("http://" + snapshot["ui_addr"] + "/api/settings", timeout=1):
                        return snapshot
                except (OSError, ValueError):
                    return None

            try:
                return process, eventually(ready)
            except BaseException:
                process.kill()
                process.wait(timeout=10)
                raise

        def api(path, payload=None, method=None):
            request = urllib.request.Request("http://" + runtime["ui_addr"] + path,
                data=None if payload is None else json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method=method)
            try:
                with opener.open(request, timeout=10) as response:
                    body = response.read()
                    return json.loads(body) if body else None
            except urllib.error.HTTPError as error:
                raise AssertionError(f"{request.get_method()} {path} failed: {error.code} {error.read().decode()}") from error

        def capture(path):
            proxy_host, proxy_port = runtime["proxy_addr"].rsplit(":", 1)
            connection = http.client.HTTPConnection(proxy_host, int(proxy_port), timeout=10)
            try:
                connection.request("GET", f"http://127.0.0.1:{upstream.server_port}{path}")
                response = connection.getresponse()
                assert response.status == 200
                assert response.read().decode() == "synthetic:" + path
            finally:
                connection.close()

        try:
            child, runtime = start()
            session_id = api("/api/settings")["active_session"]["id"]
            # The exported certificate path is authoritative across layouts.
            initial_ca = Path(api("/api/settings")["certificate"]["pem_path"]).read_bytes()
            cli = subprocess.run([str(binaries / ("sniper-cli" + suffix)), "session", "list"],
                                 env=env, capture_output=True, timeout=15, creationflags=flags)
            assert cli.returncode == 0, "CLI could not discover the running server"
            json.loads(cli.stdout)
            duplicate = subprocess.run([str(binaries / ("sniper" + suffix))], env=env,
                                       capture_output=True, timeout=10, creationflags=flags)
            assert duplicate.returncode != 0
            assert b"already using data dir" in duplicate.stderr
            print("PASS: startup, CLI discovery and exclusive data directory ownership", flush=True)

            capture("/first")
            first = eventually(lambda: next((r for r in api("/api/transactions") if r["path"] == "/first"), None))
            api("/api/runtime", {"intercept_enabled": True, "intercept_scope_only": False})
            with concurrent.futures.ThreadPoolExecutor() as pool:
                held = pool.submit(capture, "/held")
                eventually(lambda: api("/api/intercepts"))
                assert not held.done(), "Request was not held for interception"
                api("/api/intercepts/forward-all", {})
                held.result(timeout=10)
            api("/api/runtime", {"intercept_enabled": False})
            replay = api("/api/replay/send", {"session_id": session_id, "request": {
                "scheme": "http", "host": f"127.0.0.1:{upstream.server_port}",
                "method": "GET", "path": "/replay", "headers": [], "body": ""
            }})
            assert replay["response"]["body_preview"] == "synthetic:/replay"
            # Save a full snapshot after each journaled annotation to exercise body-locator rewrites.
            for note in ["before replacement", "after replacement"]:
                api(f"/api/transactions/{first['id']}/annotations", {"user_note": note}, "PATCH")
                api("/api/runtime", {"intercept_enabled": False})
            records = eventually(lambda: (rows if len(rows := api("/api/transactions")) >= 3 else None))
            print("PASS: HTTP capture, intercept forwarding, replay and atomic snapshot replacement", flush=True)

            # Kill and restart to validate disk recovery and OS lock release.
            child.kill()
            child.wait(timeout=10)
            child, runtime = start()
            assert Path(api("/api/settings")["certificate"]["pem_path"]).read_bytes() == initial_ca
            for record in records:
                restored = api(f"/api/transactions/{record['id']}")
                assert restored["response"]["body_preview"] == "synthetic:" + record["path"]
            restored_first = api(f"/api/transactions/{first['id']}")
            assert restored_first["user_note"] == "after replacement"
            capture("/after-restart")
            print("PASS: restart recovery, correct response bodies, annotations, CA reuse and capture after restart", flush=True)
            original_session = api("/api/settings")["active_session"]["id"]
            second = api("/api/sessions", {"name": "Windows lifecycle test"})
            api(f"/api/sessions/{original_session}/activate", {})
            api(f"/api/sessions/{second['id']}", method="DELETE")
            assert all(session["id"] != second["id"] for session in api("/api/sessions"))
            print("PASS: session creation, switching and deletion with cached journal writers", flush=True)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
