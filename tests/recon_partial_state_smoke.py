"""Check bounded Recon redirect status and restart persistence on loopback only.

Run: python3 tests/recon_partial_state_smoke.py [directory containing sniper]
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
    raise AssertionError("Timed out waiting for the local Recon fixture")


def main():
    binary_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    requests = []

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            location = None
            for prefix in ("/long/", "/loop/"):
                if self.path.startswith(prefix):
                    hop = int(self.path[len(prefix):])
                    if prefix == "/loop/" and hop == 5:
                        location = prefix + "0"
                    elif hop < 7:
                        location = prefix + str(hop + 1)
            if self.path == "/outside":
                location = f"http://localhost:{self.server.server_port}/never"
            self.send_response(302 if location else 200)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "0")
            self.end_headers()

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    with tempfile.TemporaryDirectory(prefix="sniper-recon-partial-") as temporary:
        data = Path(temporary)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)
        suffix = ".exe" if os.name == "nt" else ""

        def launch():
            nonlocal process
            process = subprocess.Popen([str(binary_dir / ("sniper" + suffix))], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            def ready():
                assert process.poll() is None, "Runtime exited before becoming ready"
                try:
                    runtime = json.loads((data / "runtime-state.json").read_text())
                    return runtime if runtime["pid"] == process.pid else None
                except (OSError, ValueError):
                    return None

            return "http://" + eventually(ready)["ui_addr"]

        def stop():
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        try:
            ui = launch()

            def api(path, payload=None):
                request = urllib.request.Request(ui + path,
                    data=None if payload is None else json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"})
                with opener.open(request, timeout=10) as response:
                    return json.load(response)

            sid = api("/api/settings")["active_session"]["id"]
            expected = {}
            for path, partial in (("/long/0", True), ("/loop/0", False), ("/outside", False)):
                offset = len(requests)
                job = api("/api/recon/jobs", {"session_id": sid, "target_url": origin + path,
                          "sources": ["crawler"], "max_requests": 32})

                def completed():
                    snapshot = api("/api/recon?session_id=" + sid)
                    current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
                    return current if current["status"] != "running" else None

                current = eventually(completed)
                source = current["sources"][0]
                assert current["status"] == "completed", current
                assert source["truncated"] is partial, source
                assert source["requests"] == len(requests) - offset, source
                assert any("Collection is partial" in warning for warning in source["warnings"]) is partial
                assert not any(url in ("/long/6", "/loop/6", "/never") for url in requests)
                expected[job["id"]] = partial
                print(json.dumps({"case": path, "partial": partial, "requests": source["requests"]}), flush=True)

            def persisted():
                for state_file in data.rglob("state.json"):
                    if state_file.parent.name != sid:
                        continue
                    try:
                        saved = json.loads(state_file.read_text())["recon"]["jobs"]
                        flags = {item["id"]: item["sources"][0]["truncated"] for item in saved}
                        return all(flags.get(key) is value for key, value in expected.items())
                    except (OSError, ValueError, KeyError):
                        pass
                return False

            eventually(persisted)
            stop()
            ui = launch()
            restored = api("/api/recon?session_id=" + sid)["jobs"]
            for job in restored:
                if job["id"] in expected:
                    assert job["status"] == "completed"
                    assert job["sources"][0]["truncated"] is expected[job["id"]]
            assert expected.keys() <= {job["id"] for job in restored}
            print("Redirect partial-state flags survived persisted process restart.", flush=True)
        finally:
            stop()
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
