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
    interrupted_case = sys.argv[2] if len(sys.argv) > 2 else None
    requests = []
    barrier_path = None
    seed_started = threading.Event()
    seed_release = threading.Event()
    robots_started = threading.Event()
    robots_release = threading.Event()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            if self.path == barrier_path:
                seed_started.set()
                assert seed_release.wait(20), "Initial-state persistence gate did not open"
            elif self.path == "/robots.txt" and barrier_path:
                robots_started.set()
                assert robots_release.wait(20), "Stopped-request gate did not open"
            location = None
            for prefix in ("/long/", "/loop/", "/stalled/"):
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
            self.send_header("Content-Type", "application/octet-stream" if self.path == "/binary" else "text/plain")
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

            def persisted_snapshot():
                for state_file in data.rglob("state.json"):
                    if state_file.parent.name == sid:
                        try:
                            return json.loads(state_file.read_text())["recon"]
                        except (OSError, ValueError, KeyError):
                            pass
                return {"jobs": [], "endpoints": []}

            def source_for(snapshot, job_id):
                return next((item for item in snapshot["jobs"] if item["id"] == job_id), None)

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
                expected[job["id"]] = (partial, "completed")
                print(json.dumps({"case": path, "partial": partial, "requests": source["requests"]}), flush=True)

            for name, path, partial in (("redirect", "/stalled/0", True), ("binary", "/binary", False)):
                if interrupted_case and interrupted_case != name:
                    continue
                barrier_path = path
                for event in (seed_started, seed_release, robots_started, robots_release):
                    event.clear()
                offset = len(requests)
                job = api("/api/recon/jobs", {"session_id": sid, "target_url": origin + path,
                          "sources": ["crawler"], "max_requests": 32})
                assert seed_started.wait(10)
                # Flush the initial job before allowing the first response, so
                # an earlier pending write cannot mask a missing crawl checkpoint.
                eventually(lambda: source_for(persisted_snapshot(), job["id"]))
                seed_release.set()
                assert robots_started.wait(10)
                current = source_for(api("/api/recon?session_id=" + sid), job["id"])
                assert current["status"] == "running", current
                assert current["sources"][0]["truncated"] is partial, current

                def evidence_checkpointed():
                    snapshot = persisted_snapshot()
                    saved = source_for(snapshot, job["id"])
                    return (saved and saved["sources"][0]["truncated"] is partial
                            and any(item["url"] == origin + path for item in snapshot["endpoints"]))

                eventually(evidence_checkpointed, timeout=10)
                stopped = api("/api/recon/jobs/" + job["id"] + "/stop", {"session_id": sid})
                assert stopped["stopped"]
                robots_release.set()
                current = source_for(api("/api/recon?session_id=" + sid), job["id"])
                source = current["sources"][0]
                assert current["status"] == "cancelled", current
                assert source["truncated"] is partial, source
                assert source["requests"] == len(requests) - offset, source
                assert sum("redirect" in warning for warning in source["warnings"]) == int(partial)
                assert "/stalled/6" not in requests
                expected[job["id"]] = (partial, "cancelled")
                barrier_path = None
                print(json.dumps({"case": name + "-stopped", "partial": partial,
                                  "requests": source["requests"], "checkpointed_before_stop": True}), flush=True)

            def persisted():
                saved = persisted_snapshot()["jobs"]
                flags = {item["id"]: (item["sources"][0]["truncated"], item["status"]) for item in saved}
                return all(flags.get(key) == value for key, value in expected.items())

            eventually(persisted)
            stop()
            ui = launch()
            restored = api("/api/recon?session_id=" + sid)["jobs"]
            for job in restored:
                if job["id"] in expected:
                    partial, status = expected[job["id"]]
                    assert job["status"] == status
                    assert job["sources"][0]["truncated"] is partial
            assert expected.keys() <= {job["id"] for job in restored}
            print("Redirect partial-state flags survived persisted process restart.", flush=True)
        finally:
            seed_release.set()
            robots_release.set()
            stop()
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
