"""Verify unmatched Active Scan progress through an abrupt isolated restart.

Run: python3 tests/active_scan_recovery_smoke.py [directory containing sniper]
Only synthetic imported templates, a temporary session and loopback are used.
"""

import gzip
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
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
    raise AssertionError("Timed out waiting for the isolated Active Scan fixture")


def release():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, paths in [("progress", ["/first", "/waiting"]), ("fresh", ["/fresh"])]:
            template = (f"id: example-{name}\ninfo:\n  name: Example {name}\n  severity: info\n"
                        "http:\n  - method: GET\n    path: "
                        + json.dumps(["{{BaseURL}}" + path for path in paths])
                        + "\n    matchers:\n      - type: word\n        words: ['never-present']\n")
            data = template.encode()
            info = tarfile.TarInfo(f"example-templates-1/http/{name}.yaml")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    first_seen, second_seen = threading.Event(), threading.Event()
    first_release, second_release = threading.Event(), threading.Event()
    requests, request_lock = [], threading.Lock()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with request_lock:
                requests.append(self.path)
            if self.path == "/first":
                first_seen.set()
                first_release.wait(40)
            elif self.path == "/waiting":
                second_seen.set()
                second_release.wait(40)
            body = b"synthetic clean response"
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
    temporary = tempfile.TemporaryDirectory(prefix="sniper-active-scan-recovery-")
    process = None
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

        def api(path, body=None, raw=None):
            data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
            request = urllib.request.Request(ui + path, data=data, headers={
                "Content-Type": "application/gzip" if raw is not None else "application/json", "Origin": ui})
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        eventually(lambda: api("/api/templates/library")["state"] == "idle")
        api("/api/templates/library/import", raw=release())
        eventually(lambda: (status := api("/api/templates/library"))["state"] == "idle"
                   and status["templates"] == 2)
        session_id = api("/api/settings")["active_session"]["id"]
        query = f"?session_id={session_id}"

        def start(name):
            return api("/api/templates/scans", {"session_id": session_id,
                "targets": [f"http://127.0.0.1:{upstream.server_port}"],
                "ids": ["example-" + name], "acknowledged": True,
                "history": "matched", "rate": 50, "concurrency": 1})

        started = start("progress")
        identifier = started["id"]
        assert first_seen.wait(5), "The first local request did not start"

        def disk_job():
            try:
                snapshot = json.loads((data_dir / "sessions" / session_id / "state.json").read_text())
                return next((job for job in snapshot["template_scans"]["jobs"] if job["id"] == identifier), None)
            except (OSError, ValueError, KeyError):
                return None

        # Do not let the start/import checkpoint incidentally save later work.
        eventually(lambda: (job := disk_job()) and job["status"] == "running" and job["sent"] == 0)
        first_release.set()
        assert second_seen.wait(5), "The second local request did not start"
        live = eventually(lambda: (job := api(f"/api/templates/scans/{identifier}{query}"))
                          and job["sent"] == 1 and len(job["recent"]) == 1 and job)
        assert live["matched"] == 0 and not live.get("results", []), live
        saved = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            saved = disk_job()
            if saved and saved["sent"] == 1 and len(saved["recent"]) == 1:
                break
            time.sleep(0.02)
        print(json.dumps({"live_sent": live["sent"], "disk_sent_before_kill": saved["sent"] if saved else None}), flush=True)
        process.kill()  # A graceful shutdown must not rescue a missing checkpoint.
        process.wait(timeout=5)
        process = launch()
        ui = "http://" + eventually(ready)["ui_addr"]
        recovered = api(f"/api/templates/scans/{identifier}{query}")
        print(json.dumps({"recovered_status": recovered["status"], "recovered_sent": recovered["sent"],
                          "recovered_recent": len(recovered.get("recent", []))}), flush=True)
        assert recovered["status"] == "interrupted", recovered
        assert recovered["sent"] == 1 and len(recovered.get("recent", [])) == 1, "Completed unmatched progress was lost across abrupt restart"
        assert recovered["matched"] == 0 and not recovered.get("results", []), recovered
        assert recovered["recent"][0]["url"].endswith("/first"), recovered
        with request_lock:
            assert requests == ["/first", "/waiting"], requests
        eventually(lambda: api("/api/templates/library")["state"] == "idle")
        fresh = start("fresh")
        finished = eventually(lambda: (job := api(f"/api/templates/scans/{fresh['id']}{query}"))
                              and job["status"] == "completed" and job)
        assert finished["sent"] == 1 and finished["matched"] == 0, finished
        with request_lock:
            assert requests == ["/first", "/waiting", "/fresh"], requests
        print("Unmatched progress survived abrupt restart without resending; a fresh explicit scan completed.", flush=True)
    finally:
        first_release.set()
        second_release.set()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
