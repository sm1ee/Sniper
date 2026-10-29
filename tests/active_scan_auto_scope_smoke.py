"""Verify that a running auto scan uses its current host list and Scope.

Run: python3 tests/active_scan_auto_scope_smoke.py [directory containing sniper]
Only synthetic imported templates, a temporary session and loopback are used.
"""

from contextlib import closing
import gzip
import http.client
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
    raise AssertionError("Timed out waiting for the isolated auto-scan fixture")


def release():
    template = b"""id: example-auto-boundary
info:
  name: Example auto boundary
  severity: info
http:
  - method: GET
    path: ['{{BaseURL}}/first', '{{BaseURL}}/second']
    stop-at-first-match: false
    matchers:
      - type: word
        words: ['synthetic match']
"""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        info = tarfile.TarInfo("example-templates-1/http/boundary.yaml")
        info.size = len(template)
        archive.addfile(info, io.BytesIO(template))
    return gzip.compress(raw.getvalue())


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="sniper-active-auto-scope-") as temporary:
        data_dir = Path(temporary)
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
        try:
            def ready():
                assert process.poll() is None, "Runtime exited before becoming ready"
                try:
                    runtime = json.loads((data_dir / "runtime-state.json").read_text())
                    return runtime if runtime["pid"] == process.pid else None
                except (OSError, ValueError):
                    return None

            runtime = eventually(ready)
            ui = "http://" + runtime["ui_addr"]

            def api(path, body=None, raw=None):
                data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
                request = urllib.request.Request(ui + path, data=data, headers={
                    "Content-Type": "application/gzip" if raw is not None else "application/json", "Origin": ui})
                with opener.open(request, timeout=10) as response:
                    return json.load(response)

            eventually(lambda: api("/api/templates/library")["state"] == "idle")
            api("/api/templates/library/import", raw=release())
            eventually(lambda: (status := api("/api/templates/library"))["state"] == "idle"
                       and status["templates"] == 1)
            api("/api/templates/auto/templates", {"ids": ["example-auto-boundary"], "enabled": True})
            session_id = api("/api/settings")["active_session"]["id"]
            query = f"?session_id={session_id}"

            def scenario(in_scope):
                first_seen, first_release = threading.Event(), threading.Event()
                requests, request_lock = [], threading.Lock()

                class Fixture(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_):
                        pass

                    def do_GET(self):
                        with request_lock:
                            requests.append(self.path)
                        if self.path == "/first":
                            first_seen.set()
                            first_release.wait(20)
                        body = b"synthetic match"
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
                origin = f"http://127.0.0.1:{upstream.server_port}"

                def capture(path):
                    host, port = runtime["proxy_addr"].rsplit(":", 1)
                    with closing(http.client.HTTPConnection(host, int(port), timeout=10)) as connection:
                        connection.request("GET", origin + path)
                        response = connection.getresponse()
                        response.read()
                        assert response.status == 200, response.status

                def auto(hosts):
                    return api("/api/templates/auto", {"session_id": session_id, "enabled": True,
                        "acknowledged": True, "hosts": hosts, "rate": 50, "concurrency": 1})

                try:
                    api("/api/runtime", {"scope_patterns": ["127.0.0.1"] if in_scope else [],
                                         "excluded_scope_patterns": []})
                    auto(["127.0.0.1"])
                    capture("/capture")
                    assert first_seen.wait(5), "The auto scan did not send its first request"
                    job = next(job for job in api("/api/templates/scans" + query)["jobs"] if job["targets"] == [origin])
                    assert job["auto"] and job["status"] == "running", job
                    status = auto([])
                    assert status["enabled"] and status["hosts"] == [], status
                    first_release.set()
                    identifier = job["id"]
                    job = eventually(lambda: (job := api(f"/api/templates/scans/{identifier}{query}"))
                                     and job["status"] != "running" and job)
                    expected = 2 if in_scope else 1
                    with request_lock:
                        sent_paths = [path for path in requests if path in ("/first", "/second")]
                    print(json.dumps({"ambient_scope": in_scope, "sent_paths": sent_paths,
                                      "sent": job["sent"], "matched": job["matched"],
                                      "blocked": job["blocked"]}), flush=True)
                    assert sent_paths == ["/first", "/second"][:expected], "The removed host received a later auto-scan request"
                    assert job["status"] == "completed" and job["sent"] == expected, job
                    assert job["matched"] == expected and len(job.get("results", [])) == expected, job
                    assert len(job.get("recent", [])) == expected and job["blocked"] == int(not in_scope), job
                    first = next(result for result in job["results"] if result["url"].endswith("/first"))
                    record = api(f"/api/transactions/{first['record_id']}")
                    assert record["response"]["body_preview"] == "synthetic match", record
                    before = [item["id"] for item in api("/api/templates/scans" + query)["jobs"]]
                    auto(["127.0.0.1"])
                    capture("/capture-again")
                    # Reallowing and recapturing an already scanned origin must
                    # not resume the completed job or queue an implicit retry.
                    deadline = time.monotonic() + 1
                    while time.monotonic() < deadline:
                        assert [item["id"] for item in api("/api/templates/scans" + query)["jobs"]] == before
                        assert api("/api/templates/auto" + query)["queued"] == 0
                        with request_lock:
                            assert [path for path in requests if path in ("/first", "/second")] == sent_paths
                        time.sleep(0.02)
                finally:
                    first_release.set()
                    upstream.shutdown()
                    upstream.server_close()

            scenario(True)  # Ambient Scope remains an independent permission.
            scenario(False)
            print("Live auto-host narrowing kept completed evidence and did not implicitly resume.", flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
