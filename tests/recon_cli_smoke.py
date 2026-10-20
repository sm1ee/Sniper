"""Exercise the Recon operator CLI against an isolated runtime and local origin.

Run: python3 tests/recon_cli_smoke.py [directory containing sniper and sniper-cli]
No provider source, third-party target, real session or installed skill is used.
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


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for isolated Recon CLI fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    requests = []
    request_lock = threading.Lock()
    slow_started = {path: threading.Event() for path in ("/slow-cancel", "/slow-restart")}
    release_slow = threading.Event()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with request_lock:
                requests.append(self.path)
            content_type, body = "text/plain", b""
            if self.path == "/start":
                content_type = "text/html"
                body = (
                    b'<a href="/page?first=1&amp;second=2">page</a>'
                    b'<script>fetch("/candidate?first=1&second=2")</script>'
                    b'<form method="post" action="/form"><input name="example"></form>'
                )
            elif self.path.startswith("/page?"):
                body = b"local fixture"
            elif self.path in slow_started:
                slow_started[self.path].set()
                release_slow.wait(60)
                content_type = "text/html"
                body = b'<a href="/after-stop">late reference</a>'
            self.send_response(200)
            self.send_header("Content-Type", content_type)
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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    temporary = tempfile.TemporaryDirectory(prefix="sniper-recon-cli-")
    try:
        data_dir = Path(temporary.name)
        env = dict(
            os.environ,
            SNIPER_DATA_DIR=str(data_dir),
            SNIPER_UI_ADDR="127.0.0.1:0",
            SNIPER_PROXY_ADDR="127.0.0.1:0",
            SNIPER_INSTALL_AGENT_SKILLS="0",
            SNIPER_INSTALL_CLI_PATH="0",
            RUST_LOG="off",
        )
        for key in (
            "SNIPER_API_ADDR", "URLSCAN_API_KEY", "HTTP_PROXY", "HTTPS_PROXY",
            "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
        ):
            env.pop(key, None)

        def launch():
            return subprocess.Popen(
                [str(binaries / ("sniper" + suffix))], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
            )

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                runtime = json.loads((data_dir / "runtime-state.json").read_text())
                return runtime if runtime["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        process = launch()
        ui = "http://" + eventually(ready)["ui_addr"]

        def api(path):
            with opener.open(ui + path, timeout=10) as response:
                return json.load(response)

        session_id = api("/api/settings")["active_session"]["id"]

        def call(operation, payload, flag=None, expected_error=None):
            command = [
                str(binaries / ("sniper-cli" + suffix)), "--api", ui, "--output", "compact",
                "call", operation, "--input", json.dumps(payload),
            ]
            if flag is not None:
                command.append(flag)
            output = subprocess.run(
                command, env=env, capture_output=True, text=True, timeout=15,
                creationflags=flags, check=False,
            )
            envelope = json.loads(output.stdout)
            assert envelope["operation"] == operation, envelope
            if expected_error is not None:
                assert output.returncode != 0 and envelope["ok"] is False, envelope
                assert envelope["error"]["code"] == expected_error, envelope
            else:
                assert output.returncode == 0 and envelope["ok"] is True, (
                    envelope, output.stderr
                )
                if flag != "--dry-run":
                    assert envelope["meta"]["session_id"] == session_id, envelope
            return envelope

        def inventory():
            return call("recon.list", {"session_id": session_id})["data"]

        def start_input(path):
            return {
                "session_id": session_id, "target_url": origin + path,
                "sources": ["crawler"], "max_requests": 10, "max_depth": 2,
                "max_endpoints": 20, "max_pages": 1,
            }

        def start(path):
            payload = start_input(path)
            plan = call("recon.start", payload, "--dry-run")["data"]
            assert plan["dry_run"] is True
            assert plan["api"]["method"] == "POST"
            assert plan["api"]["path"] == "/api/recon/jobs"
            assert plan["api"]["body"]["session_id"] == session_id
            assert plan["api"]["body"]["sources"] == ["crawler"]
            return call("recon.start", payload, "--yes")["data"]

        def finished(job_id):
            snapshot = inventory()
            job = next(job for job in snapshot["jobs"] if job["id"] == job_id)
            return (job, snapshot) if job["status"] != "running" else None

        assert inventory() == {"session_id": session_id, "jobs": [], "endpoints": []}
        call("recon.start", start_input("/start"), expected_error="CONFIRMATION_REQUIRED")
        assert inventory()["jobs"] == []
        assert requests == [], "Unconfirmed start sent target traffic"

        started = start("/start")
        completed_job, completed_snapshot = eventually(lambda: finished(started["id"]))
        assert completed_job["status"] == "completed", completed_job
        source = completed_job["sources"][0]
        assert source["source"] == "crawler" and source["status"] == "completed", source
        assert source["truncated"] is False, source
        assert any("Static extraction only" in warning for warning in source["warnings"]), source
        assert not any("Collection is partial" in warning for warning in source["warnings"]), source
        assert 0 < source["requests"] <= 10, source
        endpoints = {item["url"]: item for item in completed_snapshot["endpoints"]}
        assert source["discovered"] == len(endpoints) <= 20, source
        assert any(
            evidence["kind"] == "live" and evidence["status"] == 200
            for evidence in endpoints[origin + "/page?first=1&second=2"]["evidence"]
        )
        assert any(
            evidence["kind"] == "candidate"
            for evidence in endpoints[origin + "/candidate?first=1&second=2"]["evidence"]
        )
        with request_lock:
            assert not any(path.startswith(("/candidate", "/form")) for path in requests)
            assert source["requests"] == len(requests)
        assert api("/api/transactions?session_id=" + session_id) == []
        print("Structured CLI start/list preserved budgets and live/candidate evidence without captured traffic.", flush=True)

        cancelled = start("/slow-cancel")
        assert slow_started["/slow-cancel"].wait(5), "Slow cancellation fixture was not requested"
        stop_input = {"session_id": session_id, "id": cancelled["id"]}
        call("recon.stop", stop_input, expected_error="CONFIRMATION_REQUIRED")
        stop_plan = call("recon.stop", stop_input, "--dry-run")["data"]
        assert stop_plan["api"]["path"] == f'/api/recon/jobs/{cancelled["id"]}/stop'
        assert stop_plan["api"]["body"] == {"session_id": session_id}
        assert next(job for job in inventory()["jobs"] if job["id"] == cancelled["id"])["status"] == "running"
        assert call("recon.stop", stop_input, "--yes")["data"] == {
            "stopped": True, "session_id": session_id,
        }
        cancelled_job, cancelled_snapshot = eventually(lambda: finished(cancelled["id"]))
        assert cancelled_job["status"] == "cancelled", cancelled_job
        assert cancelled_job["sources"][0]["status"] == "cancelled", cancelled_job
        assert cancelled_snapshot["endpoints"] == completed_snapshot["endpoints"]
        print("Unconfirmed stop and dry-run left the job running; confirmed stop cancelled only its local work.", flush=True)

        interrupted = start("/slow-restart")
        assert slow_started["/slow-restart"].wait(5), "Slow restart fixture was not requested"
        before_restart = inventory()
        expected_stored = {key: before_restart[key] for key in ("jobs", "endpoints")}

        # Wait for the actual atomic debounced save, not just an in-memory read.
        def persisted():
            for path in data_dir.rglob("state.json"):
                if path.parent.name != session_id:
                    continue
                try:
                    if json.loads(path.read_text())["recon"] == expected_stored:
                        return True
                except (OSError, ValueError, KeyError):
                    pass
            return False

        eventually(persisted)
        with request_lock:
            request_count = len(requests)
        process.kill()
        process.wait(timeout=10)
        process = launch()
        ui = "http://" + eventually(ready)["ui_addr"]
        assert api("/api/settings")["active_session"]["id"] == session_id
        after_restart = inventory()
        assert after_restart["endpoints"] == completed_snapshot["endpoints"]
        restored_jobs = {job["id"]: job for job in after_restart["jobs"]}
        assert restored_jobs[completed_job["id"]] == completed_job
        assert restored_jobs[cancelled_job["id"]] == cancelled_job
        assert restored_jobs[interrupted["id"]]["status"] == "interrupted"
        assert restored_jobs[interrupted["id"]]["finished_at"] is not None
        assert restored_jobs[interrupted["id"]]["sources"][0]["status"] == "interrupted"
        release_slow.set()
        assert inventory() == after_restart
        with request_lock:
            assert len(requests) == request_count, "Restart resumed network work"
            assert "/after-stop" not in requests, "Stopped job followed a late response"
        assert api("/api/transactions?session_id=" + session_id) == []
        print("Restart restored inventory, retained completed/cancelled jobs, and marked unfinished work interrupted without resuming it.", flush=True)
        print("Recon CLI lifecycle smoke passed using loopback only.", flush=True)
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
