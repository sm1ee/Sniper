"""Check complete gzip members through capture, rewrite, held forwarding and restart.

Run against a built headless binary (default target/release/sniper):
  python3 tests/gzip_members_smoke.py [path/to/sniper] \
    [--binary-sha256 EXPECTED_SHA256] [--evidence-dir NEW_EMPTY_OUTPUT_DIRECTORY]
Exit 0: all integrity checks pass. Exit 1: intact-wire controls pass, but at least
one full-body integrity assertion fails. Exit 2: fixture/control/setup failure.
No browser, CLI workspace mutation, Cargo, or external origin is used.
"""

import argparse
import concurrent.futures
import datetime
import gzip
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import traceback


FIRST = b"alpha=one;"
SECOND = b"beta=two;"
FULL = FIRST + SECOND
CHANGED = FULL.replace(b"one", b"changed")
PATHS = {"/no-rules", "/nonmatching-request", "/nonmatching-response",
         "/matching-request", "/matching-response", "/held-forward-all"}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def eventually(operation, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        threading.Event().wait(0.05)
    raise AssertionError("Timed out waiting for owned local fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, nargs="?",
                        default=Path("target/release") / ("sniper.exe" if os.name == "nt" else "sniper"))
    parser.add_argument("--binary-sha256", help="refuse to run any other build")
    parser.add_argument("--evidence-dir", type=Path, help="a new directory; defaults to one under the temp dir")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    assert binary.name in {"sniper", "sniper.exe"}, "Headless binary required"
    binary_hash = digest(binary.read_bytes())
    assert args.binary_sha256 in (None, binary_hash), "Pinned executable hash mismatch"
    evidence = (args.evidence_dir or Path(tempfile.mkdtemp(prefix="sniper-evidence-")) / "evidence").resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    wire = gzip.compress(FIRST, mtime=0) + gzip.compress(SECOND, mtime=0)
    assert gzip.decompress(wire) == FULL
    report = {"stage": "RUNNING", "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "binary": str(binary), "binary_sha256": binary_hash,
              "script_sha256": digest(Path(__file__).read_bytes()), "controls": [], "integrity": [],
              "fixture": {"member_count": 2, "wire_bytes": len(wire), "wire_sha256": digest(wire),
                          "full_bytes": len(FULL), "full_sha256": digest(FULL)},
              "network_scope": "owned 127.0.0.1 endpoints only", "cli_reuse": "deferred; not run"}
    seen, errors = {}, []
    lock = threading.Lock()
    child = None
    upstream = None
    upstream_thread = None
    pool = None
    runtime = None
    temporary = None

    def control(name, condition):
        assert condition, "Control failed: " + name
        report["controls"].append(name)

    def integrity(name, actual, expected):
        report["integrity"].append({"name": name, "pass": actual == expected,
                                    "actual_bytes": len(actual), "actual_sha256": digest(actual),
                                    "expected_bytes": len(expected), "expected_sha256": digest(expected),
                                    "matches_single_member_prefix": actual in (FIRST, FIRST.replace(b"one", b"changed"))})

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path not in PATHS:
                errors.append("Unexpected request path")
                self.send_error(400)
                return
            self.connection.settimeout(10)
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 1024 or self.headers.get("Transfer-Encoding"):
                errors.append("Unexpected request framing")
                self.send_error(400)
                return
            body = self.rfile.read(size)
            with lock:
                if self.path in seen:
                    errors.append("Duplicate fixture request")
                seen[self.path] = (body, {k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

    try:
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        upstream.daemon_threads = True
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        temporary = tempfile.TemporaryDirectory(prefix="sniper-gzip-members-")
        data = Path(temporary.name)
        env = {k: v for k, v in os.environ.items()
               if not k.lower().endswith("_proxy") and not k.startswith("SNIPER_")}
        env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")

        def api_at(address, path, payload=None):
            host, port = address.rsplit(":", 1)
            assert host == "127.0.0.1"
            connection = http.client.HTTPConnection(host, int(port), timeout=10)
            try:
                connection.request("GET" if payload is None else "POST", path,
                                   body=None if payload is None else json.dumps(payload).encode(),
                                   headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                body = response.read()
                assert 200 <= response.status < 300, (path, response.status)
                return json.loads(body) if body else None
            finally:
                connection.close()

        def api(path, payload=None):
            return api_at(runtime["ui_addr"], path, payload)

        def start():
            nonlocal child, runtime
            child = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

            def ready():
                assert child.poll() is None, "Owned runtime exited before ready"
                try:
                    snapshot = json.loads((data / "runtime-state.json").read_text())
                    if snapshot["pid"] != child.pid:
                        return None
                    api_at(snapshot["ui_addr"], "/api/settings")
                    return snapshot
                except (OSError, ValueError):
                    return None
            runtime = eventually(ready)
            report.setdefault("owned_runtime_pids", []).append(child.pid)

        def stop():
            nonlocal child
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=10)
                child = None

        def capture(path):
            host, port = runtime["proxy_addr"].rsplit(":", 1)
            assert host == "127.0.0.1"
            connection = http.client.HTTPConnection(host, int(port), timeout=15)
            try:
                connection.request("POST", f"http://127.0.0.1:{upstream.server_port}{path}", wire,
                                   {"Content-Type": "text/plain", "Content-Encoding": "gzip",
                                    "Content-Length": str(len(wire))})
                response = connection.getresponse()
                assert response.status == 200
                return response.read(), {k.lower(): v for k, v in response.getheaders()}
            finally:
                connection.close()

        start()
        session = api("/api/settings")["active_session"]["id"]
        query = f"?session_id={session}&expected_active_session_id={session}"
        read_query = f"?session_id={session}"
        control("new fixture has no intercept rules", api("/api/intercept-rules" + read_query) == [])

        def rules(scope=None, search="NOT_PRESENT_SYNTHETIC"):
            value = [] if scope is None else [{"id": "00000000-0000-4000-8000-000000000001",
                "enabled": True, "description": "synthetic gzip member integrity",
                "scope": scope, "target": "body", "search": search, "replace": "changed",
                "regex": False, "case_sensitive": True}]
            actual = api("/api/match-replace" + query, {"session_id": session, "rules": value})
            assert actual == value, "Match&Replace configuration was not adopted"

        def detail(path):
            summary = eventually(lambda: next((row for row in api("/api/transactions" + read_query)
                                                if row["path"] == path), None))
            def completed():
                record = api("/api/transactions/" + summary["id"] + read_query)
                response = record.get("response")
                return record if response and response.get("body_size", 0) > 0 and not any(
                    "Streaming response capture is still in progress." == note for note in record.get("notes", [])) else None
            return eventually(completed)

        def check_captured(label, record):
            for direction in ("request", "response"):
                message = record[direction]
                control(label + " " + direction + " decode metadata",
                        message["body_encoding"] == "utf8" and message.get("content_decoded") is True
                        and message["preview_truncated"] is False and message["body_size"] == len(wire))
                preview = message["body_preview"].encode()
                control(label + " " + direction + " decoded-size matches stored preview",
                        message["decoded_body_size"] == len(preview))
                integrity(label + " " + direction + " full decoded body", preview, FULL)

        api("/api/runtime", {"session_id": session, "expected_active_session_id": session,
                             "intercept_enabled": False})
        for path, scope in (("/no-rules", None), ("/nonmatching-request", "request"),
                            ("/nonmatching-response", "response")):
            rules(scope)
            response_body, response_headers = capture(path)
            request_body, request_headers = seen[path]
            control(path + " exact upstream request bytes", request_body == wire)
            control(path + " upstream encoding and length", request_headers.get("content-encoding") == "gzip"
                    and request_headers.get("content-length") == str(len(wire)))
            control(path + " exact client response bytes", response_body == wire)
            control(path + " response encoding and valid framing", response_headers.get("content-encoding") == "gzip"
                    and (response_headers.get("content-length") == str(len(wire))
                         or ("content-length" not in response_headers
                             and response_headers.get("transfer-encoding") == "chunked")))
            detail(path)  # Wait for capture/journal publication before restart.
        captured = detail("/no-rules")
        check_captured("capture", captured)
        # Buffered completion publishes the journaled full record atomically;
        # restart this control, not an in-progress streaming record update.
        persisted = detail("/nonmatching-response")
        rules()
        stop()
        start()
        control("restart retains isolated session", api("/api/settings")["active_session"]["id"] == session)
        restored = api("/api/transactions/" + persisted["id"] + read_query)
        check_captured("restart", restored)

        rules("request", "one")
        response_body, _ = capture("/matching-request")
        request_body, request_headers = seen["/matching-request"]
        control("request rewrite leaves response wire intact", response_body == wire)
        control("request rewrite entity headers", "content-encoding" not in request_headers
                and request_headers.get("content-length") == str(len(request_body)))
        integrity("matching request body rule retains later member", request_body, CHANGED)
        detail("/matching-request")

        rules("response", "one")
        response_body, response_headers = capture("/matching-response")
        control("response rewrite leaves request wire intact", seen["/matching-response"][0] == wire)
        control("response rewrite entity headers", "content-encoding" not in response_headers
                and response_headers.get("content-length") == str(len(response_body)))
        integrity("matching response body rule retains later member", response_body, CHANGED)
        detail("/matching-response")

        rules()
        api("/api/runtime", {"session_id": session, "expected_active_session_id": session,
                             "intercept_enabled": True, "intercept_scope_only": False})
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        held = pool.submit(capture, "/held-forward-all")
        pending = eventually(lambda: api("/api/intercepts" + read_query))
        control("owned request is held", len(pending) == 1 and not held.done())
        api("/api/intercepts/forward-all" + query, {"session_id": session})
        pending = eventually(lambda: api("/api/response-intercepts" + read_query))
        control("owned response is held", len(pending) == 1 and not held.done())
        api("/api/response-intercepts/forward-all" + query, {"session_id": session})
        response_body, response_headers = held.result(timeout=15)
        control("clean request Forward All preserves wire", seen["/held-forward-all"][0] == wire)
        control("clean response Forward All decoded entity headers", "content-encoding" not in response_headers
                and response_headers.get("content-length") == str(len(response_body)))
        integrity("clean response Forward All retains later member", response_body, FULL)
        api("/api/runtime", {"session_id": session, "expected_active_session_id": session,
                             "intercept_enabled": False})
        detail("/held-forward-all")
        control("exactly six owned fixture captures", set(seen) == PATHS and not errors)
        failures = sum(not check["pass"] for check in report["integrity"])
        report["stage"] = "INTEGRITY_FAILURES" if failures else "PASS"
        report["integrity_failures"] = failures
        report["all_failed_bodies_match_single_member_prefix"] = all(
            check["matches_single_member_prefix"] for check in report["integrity"] if not check["pass"])
        stop()
    except BaseException as error:
        report["stage"] = "FIXTURE_OR_CONTROL_ERROR"
        report["error"] = type(error).__name__ + ": " + str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
        if upstream_thread is not None:
            upstream_thread.join(timeout=10)
        if temporary is not None:
            temporary.cleanup()
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["binary_post_sha256"] = digest(binary.read_bytes())
        report["script_post_sha256"] = digest(Path(__file__).read_bytes())
        if report["binary_post_sha256"] != binary_hash:
            report["stage"] = "FIXTURE_OR_CONTROL_ERROR"
            report["error"] = "Executable changed during diagnostic"
        (evidence / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    return 0 if report["stage"] == "PASS" else 1 if report["stage"] == "INTEGRITY_FAILURES" else 2


if __name__ == "__main__":
    raise SystemExit(main())
