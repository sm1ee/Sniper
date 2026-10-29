"""Six tiny local sends -> stopped persisted gap -> served-JS Reuse in inert VM.

Run: python3 tests/fuzzer_reuse_smoke.py [binary directory] [--evidence-dir DIR]
No browser/DOM engine, third-party target, real session or auto-resend is used.
"""
import argparse
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


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.03)
    raise AssertionError("Owned fixture did not reach the required gate")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path, nargs="?", default="target/release")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    binaries = args.binaries.resolve()
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True, exist_ok=False)
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    held, release, held_done = threading.Event(), threading.Event(), threading.Event()
    received, errors, lock = [], [], threading.Lock()
    expected_bodies = {0: "A|right", 1: "B|right", 2: "C|right", 3: "left|A", 4: "left|B", 5: "left|C"}

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if size > 32 or self.path != "/owned-gap":
                errors.append("Unexpected fixture request")
                self.send_error(400)
                return
            body = self.rfile.read(size).decode("ascii")
            with lock:
                received.append(body)
            waiting = body == "B|right"
            try:
                if waiting:
                    held.set()
                    release.wait(60)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                if waiting:
                    held_done.set()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="sniper-fuzzer-reuse-") as temporary:
            data = Path(temporary)
            env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
            env.pop("SNIPER_API_ADDR", None)
            env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0", SNIPER_PROXY_ADDR="127.0.0.1:0",
                       SNIPER_INSTALL_AGENT_SKILLS="0", SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")

            def start():
                child = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env, cwd=data,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

                def ready():
                    assert child.poll() is None, "Owned runtime exited before readiness"
                    try:
                        value = json.loads((data / "runtime-state.json").read_text())
                        return value if value["pid"] == child.pid else None
                    except (OSError, ValueError):
                        return None
                try:
                    return child, eventually(ready)
                except BaseException:
                    child.kill()
                    child.wait(timeout=10)
                    raise

            def read(path, body=None):
                host, port = runtime["ui_addr"].rsplit(":", 1)
                assert host == "127.0.0.1"
                connection = http.client.HTTPConnection(host, int(port), timeout=15)
                try:
                    connection.request("GET" if body is None else "POST", path,
                                       body=None if body is None else json.dumps(body),
                                       headers={"Content-Type": "application/json", "Accept-Encoding": "identity"})
                    response = connection.getresponse()
                    payload = response.read()
                    assert response.status == 200, (path, response.status)
                    return payload
                finally:
                    connection.close()

            def api(path, body=None):
                return json.loads(read(path, body))

            def settings_ready():
                try:
                    return api("/api/settings")
                except (ConnectionError, OSError):
                    return None

            try:
                process, runtime = start()
                session = eventually(settings_ready)["active_session"]["id"]
                started = api("/api/fuzzer/attacks", {"session_id": session,
                    "template": {"scheme": "http", "host": f"127.0.0.1:{server.server_port}", "method": "POST",
                                 "path": "/owned-gap", "headers": [], "body": "§left§|§right§", "body_encoding": "utf8", "preview_truncated": False},
                    "payloads": ["A", "B", "C"], "attack_type": "sniper", "url_encode": False, "concurrency": 3})
                assert (started["planned"], started["payload_count"], started["marker_count"]) == (6, 3, 2)
                assert held.wait(10), "The index1-equivalent response was not held"
                attack_path = f"/api/fuzzer/attacks/{started['id']}"

                def five_completed():
                    record = api(attack_path + "?session_id=" + session)
                    assert record.get("running"), "Attack ended before the gate was released"
                    return record if sorted(row["index"] for row in record["results"]) == [0, 2, 3, 4, 5] else None

                eventually(five_completed)
                stopped = api(attack_path + "/stop", {"session_id": session})
                assert stopped.get("stopped") and not stopped.get("running")
                assert [row["index"] for row in stopped["results"]] == [0, 2, 3, 4, 5]
                assert all(row.get("status") == 200 and row.get("transaction_id") for row in stopped["results"])

                def persisted():
                    try:
                        state = json.loads((data / "sessions" / session / "state.json").read_text())
                        return next((record for record in state["fuzzer_attacks"] if record == stopped), None)
                    except (OSError, ValueError, KeyError):
                        return None

                eventually(persisted)
                process.kill()
                process.wait(timeout=10)
                process, runtime = start()
                assert eventually(settings_ready)["active_session"]["id"] == session
                saved = api(attack_path + "?session_id=" + session)
                assert saved == stopped, "Persisted stopped record changed on restart"
                ids = []
                for row in saved["results"]:
                    captured = api(f"/api/transactions/{row['transaction_id']}?session_id={session}")
                    assert captured["id"] == row["transaction_id"] and captured["path"] == "/owned-gap"
                    assert captured["request"]["body_preview"] == expected_bodies[row["index"]]
                    assert captured["response"]["body_preview"] == "OK"
                    ids.append(captured["id"])
                assert len(set(ids)) == 5
                with lock:
                    assert sorted(received) == sorted(expected_bodies.values()) and not errors
                    observed = list(received)
                assert not release.is_set()
                served = read("/app.js")
                expected_source = (Path(__file__).resolve().parents[1] / "web/app.js").read_bytes()
                assert served == expected_source, "Served UI is not the tested checkout"
                record_path, source_path = data / "stopped-record.json", data / "served-app.js"
                record_path.write_text(json.dumps(saved, indent=2) + "\n")
                source_path.write_bytes(served)
                proof = {"requests": observed, "retained_indices": [row["index"] for row in saved["results"]],
                         "readable_transaction_ids": ids, "restart_record_identical": True,
                         "record_sha256": hashlib.sha256(record_path.read_bytes()).hexdigest(),
                         "served_app_sha256": hashlib.sha256(served).hexdigest()}
                if args.evidence_dir:
                    (args.evidence_dir / "stopped-record.json").write_bytes(record_path.read_bytes())
                    (args.evidence_dir / "runtime-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
                print(json.dumps(proof), flush=True)
                print("PASS: exactly 6 tiny sends, stopped gap persisted before kill, identical restart and 5 readable exchange bodies; no resume", flush=True)
                subprocess.run(["node", str(Path(__file__).with_name("fuzzer-reuse-runtime-check.cjs")),
                                str(source_path), str(record_path)], env=env, timeout=20, check=True, creationflags=flags)
                with lock:
                    assert len(received) == 6 and not errors
                print("PASS: runtime-to-served-Reuse chain and derived controls; no additional requests", flush=True)
            finally:
                release.set()
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if held.is_set():
            assert held_done.wait(5), "Owned held handler did not finish"
        assert not thread.is_alive()


if __name__ == "__main__":
    main()
