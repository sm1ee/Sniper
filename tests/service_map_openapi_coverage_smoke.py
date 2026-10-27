"""Check parameter-cap provenance through local capture, OpenAPI API/CLI and restart.

Run: python3 tests/service_map_openapi_coverage_smoke.py [binary directory]
Optional --evidence-dir saves only the synthetic, value-free OpenAPI documents.
"""

import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.parse


SIGNAL = "x-sniper-parameter-cap-truncated"
MARKER = "SYNTHETIC_PRIVATE_PARAMETER_VALUE"


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for isolated OpenAPI fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="?", default="target/release", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    binaries = args.binaries.resolve()
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    fields = lambda count: [f"p{i:03}" for i in range(count)]
    cases = [
        ("GET", "/control", fields(200), "query"),
        ("GET", "/overflow", fields(201), "query"),
        ("POST", "/body-control", fields(200), "json"),
        ("POST", "/body-overflow", fields(201), "json"),
        ("GET", "/items/42", fields(201), "query"),
        ("GET", "/items/507f1f77bcf86cd799439011", fields(201), "query"),
        ("GET", "/items/550e8400-e29b-41d4-a716-446655440000", ["p200"], "query"),
        ("PATCH", "/items/42", fields(200), "query"),
    ]
    seen = []
    upstream_errors = []

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self):
            parsed = urllib.parse.urlsplit(self.path)
            match = next((case for case in cases if case[:2] == (self.command, parsed.path)), None)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if match is None:
                upstream_errors.append("Unexpected local fixture request")
                self.send_error(400)
                return
            _, path, names, location = match
            expected = {name: MARKER for name in names}
            valid = (not body and urllib.parse.parse_qsl(parsed.query) == list(expected.items())
                     if location == "query" else not parsed.query and json.loads(body) == expected)
            if not valid:
                upstream_errors.append("Unexpected local fixture fields")
                self.send_error(400)
                return
            seen.append((self.command, path))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = do_PATCH = respond

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix="sniper-openapi-coverage-") as temporary:
            data = Path(temporary)
            env = {key: value for key, value in os.environ.items()
                   if not key.lower().endswith("_proxy")}
            env.pop("SNIPER_API_ADDR", None)
            env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                       SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                       SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")

            def api(path):
                host, port = runtime["ui_addr"].rsplit(":", 1)
                assert host == "127.0.0.1"
                connection = http.client.HTTPConnection(host, int(port), timeout=10)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    payload = response.read()
                    assert response.status == 200, (response.status, payload)
                    return json.loads(payload)
                finally:
                    connection.close()

            def start():
                process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           creationflags=flags)

                def ready():
                    assert process.poll() is None, "Runtime exited before becoming ready"
                    try:
                        value = json.loads((data / "runtime-state.json").read_text())
                        return value if value["pid"] == process.pid else None
                    except (OSError, ValueError):
                        return None

                try:
                    return process, eventually(ready)
                except BaseException:
                    process.kill()
                    process.wait(timeout=10)
                    raise

            def settings_ready():
                try:
                    return api("/api/settings")
                except (ConnectionError, OSError):
                    return None

            def verify(stage):
                selection = dict(session_id=session_id, origin=origin)
                document = api("/api/target/service-map/openapi?" + urllib.parse.urlencode(selection))
                output = subprocess.run(
                    [str(binaries / ("sniper-cli" + suffix)), "--api", "http://" + runtime["ui_addr"],
                     "--output", "compact", "call", "target.service_map.openapi.get", "--input", json.dumps(selection)],
                    env=env, capture_output=True, timeout=20, creationflags=flags,
                )
                assert output.returncode == 0, output.stderr.decode()
                via_cli = json.loads(output.stdout)
                assert via_cli["ok"] is True and via_cli["data"] == document
                assert "SYNTHETIC_PRIVATE" not in json.dumps(document)
                assert document["openapi"] == "3.1.0"
                assert document["servers"] == [{"url": origin}]
                assert set(document["paths"]) == {"/control", "/overflow", "/body-control", "/body-overflow", "/items/{id}"}
                failures = []
                for method, path, names, location in cases:
                    parameters = api("/api/target/service-map/parameters?" + urllib.parse.urlencode(
                        dict(selection, method=method, path=path)))
                    assert parameters["available"] and parameters["rows"] == 1 and not parameters["more_rows"]
                    assert len(parameters["parameters"]) == min(len(names), 200)
                    assert parameters["omitted_parameters"] == max(len(names) - 200, 0)
                for path, method, expected_cap, retained, location in [
                    ("/control", "get", False, 200, "query"),
                    ("/overflow", "get", True, 200, "query"),
                    ("/body-control", "post", False, 200, "json"),
                    ("/body-overflow", "post", True, 200, "json"),
                    ("/items/{id}", "get", True, 201, "query"),
                    ("/items/{id}", "patch", False, 200, "query"),
                ]:
                    operation = document["paths"][path][method]
                    fields_read = (operation["parameters"] if location == "query" else
                                   operation["requestBody"]["content"]["application/json"]["schema"]["properties"])
                    assert len(fields_read) == retained
                    if (operation.get(SIGNAL) is not True if expected_cap else SIGNAL in operation):
                        failures.append(f"{method.upper()} {path}: expected cap provenance {expected_cap}, got {operation.get(SIGNAL)!r}")
                merged = document["paths"]["/items/{id}"]
                assert merged["get"]["parameters"][-1]["name"] == "p200"
                assert merged["get"]["x-sniper-requests"] == 3
                assert len(merged["parameters"][0]["schema"]["anyOf"]) == 3
                assert not failures, "; ".join(failures)
                if args.evidence_dir:
                    args.evidence_dir.mkdir(parents=True, exist_ok=True)
                    (args.evidence_dir / f"{stage}-openapi.json").write_text(json.dumps(document, indent=2) + "\n")
                print(f"PASS: {stage} query/body 200/201 caps, merged recovery/method control, API/CLI parity and value omission", flush=True)
                return document

            try:
                child, runtime = start()
                session_id = eventually(settings_ready)["active_session"]["id"]
                for method, path, names, location in cases:
                    host, port = runtime["proxy_addr"].rsplit(":", 1)
                    assert host == "127.0.0.1"
                    connection = http.client.HTTPConnection(host, int(port), timeout=10)
                    payload = {name: MARKER for name in names}
                    body = json.dumps(payload).encode() if location == "json" else None
                    target = origin + path + ("?" + urllib.parse.urlencode(payload) if location == "query" else "")
                    try:
                        connection.request(method, target, body=body,
                                           headers={"Content-Type": "application/json"} if body is not None else {})
                        response = connection.getresponse()
                        assert response.status == 200 and response.read() == b"{}"
                    finally:
                        connection.close()
                eventually(lambda: len(api("/api/transactions")) == len(cases))
                assert seen == [case[:2] for case in cases] and not upstream_errors
                captured = verify("captured")
                child.kill()
                child.wait(timeout=10)
                child, runtime = start()
                assert eventually(settings_ready)["active_session"]["id"] == session_id
                eventually(lambda: len(api("/api/transactions")) == len(cases))
                assert verify("restarted") == captured
            finally:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


if __name__ == "__main__":
    main()
