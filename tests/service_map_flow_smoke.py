"""Check Flow coverage through captured loopback traffic, API, CLI and restart.

Run: python3 tests/service_map_flow_smoke.py [directory with sniper and sniper-cli]
Only an isolated data directory and this script's local synthetic origin are used.
"""

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
import urllib.parse
import urllib.request


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for the isolated Flow fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    cases = [
        ("/flow-no-location-csp", None, False),
        ("/flow-no-location-cors", None, False),
        ("/flow-valid-location-csp", None, True),
        ("/flow-unread-location", "header_value_limit", False),
        ("/flow-ambiguous-location", "ambiguous_location_headers", False),
    ]

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            assert self.path in [case[0] for case in cases], "Unexpected fixture request"
            self.send_response(302)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            if self.path.endswith("-csp"):
                self.send_header("Content-Security-Policy", "x" * 4097)
            if self.path.endswith("-cors"):
                self.send_header("Access-Control-Allow-Origin", "x" * 4097)
            if self.path == "/flow-valid-location-csp":
                self.send_header("Location", "/next")
            if self.path == "/flow-unread-location":
                self.send_header("Location", "/" + "x" * 4097)
            if self.path == "/flow-ambiguous-location":
                self.send_header("Location", "/first")
                self.send_header("Location", "/second")
            self.end_headers()
            self.wfile.write(b"{}")

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    child = None
    with tempfile.TemporaryDirectory(prefix="sniper-flow-smoke-") as temporary:
        data = Path(temporary)
        env = dict(
            os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
            SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
            SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off",
        )
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)

        def start():
            process = subprocess.Popen(
                [str(binaries / ("sniper" + suffix))], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
            )

            def ready():
                assert process.poll() is None, "Runtime exited before becoming ready"
                try:
                    runtime = json.loads((data / "runtime-state.json").read_text(encoding="utf-8"))
                    if runtime["pid"] != process.pid:
                        return None
                    with opener.open("http://" + runtime["ui_addr"] + "/api/settings", timeout=1):
                        return runtime
                except (OSError, ValueError):
                    return None

            try:
                return process, eventually(ready)
            except BaseException:
                process.kill()
                process.wait(timeout=10)
                raise

        def api(path):
            with opener.open("http://" + runtime["ui_addr"] + path, timeout=10) as response:
                return json.load(response)

        def flow(**query):
            return api("/api/target/service-map/flow?" + urllib.parse.urlencode(
                dict(origin=origin, session_id=session_id, **query)))

        def capture(path):
            host, port = runtime["proxy_addr"].rsplit(":", 1)
            connection = http.client.HTTPConnection(host, int(port), timeout=10)
            try:
                connection.request("GET", origin + path)
                response = connection.getresponse()
                assert response.status == 302
                assert response.read() == b"{}"
            finally:
                connection.close()

        def verify():
            for path, reason, redirected in cases:
                result = flow(advanced_search=path)
                assert result["considered_rows"] == len(cases), (path, result)
                assert result["flow_rows"] == 1, (path, result)
                assert result["complete"] == (reason is None), (path, result)
                assert result.get("stopped_by", []) == ([] if reason is None else [reason]), (path, result)
                steps = [step for phase in result["phases"] for step in phase["steps"]]
                assert len(steps) == 1 and steps[0]["path"] == path
                assert (steps[0].get("redirect") is not None) == redirected
            empty = flow(advanced_search="/not-captured", max_records=2)
            assert empty["considered_rows"] == 2 and empty["flow_rows"] == 0, empty
            assert empty["phases"] == [] and not empty["complete"], empty
            assert empty["stopped_by"] == ["max_records"], empty
            request = dict(origin=origin, session_id=session_id)
            output = subprocess.run(
                [str(binaries / ("sniper-cli" + suffix)), "--api", "http://" + runtime["ui_addr"],
                 "--output", "compact", "call", "target.service_map.flow.get", "--input", json.dumps(request)],
                env=env, capture_output=True, timeout=20, creationflags=flags,
            )
            assert output.returncode == 0, output.stderr.decode()
            response = json.loads(output.stdout)
            assert response["ok"] is True, response
            combined = response["data"]
            assert combined["considered_rows"] == len(cases) and combined["flow_rows"] == len(cases), combined
            assert not combined["complete"], combined
            assert combined["stopped_by"] == ["ambiguous_location_headers", "header_value_limit"], combined

        try:
            child, runtime = start()
            session_id = api("/api/settings")["active_session"]["id"]
            for path, _, _ in cases:
                capture(path)
            eventually(lambda: len(api("/api/transactions")) == len(cases))
            verify()
            print("PASS: captured Flow omission controls, row-window counts, empty bounds and CLI", flush=True)
            child.kill()
            child.wait(timeout=10)
            child, runtime = start()
            assert api("/api/settings")["active_session"]["id"] == session_id
            eventually(lambda: len(api("/api/transactions")) == len(cases))
            verify()
            print("PASS: Flow coverage survives metadata reconstruction after restart", flush=True)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
