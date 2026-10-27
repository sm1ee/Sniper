"""Check passive HTML attribute evidence and supported crawl links on loopback.

Run: python3 tests/recon_html_attributes_smoke.py [directory containing sniper]
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
    raise AssertionError("Timed out waiting for isolated HTML attribute fixture")


def main():
    binary_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    requested = []
    candidates = {"/candidate-href?x=1&x=2", "/candidate-src", "/candidate-poster",
                  "/candidate-span", "/candidate-custom", "/candidate-input",
                  "/candidate-source", "/candidate-foreign-script", "/candidate-foreign-image",
                  "/candidate-slash-value", "/candidate-slash-space"}
    followed = {"/valid-link", "/valid-image", "/valid-script.js", "/valid-poster",
                "/valid-object", "/valid-area", "/valid-embed", "/valid-stylesheet",
                "/valid-image-input", "/after-foreign"}
    body = b'''<!doctype html><base href="/">
        <div href="/candidate-href?x=1&amp;x=2" src="/candidate-src" poster="/candidate-poster"></div>
        <span src="/candidate-span"></span><custom-widget src="/candidate-custom"></custom-widget>
        <div src="/valid-image"></div><img src="/valid-image">
        <a href="/valid-link">Link</a><script src="/valid-script.js"></script>
        <video poster="/valid-poster"></video><object data="/valid-object"></object>
        <map name="fixture"><area href="/valid-area"></map>
        <embed src="/valid-embed"><link rel="stylesheet" href="/valid-stylesheet">
        <input type="image" src="/valid-image-input"><input type="text" src="/candidate-input">
        <video><source src="/candidate-source"></video>
        <svg><script src="/candidate-foreign-script"></script>
          <foreignObject><img src="/candidate-foreign-image"></foreignObject></svg>
        <svg data-x= /><a href="/candidate-slash-value"></a></svg>
        <svg data-x='v'/ ><a href="/candidate-slash-space"></a></svg>
        <svg/><svg data-x='v'/><img src="/after-foreign">'''

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requested.append(self.path)
            content = body if self.path == "/fixture" else b""
            content_type = "text/html" if self.path == "/fixture" else "text/plain"
            if self.path.endswith(".js"):
                content_type = "application/javascript"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    with tempfile.TemporaryDirectory(prefix="sniper-recon-html-") as temporary:
        data = Path(temporary)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)

        def launch():
            nonlocal process
            suffix = ".exe" if os.name == "nt" else ""
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
            request_budget = int(sys.argv[2]) if len(sys.argv) > 2 else 32
            job = api("/api/recon/jobs", {"session_id": sid, "target_url": origin + "/fixture",
                      "sources": ["crawler"], "max_requests": request_budget})

            def completed():
                snapshot = api("/api/recon?session_id=" + sid)
                current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
                return snapshot if current["status"] != "running" else None

            snapshot = eventually(completed)
            current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
            endpoints = {item["url"].removeprefix(origin): item for item in snapshot["endpoints"]}
            site_map = api("/api/target/site-map?session_id=" + sid)
            paths = {item["path"]: item for host in site_map for item in host["paths"]}
            kinds = lambda item: {evidence["kind"] for evidence in item["evidence"]}
            checks = {
                "completed": current["status"] == "completed" and not current["sources"][0]["truncated"],
                "all_urls_retained": (candidates | followed) <= endpoints.keys(),
                "unsupported_are_candidates": all(kinds(endpoints[path]) == {"candidate"} for path in candidates),
                "unsupported_not_followed": not candidates.intersection(requested),
                "supported_links_followed": followed <= set(requested),
                "shared_url_keeps_both_evidence_kinds": kinds(endpoints["/valid-image"]) == {"candidate", "observed", "live"},
                "requests_counted": current["sources"][0]["requests"] == len(requested),
                "map_candidate_provenance": all(paths[path]["recon_kinds"] == ["candidate"] for path in candidates),
                "no_fabricated_capture": all(not item["captured"] and item["discovered"] and item["status"] is None for item in paths.values())
                                          and all(host["request_count"] == 0 for host in site_map)
                                          and api("/api/transactions?session_id=" + sid) == [],
            }
            print(json.dumps({"checks": checks, "requests": requested,
                              "candidate_kinds": {path: sorted(kinds(endpoints[path])) for path in candidates},
                              "shared_url_kinds": sorted(kinds(endpoints["/valid-image"]))}), flush=True)
            assert all(checks.values()), [name for name, passed in checks.items() if not passed]

            def persisted():
                for state_file in data.rglob("state.json"):
                    if state_file.parent.name == sid:
                        try:
                            saved = json.loads(state_file.read_text())["recon"]
                            return saved == {"jobs": snapshot["jobs"], "endpoints": snapshot["endpoints"]}
                        except (OSError, ValueError, KeyError):
                            pass
                return False

            eventually(persisted)
            stop()
            ui = launch()
            assert api("/api/recon?session_id=" + sid) == snapshot
            assert api("/api/target/site-map?session_id=" + sid) == site_map
            print("Attribute candidates and valid-link provenance survived process restart without captured traffic.", flush=True)
        finally:
            stop()
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
