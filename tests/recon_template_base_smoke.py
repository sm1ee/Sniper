"""Compare ordinary outside-link resolution around literal template base tags.

Check static document-base isolation, not browser conformance.
Run: python3 tests/recon_template_base_smoke.py [directory containing sniper]
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
        value = operation()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for owned loopback fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    requested = []
    cases = {
        "no-base": "",
        "document-base": '<base href="/document/">',
        "template-only": '<template><base href="/template/"></template>',
        "template-first": '<template><base href="/template/"></template><base href="/document/">',
        "document-first": '<base href="/document/"><template><base href="/template/"></template>',
        "template-offscope": None,
        "template-nested": '<template><template><base href="/inner/"></template><base href="/outer/"></template><base href="/document/">',
        "template-self-closing": '<template/><base href="/template/">',
        "template-raw-closer": '<template><iframe></template></iframe><base href="/template/"></template><base href="/document/">',
        "template-name-prefix": '<template_x><base href="/document/">',
        "template-evidence": '<template><div src="/kept-candidate"></div><img src="/kept-resource"></template>',

    }

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requested.append({"path": self.path, "host": self.headers.get("Host")})
            case = self.path.removeprefix("/case/")
            content = b""
            if self.path.startswith("/case/") and case in cases:
                prefix = cases[case]
                if prefix is None:
                    prefix = f'<template><base href="http://localhost:{self.server.server_port}/template/"></template>'
                content = (prefix + '<a href="outside">Outside link</a>'
                           + f'<a href="http://localhost:{self.server.server_port}/scope-forbidden">Scope control</a>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html" if content else "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    authority = f"127.0.0.1:{upstream.server_port}"
    origin = "http://" + authority
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    with tempfile.TemporaryDirectory(prefix="sniper-template-base-") as temporary:
        data = Path(temporary)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        for key in ("SNIPER_API_ADDR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)
        try:
            process = subprocess.Popen([str(binaries / "sniper")], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            def ready():
                assert process.poll() is None, "Owned runtime exited before becoming ready"
                try:
                    runtime = json.loads((data / "runtime-state.json").read_text())
                    return runtime if runtime["pid"] == process.pid else None
                except (OSError, ValueError):
                    return None

            ui = "http://" + eventually(ready)["ui_addr"]

            def api(path, payload=None):
                request = urllib.request.Request(ui + path,
                    data=None if payload is None else json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"})
                with opener.open(request, timeout=10) as response:
                    return json.load(response)

            sid = api("/api/settings")["active_session"]["id"]
            results = {}
            for case, budget in [(name, 5 if name == "template-evidence" else 4) for name in cases] + [("no-base", 1)]:
                name = "budget-one" if budget == 1 else case
                target = origin + "/case/" + case
                offset = len(requested)
                job = api("/api/recon/jobs", {"session_id": sid, "target_url": target,
                          "sources": ["crawler"], "max_requests": budget})

                def complete():
                    snapshot = api("/api/recon?session_id=" + sid)
                    current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
                    return (current, snapshot) if current["status"] != "running" else None

                current, snapshot = eventually(complete)
                source = current["sources"][0]
                relative_links = sorted(item["url"].removeprefix(origin) for item in snapshot["endpoints"]
                    if item["url"].endswith("/outside") and any(
                        evidence["source"] == "crawler" and evidence["kind"] == "observed"
                        and evidence["location"] == "link: " + target
                        for evidence in item["evidence"]))
                requests = requested[offset:]
                assert current["status"] == "completed", current
                assert source["requests"] == len(requests) <= budget, (source, requests)
                assert all(request["host"] == authority for request in requests), requests
                assert not any(request["path"] == "/scope-forbidden" for request in requests), requests
                assert source["truncated"] is (budget == 1), source
                results[name] = {"resolved_links": relative_links, "requests": requests,
                                 "count": source["requests"], "budget": budget,
                                 "partial": source["truncated"]}
                print(json.dumps({"case": name, **results[name]}), flush=True)

            assert results["no-base"]["resolved_links"] == ["/case/outside"]
            assert results["document-base"]["resolved_links"] == ["/document/outside"]
            assert results["document-first"]["resolved_links"] == ["/document/outside"]
            assert results["budget-one"]["count"] == 1
            assert api("/api/transactions?session_id=" + sid) == []
            print("Ordinary-base controls, Scope, explicit request budgets and no fabricated capture all passed.", flush=True)

            endpoints = {item["url"].removeprefix(origin): item for item in snapshot["endpoints"]}
            kinds = lambda item: {evidence["kind"] for evidence in item["evidence"]}
            assert kinds(endpoints["/kept-candidate"]) == {"candidate"}
            assert kinds(endpoints["/kept-resource"]) == {"observed", "live"}
            assert not any(request["path"] == "/kept-candidate" for request in requested)
            assert all(evidence["location"] == "attribute div[src]: " + origin + "/case/template-evidence"
                       for evidence in endpoints["/kept-candidate"]["evidence"])
            print("Existing template-child evidence and followability were preserved.", flush=True)

            isolation = {
                "template-only_matches_no-base": results["template-only"]["resolved_links"] == results["no-base"]["resolved_links"],
                "template-first_matches_document-base": results["template-first"]["resolved_links"] == results["document-base"]["resolved_links"],
                "template-offscope_preserves_ordinary-link": results["template-offscope"]["resolved_links"] == results["no-base"]["resolved_links"],
                "nested_template_base_isolated": results["template-nested"]["resolved_links"] == ["/document/outside"],
                "self_closing_html_template_stays_open": results["template-self-closing"]["resolved_links"] == ["/case/outside"],
                "raw_text_fake_closer_ignored": results["template-raw-closer"]["resolved_links"] == ["/document/outside"],
                "non_template_name_keeps_document_base": results["template-name-prefix"]["resolved_links"] == ["/document/outside"],
            }
            print(json.dumps({"isolation": isolation}), flush=True)
            assert all(isolation.values()), "Literal template base affects outside-link resolution"
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    main()
