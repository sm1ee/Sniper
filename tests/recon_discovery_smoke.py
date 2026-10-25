"""Verify Recon extraction, sitemap projection and persistence on loopback only.

Run: python tests/recon_discovery_smoke.py [directory containing sniper]
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
    raise AssertionError("Timed out waiting for isolated Recon fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    types = {
        "javascript": "application/javascript", "text-javascript": "text/javascript",
        "ecmascript": "application/ecmascript", "text-ecmascript": "text/ecmascript",
        "mixed-ecmascript": "APPLICATION/ECMASCRIPT; charset=UTF-8",
        "parameter-javascript": "text/javascript; charset=utf-8", "legacy-javascript": "application/x-javascript",
        "missing.js": None, "unsupported.js": "application/octet-stream",
    }
    cases = {name: (False, name != "unsupported.js") for name in types}
    cases.update({"tags-before": (False, True), "tags-exact": (False, False), "tags-after": (False, True)})
    large_count = 5501
    requested = []
    slow_started, release_slow = threading.Event(), threading.Event()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requested.append(self.path)
            content_type, body = "text/plain", b""
            if self.path.startswith("/case/"):
                name = self.path.removeprefix("/case/")
                content_type = "text/html"
                if name in types:
                    body = f'<script src="/script/{name}"></script>'.encode()
                else:
                    count = 4999 if name == "tags-before" else 5000
                    body = b"<span></span>" * count
                    if name != "tags-exact":
                        body += f'<a href="/found/{name}">link</a>'.encode()
            elif self.path.startswith("/script/"):
                name = self.path.removeprefix("/script/")
                content_type = types[name]
                body = f'fetch("/found/{name}")'.encode()
            elif self.path in ("/large.js", "/budget.js"):
                content_type = "application/javascript"
                prefix = "large" if self.path == "/large.js" else "budget"
                count = large_count if prefix == "large" else 20
                # Cross the old 2 MiB body, 10,000-token and 5,000-endpoint caps
                # without following thousands of URLs or contacting a real host.
                padding = b" " * (2 * 1024 * 1024 + 1) if prefix == "large" else b""
                body = padding + b"'ignored';" * 10001 + "".join(
                    f'fetch("/{prefix}-candidate/{index}?first=1&second=2");'
                    for index in range(count)
                ).encode()
            elif self.path == "/forms":
                content_type = "text/html"
                body = b'''<form method="post" action="/form-fixture/save">
                  <button formaction="/form-fixture/close" formmethod="DiAlOg">Close</button>
                  <button formaction="/form-fixture/invalid" formmethod="DELETE">Invalid</button>
                  <button formaction="/form-fixture/empty" formmethod="">Empty</button>
                  <button formaction="/form-fixture/inherited">Inherited</button>
                </form><form method="dialog" action="/form-fixture/dialog">
                  <button formaction="/form-fixture/inherited-dialog">Close</button>
                  <button formaction="/form-fixture/explicit-post" formmethod="POST">Post</button>
                </form><form method="dialog" action="javascript:void(0)">
                  <button formaction="/form-fixture/dialog-close">Close</button>
                </form><form method="post" action="javascript:void(0)">
                  <button formaction="/form-fixture/post-override">Post</button>
                </form>'''
            elif self.path == "/slow":
                slow_started.set()
                release_slow.wait(10)
                content_type, body = "text/html", b'<a href="/after-stop">late</a>'
            self.send_response(200)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{upstream.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    temporary = tempfile.TemporaryDirectory(prefix="sniper-recon-discovery-")
    try:
        data = Path(temporary.name)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        env.pop("SNIPER_API_ADDR", None)
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
            env.pop(key, None)
        suffix = ".exe" if os.name == "nt" else ""
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        def launch():
            return subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

        process = launch()

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                state = json.loads((data / "runtime-state.json").read_text())
                return state if state["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        runtime = eventually(ready)
        ui = "http://" + runtime["ui_addr"]

        def api(path, payload=None):
            request = urllib.request.Request(ui + path, data=None if payload is None else json.dumps(payload).encode(),
                                             headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        sid = api("/api/settings")["active_session"]["id"]
        with opener.open(ui + "/recon.js", timeout=10) as response:
            assert response.read() == (Path(__file__).resolve().parents[1] / "web/recon.js").read_bytes(), "Embedded Recon UI differs from tested source"

        def start(path, **budgets):
            return api("/api/recon/jobs", {"session_id": sid, "target_url": origin + path,
                       "sources": ["crawler"], "max_requests": 0, "max_depth": 0,
                       "max_endpoints": 0, "max_pages": 0, **budgets})

        def completed(job):
            snapshot = api("/api/recon?session_id=" + sid)
            current = next(item for item in snapshot["jobs"] if item["id"] == job["id"])
            return (current, snapshot) if current["status"] != "running" else None

        failures, results = [], []
        for name, (clipped, found) in cases.items():
            before = api("/api/recon?session_id=" + sid)
            offset = len(requested)
            job = start("/case/" + name)
            job, snapshot = eventually(lambda: completed(job))
            source = job["sources"][0]
            paths = requested[offset:]
            endpoints = snapshot["endpoints"]
            checks = {
                "completed": job["status"] == "completed" and source["status"] == "completed",
                "truncation": source["truncated"] == clipped,
                "endpoint": any(item["url"] == origin + "/found/" + name for item in endpoints) == found,
                "requests": source["requests"] == len(paths),
                "discovered": source["discovered"] == len(endpoints) - len(before["endpoints"]),
                "static_only": ("/found/" + name in paths) == (name in ("tags-before", "tags-after")),
                "bounded_warning": any("Collection is partial" in warning for warning in source["warnings"]) == clipped,
                "extraction_warning": any("extraction was partial" in warning for warning in source["warnings"]) == clipped,
            }
            failed = [key for key, passed in checks.items() if not passed]
            failures.extend(f"{name}: {key}" for key in failed)
            results.append({"case": name, "checks": checks, "job": job, "requested_paths": paths, "snapshot": snapshot})
            print(json.dumps({"case": name, "requests": source["requests"], "discovered": source["discovered"],
                              "truncated": source["truncated"], "failed": failed}), flush=True)

        offset = len(requested)
        form_job = start("/forms")
        form_job, form_snapshot = eventually(lambda: completed(form_job))
        forms = sorted((item["url"].removeprefix(origin), item["method"])
                       for item in form_snapshot["endpoints"] if "/form-fixture/" in item["url"])
        expected_forms = sorted([("/form-fixture/save", "POST"), ("/form-fixture/invalid", "GET"),
                                 ("/form-fixture/empty", "GET"), ("/form-fixture/inherited", "POST"),
                                 ("/form-fixture/explicit-post", "POST"),
                                 ("/form-fixture/post-override", "POST")])
        assert forms == expected_forms, forms
        assert set(requested[offset:]) == {"/forms", "/robots.txt", "/sitemap.xml"}
        assert all(item["evidence"][0]["kind"] == "candidate" for item in form_snapshot["endpoints"]
                   if "/form-fixture/" in item["url"])
        print("HTML form methods retain GET/POST candidates without inventing dialog or custom-method submissions.", flush=True)

        before_large = api("/api/recon?session_id=" + sid)
        offset = len(requested)
        large_job = start("/large.js")
        large_job, large_snapshot = eventually(lambda: completed(large_job))
        large_source = large_job["sources"][0]
        large_paths = {"/large-candidate/" + str(index) + "?first=1&second=2" for index in range(large_count)}
        assert large_job["status"] == "completed" and not large_source["truncated"], large_source
        assert large_source["discovered"] == large_count + 1
        assert len(large_snapshot["endpoints"]) == len(before_large["endpoints"]) + large_count + 1
        assert set(requested[offset:]) == {"/large.js", "/robots.txt", "/sitemap.xml"}
        assert not any(path.startswith("/large-candidate/") for path in requested)

        def read_site_map():
            return api("/api/target/site-map?session_id=" + sid)

        site_map = read_site_map()
        all_paths = {path["path"]: path for host in site_map for path in host["paths"]}
        assert large_paths <= all_paths.keys(), "Sitemap omitted Recon URLs past the old cap"
        assert all(host["request_count"] == 0 for host in site_map), "Recon fabricated captured traffic"
        for name in large_paths | {"/large.js"}:
            path = all_paths[name]
            assert path["captured"] is False and path["discovered"] is True, path
            assert path["status"] is None, "Discovery status was presented as a captured response"
            assert path["methods"] == ["GET"] and path["note_count"] == 0, path
            assert path["recon_sources"] == ["crawler"] and path["recon_last_seen"], path
            assert path["recon_kinds"] == (["live"] if name == "/large.js" else ["candidate"]), path
        assert api("/api/transactions?session_id=" + sid) == []
        print("Uncapped extraction retained all 5,501 candidates past 2 MiB and 10,000 tokens; sitemap shows provenance without captured traffic.", flush=True)

        budget_job = start("/budget.js", max_endpoints=7)
        budget_job, budget_snapshot = eventually(lambda: completed(budget_job))
        budget_source = budget_job["sources"][0]
        assert budget_job["status"] == "completed" and budget_source["truncated"], budget_source
        assert budget_source["discovered"] == 7, budget_source
        assert len(budget_snapshot["endpoints"]) == len(large_snapshot["endpoints"]) + 7
        assert len([item for item in budget_snapshot["endpoints"] if "/budget-candidate/" in item["url"]]) == 6
        print("Explicit endpoint budgets still stop additions and report partial collection.", flush=True)

        job = start("/slow")
        assert slow_started.wait(5), "Slow fixture was not requested"
        stopped = api("/api/recon/jobs/" + job["id"] + "/stop", {"session_id": sid})
        assert stopped["stopped"]
        current, _ = eventually(lambda: completed(job))
        assert current["status"] == "cancelled", current
        release_slow.set()
        next_job = start("/after-cancel")
        current, snapshot = eventually(lambda: completed(next_job))
        assert current["status"] == "completed"
        assert "/after-stop" not in requested
        assert not any(item["url"] == origin + "/after-stop" for item in snapshot["endpoints"])
        print("Cancellation discards late work and permits a fresh completed job.", flush=True)

        # Wait for the real debounced atomic publication before killing the
        # process; a passing in-memory read alone does not prove durability.
        expected = api("/api/recon?session_id=" + sid)
        expected_stored = {key: expected[key] for key in ("jobs", "endpoints")}
        expected_map = read_site_map()

        def persisted():
            for path in data.rglob("state.json"):
                if path.parent.name != sid:
                    continue
                try:
                    stored = json.loads(path.read_text())["recon"]
                    if stored == expected_stored:
                        return True
                except (OSError, ValueError, KeyError):
                    pass
            return False

        eventually(persisted)
        process.kill()
        process.wait(timeout=10)
        process = launch()
        runtime = eventually(ready)
        ui = "http://" + runtime["ui_addr"]
        assert api("/api/settings")["active_session"]["id"] == sid
        assert api("/api/recon?session_id=" + sid) == expected
        assert read_site_map() == expected_map, "Recon sitemap projection changed across restart"
        assert api("/api/transactions?session_id=" + sid) == []
        print("Restart restored the full Recon inventory, provenance and sitemap without fabricated transactions.", flush=True)
        if output := os.environ.get("SNIPER_RECON_SMOKE_RESULTS"):
            Path(output).write_text(json.dumps(results, indent=2) + "\n")
        assert not failures, "; ".join(failures)
        print(f"All {len(cases)} extraction fixtures, uncapped collection, explicit budgets, sitemap, cancellation and restart checks passed.", flush=True)
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
