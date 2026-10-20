"""Verify Nuclei templates against an isolated Sniper and a loopback upstream:
import a synthetic release, enable passive templates, capture in scope,
restart, and rescan after disabling; then run a Template Scan, check it sent
only to its target, kept only matches, survives a rescan, sends raw requests
as Nuclei does, and is marked interrupted when Sniper stops mid-scan. Nothing
leaves this machine.

Run: python tests/template_smoke.py [directory containing sniper]
"""

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

DETECT = """id: example-detect
info:
  name: Example Detect
  severity: low
  tags: tech
http:
  - method: GET
    path: ['{{BaseURL}}']
    matchers:
      - type: word
        words: ['Example Server']
    extractors:
      - type: regex
        group: 1
        regex: ['Example Server ([0-9.]+)']
"""

GLOBAL = """id: example-global
info:
  name: Example Global
  severity: info
http:
  - global-matchers: true
    matchers:
      - type: regex
        name: example-header
        part: header
        regex: ['(?i)x-example: yes']
"""

ACTIVE = """id: example-active
info:
  name: Example Active
  severity: medium
http:
  - method: GET
    path: ['{{BaseURL}}/.env']
    matchers:
      - type: word
        words: ['APP_KEY=']
"""

SLOW = """id: example-slow
info:
  name: Example Slow
  severity: info
http:
  - method: GET
    path: ['{{BaseURL}}/slow-a', '{{BaseURL}}/slow-b']
    matchers:
      - type: status
        status: [200]
"""

# The second request needs the cookie the first answer set and the token it
# carried, and the matcher reads both answers; `{{7*7}}` names nothing, so it
# goes as written.
RAW = """id: example-raw
info:
  name: Example Raw
  severity: high
http:
  - raw:
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /account?probe={{7*7}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        name=example&csrf={{csrf}}
    extractors:
      - type: regex
        name: csrf
        internal: true
        group: 1
        regex: ['csrf=([a-z0-9]+)']
    matchers:
      - type: dsl
        dsl: ['status_code_1 == 302 && contains(body_2, "Welcome example")']
"""

DNS = """id: example-dns
info:
  name: Example DNS
  severity: info
dns:
  - name: '{{FQDN}}'
"""


def release():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for path, text in [("http/detect.yaml", DETECT), ("http/global.yaml", GLOBAL),
                           ("http/active.yaml", ACTIVE), ("http/slow.yaml", SLOW), ("http/raw.yaml", RAW),
                           ("dns/dns.yaml", DNS)]:
            body = text.encode()
            info = tarfile.TarInfo("example-templates-1.0/" + path)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return gzip.compress(raw.getvalue())


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for the isolated runtime")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()

    seen = []
    posted = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Host")))
            if self.path.startswith("/slow"):
                time.sleep(30)
            if self.path == "/login":
                body = b"csrf=xyz789"
                self.send_response(302)
                self.send_header("Location", "/account")
                self.send_header("Set-Cookie", "sid=abc; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b"APP_KEY=base64:example" if self.path == "/.env" else b"<html><title>Example Server 1.2</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Example", "yes")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            seen.append((self.path, self.headers.get("Host")))
            sent = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            cookie = self.headers.get("Cookie") or ""
            posted.append((self.path, cookie, sent))
            body = b"Welcome example" if "sid=abc" in cookie and sent == "name=example&csrf=xyz789" else b"Who are you"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{upstream.server_port}/"
    # Loopback API calls must not go through any proxy the environment sets.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    temporary = tempfile.TemporaryDirectory(prefix="sniper-template-smoke-")
    data = Path(temporary.name)
    env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
               SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
               SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
    env.pop("SNIPER_API_ADDR", None)
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
        env.pop(key, None)
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = None

    def start():
        nonlocal process
        process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

        def ready():
            assert process.poll() is None, "Runtime exited before becoming ready"
            try:
                state = json.loads((data / "runtime-state.json").read_text())
                return state if state["pid"] == process.pid else None
            except (OSError, ValueError):
                return None

        return eventually(ready)

    def stop():
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    try:
        runtime = start()
        ui = "http://" + runtime["ui_addr"]

        def call(path, payload=None, raw=None, content_type="application/json", expect=200):
            body = raw if raw is not None else (None if payload is None else json.dumps(payload).encode())
            request = urllib.request.Request(ui + path, data=body, headers={"Content-Type": content_type,
                                                                            "Origin": ui})
            try:
                with opener.open(request, timeout=30) as response:
                    assert response.status == expect, (path, response.status)
                    text = response.read()
                    return json.loads(text) if text else None
            except urllib.error.HTTPError as error:
                raise AssertionError(f"{path}: {error.code} {error.read()[:200]!r}") from error

        status = eventually(lambda: (s := call("/api/templates/library"))["state"] == "idle" and s)
        assert status["templates"] == 0, status
        call("/api/templates/library/import", raw=release(), content_type="application/gzip", expect=202)
        status = eventually(lambda: (s := call("/api/templates/library"))["state"] == "idle"
                            and s["templates"] == 6 and s)
        assert status["passive_supported"] == 2, status
        assert status["active_supported"] == 4, status
        assert status["library"]["source"] == "import" and not status["library"]["verified"], status
        listed = call("/api/templates?support=passive")
        assert sorted(item["id"] for item in listed["items"]) == ["example-detect", "example-global"], listed
        detail = call("/api/templates/example-dns")
        assert detail["protocol"] == "dns" and "protocol:dns" in detail["reasons"], detail
        enabled = call("/api/templates/passive", {"filter": {"support": "passive"}, "enabled": True})
        assert enabled["passive_enabled"] == 2, enabled

        call("/api/runtime", {"scope_patterns": ["127.0.0.1"]})
        proxy_host, proxy_port = runtime["proxy_addr"].rsplit(":", 1)
        connection = http.client.HTTPConnection(proxy_host, int(proxy_port), timeout=10)
        connection.request("GET", target)
        response = connection.getresponse()
        response.read()
        assert response.status == 200, response.status

        def template_findings():
            findings = call("/api/findings?limit=1000")
            found = {item["rule_id"]: item for item in findings if item.get("rule_id", "").startswith("nuclei-passive:")}
            return found if len(found) == 2 else None

        found = eventually(template_findings)
        assert set(found) == {"nuclei-passive:example-detect", "nuclei-passive:example-global:example-header"}, found
        detect = call("/api/findings/" + found["nuclei-passive:example-detect"]["id"])
        assert detect["evidence"] == "1.2" and detect["category"] == "nuclei", detect
        print(json.dumps({"captured": sorted(found)}), flush=True)

        stop()
        runtime = start()
        ui = "http://" + runtime["ui_addr"]
        status = eventually(lambda: (s := call("/api/templates/library"))["state"] == "idle" and s)
        assert status["templates"] == 6 and status["passive_enabled"] == 2, status
        assert template_findings(), "template findings did not survive a restart"

        call("/api/templates/passive", {"ids": ["example-global"], "enabled": False})
        rescanned = call("/api/findings/rescan", {})
        assert rescanned["scanned"] == 1, rescanned
        remaining = [item["rule_id"] for item in call("/api/findings?limit=1000")
                     if item.get("rule_id", "").startswith("nuclei-passive:")]
        assert remaining == ["nuclei-passive:example-detect"], remaining
        print("Import, passive capture, restart and rescan after disabling passed.", flush=True)

        # Template Scan: the target is the upstream's origin, in Scope.
        session = next(item["id"] for item in call("/api/sessions") if item["active"])
        origin = target.rstrip("/")
        scan = {"session_id": session, "targets": [origin], "ids": ["example-active", "example-detect"]}
        preview = call("/api/templates/scans", dict(scan, preview=True))
        assert preview["templates"] == 2 and preview["requests"] == 2, preview
        before = len(seen)
        job = call("/api/templates/scans", dict(scan, acknowledged=True))
        query = f"?session_id={session}"
        job = eventually(lambda: (j := call(f"/api/templates/scans/{job['id']}{query}"))["status"] != "running" and j)
        assert job["status"] == "completed" and job["sent"] == 2 and job["matched"] == 2, job
        host = f"127.0.0.1:{upstream.server_port}"
        assert sorted(seen[before:]) == [("/", host), ("/.env", host)], seen[before:]
        scanned = {item["rule_id"] for item in call("/api/findings?limit=1000")
                   if item.get("rule_id", "").startswith("nuclei:")}
        assert scanned == {"nuclei:example-active", "nuclei:example-detect"}, scanned
        kept = [result["record_id"] for result in job["results"]]
        for record_id in kept:
            record = call(f"/api/transactions/{record_id}")
            assert "Sent by Template Scan." in record["notes"], record["notes"]
        call("/api/findings/rescan", {})
        after = {item["rule_id"] for item in call("/api/findings?limit=1000")
                 if item.get("rule_id", "").startswith("nuclei:")}
        assert after == scanned, after
        print(json.dumps({"scanned": sorted(scanned), "requests": seen[before:]}), flush=True)

        # Raw requests go to the target with its Host, share the cookie the
        # first answer set and the token it carried, send `{{7*7}}` as
        # written and leave out the body's last line end; the matcher reads
        # both answers.
        before = len(seen)
        raw_job = call("/api/templates/scans", {"session_id": session, "targets": [origin],
                                                "ids": ["example-raw"], "acknowledged": True})
        raw_job = eventually(lambda: (j := call(f"/api/templates/scans/{raw_job['id']}{query}"))["status"] != "running" and j)
        assert raw_job["status"] == "completed" and raw_job["sent"] == 2 and raw_job["matched"] == 1, raw_job
        assert seen[before:] == [("/login", host), ("/account?probe={{7*7}}", host)], seen[before:]
        assert posted == [("/account?probe={{7*7}}", "sid=abc", "name=example&csrf=xyz789")], posted
        scanned.add("nuclei:example-raw")
        print(json.dumps({"raw": seen[before:]}), flush=True)

        # A crash mid-scan leaves the job interrupted, not running: kill
        # Sniper once the started job has been saved.
        slow = call("/api/templates/scans", {"session_id": session, "targets": [origin],
                                             "ids": ["example-slow"], "acknowledged": True})
        eventually(lambda: any(path.startswith("/slow") for path, _ in seen))
        time.sleep(1.5)
        process.kill()
        process.wait(timeout=10)
        runtime = start()
        ui = "http://" + runtime["ui_addr"]
        eventually(lambda: call("/api/templates/library")["state"] == "idle")
        jobs = {item["id"]: item["status"] for item in call(f"/api/templates/scans{query}")["jobs"]}
        assert jobs == {job["id"]: "completed", raw_job["id"]: "completed", slow["id"]: "interrupted"}, jobs
        survived = {item["rule_id"] for item in call("/api/findings?limit=1000")
                    if item.get("rule_id", "").startswith("nuclei:")}
        assert survived == scanned, survived
        print("Template Scan, rescan and interruption by a restart passed.", flush=True)
    finally:
        if process is not None and process.poll() is None:
            stop()
        upstream.shutdown()
        upstream.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
