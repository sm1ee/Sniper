#!/usr/bin/env python3
"""Bounded owned-loopback proof for literal Replace note/color actions.

Run only against an explicitly pinned rebuilt headless binary. This fixture never
uses a browser, external origin, script runtime, CLI install or real data directory.
The held first-chunk barriers prove annotation-only response rules do not buffer.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import traceback
import uuid

FULL = b"flag{fixture}"
PREFIX = FULL[:5]
PREVIEW = 16
HELD = {"/stream-body-first", "/stream-header-first", "/manual-clear", "/manual-note"}
PATHS = HELD | {"/buffer-body-first", "/buffer-header-first", "/truncated", "/bodyless", "/empty-encoded", "/replacement"}
IN_PROGRESS = "Streaming response capture is still in progress."
COVERAGE = "Rule body annotation skipped: complete text unavailable."


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def eventually(operation, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = operation()
        if value:
            return value
        threading.Event().wait(0.025)
    raise AssertionError("Timed out waiting for owned fixture barrier")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    assert binary.name in {"sniper", "sniper.exe"}
    assert sha(binary) == args.binary_sha256, "Executable pin mismatch"
    evidence = args.evidence_dir.absolute()
    assert evidence.parent.is_dir() and not evidence.exists()
    assert not evidence.resolve().is_relative_to(Path(__file__).resolve().parent.parent), "Evidence must be outside source"
    evidence.mkdir(mode=0o700)
    report = {"status": "RUNNING", "binary_sha256": args.binary_sha256,
              "script_sha256": sha(__file__), "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "network_scope": "owned 127.0.0.1 only", "controls": [], "cases": {}, "processes": []}
    controls = report["controls"]
    releases = {path: threading.Event() for path in HELD}
    first_received = {path: threading.Event() for path in HELD}
    first_sent = {path: threading.Event() for path in HELD}
    seen, errors = [], []
    lock = threading.Lock()
    upstream = child = log = runtime = pool = temporary = None
    data = None
    records = {}
    session = None

    def check(name, condition):
        controls.append({"name": name, "pass": bool(condition)})
        assert condition, name

    class Fixture(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            with lock:
                if self.path not in PATHS or self.path in seen:
                    errors.append("Unexpected or duplicate owned request")
                    self.send_error(400)
                    return
                seen.append(self.path)
            self.connection.settimeout(25)
            body = FULL
            status = 200
            if self.path == "/truncated":
                body = FULL + b"x" * 84
            if self.path in {"/bodyless", "/empty-encoded"}:
                body = b""
                status = 204 if self.path == "/bodyless" else 200
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Flag", "header-marker")
            self.send_header("Content-Length", str(len(body)))
            if self.path in {"/bodyless", "/empty-encoded"}:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            try:
                if self.path in HELD:
                    self.wfile.write(PREFIX)
                    self.wfile.flush()
                    first_sent[self.path].set()
                    if not releases[self.path].wait(20):
                        errors.append("Owned upstream release barrier timed out")
                        return
                    self.wfile.write(body[len(PREFIX):])
                else:
                    self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                errors.append("Owned fixture stream unexpectedly disconnected")

    def api_at(address, path, payload=None, method=None):
        host, port = address.rsplit(":", 1)
        assert host == "127.0.0.1" and 0 < int(port) < 65536
        method = method or ("POST" if payload is not None else "GET")
        route = path.split("?", 1)[0]
        allowed = route in {"/api/settings", "/api/runtime", "/api/scanner-config", "/api/match-replace", "/api/transactions", "/api/event-log", "/api/findings"}
        if route.startswith("/api/transactions/"):
            parts = route.split("/")
            uuid.UUID(parts[3])
            allowed = len(parts) == 4 or (len(parts) == 5 and parts[4] == "annotations")
        assert allowed and method in {"GET", "POST", "PATCH"}
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            connection.request(method, path, None if payload is None else json.dumps(payload).encode(),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            assert 200 <= response.status < 300, (route, response.status, body[:160])
            return json.loads(body) if body else None
        finally:
            connection.close()

    def api(path, payload=None, method=None):
        assert child and child.poll() is None and runtime["pid"] == child.pid
        return api_at(runtime["ui_addr"], path, payload, method)

    def start(env):
        nonlocal child, runtime, log
        log = (evidence / ("server-%d.log" % (len(report["processes"]) + 1))).open("xb")
        child = subprocess.Popen([str(binary)], env=env, cwd=str(evidence), stdout=log, stderr=subprocess.STDOUT)
        report["processes"].append({"pid": child.pid})

        def ready():
            assert child.poll() is None, "Owned runtime exited before readiness"
            try:
                state = json.loads((data / "runtime-state.json").read_text())
                if state["pid"] != child.pid:
                    return None
                for key in ("ui_addr", "proxy_addr"):
                    host, port = state[key].rsplit(":", 1)
                    assert host == "127.0.0.1" and 0 < int(port) < 65536
                api_at(state["ui_addr"], "/api/settings")
                return {key: state[key] for key in ("pid", "ui_addr", "proxy_addr")}
            except (OSError, ValueError, http.client.HTTPException):
                return None
        runtime = eventually(ready)

    def stop():
        nonlocal child, runtime, log
        if child is None:
            return
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
        forced = False
        try:
            code = child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            forced = True
            child.kill()
            code = child.wait(timeout=5)
        report["processes"][-1].update(exit=code, forced_cleanup=forced)
        child = runtime = None
        log.close()
        log = None
        check("owned graceful process " + str(len(report["processes"])), code == 0 and not forced)

    def proxy_get(path):
        assert path in PATHS
        host, port = runtime["proxy_addr"].rsplit(":", 1)
        assert host == "127.0.0.1"
        connection = http.client.HTTPConnection(host, int(port), timeout=25)
        try:
            connection.request("GET", f"http://127.0.0.1:{upstream.server_port}{path}")
            response = connection.getresponse()
            first = b""
            if path in HELD:
                first = response.read(len(PREFIX))
                assert first == PREFIX, "Initial stream bytes changed"
                first_received[path].set()
            body = first + response.read()
            return response.status, body, {key.lower(): value for key, value in response.getheaders()}
        finally:
            connection.close()

    def rule(scope, target, search, *, color=None, note=None, regex=False, replace=None):
        value = {"id": str(uuid.uuid4()), "enabled": replace is not None, "description": "private synthetic description",
                 "scope": scope, "target": target, "search": search, "replace": "unused" if replace is None else replace,
                 "regex": regex, "case_sensitive": True}
        if replace is None:
            value["annotation_only_enabled"] = True
        if color is not None:
            value["annotation_color"] = color
        if note is not None:
            value["annotation_note"] = note
        return value

    def ordered_rules(body_first=True, buffered=False):
        request = rule("request", "path", "/", color="green", note="request marker")
        body = rule("response", "body", r"flag\{[^}]+\}", color="yellow", note="flag 탐지", regex=True)
        header = rule("response", "header_value", "header-marker", color="blue", note="header marker")
        result = [request] + ([body, header] if body_first else [header, body])
        if buffered:
            result.append(rule("response", "header_value", "never-present", replace="unused"))
        return result

    def set_rules(value):
        adopted = api("/api/match-replace" + write_query, {"session_id": session, "rules": value})
        check("canonical rule adoption " + str(len(controls)), adopted == value)
        return adopted

    def lookup(path, complete=True):
        def ready():
            row = next((row for row in api("/api/transactions" + read_query) if row["path"] == path), None)
            if row is None:
                return None
            record = api("/api/transactions/" + row["id"] + read_query)
            if complete and IN_PROGRESS in record.get("notes", []):
                return None
            return record, row
        return eventually(ready)

    def inspect(path, expected_color, expected_body, expected_status=200, manual=None, changed=False, coverage=False):
        record, summary = lookup(path)
        check(path + " color", record.get("color_tag") == expected_color and summary.get("color_tag") == expected_color)
        check(path + " manual note", record.get("user_note") == manual)
        check(path + " traffic badge", bool(summary.get("has_match_replace")) == changed)
        check(path + " originals", bool(record.get("original_request") or record.get("original_response")) == changed)
        check(path + " response status/size", record["status"] == expected_status and record["response"]["body_size"] == len(expected_body))
        check(path + " coverage", (COVERAGE in record.get("notes", [])) == coverage)
        check(path + " no duplicate generated notes", all(record["notes"].count(note) == 1 for note in record["notes"] if note.startswith("Rule (")))
        records[path] = {key: record.get(key) for key in ("id", "path", "status", "notes", "color_tag", "user_note", "annotation_revision", "original_request", "original_response", "response")}
        report["cases"][path] = {"id": record["id"], "color": record.get("color_tag"), "manual_note": record.get("user_note"),
                                  "annotation_revision": record.get("annotation_revision", 0), "response_size": len(expected_body),
                                  "coverage": coverage, "traffic_changed": changed}
        return record

    try:
        temporary = tempfile.TemporaryDirectory(prefix="sniper-rule-annotations-")
        data = Path(temporary.name)
        env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy") and not key.startswith("SNIPER_")}
        env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0", SNIPER_PROXY_ADDR="127.0.0.1:0",
                   SNIPER_BODY_PREVIEW_BYTES=str(PREVIEW), SNIPER_INSTALL_AGENT_SKILLS="0", SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        upstream.daemon_threads = True
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        start(env)
        session = api("/api/settings")["active_session"]["id"]
        uuid.UUID(session)
        read_query = "?session_id=" + session
        write_query = read_query + "&expected_active_session_id=" + session
        api("/api/runtime", {"session_id": session, "expected_active_session_id": session, "intercept_enabled": False})
        scanner = api("/api/scanner-config" + read_query)
        api("/api/scanner-config" + write_query, {"session_id": session, "expected_config_token": scanner["config_token"],
            "enabled": False, "rules": scanner["rules"], "custom_rules": scanner["custom_rules"]})

        for path in ("/stream-body-first", "/stream-header-first", "/manual-clear", "/manual-note"):
            body_first = path != "/stream-header-first"
            set_rules(ordered_rules(body_first))
            pending = pool.submit(proxy_get, path)
            check(path + " upstream first chunk", first_sent[path].wait(10))
            check(path + " client first chunk before EOF release", first_received[path].wait(10) and not releases[path].is_set())
            provisional, _ = lookup(path, complete=False)
            check(path + " provisional current owner", IN_PROGRESS in provisional["notes"] and provisional.get("color_tag") == "green")
            if path == "/stream-body-first":
                set_rules([rule("response", "body", "flag", color="purple", note="new rule must not apply")])
            if path == "/manual-clear":
                api("/api/transactions/" + provisional["id"] + "/annotations" + write_query,
                    {"session_id": session, "color_tag": None, "user_note": "manual stays"}, "PATCH")
            if path == "/manual-note":
                api("/api/transactions/" + provisional["id"] + "/annotations" + write_query,
                    {"session_id": session, "user_note": "manual stays"}, "PATCH")
            releases[path].set()
            status, body, headers = pending.result(timeout=15)
            check(path + " intact wire", status == 200 and body == FULL and headers.get("x-flag") == "header-marker"
                  and (headers.get("content-length") == str(len(FULL))
                       or ("content-length" not in headers and headers.get("transfer-encoding") == "chunked")))
            color = None if path == "/manual-clear" else "green" if path == "/manual-note" else "blue" if body_first else "yellow"
            record = inspect(path, color, FULL, manual="manual stays" if path.startswith("/manual-") else None)
            check(path + " frozen literal notes", "Rule (response): flag 탐지" in record["notes"] and not any("new rule" in note for note in record["notes"]))
            if path.startswith("/manual-"):
                check(path + " manual revision", record.get("annotation_revision", 0) > 0)

        for path, body_first in (("/buffer-body-first", True), ("/buffer-header-first", False)):
            set_rules(ordered_rules(body_first, buffered=True))
            status, body, headers = proxy_get(path)
            check(path + " intact buffered wire", status == 200 and body == FULL and headers.get("content-length") == str(len(FULL)))
            record = inspect(path, "blue" if body_first else "yellow", FULL)
            stream = records["/stream-body-first" if body_first else "/stream-header-first"]
            check(path + " ordered stream parity", record["notes"] == stream["notes"] and record.get("color_tag") == stream["color_tag"])

        set_rules([rule("response", "body", r"^flag\{fixture\}xxx$", regex=True, note="prefix must not match", color="yellow")])
        status, body, _ = proxy_get("/truncated")
        check("truncated wire intact", status == 200 and body == FULL + b"x" * 84)
        truncated = inspect("/truncated", None, body, coverage=True)
        check("truncated retained prefix is not a match", truncated["response"]["preview_truncated"] and not any("prefix must" in note for note in truncated["notes"]))

        set_rules([rule("response", "body", "^$", regex=True, note="known empty", color="yellow")])
        for path, expected_status, color, partial in (("/bodyless", 204, "yellow", False), ("/empty-encoded", 200, None, True)):
            status, body, headers = proxy_get(path)
            check(path + " bodyless wire metadata", status == expected_status and body == b"" and headers.get("content-encoding") == "gzip")
            inspect(path, color, b"", expected_status, coverage=partial)

        set_rules([rule("response", "body", "fixture", replace="changed", note="mixed action", color="yellow")])
        status, body, headers = proxy_get("/replacement")
        changed = FULL.replace(b"fixture", b"changed")
        check("legacy replacement preserved", status == 200 and body == changed and headers.get("content-length") == str(len(changed)))
        inspect("/replacement", "yellow", changed, changed=True)
        events = api("/api/event-log" + read_query)
        check("literal annotation not copied to event log", all("flag 탐지" not in json.dumps(event, ensure_ascii=False) and "mixed action" not in json.dumps(event) for event in events))
        check("passive scanner remains disabled", api("/api/findings" + read_query) == [])
        check("exact bounded requests", len(seen) == len(PATHS) == 10 and set(seen) == PATHS and not errors)

        def disk_records():
            # Read only this fixture's synthetic journal/snapshot, never another data dir.
            found = {}
            directory = data / "sessions" / session
            for name in ("transactions.ndjson", "transactions.journal.checkpoint", "transactions.journal"):
                file = directory / name
                if not file.exists():
                    continue
                for line in file.read_text().splitlines():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        return None
                    record = value.get("record") if value.get("type") in {"insert", "update"} else value if "id" in value and "request" in value else None
                    if record is not None:
                        found[record["id"]] = record
            return found if all(expected["id"] in found and all(found[expected["id"]].get(key) == expected.get(key) for key in expected) for expected in records.values()) else None
        disk = eventually(disk_records)
        check("completed annotations present on disk before shutdown", len(disk) == 10)
        report["pre_shutdown_disk"] = {name: sha(data / "sessions" / session / name) for name in ("transactions.ndjson", "transactions.journal.checkpoint", "transactions.journal") if (data / "sessions" / session / name).exists()}
        stop()
        start(env)
        check("restart same isolated session", api("/api/settings")["active_session"]["id"] == session)
        for path, expected in records.items():
            actual = api("/api/transactions/" + expected["id"] + read_query)
            check(path + " restart annotations and capture", all(actual.get(key) == expected.get(key) for key in expected))
        check("restart makes no new origin requests", len(seen) == 10 and not errors)
        stop()
        report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAILED"
        report["error"] = str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        for release in releases.values():
            release.set()
        if child is not None:
            try:
                stop()
            except BaseException as error:
                report["status"] = "FAILED"
                report["cleanup_error"] = str(error)
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)
        if temporary is not None:
            temporary.cleanup()
            report["owned_data_removed"] = not data.exists()
        report["origin_request_count"] = len(seen)
        report["origin_paths"] = seen
        report["fixture_errors"] = errors
        report["binary_post_sha256"] = sha(binary)
        report["script_post_sha256"] = sha(__file__)
        if errors or report["binary_post_sha256"] != args.binary_sha256 or report["script_post_sha256"] != report["script_sha256"]:
            report["status"] = "FAILED"
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with (evidence / "receipt.json").open("x") as output:
            json.dump(report, output, indent=2, ensure_ascii=False)
            output.write("\n")
        print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
