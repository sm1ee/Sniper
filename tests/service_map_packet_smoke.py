#!/usr/bin/env python3
"""Owned-loopback retained-packet proof.

Run: python3 tests/service_map_packet_smoke.py [path/to/sniper] [--binary-sha256 SHA256]
[--evidence-dir NEW_DIRECTORY]; the binary defaults to target/release/sniper.

Four tiny origin requests only. Packet reads are local metadata/body reads, never
sends. No browser, encoded-content scenario, external target or existing user data.
"""
import argparse
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
import urllib.parse
import uuid

PATHS = {"/control", "/changed", "/truncated", "/binary"}
PREVIEW = 32
IN_PROGRESS = "Streaming response capture is still in progress."


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def eventually(operation, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = operation()
        if value:
            return value
        threading.Event().wait(0.025)
    raise AssertionError("Timed out waiting for owned packet fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, nargs="?",
                        default=Path("target/release") / ("sniper.exe" if os.name == "nt" else "sniper"))
    parser.add_argument("--binary-sha256", help="refuse to run any other build")
    parser.add_argument("--evidence-dir", type=Path, help="a new directory; defaults to one under the temp dir")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.binary_sha256 = args.binary_sha256 or sha(binary)
    assert binary.name in {"sniper", "sniper.exe"} and sha(binary) == args.binary_sha256
    evidence = (args.evidence_dir or Path(tempfile.mkdtemp(prefix="sniper-evidence-")) / "evidence").absolute()
    assert evidence.parent.is_dir() and not evidence.exists()
    assert not evidence.resolve().is_relative_to(Path(__file__).resolve().parent.parent)
    evidence.mkdir(mode=0o700)
    report = {"status": "RUNNING", "binary_sha256": args.binary_sha256, "script_sha256": sha(__file__),
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "network_scope": "owned 127.0.0.1 only", "controls": [], "processes": [], "cases": {}}
    child = log = upstream = temporary = runtime = data = None
    seen, errors = [], []
    records, packets = {}, {}
    lock = threading.Lock()

    def check(name, condition):
        report["controls"].append({"name": name, "pass": bool(condition)})
        assert condition, name

    class Fixture(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def respond(self):
            expected_method = "POST" if self.path == "/changed" else "GET"
            with lock:
                if self.path not in PATHS or self.path in seen or self.command != expected_method:
                    errors.append("Unexpected owned origin request")
                    self.send_error(400)
                    return
                seen.append(self.path)
            self.connection.settimeout(10)
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or not 0 <= size <= 64:
                errors.append("Unexpected request framing")
                self.send_error(400)
                return
            request = self.rfile.read(size)
            expected_request = b"after-request" if self.path == "/changed" else b""
            if request != expected_request:
                errors.append("Unexpected request bytes")
            body = {"/control": b"control", "/changed": b"before-response", "/truncated": b"t" * 96,
                    "/binary": b"\x00\xff\x01"}[self.path]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream" if self.path == "/binary" else "text/plain")
            self.send_header("X-Example", "first")
            self.send_header("X-Example", "second")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = respond

    def api_at(address, path, payload=None):
        host, port = address.rsplit(":", 1)
        assert host == "127.0.0.1" and 0 < int(port) < 65536
        route = urllib.parse.urlsplit(path).path
        allowed = route in {"/api/settings", "/api/runtime", "/api/scanner-config", "/api/match-replace",
                            "/api/transactions", "/api/findings", "/api/target/service-map", "/api/target/service-map/packet"}
        if route.startswith("/api/transactions/"):
            uuid.UUID(route.removeprefix("/api/transactions/"))
            allowed = payload is None
        assert allowed and not urllib.parse.urlsplit(path).netloc
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            connection.request("GET" if payload is None else "POST", path,
                               body=None if payload is None else json.dumps(payload).encode(),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(2 * 1024 * 1024 + 1)
            assert response.status == 200 and len(body) <= 2 * 1024 * 1024, (route, response.status)
            return json.loads(body) if body else None
        finally:
            connection.close()

    def api(path, payload=None):
        return api_at(runtime["ui_addr"], path, payload)

    def start(env):
        nonlocal child, runtime, log
        log = (evidence / ("server-%d.log" % (len(report["processes"]) + 1))).open("xb")
        child = subprocess.Popen([str(binary)], env=env, cwd=str(evidence), stdout=log, stderr=subprocess.STDOUT)
        report["processes"].append({"pid": child.pid})

        def ready():
            assert child.poll() is None, "Owned runtime exited before readiness"
            try:
                value = json.loads((data / "runtime-state.json").read_text())
                if value["pid"] != child.pid:
                    return None
                for key in ("ui_addr", "proxy_addr"):
                    host, port = value[key].rsplit(":", 1)
                    assert host == "127.0.0.1" and 0 < int(port) < 65536
                api_at(value["ui_addr"], "/api/settings")
                return {key: value[key] for key in ("pid", "ui_addr", "proxy_addr")}
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
        check("graceful owned stop " + str(len(report["processes"])), code == 0 and not forced)

    def capture(path):
        host, port = runtime["proxy_addr"].rsplit(":", 1)
        assert host == "127.0.0.1" and path in PATHS
        body = b"before-request" if path == "/changed" else b""
        connection = http.client.HTTPConnection(host, int(port), timeout=15)
        try:
            connection.request("POST" if path == "/changed" else "GET",
                               f"http://127.0.0.1:{upstream.server_port}{path}", body,
                               {"Content-Type": "text/plain", "Content-Length": str(len(body))})
            response = connection.getresponse()
            value = response.read()
            expected = {"/control": b"control", "/changed": b"after-response", "/truncated": b"t" * 96,
                        "/binary": b"\x00\xff\x01"}[path]
            check(path + " expected live wire", response.status == 200 and value == expected)
        finally:
            connection.close()

    def read_packet(token, variant):
        query = urllib.parse.urlencode({"session_id": session, "evidence_id": token, "variant": variant})
        return api("/api/target/service-map/packet?" + query)

    def token_for(path):
        value = api("/api/target/service-map?" + urllib.parse.urlencode({"session_id": session, "all_rows": "true", "fresh": "true"}))
        endpoint = next(endpoint for origin in value["origins"] for endpoint in origin["endpoints"] if endpoint["path"] == path)
        assert len(endpoint["evidence"]) == 1
        return endpoint["evidence"][0]

    def compare(record, packet, variant, token):
        check(record["path"] + " " + variant + " exact identity", packet["available"] and packet["source"]["record_id"] == record["id"]
              and packet["source"]["sequence"] == str(record["sequence"]) and packet["variant"] == variant)
        check(record["path"] + " " + variant + " exact envelope owner", packet["session_id"] == session
              and packet["evidence_id"] == token and packet["source"]["started_at"] == record["started_at"])
        for side in ("request", "response"):
            selected = record.get(("original_" if variant == "original" else "") + side)
            result = packet[side]
            if selected is None:
                check(record["path"] + side + variant + " absent not empty", result == {"status": "not_retained", "message": None})
                continue
            message = result["message"]
            check(record["path"] + side + variant + " ordered headers", message["headers"] == selected["headers"])
            body = message["body"]
            check(record["path"] + side + variant + " retained preview", body["available"] and body["reason"] is None and body["body_preview"] == selected["body_preview"])
            for key in ("body_encoding", "body_size", "decoded_body_size", "preview_truncated", "content_type", "content_decoded"):
                check(record["path"] + side + variant + " " + key, body[key] == selected.get(key, False if key == "content_decoded" else None))
            if variant == "original":
                check(side + " original unknown line fields", all(message[key] is None for key in ("scheme", "authority", "http_version", "status_code")))
                check(side + " original observed method and path", message["method"] == (record.get("original_method") if side == "request" else None)
                      and message["path"] == (record.get("original_path") if side == "request" else None))
            else:
                expected_line = {"method": record["method"], "path": record["path"], "scheme": record["scheme"],
                                 "authority": record["host"], "status_code": None} if side == "request" else {
                                 "method": None, "path": None, "scheme": None, "authority": None, "status_code": record["status"]}
                check(side + " current observed line", all(message[key] == value for key, value in expected_line.items()))
                expected_version = record.get("http_version" if side == "request" else "response_http_version")
                check(side + " current observed version", message["http_version"] == expected_version)
        text = json.dumps(packet)
        check(record["path"] + variant + " no unrelated annotations", all('"' + key + '"' not in text for key in ("notes", "user_note", "color_tag", "annotation_revision", "workspace")))
        check(record["path"] + variant + " exact limits", packet["limits"] == {"packet_bytes": 2097152, "serialized_row_bytes": 2097152})

    try:
        temporary = tempfile.TemporaryDirectory(prefix="sniper-map-packet-")
        data = Path(temporary.name)
        env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy") and not key.startswith("SNIPER_")}
        env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0", SNIPER_PROXY_ADDR="127.0.0.1:0",
                   SNIPER_BODY_PREVIEW_BYTES=str(PREVIEW), SNIPER_INSTALL_AGENT_SKILLS="0", SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        upstream.daemon_threads = True
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        start(env)
        session = api("/api/settings")["active_session"]["id"]
        uuid.UUID(session)
        read_query = "?session_id=" + session
        write_query = read_query + "&expected_active_session_id=" + session
        api("/api/runtime", {"session_id": session, "expected_active_session_id": session, "intercept_enabled": False})
        scanner = api("/api/scanner-config" + read_query)
        api("/api/scanner-config" + write_query, {"session_id": session, "expected_config_token": scanner["config_token"],
            "enabled": False, "rules": scanner["rules"], "custom_rules": scanner["custom_rules"]})
        rules = [{"id": str(uuid.uuid4()), "enabled": True, "description": "owned packet fixture", "scope": scope,
                  "target": "body", "search": "before-" + suffix, "replace": "after-" + suffix,
                  "regex": False, "case_sensitive": True} for scope, suffix in (("request", "request"), ("response", "response"))]
        api("/api/match-replace" + write_query, {"session_id": session, "rules": rules})
        for path in ("/control", "/changed", "/truncated", "/binary"):
            capture(path)
            def completed():
                row = next((row for row in api("/api/transactions" + read_query) if row["path"] == path), None)
                if row is None:
                    return None
                value = api("/api/transactions/" + row["id"] + read_query)
                return value if value.get("response") and IN_PROGRESS not in value.get("notes", []) else None
            record = eventually(completed)
            records[path] = record
            token = token_for(path)
            packets[path] = {"token": token}
            for variant in ("current", "original"):
                packet = read_packet(token, variant)
                compare(record, packet, variant, token)
                packets[path][variant] = packet
            report["cases"][path] = {"record_id": record["id"], "sequence": str(record["sequence"]),
                                      "originals": packets[path]["current"]["originals"],
                                      "capture_preview_truncated": record["response"]["preview_truncated"]}
        check("replacement retained both originals", packets["/changed"]["current"]["originals"] == {"request": True, "response": True})
        check("truncated capture remains explicit", packets["/truncated"]["current"]["response"]["message"]["body"]["preview_truncated"] is True)
        check("binary representation unchanged", packets["/binary"]["current"]["response"]["message"]["body"]["body_encoding"] == "base64")
        check("exact four origin requests and no scanner findings", len(seen) == 4 and set(seen) == PATHS and not errors and api("/api/findings" + read_query) == [])

        def disk_ready():
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
            return found if all(found.get(record["id"]) == record for record in records.values()) else None
        eventually(disk_ready)
        check("exact completed capture records persisted before stop", True)
        report["pre_stop_disk_sha256"] = {name: sha(data / "sessions" / session / name) for name in ("transactions.ndjson", "transactions.journal.checkpoint", "transactions.journal") if (data / "sessions" / session / name).exists()}
        stop()
        start(env)
        check("restart retains session", api("/api/settings")["active_session"]["id"] == session)
        for path, record in records.items():
            old = read_packet(packets[path]["token"], "current")
            check(path + " old generation refused", not old["available"] and old["reason"] == "stale_generation" and old["request"] is None and old["response"] is None)
            fresh = token_for(path)
            for variant in ("current", "original"):
                compare(record, read_packet(fresh, variant), variant, fresh)
        check("read-only packet/restart causes no origin requests", len(seen) == 4 and not errors)
        stop()
        report["origin_request_count"] = len(seen)
        report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAILED"
        report["error"] = str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        if child is not None:
            try:
                stop()
            except BaseException as error:
                report["status"] = "FAILED"
                report["cleanup_error"] = str(error)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)
        if temporary is not None:
            temporary.cleanup()
            report["owned_data_removed"] = not data.exists()
        report["origin_request_count"] = len(seen)
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (evidence / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
