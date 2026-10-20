"""Verify wire request targets with an isolated running Sniper and local origins.

Run: python tests/raw_request_target_smoke.py [release binary directory]
Requires curl and Python SSL; never installs a CA or changes system proxy settings.
"""
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
from runtime_smoke import eventually
from proxy_chain_smoke import Chain, ChainServer


class Origin(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # BaseHTTPRequestHandler itself rewrites leading // in self.path.
        target = self.raw_requestline.decode("ascii").split(" ")[1]
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.dumps({"target": target, "method": self.command,
                              "body": body.hex(), "host": self.headers["Host"],
                              "authorization": self.headers["Authorization"],
                              "cookie": self.headers["Cookie"],
                              "duplicates": self.headers.get_all("X-Synthetic"),
                              "proxy_authorization": self.headers["Proxy-Authorization"]}).encode()
        self.send_response(302 if "redirect=1" in target else 200)
        if "redirect=1" in target:
            self.send_header("Location", "/must-not-follow")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def run_curl(command, env):
    response = subprocess.run(command, env=env, capture_output=True)
    if response.returncode:
        # This fixture only talks to its synthetic origins. Keep TLS diagnostics
        # without printing the command's headers/body or unbounded tool output.
        stderr = response.stderr.decode("utf-8", errors="replace")
        bounded = stderr[:4096] + (" [truncated]" if len(stderr) > 4096 else "")
        raise AssertionError(f"curl failed ({response.returncode}) for synthetic traffic: {bounded}")
    return response


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    suffix = ".exe" if os.name == "nt" else ""
    curl = shutil.which("curl")
    assert curl is not None, "curl is required for the raw request-target regression"
    curl_version = subprocess.run([curl, "--version"], check=True, capture_output=True, text=True)
    print(f"curl executable: {curl}\n{curl_version.stdout.splitlines()[0]}", flush=True)
    # This throwaway CA has no CRL distribution point. Schannel otherwise rejects
    # its valid chain with CERT_TRUST_REVOCATION_STATUS_UNKNOWN. Tolerate only
    # missing/offline revocation data in this fixture; CA/hostname checks remain
    # enabled, and known revoked certificates are still rejected.
    tls_options = ["--ssl-revoke-best-effort"] if "Schannel" in curl_version.stdout else []
    servers = []
    child = None
    with tempfile.TemporaryDirectory(prefix="sniper-raw-target-") as temporary:
        root = Path(temporary)
        data, home = root / "data", root / "home"
        home.mkdir()
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                   SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", RUST_LOG="off")
        env.pop("SNIPER_API_ADDR", None)
        for name in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            env.pop(name, None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(path, payload=None):
            request = urllib.request.Request("http://" + runtime["ui_addr"] + path,
                data=None if payload is None else json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=15) as response:
                return json.load(response)

        try:
            child = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            def ready():
                assert child.poll() is None, "Isolated runtime exited during startup"
                try:
                    result = json.loads((data / "runtime-state.json").read_text())
                    return result if result["pid"] == child.pid else None
                except (OSError, ValueError):
                    return None

            runtime = eventually(ready)
            settings = eventually(lambda: api("/api/settings"))
            session_id = settings["active_session"]["id"]
            ca = settings["certificate"]["pem_path"]
            # Like proxy_chain_smoke, use only this throwaway instance's CA as
            # the synthetic origin certificate. It is not installed as trust.
            origins = {}
            for scheme in ("http", "https"):
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
                if scheme == "https":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(ca, data / "certificates/sniper-root-ca.key")
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                servers.append(server)
                origins[scheme] = server.server_port
                threading.Thread(target=server.serve_forever, daemon=True).start()

            # Only this isolated Sniper trusts the synthetic self-signed origin.
            api("/api/runtime", {"upstream_insecure": True})
            body = "synthetic=body&escaped=%2F"
            headers = [{"name": "Authorization", "value": "Bearer synthetic-only"},
                       {"name": "Cookie", "value": "synthetic=only"},
                       {"name": "X-Synthetic", "value": "one"},
                       {"name": "X-Synthetic", "value": "two"}]

            def check(result, target, host):
                assert result["target"] == target, (target, result["target"])
                assert result["method"] == "POST"
                assert result["body"] == body.encode().hex()
                assert result["host"] == host
                assert result["authorization"] == "Bearer synthetic-only"
                assert result["cookie"] == "synthetic=only"
                assert result["duplicates"] == ["one", "two"]
                assert result["proxy_authorization"] is None

            def exercise(scheme, target, name="127.0.0.1"):
                host = f"{name}:{origins[scheme]}"
                command = [curl, "--silent", "--show-error", "--path-as-is", "--max-time", "15",
                           "--noproxy", "", "--proxy", "http://" + runtime["proxy_addr"],
                           "--cacert", ca, "--data-binary", body]
                if scheme == "https":
                    command += tls_options
                for header in headers:
                    command += ["-H", header["name"] + ": " + header["value"]]
                # curl drops an empty query delimiter while parsing its URL;
                # explicitly set the wire target to exercise that valid case.
                if target.endswith("?"):
                    command += ["--request-target", f"http://{host}{target}" if scheme == "http" else target]
                response = run_curl(command + [f"{scheme}://{host}{target}"], env)
                check(json.loads(response.stdout), target, host)
                record = eventually(lambda: next((r for r in api("/api/transactions")
                    if r["path"] == target and r["host"] == host and r["scheme"] == scheme), None))
                assert record["status"] == (302 if "redirect=1" in target else 200)
                replay = api("/api/replay/send", {"session_id": session_id, "request": {
                    "scheme": scheme, "host": host, "method": "POST", "path": target,
                    "headers": headers, "body": body}})
                assert replay["path"] == target
                assert replay["status"] == record["status"]
                check(json.loads(replay["response"]["body_preview"]), target, host)

            # Invalid Replay targets must fail before reaching either origin.
            request = {"scheme": "http", "host": f"127.0.0.1:{origins['http']}",
                       "method": "POST", "path": "/", "headers": headers, "body": body}
            for invalid in ["/fragment#hidden", "/bad\r\nInjected: yes", "/bad\0path",
                            "relative", "http://example.com/path"]:
                try:
                    api("/api/replay/send", {"session_id": session_id,
                        "request": dict(request, path=invalid)})
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                else:
                    raise AssertionError("Replay accepted an invalid request target")

            # The raw path must not opt out of configured upstream TLS validation.
            api("/api/runtime", {"upstream_insecure": False})
            try:
                api("/api/replay/send", {"session_id": session_id, "request": dict(request,
                    scheme="https", host=f"127.0.0.1:{origins['https']}", path="/a/../tls")})
            except urllib.error.HTTPError as error:
                failure = json.load(error)
                assert failure["record"]["status"] == 502
            else:
                raise AssertionError("Strict TLS accepted the self-signed origin")
            api("/api/runtime", {"upstream_insecure": True})

            # DNS dial override retains the logical Host and the raw target.
            override = api("/api/replay/send", {"session_id": session_id,
                "request": dict(request, host=f"example.com:{origins['http']}", path="/a/../override?x=%2f"),
                "target": {"scheme": "http", "host": "127.0.0.1", "port": str(origins["http"])}})
            check(json.loads(override["response"]["body_preview"]), "/a/../override?x=%2f",
                  f"example.com:{origins['http']}")
            print("PASS: invalid Replay targets, strict TLS and DNS target override", flush=True)

            targets = ["/a/../b", "/a/%2e%2E/b?x=%2f&x=%2F+%20",
                       "/./a/.%2e/b/..;literal/%252e%252e",
                       "//a///b/%2f/%5C?empty=&bare&x=../", "/a/../b?",
                       "/a/../b?redirect=1", "/ordinary?unchanged=yes"]
            for scheme in origins:
                for target in targets:
                    exercise(scheme, target)
            # Export an unrelated, currently valid platform root into the
            # temporary fixture. Reading it does not modify platform trust.
            # Reusing another Sniper root with the same subject can instead
            # trigger an ambiguous signature error in OpenSSL's chain builder.
            own_trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            own_trust.load_verify_locations(cafile=ca)
            own_subject = own_trust.get_ca_certs()[0]["subject"]
            own_der = ssl.PEM_cert_to_DER_cert(Path(ca).read_text())
            platform_trust = ssl.create_default_context()
            details = platform_trust.get_ca_certs()
            certificates = platform_trust.get_ca_certs(binary_form=True)
            assert len(details) == len(certificates)
            wrong_ca = root / "unrelated-ca.pem"
            now = time.time()
            for detail, certificate in zip(details, certificates):
                if (detail["subject"] != own_subject and detail["subject"] == detail["issuer"]
                        and certificate != own_der
                        and ssl.cert_time_to_seconds(detail["notBefore"]) <= now
                        <= ssl.cert_time_to_seconds(detail["notAfter"])):
                    wrong_ca.write_text(ssl.DER_cert_to_PEM_cert(certificate), encoding="ascii")
                    break
            else:
                raise AssertionError("A valid unrelated platform root is required for the negative TLS check")

            # The fixture-only CRL option must not become a TLS verification
            # bypass. Use the wrong valid CA; then trust the correct CA but
            # CONNECT to an IP leaf while verifying the URL's DNS hostname.
            # Both use the same reachable MITM endpoint as the positive cases.
            port = origins["https"]
            tls_command = [curl, "--silent", "--show-error", "--max-time", "15",
                           "--noproxy", "", "--proxy", "http://" + runtime["proxy_addr"],
                           *tls_options]
            negatives = [
                ("untrusted CA", ["--cacert", str(wrong_ca), f"https://127.0.0.1:{port}/tls-negative"],
                    ["self-signed certificate", "unable to get local issuer",
                     "untrusted_root", "untrusted root", "unknown ca"]),
                ("hostname mismatch", ["--cacert", ca, "--connect-to",
                    f"example.com:{port}:127.0.0.1:{port}", f"https://example.com:{port}/tls-negative"],
                    ["hostname", "host name", "wrong_principal", "principal name is incorrect"]),
            ]
            for label, arguments, reasons in negatives:
                rejected = subprocess.run(tls_command + arguments, env=env, capture_output=True)
                diagnostic = rejected.stderr.decode("utf-8", errors="replace")[:4096]
                assert rejected.returncode == 60, (
                    f"Expected curl certificate rejection for {label}, got {rejected.returncode}: {diagnostic}"
                )
                assert any(reason in diagnostic.lower() for reason in reasons), (
                    f"Unexpected certificate rejection for {label}: {diagnostic}"
                )
                print(f"Expected {label} rejection: {diagnostic.splitlines()[0]}", flush=True)
            print("PASS: client still rejects an untrusted CA and a hostname mismatch", flush=True)

            # Exercise the real CLI raw-file entry point, not just its parser.
            cli_target = "/cli/a/../%2e%2E/b?raw=%2f"
            cli_host = f"127.0.0.1:{origins['http']}"
            raw_file = root / "synthetic-request.txt"
            raw_headers = "".join(header["name"] + ": " + header["value"] + "\r\n" for header in headers)
            raw_file.write_bytes((f"POST http://{cli_host}{cli_target} HTTP/1.1\r\n"
                f"Host: {cli_host}\r\n" + raw_headers + f"Content-Length: {len(body)}\r\n\r\n" + body).encode())

            def cli(*arguments):
                result = subprocess.run([str(binaries / ("sniper-cli" + suffix)),
                    "--output", "compact", "--api", "http://" + runtime["ui_addr"], *arguments],
                    env=env, check=True, capture_output=True, timeout=15)
                value = json.loads(result.stdout)
                return value.get("data", value)

            opened = cli("replay", "open", "--request-file", str(raw_file), "--yes")
            cli("replay", "send", "--tab-id", opened["id"], "--yes")
            cli_record = eventually(lambda: next((r for r in api("/api/transactions")
                if r["path"] == cli_target and r["host"] == cli_host), None))
            detail = api("/api/transactions/" + cli_record["id"])
            check(json.loads(detail["response"]["body_preview"]), cli_target, cli_host)
            print("PASS: CLI raw absolute request file reaches the origin unchanged", flush=True)

            # Exercise the buffered capture path with request/response interception.
            api("/api/runtime", {"intercept_enabled": True, "intercept_scope_only": False})
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(exercise, "https", "/a/../%2e%2e/intercept?raw=%2f")
                eventually(lambda: api("/api/intercepts"))
                api("/api/intercepts/forward-all", {})
                eventually(lambda: api("/api/response-intercepts"))
                api("/api/response-intercepts/forward-all", {})
                # Replay is intentionally outside intercept queues.
                pending.result(timeout=15)
            api("/api/runtime", {"intercept_enabled": False})

            connection = http.client.HTTPConnection(runtime["proxy_addr"], timeout=10)
            connection.request("POST", f"http://127.0.0.1:{origins['http']}", body=body)
            response = connection.getresponse()
            assert response.status == 200
            assert json.load(response)["target"] == "/"
            connection.close()
            connection = http.client.HTTPConnection(runtime["proxy_addr"], timeout=10)
            connection.request("OPTIONS", "*", headers={"Host": f"127.0.0.1:{origins['http']}"})
            response = connection.getresponse()
            assert response.status == 400  # Existing unsupported star-form behavior.
            response.read()
            connection.close()
            print("PASS: raw HTTP, CONNECT MITM, replay, buffered intercept, capture equality, bodies, headers and redirects", flush=True)

            for kind in ("http", "socks5", "socks5h"):
                chain = ChainServer(("127.0.0.1", 0), Chain)
                chain.kind, chain.auth = kind, True
                chain.attempts, chain.hits, chain.destinations = 0, 0, []
                servers.append(chain)
                threading.Thread(target=chain.serve_forever, daemon=True).start()
                api("/api/runtime", {"upstream_proxy": {"enabled": True,
                    "url": f"{kind}://127.0.0.1:{chain.server_address[1]}",
                    "username": "tester", "password": "chain-secret"}})
                for scheme in origins:
                    exercise(scheme, "/a/../%2E%2e/b?chain=yes", "example.com")
                assert chain.hits >= 4
                api("/api/runtime", {"upstream_bypass_hosts": ["127.0.0.1"]})
                attempts = chain.attempts
                for scheme in origins:
                    exercise(scheme, "/a/../%2e%2e/b?bypass=yes")
                assert chain.attempts == attempts
                api("/api/runtime", {"upstream_bypass_hosts": []})
                print(f"PASS: {kind} raw targets, auth, remote DNS and bypass", flush=True)
        finally:
            if child is not None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
