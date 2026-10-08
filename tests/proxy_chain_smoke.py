"""Local HTTP/SOCKS5 chain integration test; no external destinations or user data.

Run: python tests/proxy_chain_smoke.py [release binary directory]
"""
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
from runtime_smoke import eventually


def exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError()
        result += chunk
    return result


def headers(sock):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        assert len(result) < 16384
    return result


def relay(left, right):
    while True:
        ready, _, _ = select.select([left, right], [], [], 10)
        if not ready:
            return
        for source in ready:
            data = source.recv(65536)
            if not data:
                return
            (right if source is left else left).sendall(data)


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers.get("Proxy-Authorization") is None
        self.server.hits += 1
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            accept = base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()
            self.protocol_version = "HTTP/1.1"
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            try:
                first, second = exact(self.connection, 2)
                assert first == 0x81 and second & 0x80
                mask = exact(self.connection, 4)
                body = exact(self.connection, second & 0x7f)
                body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
                self.connection.sendall(bytes([0x81, len(body)]) + body)
            except (OSError, EOFError):
                pass
            return
        body = b"chain-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Chain(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        self.server.attempts += 1
        client.settimeout(10)
        try:
            if self.server.kind == "http":
                raw = headers(client)
                lines = raw.decode().split("\r\n")
                method, target, _ = lines[0].split()
                auth = next((line.split(": ", 1)[1] for line in lines if line.lower().startswith("proxy-authorization: ")), "")
                expected = "Basic " + base64.b64encode(b"tester:chain-secret").decode()
                if self.server.auth and auth != expected:
                    client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                    return
                parsed = urllib.parse.urlsplit("//" + target if method == "CONNECT" else target)
                host, port = parsed.hostname, parsed.port or 80
            else:
                version, length = exact(client, 2)
                assert version == 5
                methods = exact(client, length)
                method = 2 if self.server.auth else 0
                assert method in methods
                client.sendall(bytes([5, method]))
                if method == 2:
                    assert exact(client, 1) == b"\x01"
                    user = exact(client, exact(client, 1)[0])
                    password = exact(client, exact(client, 1)[0])
                    valid = user == b"tester" and password == b"chain-secret"
                    client.sendall(bytes([1, 0 if valid else 1]))
                    if not valid:
                        return
                version, command, reserved, kind = exact(client, 4)
                assert (version, command, reserved) == (5, 1, 0)
                if kind == 3:
                    host = exact(client, exact(client, 1)[0]).decode()
                else:
                    host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, exact(client, 4 if kind == 1 else 16))
                port = int.from_bytes(exact(client, 2), "big")
                self.server.destinations.append(host)
            # example.com is resolved here, so tests also prove remote DNS.
            assert host in ("127.0.0.1", "example.com")
            with socket.create_connection(("127.0.0.1", port), timeout=10) as upstream:
                self.server.hits += 1
                if self.server.kind == "http":
                    if method == "CONNECT":
                        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    else:
                        path = parsed.path or "/"
                        if parsed.query:
                            path += "?" + parsed.query
                        clean = [line for line in lines[1:] if not line.lower().startswith(("proxy-authorization:", "proxy-connection:"))]
                        upstream.sendall((f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(clean)).encode())
                else:
                    client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                relay(client, upstream)
        except (OSError, EOFError):
            pass


class ChainServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    servers = []
    child = None
    with tempfile.TemporaryDirectory(prefix="sniper-chain-") as temporary:
        data = Path(temporary)
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0", SNIPER_PROXY_ADDR="127.0.0.1:0", RUST_LOG="off")
        env.pop("SNIPER_API_ADDR", None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def start():
            process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
            def ready():
                assert process.poll() is None
                try:
                    snapshot = json.loads((data / "runtime-state.json").read_text(encoding="utf-8"))
                    if snapshot["pid"] == process.pid:
                        with opener.open("http://" + snapshot["ui_addr"] + "/api/settings", timeout=1):
                            return snapshot
                except (OSError, ValueError):
                    pass
            try:
                return process, eventually(ready)
            except BaseException:
                process.kill()
                process.wait(timeout=10)
                raise

        def api(path, payload=None):
            request = urllib.request.Request("http://" + runtime["ui_addr"] + path, data=None if payload is None else json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=15) as response:
                return json.load(response)

        def serve(server):
            server.hits = 0
            server.attempts = 0
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return server

        def capture(port, secure=False, host="example.com", expected=200):
            proxy_host, proxy_port = runtime["proxy_addr"].rsplit(":", 1)
            if secure:
                connection = http.client.HTTPSConnection(proxy_host, int(proxy_port), context=ssl._create_unverified_context(), timeout=15)
                connection.set_tunnel(host, port)
                path = "/secure"
            else:
                connection = http.client.HTTPConnection(proxy_host, int(proxy_port), timeout=15)
                path = f"http://{host}:{port}/plain"
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                assert response.status == expected, response.status
                body = response.read()
                if expected == 200:
                    assert body == b"chain-ok"
            finally:
                connection.close()

        def websocket(port, secure=False, name="example.com"):
            proxy_host, proxy_port = runtime["proxy_addr"].rsplit(":", 1)
            stream = socket.create_connection((proxy_host, int(proxy_port)), timeout=15)
            try:
                host = f"{name}:{port}"
                if secure:
                    stream.sendall(f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                    assert b" 200 " in headers(stream)
                    stream = ssl._create_unverified_context().wrap_socket(stream, server_hostname="example.com")
                path = "/ws" if secure else f"http://{host}/ws"
                stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".encode())
                assert b" 101 " in headers(stream)
                stream.sendall(b"\x81\x84\x00\x00\x00\x00ping")
                assert exact(stream, 6) == b"\x81\x04ping"
            finally:
                stream.close()

        try:
            child, runtime = start()
            origin = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin))
            tls_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(str(data / "certificates/sniper-root-ca.pem"), str(data / "certificates/sniper-root-ca.key"))
            tls_origin.socket = tls.wrap_socket(tls_origin.socket, server_side=True)
            serve(tls_origin)
            session_id = api("/api/settings")["active_session"]["id"]
            for kind in ("http", "socks5h", "SOCKS5"):
                chain = ChainServer(("127.0.0.1", 0), Chain)
                chain.kind, chain.auth, chain.destinations = kind, True, []
                serve(chain)
                settings = dict(enabled=True, url=f"{kind}://127.0.0.1:{chain.server_address[1]}", username="tester", password="chain-secret")
                result = api("/api/runtime", {"upstream_proxy": settings})
                assert result["upstream_proxy"]["password"] == "********"
                assert "chain-secret" not in json.dumps(api("/api/settings"))
                if kind == "http":
                    second = api("/api/sessions", {"name": "Isolated chain settings"})
                    api(f"/api/sessions/{second['id']}/activate", {})
                    assert not api("/api/runtime")["upstream_proxy"]["enabled"]
                    api(f"/api/sessions/{session_id}/activate", {})
                    assert api("/api/runtime")["upstream_proxy"]["enabled"]
                capture(origin.server_port)
                capture(tls_origin.server_port, secure=True)
                websocket(origin.server_port)
                websocket(tls_origin.server_port, secure=True)
                result = api("/api/replay/send", {"session_id": session_id, "request": {"scheme": "http", "host": f"example.com:{origin.server_port}", "method": "GET", "path": "/replay", "headers": [], "body": ""}})
                assert result["response"]["body_preview"] == "chain-ok"
                ws_id = str(uuid.uuid4())
                api("/api/replay/ws-connect", {"session_id": session_id, "id": ws_id, "scheme": "ws", "host": "example.com", "port": origin.server_port, "path": "/ws"})
                eventually(lambda: api(f"/api/replay/ws-snapshot/{ws_id}?session_id={session_id}")["status"] == "connected")
                api("/api/replay/ws-send", {"session_id": session_id, "id": ws_id, "body": "ping"})
                eventually(lambda: any(frame["direction"] == "server_to_client" and frame["body"] == "ping" for frame in api(f"/api/replay/ws-snapshot/{ws_id}?session_id={session_id}")["frames"]))
                api("/api/replay/ws-disconnect", {"session_id": session_id, "id": ws_id})
                api("/api/runtime", {"passthrough_hosts": ["example.com"]})
                capture(tls_origin.server_port, secure=True)
                api("/api/runtime", {"passthrough_hosts": []})
                assert chain.hits >= 7
                if kind != "http":
                    assert "example.com" in chain.destinations
                print(f"PASS: {kind} authentication, remote DNS, HTTP, HTTPS MITM, passthrough, WS/WSS and replay", flush=True)

                # A host on the bypass list is dialled directly on every path; any
                # other host keeps using the chain.
                api("/api/runtime", {"upstream_bypass_hosts": ["127.0.0.1"]})
                attempts, hits = chain.attempts, origin.hits
                capture(origin.server_port, host="127.0.0.1")
                capture(tls_origin.server_port, secure=True, host="127.0.0.1")
                websocket(origin.server_port, name="127.0.0.1")
                api("/api/runtime", {"passthrough_hosts": ["127.0.0.1"]})
                capture(tls_origin.server_port, secure=True, host="127.0.0.1")
                api("/api/runtime", {"passthrough_hosts": []})
                direct = {"scheme": "http", "host": f"127.0.0.1:{origin.server_port}", "method": "GET", "path": "/replay", "headers": [], "body": ""}
                assert api("/api/replay/send", {"session_id": session_id, "request": direct})["response"]["body_preview"] == "chain-ok"
                # A destination override is allowed with a chain only when its target is bypassed.
                named = dict(direct, host=f"example.com:{origin.server_port}")
                result = api("/api/replay/send", {"session_id": session_id, "request": named, "target": {"scheme": "http", "host": "127.0.0.1", "port": str(origin.server_port)}})
                assert result["response"]["body_preview"] == "chain-ok"
                ws_id = str(uuid.uuid4())
                api("/api/replay/ws-connect", {"session_id": session_id, "id": ws_id, "scheme": "ws", "host": "127.0.0.1", "port": origin.server_port, "path": "/ws"})
                eventually(lambda: api(f"/api/replay/ws-snapshot/{ws_id}?session_id={session_id}")["status"] == "connected")
                api("/api/replay/ws-send", {"session_id": session_id, "id": ws_id, "body": "ping"})
                eventually(lambda: any(frame["direction"] == "server_to_client" and frame["body"] == "ping" for frame in api(f"/api/replay/ws-snapshot/{ws_id}?session_id={session_id}")["frames"]))
                api("/api/replay/ws-disconnect", {"session_id": session_id, "id": ws_id})
                assert chain.attempts == attempts, "A bypassed host went through the chain"
                assert origin.hits >= hits + 5, "A bypassed request did not reach the origin"
                capture(origin.server_port)
                assert chain.attempts > attempts, "A host not on the bypass list skipped the chain"
                # The list sits beside the proxy, so replacing the proxy keeps it.
                api("/api/runtime", {"upstream_proxy": settings})
                assert api("/api/runtime")["upstream_bypass_hosts"] == ["127.0.0.1"]
                api("/api/runtime", {"upstream_bypass_hosts": []})
                try:
                    api("/api/replay/send", {"session_id": session_id, "request": named, "target": {"scheme": "http", "host": "127.0.0.1", "port": str(origin.server_port)}})
                    raise AssertionError("Replay override was combined with a chain for a host that is not bypassed")
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                print(f"PASS: {kind} bypass list on HTTP, HTTPS MITM, passthrough, WS, replay, replay override and WS replay", flush=True)

                # Redacted round-trip must preserve the real password across restart.
                api("/api/runtime", {"upstream_proxy": dict(settings, password="********")})
                api("/api/runtime", {"upstream_bypass_hosts": ["https://Direct.Example.com:8443/path"]})
                child.kill()
                child.wait(timeout=10)
                child, runtime = start()
                assert api("/api/runtime")["upstream_proxy"]["password"] == "********"
                assert api("/api/runtime")["upstream_bypass_hosts"] == ["direct.example.com"]
                api("/api/runtime", {"upstream_bypass_hosts": []})
                capture(origin.server_port)
                before = origin.hits
                api("/api/runtime", {"upstream_proxy": dict(settings, password="wrong")})
                capture(origin.server_port, host="127.0.0.1", expected=407 if kind == "http" else 502)
                assert origin.hits == before, "Failed chain bypassed to direct connection"
                tls_hits = tls_origin.hits
                attempts = chain.attempts
                capture(tls_origin.server_port, secure=True, host="127.0.0.1", expected=502)
                assert chain.attempts >= attempts + 2, "TLS retry did not use the chain"
                assert tls_origin.hits == tls_hits, "TLS retry bypassed proxy authentication"
                attempts = chain.attempts
                try:
                    api("/api/replay/send", {"session_id": session_id, "request": {"scheme": "https", "host": f"127.0.0.1:{tls_origin.server_port}", "method": "GET", "path": "/retry", "headers": [], "body": ""}})
                    raise AssertionError("Replay accepted incorrect proxy credentials")
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                    assert json.load(error)["record"]["status"] == 502
                assert chain.attempts >= attempts + 2, "Replay TLS retry did not use the chain"
                assert tls_origin.hits == tls_hits, "Replay TLS retry bypassed proxy authentication"
                api("/api/runtime", {"passthrough_hosts": ["127.0.0.1"]})
                try:
                    capture(tls_origin.server_port, secure=True, host="127.0.0.1")
                    raise AssertionError("Tunnel accepted incorrect proxy credentials")
                except OSError as error:
                    assert "502" in str(error)
                api("/api/runtime", {"passthrough_hosts": []})
                chain.auth = False
                api("/api/runtime", {"upstream_proxy": dict(settings, username="", password="")})
                capture(origin.server_port)
                assert api("/api/runtime")["upstream_proxy"]["password"] == ""
                print(f"PASS: {kind} restart, masked password preservation, auth failure without bypass, credential clearing", flush=True)

            for url in ("http://user:secret@example.com:8080", "ftp://example.com:21", "http://example.com:8080/path", "http://example.com:80\n80", "http://" + runtime["proxy_addr"], "http://127.1:" + runtime["proxy_addr"].rsplit(":", 1)[1]):
                try:
                    api("/api/runtime", {"upstream_proxy": dict(enabled=True, url=url)})
                    raise AssertionError("Invalid chain accepted")
                except urllib.error.HTTPError as error:
                    assert error.code == 400
            # A stopped proxy cannot silently turn into a direct connection.
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                api("/api/runtime", {"upstream_proxy": dict(enabled=True, url=f"http://127.0.0.1:{reserved.getsockname()[1]}")})
                capture(origin.server_port, host="127.0.0.1", expected=502)
            api("/api/runtime", {"upstream_proxy": {"enabled": False}})
            capture(origin.server_port, host="127.0.0.1")
            print("PASS: address validation, loop prevention, unreachable proxy and disabled direct connection", flush=True)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
