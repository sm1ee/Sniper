#!/usr/bin/env python3
"""Isolated native HTTP force-switch regression, using only synthetic loopback peers.

Build sniper first. --data-dir must not already exist; artifacts are retained.
No TCP listener is started until the final coexistence case. Network/body waits
remain deliberately non-cancellable: force must fail safely instead of dropping
an in-progress history commit or releasing traffic into the wrong session.
"""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid


def poll(fn, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(.02)
    raise AssertionError('condition did not become true before timeout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/sniper')
    parser.add_argument('--data-dir', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), 'Build sniper before running the fixture'
    if args.data_dir:
        data = args.data_dir.resolve()
        data.mkdir(parents=True, exist_ok=False)
    else:
        data = Path(tempfile.mkdtemp(prefix='sniper-http-force-'))
    (data / 'templates').mkdir()
    (data / 'templates/templates.json').write_text('{"auto_update":false}')
    log = (data / 'runtime.log').open('w')
    passes, sockets, hits = [], [], []
    slow_entered, slow_release = threading.Event(), threading.Event()
    runtime, proc = {}, None

    def check(name, condition=True):
        assert condition, name
        passes.append(name)
        print('PASS', name, flush=True)

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == '/slow-headers':
                slow_entered.set()
                if not slow_release.wait(30):
                    return
            body = ('synthetic-origin:' + self.path).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        do_HEAD = do_GET

        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.do_GET()

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    upstream = socket.socket()
    upstream.bind(('127.0.0.1', 0))
    upstream.listen()
    upstream.settimeout(10)

    def api(path, body=None, method=None, expected=200):
        host, port = runtime['ui_addr'].rsplit(':', 1)
        assert host == '127.0.0.1'
        conn = http.client.HTTPConnection(host, int(port), timeout=15)
        try:
            conn.request(method or ('POST' if body is not None else 'GET'), path,
                         body=None if body is None else json.dumps(body),
                         headers={'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read()
            assert response.status in (expected if isinstance(expected, tuple) else (expected,)), (path, response.status, raw)
            try:
                return json.loads(raw) if raw else None
            except ValueError:
                return raw.decode()
        finally:
            conn.close()

    def start():
        nonlocal proc, runtime
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR='127.0.0.1:0',
                   SNIPER_PROXY_ADDR='127.0.0.1:0', SNIPER_INSTALL_AGENT_SKILLS='0',
                   SNIPER_INSTALL_CLI_PATH='0', RUST_LOG='warn')
        proc = subprocess.Popen([str(binary)], env=env, stdout=log, stderr=log)

        def ready():
            nonlocal runtime
            assert proc.poll() is None, 'runtime exited; see runtime.log'
            try:
                runtime = json.loads((data / 'runtime-state.json').read_text())
                return runtime['pid'] == proc.pid and api('/api/settings')
            except (OSError, ValueError, http.client.HTTPException):
                return False
        poll(ready)

    def stop():
        nonlocal proc
        proc.terminate()
        proc.wait(timeout=25)
        check('graceful shutdown exits zero', proc.returncode == 0)
        proc = None

    def active():
        return api('/api/settings')['active_session']['id']

    def activate(sid, force=False, expected=200):
        return api('/api/sessions/' + sid + '/activate' + ('?force=true' if force else ''),
                   method='POST', expected=expected)

    def intercept(enabled):
        api('/api/runtime', {'intercept_enabled': enabled, 'intercept_scope_only': False})

    def request(path, method='GET', stalled=False):
        host, port = runtime['proxy_addr'].rsplit(':', 1)
        assert host == '127.0.0.1'
        client = socket.create_connection((host, int(port)), timeout=10)
        sockets.append(client)
        authority = '127.0.0.1:' + str(origin.server_port)
        extra = 'Content-Length: 6\r\nExpect: 100-continue\r\n' if stalled else ''
        client.sendall((f'{method} http://{authority}{path} HTTP/1.1\r\n'
                        f'Host: {authority}\r\nConnection: close\r\n{extra}\r\n').encode())
        if stalled:
            # Hyper emits 100 only once it polls the body: no timing guess is
            # needed to know that the old session owns the pending request.
            interim = b''
            while not interim.endswith(b'\r\n\r\n'):
                interim += client.recv(1)
            assert interim.startswith(b'HTTP/1.1 100 '), interim
        return client

    def response(client, expected, method='GET', path=None):
        reply = http.client.HTTPResponse(client, method=method)
        reply.begin()
        body = reply.read()
        assert reply.status == expected, (reply.status, body)
        if expected == 503:
            assert reply.getheader('Connection', '').lower() == 'close'
            assert b'synthetic-origin:' not in body
            if method == 'HEAD':
                assert body == b''
            # Also reject illegal bytes after a HEAD response and assure closure.
            assert client.recv(1) == b'', 'cancelled connection stayed open or leaked bytes'
        elif path is not None:
            assert body == ('synthetic-origin:' + path).encode()
        client.close()
        return body

    def empty_queues():
        return api('/api/intercepts') == [] and api('/api/response-intercepts') == []

    def history(sid):
        return api('/api/transactions?session_id=' + sid)

    def details(sid):
        return {row['id']: api('/api/transactions/' + row['id'] + '?session_id=' + sid)
                for row in history(sid)}

    try:
        start()
        old = active()
        new = api('/api/sessions', {'name': 'force-switch-target'})['id']
        activate(old)
        response(request('/completed-before-switch'), 200, path='/completed-before-switch')
        poll(lambda: len(history(old)) == 1)
        intercept(True)
        dropped = request('/ordinary-request-drop')
        item = poll(lambda: api('/api/intercepts'))[0]
        api('/api/intercepts/' + item['id'] + '/drop', method='POST', expected=204)
        assert response(dropped, 403) == b'Request dropped in intercept.'
        poll(lambda: len(history(old)) == 2)
        row = next(value for value in details(old).values() if value['path'] == '/ordinary-request-drop')
        check('ordinary request Drop still records its 403 without forwarding',
              row['status'] == 403 and 'Request dropped in intercept.' in row['notes']
              and '/ordinary-request-drop' not in hits and empty_queues())
        dropped = request('/ordinary-response-drop')
        poll(lambda: api('/api/intercepts'))
        api('/api/intercepts/forward-all', {})
        item = poll(lambda: api('/api/response-intercepts'))[0]
        api('/api/response-intercepts/' + item['id'] + '/drop', method='POST', expected=204)
        assert response(dropped, 502) == b'Response dropped in intercept.'
        poll(lambda: len(history(old)) == 3)
        row = next(value for value in details(old).values() if value['path'] == '/ordinary-response-drop')
        check('ordinary response Drop still records its 502 instead of cancellation',
              row['status'] == 502 and 'Response dropped in intercept.' in row['notes']
              and hits.count('/ordinary-response-drop') == 1 and empty_queues())
        preserved = details(old)
        held = request('/held-request')
        queued = poll(lambda: api('/api/intercepts'))
        check('HTTP-only setup has never started TCP', not api('/api/tcp/status')['enabled']
              and api('/api/tcp/connections') == [])
        activate(new, expected=409)
        check('ordinary switch preserves held request and active session', active() == old
              and api('/api/intercepts') == queued and '/held-request' not in hits)
        activate(str(uuid.uuid4()), force=True, expected=404)
        check('invalid force target preserves held request', active() == old
              and api('/api/intercepts') == queued and '/held-request' not in hits)
        activate(old, force=True)
        check('force to same active session preserves held request', active() == old
              and api('/api/intercepts') == queued and '/held-request' not in hits)
        activate(new, force=True)
        response(held, 503)
        check('valid HTTP-only force cancels request without forwarding', active() == new
              and '/held-request' not in hits and empty_queues())
        check('completed old HTTP history is unchanged and new history is empty',
              details(old) == preserved and history(new) == [])

        activate(old)
        intercept(True)
        held = request('/held-response')
        poll(lambda: api('/api/intercepts'))
        api('/api/intercepts/forward-all', {})
        poll(lambda: api('/api/response-intercepts'))
        activate(new, force=True)
        response(held, 503)
        check('held response cancellation emits no origin bytes and drains both queues',
              hits.count('/held-response') == 1 and empty_queues() and history(new) == [])

        activate(old)
        intercept(True)
        held = request('/held-response-storage-failure')
        poll(lambda: api('/api/intercepts'))
        api('/api/intercepts/forward-all', {})
        poll(lambda: api('/api/response-intercepts'))
        registry = data / 'sessions/registry.json'
        registry_backup = data / 'sessions/registry.fixture-backup'
        registry.rename(registry_backup)
        registry.mkdir()
        try:
            activate(new, force=True, expected=500)
        finally:
            registry.rmdir()
            registry_backup.rename(registry)
        response(held, 503)
        check('response cancellation stays fail-closed when registry persistence fails',
              active() == old and empty_queues()
              and hits.count('/held-response-storage-failure') == 1
              and all(row['path'] != '/held-response-storage-failure' for row in history(old))
              and all(details(old).get(key) == value for key, value in preserved.items()))
        activate(new)

        activate(old)
        intercept(True)
        held = request('/held-head', method='HEAD')
        poll(lambda: api('/api/intercepts'))
        activate(new, force=True)
        response(held, 503, method='HEAD')
        check('HEAD cancellation has no body and does not reach origin',
              '/held-head' not in hits and empty_queues())

        activate(old)
        intercept(True)
        before = len(history(old))
        held = request('/slow-headers')
        poll(lambda: api('/api/intercepts'))
        force_errors, force_results = [], []
        def race_force():
            try:
                force_results.append(activate(new, force=True, expected=(200, 409)))
            except Exception as error:
                force_errors.append(error)
        force_thread = threading.Thread(target=race_force)
        force_thread.start()
        api('/api/intercepts/forward-all', {}, expected=(200, 409))
        force_thread.join(timeout=15)
        assert not force_thread.is_alive() and not force_errors, force_errors
        if active() == new:
            response(held, 503)
            check('force wins concurrent Forward without leaking request or recording it',
                  not slow_entered.is_set() and empty_queues() and len(history(old)) == before)
        else:
            assert slow_entered.is_set(), 'Forward winner did not reach the origin'
            check('Forward wins concurrent force while old owner safely blocks switching',
                  active() == old and empty_queues())
            intercept(False)
            slow_release.set()
            response(held, 200, path='/slow-headers')
            poll(lambda: len(history(old)) == before + 1)
            activate(new)
        check('concurrent decisions never leak history to the new session', history(new) == [])

        activate(old)
        intercept(False)
        before = len(history(old))
        slow_entered.clear()
        slow_release.clear()
        held = request('/slow-headers')
        assert slow_entered.wait(10), 'origin did not receive slow request'
        activate(new, force=True, expected=409)
        check('force cannot cancel network wait and keeps old ownership', active() == old)
        slow_release.set()
        response(held, 200, path='/slow-headers')
        poll(lambda: len(history(old)) == before + 1)
        activate(new)
        check('network wait completion is retained only in old history', history(new) == [])

        activate(old)
        intercept(False)
        before = len(history(old))
        held = request('/stalled-body', method='POST', stalled=True)
        intercept(True)
        cancelled_peer = request('/held-beside-stalled-body')
        poll(lambda: api('/api/intercepts'))
        activate(new, force=True, expected=409)
        response(cancelled_peer, 503)
        check('failed force cancels queued peer but preserves stalled body ownership',
              active() == old and '/stalled-body' not in hits
              and '/held-beside-stalled-body' not in hits and empty_queues())
        intercept(False)
        held.sendall(b'public')
        response(held, 200, method='POST', path='/stalled-body')
        poll(lambda: len(history(old)) == before + 1)
        activate(new)
        check('body completion is retained only in old history', history(new) == [])

        activate(old)
        intercept(True)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            relay_port = reservation.getsockname()[1]
        query = '?session_id=' + old + '&expected_active_session_id=' + old
        api('/api/tcp/start' + query, {'local_port': relay_port, 'target_host': '127.0.0.1',
                                     'target_port': upstream.getsockname()[1]})
        api('/api/tcp/intercept' + query,
            {'enabled': True, 'direction': 'client_to_server', 'expected_revision': 0}, method='PUT')
        tcp_client = socket.create_connection(('127.0.0.1', relay_port), timeout=10)
        sockets.append(tcp_client)
        tcp_origin, _ = upstream.accept()
        tcp_origin.settimeout(10)
        sockets.append(tcp_origin)
        tcp_client.sendall(b'synthetic-held-tcp')
        cid = poll(lambda: api('/api/tcp/connections'))[0]['id']
        poll(lambda: api('/api/tcp/connections/' + cid + '/pending')['items'])
        held = request('/coexisting-held-http')
        poll(lambda: api('/api/intercepts'))
        activate(new, force=True)
        response(held, 503)
        check('force cancels HTTP beside pending TCP without forwarding either',
              tcp_client.recv(1) == b'' and tcp_origin.recv(1) == b''
              and '/coexisting-held-http' not in hits and empty_queues())
        tcp_rows = api('/api/tcp/connections?session_id=' + old)
        check('old TCP capture is durably stopped and isolated', len(tcp_rows) == 1
              and tcp_rows[0]['status'] == 'stopped' and tcp_rows[0]['durable']
              and tcp_rows[0]['client_bytes'] == 0 and api('/api/tcp/connections') == [])
        check('all preexisting completed HTTP details survived every force switch',
              all(details(old).get(key) == value for key, value in preserved.items()))
        intercept(False)
        response(request('/new-session-only'), 200, path='/new-session-only')
        poll(lambda: len(history(new)) == 1)
        old_details, new_details = details(old), details(new)
        stop()
        start()
        check('restart retains both isolated HTTP histories exactly', active() == new
              and details(old) == old_details and details(new) == new_details)
        check('restart retains stopped old TCP record with listener disabled',
              api('/api/tcp/connections?session_id=' + old) == tcp_rows
              and api('/api/tcp/connections') == [] and not api('/api/tcp/status')['enabled'])
        check('restart has no leftover request or response intercepts', empty_queues())
        stop()
        report = {'passes': len(passes), 'checks': passes, 'data_dir': str(data)}
        (data / 'PASS.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        slow_release.set()
        for client in sockets:
            client.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        upstream.close()
        origin.shutdown()
        origin.server_close()
        log.close()
        print('ARTIFACTS', data, flush=True)


if __name__ == '__main__':
    main()
