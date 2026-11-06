#!/usr/bin/env python3
"""Native loopback storage-fault, retry, restart and graceful-shutdown regressions.

Uses only new temporary data directories and loopback peers. Keeps artifacts.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/sniper')
args = parser.parse_args()
binary = args.binary.resolve()
assert binary.is_file(), 'Build the release sniper binary first'
artifacts = Path(tempfile.mkdtemp(prefix='sniper-tcp-persistence-'))
results = []

def check(name, condition):
    assert condition, name
    results.append(name)
    print('PASS', name, flush=True)

def port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]

def poll(fn, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.02)
    raise AssertionError('poll timed out')

class Runtime:
    def __init__(self, name):
        self.root = artifacts / name
        (self.root / 'templates').mkdir(parents=True)
        (self.root / 'templates/templates.json').write_text('{"auto_update":false}')
        self.ui, self.proxy, self.relay = port(), port(), port()
        self.http = http.client.HTTPConnection('127.0.0.1', self.ui, timeout=8)
        self.proc = None
        self.sockets = []
        self.log = (self.root / 'runtime.log').open('w')
        self.upstream = socket.socket()
        self.upstream.bind(('127.0.0.1', 0))
        self.upstream.listen()
        self.upstream.settimeout(8)
        self.settings = dict(local_port=self.relay, target_host='127.0.0.1', target_port=self.upstream.getsockname()[1])
        self.fault = None

    def api(self, path, body=None, method=None, expected=200):
        self.http.request(method or ('POST' if body is not None else 'GET'), path,
                          body=None if body is None else json.dumps(body), headers={'content-type':'application/json'})
        response = self.http.getresponse()
        raw = response.read()
        assert response.status == expected, (path, response.status, raw)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode()

    def launch(self):
        self.http.close()
        env = dict(os.environ, SNIPER_DATA_DIR=str(self.root), SNIPER_UI_ADDR=f'127.0.0.1:{self.ui}',
                   SNIPER_PROXY_ADDR=f'127.0.0.1:{self.proxy}', SNIPER_INSTALL_AGENT_SKILLS='0',
                   SNIPER_INSTALL_CLI_PATH='0', RUST_LOG='warn')
        self.proc = subprocess.Popen([str(binary)], env=env, stdout=self.log, stderr=self.log)
        def ready():
            try:
                return self.api('/api/tcp/status')
            except (OSError, http.client.HTTPException):
                self.http.close()
                raise
        poll(ready)

    def pair(self):
        self.api('/api/tcp/start', self.settings)
        client = socket.create_connection(('127.0.0.1', self.relay), timeout=8)
        server, _ = self.upstream.accept()
        server.settimeout(8)
        self.sockets.extend([client, server])
        rows = poll(lambda: self.api('/api/tcp/connections'))
        return client, server, rows[0]['id']

    def fail_storage(self, cid):
        directory = next(self.root.rglob(cid + '.json')).parent
        held = directory.with_name('tcp-history-held')
        directory.rename(held)
        directory.write_text('transient storage fault')
        self.fault = directory, held

    def restore_storage(self):
        if self.fault:
            directory, held = self.fault
            directory.unlink()
            held.rename(directory)
            self.fault = None

    def stop_process(self):
        self.proc.terminate()
        code = self.proc.wait(timeout=15)
        self.proc = None
        self.http.close()
        assert code == 0, code

    def close(self):
        self.restore_storage()
        if self.proc is not None:
            self.stop_process()
        for sock in self.sockets:
            sock.close()
        self.upstream.close()
        self.http.close()
        self.log.close()

runtime = Runtime('manual-retry')
try:
    runtime.launch()
    client, server, cid = runtime.pair()
    runtime.api('/api/tcp/intercept', dict(enabled=True, direction='client_to_server', expected_revision=0), 'PUT')
    original, edited, reply = b'\x00\xfforiginal', b'\xff\x00edited', b'\x80reply'
    client.sendall(original)
    pending = poll(lambda: runtime.api(f'/api/tcp/connections/{cid}/pending')['items'])[0]
    runtime.api(f"/api/tcp/connections/{cid}/pending/{pending['pending_id']}/decision",
                dict(action='forward', expected_revision=pending['revision'], replacement_base64=base64.b64encode(edited).decode()), expected=202)
    assert server.recv(128) == edited
    server.sendall(reply)
    assert client.recv(128) == reply
    poll(lambda: runtime.api('/api/tcp/connections/' + cid)['server_bytes'] == len(reply))
    runtime.fail_storage(cid)
    error = runtime.api('/api/tcp/stop', method='POST', expected=500)
    check('Stop reports HTTP 500 with actionable unsaved history warning', 'Keep Sniper open' in error)
    status = runtime.api('/api/tcp/status')
    failed = runtime.api('/api/tcp/connections/' + cid)
    check('failed Stop retains terminal bytes and intercept evidence in memory', not status['enabled'] and status['persistence_error'] and not failed['durable'] and failed['client_bytes'] == len(edited) and failed['intercept_events'][0]['original_base64'] == base64.b64encode(original).decode())
    runtime.api('/api/tcp/stop', method='POST', expected=500)
    runtime.restore_storage()
    runtime.api('/api/tcp/stop', method='POST')
    saved = runtime.api('/api/tcp/connections/' + cid)
    failed['durable'] = True
    check('second Stop retries exact terminal snapshot and clears error', saved == failed and not runtime.api('/api/tcp/status')['persistence_error'])
    runtime.stop_process()
    runtime.launch()
    check('all bytes, offsets, timestamps and intercept events survive full restart', runtime.api('/api/tcp/connections/' + cid) == saved)
finally:
    runtime.close()

runtime = Runtime('shutdown-retry')
try:
    runtime.launch()
    client, server, cid = runtime.pair()
    client.sendall(b'graceful-retained')
    assert server.recv(128) == b'graceful-retained'
    poll(lambda: runtime.api('/api/tcp/connections/' + cid)['client_bytes'] == 17)
    runtime.fail_storage(cid)
    runtime.proc.terminate()
    poll(lambda: runtime.api('/api/tcp/status')['persistence_error'])
    # Cross more than one retry interval to show shutdown remains blocked.
    end = time.monotonic() + 2.2
    while time.monotonic() < end:
        assert runtime.proc.poll() is None
        time.sleep(.05)
    check('graceful shutdown keeps process and inspectable API alive while storage fails', runtime.api('/api/tcp/connections/' + cid)['captured_bytes'] == 17)
    runtime.api('/api/tcp/start', runtime.settings, expected=503)
    check('new TCP starts are rejected while shutdown waits for persistence', True)
    runtime.restore_storage()
    check('shutdown retries automatically and exits cleanly after recovery', runtime.proc.wait(timeout=15) == 0)
    runtime.proc = None
    runtime.launch()
    saved = runtime.api('/api/tcp/connections/' + cid)
    check('automatic shutdown retry persists terminal capture across restart', saved['durable'] and saved['status'] == 'stopped' and saved['client_bytes'] == 17)
finally:
    runtime.close()

runtime = Runtime('shutdown-keepalive')
try:
    runtime.launch()
    client, server, cid = runtime.pair()
    client.sendall(b'before-shutdown')
    assert server.recv(128) == b'before-shutdown'
    poll(lambda: runtime.api('/api/tcp/connections/' + cid)['client_bytes'] == 15)
    hold = socket.create_connection(('127.0.0.1', runtime.proxy), timeout=8)
    runtime.sockets.append(hold)
    hold.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n')
    time.sleep(.05)
    runtime.proc.terminate()
    poll(lambda: not runtime.api('/api/tcp/status')['enabled'])
    runtime.api('/api/tcp/start', runtime.settings, expected=503)
    check('existing API keep-alive cannot restart TCP during final shutdown drain', True)
    check('shutdown without storage faults exits cleanly', runtime.proc.wait(timeout=15) == 0)
    runtime.proc = None
    runtime.launch()
    saved = runtime.api('/api/tcp/connections/' + cid)
    check('no extra connection or unsaved capture is introduced during shutdown', saved['durable'] and saved['client_bytes'] == 15 and len(runtime.api('/api/tcp/connections')) == 1)
finally:
    runtime.close()

runtime = Runtime('inactive-session-retry')
try:
    runtime.launch()
    sid = next(row['id'] for row in runtime.api('/api/sessions') if row['active'])
    new = runtime.api('/api/sessions', dict(name='TCP persistence regression'))
    runtime.api('/api/sessions/' + sid + '/activate', method='POST')
    client, server, cid = runtime.pair()
    client.sendall(b'old-session')
    assert server.recv(128) == b'old-session'
    poll(lambda: runtime.api('/api/tcp/connections/' + cid)['client_bytes'] == 11)
    runtime.fail_storage(cid)
    # Registry activation committed even though old TCP terminal persistence failed.
    runtime.api('/api/sessions/' + new['id'] + '/activate', method='POST', expected=500)
    check('session activation reports old-capture save failure while retaining old history', runtime.api('/api/tcp/connections/' + cid + '?session_id=' + sid)['client_bytes'] == 11)
    check('committed session activation still reconciles the active session', next(row['id'] for row in runtime.api('/api/sessions') if row['active']) == new['id'])
    runtime.restore_storage()
    runtime.stop_process()
    runtime.launch()
    saved = runtime.api('/api/tcp/connections/' + cid + '?session_id=' + sid)
    check('shutdown retries switched-away cached session captures', saved['durable'] and saved['client_bytes'] == 11 and saved['status'] == 'stopped')
finally:
    runtime.close()

(artifacts / 'results.json').write_text(json.dumps(results, indent=2))
print('ARTIFACTS', artifacts, flush=True)
