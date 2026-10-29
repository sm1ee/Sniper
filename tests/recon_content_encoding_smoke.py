"""Verify bounded gzip Recon evidence and partial checkpoints on owned loopback.

Run: python3 tests/recon_content_encoding_smoke.py target/release
No forms are submitted; no proxy capture or external host is used.
"""
import gzip
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time


def eventually(operation, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError('Owned encoding fixture timed out')


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release').resolve() / 'sniper'
    process = None
    requests, violations, wire_sizes = [], [], []
    mode = 'identity'
    seed_started, seed_release = threading.Event(), threading.Event()
    body_started, body_release = threading.Event(), threading.Event()
    robots_started, robots_release = threading.Event(), threading.Event()
    padding = ''.join(hashlib.sha256(f'encoding-fixture-{index}'.encode()).hexdigest() for index in range(64))

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if any(self.headers.get(name) for name in ('Authorization', 'Cookie', 'Proxy-Authorization')):
                violations.append('Unexpected credentials')
            requests.append({'mode': mode, 'method': self.command, 'path': self.path,
                             'host': self.headers.get('Host'), 'accept_encoding': self.headers.get('Accept-Encoding')})
            if mode in ('stopped', 'header-stopped') and self.path == '/page':
                seed_started.set()
                if not seed_release.wait(20):
                    violations.append('Seed barrier timed out')
            if mode in ('stopped', 'header-stopped') and self.path == '/robots.txt':
                robots_started.set()
                if not robots_release.wait(20):
                    violations.append('Robots barrier timed out')
            body, mime = bodies.get(self.path, (b'', 'text/plain'))
            if mode == 'binary':
                mime = 'application/octet-stream'
            encodings = []
            status = 204 if self.path == '/robots.txt' else 200
            if status == 204:
                body, encodings = b'', ['gzip']  # Bodyless metadata is not malformed gzip.
            elif self.path in bodies:
                if mode in ('gzip', 'stacked', 'members'):
                    encoded = gzip.compress(body, mtime=0)
                    assert len(encoded) > len(body) // 3, 'Keep fixtures small and modest-ratio'
                    if mode == 'stacked':
                        encoded = gzip.compress(encoded, mtime=0)
                        encodings = ['gzip, identity', 'X-GZIP']
                    elif mode == 'members':
                        middle = len(body) // 2
                        encoded = gzip.compress(body[:middle], mtime=0) + gzip.compress(body[middle:], mtime=0)
                        encodings = ['gzip']
                    else:
                        encodings = ['gzip']
                    wire_sizes.append({'mode': mode, 'path': self.path, 'decoded': len(body), 'wire': len(encoded)})
                    assert gzip.decompress(gzip.decompress(encoded) if mode == 'stacked' else encoded) == body
                    body = encoded
                elif mode in ('malformed', 'stopped'):
                    encodings = ['gzip']  # Deliberately plain bytes, never a decoded fallback.
                elif mode in ('unsupported', 'binary', 'header-stopped'):
                    encodings = ['secret-unsupported']
                elif mode == 'empty':
                    body, encodings = b'', ['gzip']
            self.send_response(status)
            self.send_header('Content-Type', mime)
            if status != 204:
                self.send_header('Content-Length', str(len(body)))
            for encoding in encodings:
                self.send_header('Content-Encoding', encoding)
            self.end_headers()
            if mode == 'header-stopped' and self.path == '/page':
                self.wfile.flush()
                body_started.set()
                if not body_release.wait(20):
                    violations.append('Body barrier timed out')
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Stop closes the owned pending response.

        def do_POST(self):
            violations.append('A candidate form was submitted')
            self.send_error(405)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    authority = f'127.0.0.1:{server.server_port}'
    origin = 'http://' + authority
    bodies = {
        '/page': ((f'<!doctype html><!--{padding}--><a href="/found">link</a>'
                   '<script src="/script.js"></script><script>fetch("/inline-candidate")</script>'
                   '<form method="POST" action="/form-candidate"><input name="q"></form>'
                   f'<a href="http://localhost:{server.server_port}/offscope">no</a>').encode(), 'text/html'),
        '/script.js': (f'/*{padding}*/fetch("/external-candidate");'.encode(), 'application/javascript'),
        '/sitemap.xml': (f'<?xml version="1.0"?><!--{padding}--><urlset><url><loc>{origin}/mapped</loc></url></urlset>'.encode(), 'application/xml'),
    }
    assert all(len(body) < 6000 for body, _ in bodies.values())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='sniper-recon-encoding-') as temporary:
            data = Path(temporary)
            env = {key: value for key, value in os.environ.items() if not key.lower().endswith('_proxy')}
            env.pop('SNIPER_API_ADDR', None)
            env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR='127.0.0.1:0', SNIPER_PROXY_ADDR='127.0.0.1:0',
                       SNIPER_INSTALL_AGENT_SKILLS='0', SNIPER_INSTALL_CLI_PATH='0', RUST_LOG='off')

            def launch():
                nonlocal process
                process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                def ready():
                    assert process.poll() is None, 'Runtime exited during startup'
                    try:
                        state = json.loads((data / 'runtime-state.json').read_text())
                        return state if state['pid'] == process.pid else None
                    except (OSError, ValueError):
                        return None
                return eventually(ready)

            def stop():
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

            runtime = launch()

            def api(path, payload=None):
                host, port = runtime['ui_addr'].rsplit(':', 1)
                assert host == '127.0.0.1'
                connection = http.client.HTTPConnection(host, int(port), timeout=15)
                try:
                    connection.request('GET' if payload is None else 'POST', path,
                        body=None if payload is None else json.dumps(payload),
                        headers={} if payload is None else {'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == 200, (response.status, body)
                    return json.loads(body)
                finally:
                    connection.close()

            def disk(sid):
                for path in data.rglob('state.json'):
                    if path.parent.name == sid:
                        try:
                            return json.loads(path.read_text())['recon']
                        except (OSError, ValueError, KeyError):
                            pass
                return {'jobs': [], 'endpoints': []}

            def current_job(snapshot, jid):
                return next((job for job in snapshot['jobs'] if job['id'] == jid), None)

            def inventory(sid):
                snapshot = api('/api/recon?session_id=' + sid)
                site_map = api('/api/target/site-map?session_id=' + sid)
                assert api('/api/transactions?session_id=' + sid) == []
                assert all(host['request_count'] == 0 for host in site_map)
                assert all(row['discovered'] and not row['captured'] and row['status'] is None
                           for host in site_map for row in host['paths'])
                assert all(item['url'].startswith(origin + '/') for item in snapshot['endpoints'])
                return snapshot, site_map

            retained = {}
            reference = None
            for mode in ('identity', 'gzip', 'stacked', 'members', 'malformed', 'unsupported', 'empty', 'binary', 'stopped', 'header-stopped'):
                for event in (seed_started, seed_release, robots_started, robots_release, body_started, body_release):
                    event.clear()
                sid = api('/api/sessions', {'name': 'Synthetic encoding ' + mode})['id']
                offset = len(requests)
                job = api('/api/recon/jobs', {'session_id': sid, 'target_url': origin + '/page',
                          'sources': ['crawler'], 'max_requests': 8, 'max_endpoints': 32})
                if mode in ('stopped', 'header-stopped'):
                    assert seed_started.wait(10)
                    eventually(lambda: current_job(disk(sid), job['id']))
                    seed_release.set()
                    if mode == 'header-stopped':
                        assert body_started.wait(10)
                        eventually(lambda: any(item['url'] == origin + '/page' and any(e['kind'] == 'live' for e in item['evidence'])
                                               for item in api('/api/recon?session_id=' + sid)['endpoints']))
                        assert not body_release.is_set()
                    assert robots_started.wait(10)
                    current = current_job(api('/api/recon?session_id=' + sid), job['id'])
                    assert current['status'] == 'running' and current['sources'][0]['truncated'], current
                    warning_fragment = ('Unsupported or invalid Content-Encoding' if mode == 'header-stopped'
                                        else 'could not be decoded completely')
                    def checkpointed():
                        snapshot = disk(sid)
                        saved = current_job(snapshot, job['id'])
                        return (saved and saved['sources'][0]['truncated']
                                and any(warning_fragment in warning for warning in saved['sources'][0]['warnings'])
                                and any(item['url'] == origin + '/page' and any(e['kind'] == 'live' for e in item['evidence'])
                                        for item in snapshot['endpoints']))
                    eventually(checkpointed)
                    assert api('/api/recon/jobs/' + job['id'] + '/stop', {'session_id': sid})['stopped']
                    if mode == 'header-stopped':
                        assert not body_release.is_set()
                        body_release.set()
                    robots_release.set()
                else:
                    def complete():
                        current = current_job(api('/api/recon?session_id=' + sid), job['id'])
                        return current if current['status'] != 'running' else None
                    eventually(complete)
                snapshot, site_map = inventory(sid)
                current = current_job(snapshot, job['id'])
                source = current['sources'][0]
                assert current['status'] == ('cancelled' if mode in ('stopped', 'header-stopped') else 'completed'), current
                actual = requests[offset:]
                assert source['requests'] == len(actual) <= 8, (source, actual)
                assert all(item['host'] == authority and item['method'] == 'GET' for item in actual)
                expected_paths = {'/page', '/robots.txt', '/sitemap.xml', '/found', '/script.js', '/mapped'}
                assert all(item['path'] in expected_paths for item in actual), actual
                evidence = sorted((item['url'], item['method'], evidence['kind'], evidence['location'])
                                  for item in snapshot['endpoints'] for evidence in item['evidence']
                                  if evidence['kind'] != 'live')
                if mode in ('identity', 'gzip', 'stacked', 'members'):
                    assert not source['truncated'], source
                    assert {item['path'] for item in actual} == expected_paths and len(actual) == 6, actual
                    kinds = {(url.removeprefix(origin), method, kind) for url, method, kind, _ in evidence}
                    assert {('/found', 'GET', 'observed'), ('/mapped', 'GET', 'observed'),
                            ('/script.js', 'GET', 'observed'), ('/form-candidate', 'POST', 'candidate'),
                            ('/inline-candidate', 'GET', 'candidate'), ('/external-candidate', 'GET', 'candidate')} <= kinds, kinds
                    if reference is None:
                        reference = evidence
                    assert evidence == reference, (mode, evidence, reference)
                elif mode == 'binary':
                    assert not source['truncated'] and not evidence, (source, evidence)
                    assert not any('Content-Encoding' in warning for warning in source['warnings'])
                    assert len(actual) == 3, actual
                else:
                    assert source['truncated'] and not evidence, (source, evidence)
                    assert any('static extraction was skipped' in warning for warning in source['warnings']), source
                    assert all('secret-unsupported' not in warning for warning in source['warnings'])
                    assert len(actual) == (2 if mode in ('stopped', 'header-stopped') else 3), actual
                retained[sid] = (snapshot, site_map)
                print(json.dumps({'case': mode, 'status': current['status'], 'partial': source['truncated'],
                                  'requests': len(actual), 'evidence_count': len(evidence), 'warnings': source['warnings'],
                                  'checkpoint_before_stop': mode in ('stopped', 'header-stopped')}), flush=True)
            assert not violations, violations
            assert len(requests) == 40, requests
            assert all(item['accept_encoding'] is None for item in requests), 'Request headers must stay unchanged'
            eventually(lambda: all(disk(sid) == {'jobs': snap['jobs'], 'endpoints': snap['endpoints']}
                                   for sid, (snap, _) in retained.items()))
            stop()
            runtime = launch()
            for sid, (snapshot, site_map) in retained.items():
                assert api('/api/recon?session_id=' + sid) == snapshot
                assert api('/api/target/site-map?session_id=' + sid) == site_map
                assert api('/api/transactions?session_id=' + sid) == []
            assert not violations and len(requests) == 40, (violations, requests)
            print(json.dumps({'parity': 'HTML/JS/sitemap identity, gzip, stacked and concatenated members',
                              'wire_sizes': wire_sizes, 'total_gets': len(requests), 'captures': 0,
                              'submissions': 0, 'off_scope_requests': 0, 'disk_and_graceful_restart': 'PASS'}), flush=True)
            stop()
    finally:
        seed_release.set()
        body_release.set()
        robots_release.set()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
