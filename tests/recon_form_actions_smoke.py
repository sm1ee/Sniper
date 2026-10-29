"""Verify passive form-action URL/method evidence, Scope projection and persistence.

Run: python3 tests/recon_form_actions_smoke.py [directory containing sniper]
Uses only owned loopback GETs; forms are never submitted.
"""
import collections
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

CASES = [
    ('normal', '<base href="/assets/"><form method="post" action="save"></form>', [('POST', '/assets/save')]),
    ('omitted', '<base href="/assets/"><form method="post"></form>', [('POST', '/omitted')]),
    ('empty', '<base href="/assets/"><form method="post" action=""></form>', [('POST', '/empty')]),
    ('fragment', '<form method="post" action="#save"></form>', [('POST', '/fragment?b=2&a=1&b=3')]),
    ('empty-override', '<base href="/assets/"><form method="dialog" action="/unused"><button formaction="" formmethod="post">Save</button></form>', [('POST', '/empty-override?doc=1&doc=2')]),
    ('fragment-override', '<base href="/assets/?base=2&amp;base=3"><form method="dialog" action="/unused"><button formaction="#save" formmethod="post">Save</button></form>', [('POST', '/assets/?base=2&base=3')]),
    ('invalid-method', '<form method="DELETE" action="#save"></form>', [('GET', '/invalid-method')]),
    ('negative', '<form method="dialog" action="#close"></form><form method="post" action="javascript:void(0)"></form><a href="#local">Local</a>', []),
]

def eventually(operation, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(.03)
    raise AssertionError('Owned fixture timed out')

def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release').resolve()
    binary = binaries / ('sniper.exe' if os.name == 'nt' else 'sniper')
    targets = {name: '/' + name for name, _, _ in CASES}
    targets['fragment'] += '?b=2&a=1&b=3'
    targets['empty-override'] += '?doc=1&doc=2'
    bodies = {targets[name]: body.encode() for name, body, _ in CASES}
    requests = []
    process = None
    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            requests.append((self.command, self.path, self.headers.get('Host')))
            body = bodies.get(self.path, b'')
            if self.path in bodies:
                body += f'<form method="post" action="http://localhost:{self.server.server_port}/offscope#save"></form>'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html' if self.path in bodies else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    authority = f'127.0.0.1:{server.server_port}'
    origin = 'http://' + authority
    try:
        with tempfile.TemporaryDirectory(prefix='sniper-form-action-') as temporary:
            data = Path(temporary)
            env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
            env.pop('SNIPER_API_ADDR', None)
            env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR='127.0.0.1:0', SNIPER_PROXY_ADDR='127.0.0.1:0', SNIPER_INSTALL_AGENT_SKILLS='0', SNIPER_INSTALL_CLI_PATH='0', RUST_LOG='off')
            def launch():
                nonlocal process
                process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                def ready():
                    assert process.poll() is None
                    try:
                        value = json.loads((data / 'runtime-state.json').read_text())
                        return value if value['pid'] == process.pid else None
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
            outcomes = []
            saved_sessions = {}
            for name, html, expected in CASES:
                sid = api('/api/sessions', {'name': 'Synthetic action ' + name})['id']
                seed = origin + targets[name]
                job = api('/api/recon/jobs', {'session_id': sid, 'target_url': seed, 'sources': ['crawler'], 'max_requests': 3})
                def complete():
                    snapshot = api('/api/recon?session_id=' + sid)
                    current = next(item for item in snapshot['jobs'] if item['id'] == job['id'])
                    assert current['status'] not in ('failed', 'cancelled'), current
                    return snapshot if current['status'] == 'completed' else None
                snapshot = eventually(complete)
                current = snapshot['jobs'][0]
                assert current['sources'][0]['requests'] == 3
                assert not current['sources'][0]['truncated']
                assert all(endpoint['url'].startswith(origin + '/') for endpoint in snapshot['endpoints'])
                assert api('/api/transactions?session_id=' + sid) == []
                candidates = sorted((endpoint['method'], endpoint['url'].removeprefix(origin))
                    for endpoint in snapshot['endpoints'] if any(
                        evidence['kind'] == 'candidate' and evidence['location'] == 'form: ' + seed
                        for evidence in endpoint['evidence']))
                form_evidence = [{'url': endpoint['url'], 'method': endpoint['method'], 'raw_urls': endpoint['raw_urls'],
                    'evidence': [item for item in endpoint['evidence'] if item['location'].startswith('form: ')]}
                    for endpoint in snapshot['endpoints'] if any(item['location'].startswith('form: ') for item in endpoint['evidence'])]
                outcomes.append({'case': name, 'expected': expected, 'actual': candidates, 'pass': candidates == expected,
                    'literal_html': html, 'form_evidence': form_evidence})
                site_map = api('/api/target/site-map?session_id=' + sid)
                paths = {item['path']: item for host in site_map for item in host['paths']}
                assert all(host['request_count'] == 0 for host in site_map)
                assert all(item['discovered'] and not item['captured'] and item['status'] is None for item in paths.values())
                for method, path in candidates:
                    assert method in paths[path]['methods'] and 'candidate' in paths[path]['recon_kinds']
                saved_sessions[sid] = (snapshot, site_map)
            counts = collections.Counter(path for _, path, _ in requests)
            assert all(method == 'GET' and host == authority for method, _, host in requests), requests
            assert len(requests) == 3 * len(CASES), requests
            assert counts == collections.Counter({**{path: 1 for path in targets.values()}, '/robots.txt': len(CASES), '/sitemap.xml': len(CASES)}), counts
            print(json.dumps({'outcomes': outcomes, 'upstream_requests': requests, 'capture_count': 0,
                'candidate_submissions': 0, 'per_job_requests': 3, 'per_job_budget': 3}, indent=2), flush=True)
            failed = [result['case'] for result in outcomes if not result['pass']]
            assert not failed, 'Missing method/path candidates: ' + ', '.join(failed)
            expected_raw = {
                'fragment': origin + targets['fragment'] + '#save',
                'empty-override': origin + targets['empty-override'],
                'fragment-override': origin + '/assets/?base=2&base=3#save',
                'invalid-method': origin + '/invalid-method#save',
            }
            for result in outcomes:
                if result['case'] in expected_raw:
                    raw_urls = result['form_evidence'][0]['raw_urls']
                    if result['case'] == 'invalid-method':
                        # The seed's actual GET and its passive GET candidate share inventory.
                        assert expected_raw[result['case']] in raw_urls
                    else:
                        assert raw_urls == [expected_raw[result['case']]]
                    assert all(evidence['kind'] == 'candidate' and evidence['status'] is None
                               for item in result['form_evidence'] for evidence in item['evidence'])
            def persisted():
                states = {path.parent.name: path for path in data.rglob('state.json')}
                try:
                    return all(json.loads(states[session_id].read_text())['recon'] == {
                        'jobs': snapshot['jobs'], 'endpoints': snapshot['endpoints']}
                        for session_id, (snapshot, _) in saved_sessions.items())
                except (OSError, ValueError, KeyError):
                    return False
            eventually(persisted)
            active_sid = api('/api/settings')['active_session']['id']
            stop()
            runtime = launch()
            for session_id, (snapshot, site_map) in saved_sessions.items():
                assert api('/api/recon?session_id=' + session_id) == snapshot
                assert api('/api/target/site-map?session_id=' + session_id) == site_map
                assert api('/api/transactions?session_id=' + session_id) == []
            assert api('/api/settings')['active_session']['id'] == active_sid
            assert len(requests) == 3 * len(CASES)
            print('PASS: form action methods, raw fragments/queries, Scope/Map and disk/restart retained without submissions or captures.', flush=True)
            stop()
    finally:
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
