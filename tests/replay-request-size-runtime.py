#!/usr/bin/env python3
"""Isolated captured-request size regression: native API + production frontend.

Build sniper first. The served /app.js must match this checkout byte-for-byte.
Only synthetic loopback origins are used. CodeMirror state/history is real;
EditorView is the repository's memory adapter, not a native browser DOM.
Output defaults to a fresh temporary directory. All runtime processes are stopped.
"""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time


REPO = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(os.environ.get(
        'SNIPER_TEST_BINARY', str(REPO / 'target/release/sniper'))))
    parser.add_argument('--output-dir', type=Path, default=os.environ.get('SNIPER_TEST_OUTPUT_DIR'))
    parser.add_argument('--node', default=os.environ.get('SNIPER_TEST_NODE', 'node'))
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), 'Build sniper before running this fixture'
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix='sniper-replay-size-'))
    output.mkdir(parents=True, exist_ok=True)
    # Keep generated certificates and runtime state outside source/validation artifacts.
    data = Path(tempfile.mkdtemp(prefix='sniper-replay-size-data-'))
    (data / 'templates').mkdir()
    (data / 'templates/templates.json').write_text('{"auto_update":false}')
    log = (output / 'runtime.log').open('w')
    runtime, checks, hits, builds, lines = {}, [], [], [], []
    proc, frontend = None, None
    succeeded = False

    def check(name, condition=True, **detail):
        assert condition, name
        checks.append(dict(name=name, **detail))
        print('PASS', name, flush=True)

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            hits.append(dict(path=self.path, bytes=len(body), sha256=digest(body)))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    def connection(address):
        host, port = address.rsplit(':', 1)
        assert host == '127.0.0.1', 'fixture must remain loopback-only'
        return http.client.HTTPConnection(host, int(port), timeout=20)

    def api(path, body=None, expected=200):
        conn = connection(runtime['ui_addr'])
        try:
            conn.request('POST' if body is not None else 'GET', path,
                         None if body is None else json.dumps(body),
                         {'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read()
            assert response.status == expected, (path, response.status, raw[:300])
            return json.loads(raw) if raw else None
        finally:
            conn.close()

    def poll(fn, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = fn()
                if value:
                    return value
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(.02)
        raise AssertionError('fixture condition did not become true before timeout')

    def start():
        nonlocal proc, runtime
        env = dict(os.environ, SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR='127.0.0.1:0',
                   SNIPER_PROXY_ADDR='127.0.0.1:0', SNIPER_INSTALL_AGENT_SKILLS='0',
                   SNIPER_INSTALL_CLI_PATH='0', RUST_LOG='warn')
        executable_sha = digest(binary.read_bytes())
        proc = subprocess.Popen([str(binary)], env=env, stdout=log, stderr=log)

        def ready():
            nonlocal runtime
            assert proc.poll() is None, 'runtime exited; see runtime.log'
            runtime = json.loads((data / 'runtime-state.json').read_text())
            return runtime['pid'] == proc.pid and api('/api/settings')
        poll(ready)
        conn = connection(runtime['ui_addr'])
        try:
            conn.request('GET', '/app.js')
            response = conn.getresponse()
            app = response.read()
            assert response.status == 200
        finally:
            conn.close()
        source = (REPO / 'web/app.js').read_bytes()
        identity = dict(executable_sha256=executable_sha, served_app_sha256=digest(app),
                        source_app_sha256=digest(source),
                        normalized_app_sha256=digest(source.replace(b'\r\n', b'\n')))
        builds.append(identity)
        print('BUILD', json.dumps(identity), flush=True)
        assert identity['served_app_sha256'] == identity['source_app_sha256'], \
            'The binary serves stale app.js; rebuild sniper before this runtime regression'
        assert b'function replayRequestSizeError(' in app, 'request-size guard absent from served app.js'

    def stop():
        nonlocal proc
        proc.terminate()
        proc.wait(timeout=25)
        assert proc.returncode == 0, 'graceful shutdown must exit zero'
        proc = None

    def decoded_body(record):
        request = record['request']
        preview = request['body_preview']
        return base64.b64decode(preview) if request['body_encoding'] == 'base64' else preview.encode()

    try:
        start()
        session = api('/api/settings')['active_session']['id']
        authority = f'127.0.0.1:{origin.server_port}'
        fixtures = [
            ('ASCII', b'A' * (2304 * 1024), 'text/plain'),
            ('Base64', b'A' * (2 * 1024 * 1024 - 1) + b'\xff', 'application/octet-stream'),
            ('JSON escaping', b'"' * (1280 * 1024), 'text/plain'),
            ('Unicode', ('漢' * (768 * 1024)).encode(), 'text/plain; charset=utf-8'),
        ]
        records = []
        for name, body, mime in fixtures:
            path = '/capture-' + name.replace(' ', '-')
            conn = connection(runtime['proxy_addr'])
            try:
                conn.request('POST', f'http://{authority}{path}', body,
                             {'Host': authority, 'Content-Type': mime, 'Content-Length': str(len(body))})
                response = conn.getresponse()
                assert response.status == 200
                response.read()
            finally:
                conn.close()

            def captured():
                result = api('/api/transactions?session_id=' + session)
                rows = result if isinstance(result, list) else result.get('items', result.get('transactions', []))
                return next((row for row in rows if row['path'] == path), None)
            row = poll(captured)
            record = api('/api/transactions/' + row['id'] + '?session_id=' + session)
            check(name + ' local capture retained full bytes',
                  decoded_body(record) == body and not record['request']['preview_truncated'],
                  body_bytes=len(body), encoding=record['request']['body_encoding'])
            records.append(dict(name=name, record=record))

        workspace = api('/api/workspace-state?session_id=' + session)
        payload = dict(url='http://' + runtime['ui_addr'], authority=authority,
                       port=origin.server_port, session=session, revision=workspace['revision'],
                       records=records, report=str(output / 'frontend-report.json'))
        frontend = subprocess.Popen([args.node, '--max-old-space-size=512',
                                     str(REPO / 'tests/replay-request-size-runtime.cjs')],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
        output_queue = queue.Queue()

        def read_frontend():
            for line in frontend.stdout:
                output_queue.put(line)
            output_queue.put(None)
        threading.Thread(target=read_frontend, daemon=True).start()
        frontend.stdin.write(json.dumps(payload) + '\n')
        frontend.stdin.flush()
        while True:
            line = output_queue.get(timeout=90)
            assert line is not None, 'frontend exited before restart checkpoint: ' + ''.join(lines)
            lines.append(line)
            print(line, end='', flush=True)
            if line.startswith('{') and json.loads(line).get('phase') == 'restart-ready':
                break

        stop()
        start()
        restored = api('/api/workspace-state?session_id=' + session)
        tabs = restored['replay']['tabs']
        check('restart preserves successful edit, sent response and replay history',
              len(tabs) == 1 and '/allowed' in tabs[0]['request_text']
              and tabs[0]['response_record']['status'] == 200
              and len(tabs[0]['history_entries']) == 1 and tabs[0]['notice'] == '',
              tabs=len(tabs), revision=restored['revision'])
        for item, (_, body, _) in zip(records, fixtures):
            record = api('/api/transactions/' + item['record']['id'] + '?session_id=' + session)
            check(item['name'] + ' original capture intact after restart',
                  decoded_body(record) == body and not record['request']['preview_truncated'])

        frontend.stdin.write(json.dumps(dict(url='http://' + runtime['ui_addr'])) + '\n')
        frontend.stdin.flush()
        frontend.stdin.close()
        while True:
            line = output_queue.get(timeout=90)
            if line is None:
                break
            lines.append(line)
            print(line, end='', flush=True)
        frontend.wait(timeout=20)
        assert frontend.returncode == 0, 'frontend assertion failed; see frontend.log'
        result = json.loads((output / 'frontend-report.json').read_text())
        assert result['loadedAppSha256'] == builds[0]['normalized_app_sha256'], \
            'frontend source changed during this regression run'
        check('refused oversized imports never transmitted; small UI send exact',
              len(hits) == 5 and hits[-1]['path'] == '/allowed' and hits[-1]['bytes'] == 1
              and hits[-1]['sha256'] == digest(b'S'), target_hits=len(hits))
        stop()
        start()
        after_recovery = api('/api/workspace-state?session_id=' + session)
        check('recovered workspace persists through second restart',
              after_recovery['replay']['tabs'] == restored['replay']['tabs']
              and after_recovery['revision'] == restored['revision'] + 1)
        stop()
        succeeded = True
        print(f'PASS {len(result["checks"])} frontend + {len(checks)} native checks; artifacts: {output}', flush=True)
    finally:
        if frontend is not None and frontend.poll() is None:
            frontend.terminate()
            frontend.wait(timeout=20)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=25)
        origin.shutdown()
        origin.server_close()
        log.close()
        (output / 'frontend.log').write_text(''.join(lines))
        (output / 'runtime-report.json').write_text(json.dumps(dict(
            passed=succeeded, checks=checks, hits=hits, builds=builds, data_dir=str(data)), indent=2))


if __name__ == '__main__':
    main()
