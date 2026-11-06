#!/usr/bin/env python3
"""Native restore hardening checks. Only disposable session data and loopback APIs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/sniper')
args = parser.parse_args()
binary = args.binary.resolve()
root = Path(tempfile.mkdtemp(prefix='tcp-restore-runtime-'))
(root / 'templates').mkdir()
(root / 'templates/templates.json').write_text('{"auto_update":false}')
process = None
logs = []
results = {}

def port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]

ui, proxy = port(), port()

def api(path, body=None, method=None, expected=200):
    request = urllib.request.Request(f'http://127.0.0.1:{ui}' + path,
        data=None if body is None else json.dumps(body).encode(), method=method,
        headers={'content-type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            assert response.status == expected, (path, response.status, expected)
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        assert error.code == expected, (path, error.code, expected, error.read())
        return None

def launch():
    global process
    log = (root / f'run-{len(logs)}.log').open('w')
    logs.append(log)
    process = subprocess.Popen([str(binary)], env=dict(os.environ,
        SNIPER_DATA_DIR=str(root), SNIPER_UI_ADDR=f'127.0.0.1:{ui}',
        SNIPER_PROXY_ADDR=f'127.0.0.1:{proxy}', RUST_LOG='warn'), stdout=log, stderr=log)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            return api('/api/tcp/status')
        except (OSError, urllib.error.URLError):
            time.sleep(.03)
    raise AssertionError('Startup timed out')

def stop():
    global process
    if process:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        finally:
            process = None

def rss():
    return int(next(line.split()[1] for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if line.startswith('VmRSS:')))

def record(**overrides):
    value = dict(id=str(uuid.uuid4()), started_at='2026-11-04T00:00:00Z', ended_at='2026-11-04T00:01:00Z',
        peer='127.0.0.1:1', target='127.0.0.1:2', status='closed', client_bytes=1, server_bytes=0,
        captured_bytes=1, capture_truncated=False, durable=True,
        chunks=[dict(sequence=0, at='2026-11-04T00:00:01Z', direction='client_to_server', offset=0, data_base64='QQ==')],
        client_received_bytes=1, server_received_bytes=0, intercept_events=[], intercept_captured_bytes=0,
        intercept_truncated=False, intercept_event_count=0, intercept_schema_version=1, pending_count=0, pending_directions=[])
    value.update(overrides)
    return value

def save(directory, value):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (value['id'] + '.json')
    path.write_text(json.dumps(value))
    return path

def hashes(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}

def blocked(value):
    status = api('/api/tcp/status')
    assert status['load_error'] and status['history_count'] == 0 and not status['enabled'], status
    api('/api/tcp/connections/' + value['id'], expected=404)
    api('/api/tcp/start', dict(local_port=port(), target_host='127.0.0.1', target_port=9), expected=400)
    api('/api/tcp/stop', method='POST')
    return status

try:
    launch()
    baseline = rss()
    session = next(value for value in api('/api/sessions') if value['active'])
    stop()
    history = Path(session['storage_path']) / 'tcp-history'
    assert history.is_relative_to(root)
    for name, value in [
        ('unknown_status', record(status='nonsense')),
        ('bad_chunk_counters', record(client_bytes=0)),
        ('bad_offsets', record(chunks=[dict(sequence=999, at='2026-11-04T00:00:01Z', direction='client_to_server', offset=999, data_base64='QQ==')])),
    ]:
        path = save(history, value)
        before = hashes(history)
        launch()
        results[name] = blocked(value)
        stop()
        assert hashes(history) == before
        path.unlink()
        print('PASS', name, 'blocked and unchanged', flush=True)

    external = root / 'external-history'
    value = record()
    save(external, value)
    before = hashes(external)
    history.rmdir()
    history.symlink_to(external, target_is_directory=True)
    launch()
    results['root_symlink'] = blocked(value)
    stop()
    assert hashes(external) == before
    history.unlink()
    print('PASS root symlink blocked without external reads or writes', flush=True)

    value = record()
    save(history, value)
    before = hashes(history)
    launch()
    assert not api('/api/tcp/status')['load_error']
    assert api('/api/tcp/connections/' + value['id']) == value
    held = root / 'held-history'
    history.rename(held)
    history.symlink_to(external, target_is_directory=True)
    api('/api/tcp/connections/' + value['id'], expected=500)
    assert api('/api/tcp/status')['load_error']
    api('/api/tcp/start', dict(local_port=port(), target_host='127.0.0.1', target_port=9), expected=400)
    stop()
    assert hashes(held) == before and len(list(external.iterdir())) == 1
    history.unlink()
    history.mkdir()
    print('PASS root replacement fails detail explicitly without altering either directory', flush=True)

    for _ in range(32):
        value = record(peer='X' * 1_048_576)
        save(history, value)
    before = hashes(history)
    launch()
    results['oversized_metadata'] = dict(baseline_rss_kib=baseline, restored_rss_kib=rss(), status=blocked(value))
    stop()
    assert hashes(history) == before
    print('PASS 32 oversized metadata records rejected and preserved', flush=True)
    (root / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    print('DATA_DIR', root)
finally:
    stop()
    for log in logs:
        log.close()
