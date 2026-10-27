#!/usr/bin/env python3
"""Owned loopback metadata-only probe; no proxy/capture/scanner/provider requests."""
import argparse, hashlib, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time, traceback, urllib.error, urllib.request
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary-dir', type=pathlib.Path, required=True)
parser.add_argument('--source-dir', type=pathlib.Path, required=True)
parser.add_argument('--evidence-dir', type=pathlib.Path, required=True)
parser.add_argument('--expected-head', required=True)
parser.add_argument('--expected-tree', required=True)
parser.add_argument('--expected-binary-sha256', required=True)
args = parser.parse_args()
SOURCE = args.source_dir.resolve(strict=True)
OUT = args.evidence_dir.absolute()
BINARY = args.binary_dir.resolve(strict=True) / ('sniper.exe' if os.name == 'nt' else 'sniper')
HEAD = args.expected_head
TREE = args.expected_tree
BINARY_SHA = args.expected_binary_sha256
if OUT.exists() or not OUT.parent.is_dir() or OUT.is_relative_to(SOURCE):
    parser.error('evidence directory must be new, outside source, with an existing parent')
OUT.mkdir(mode=0o700)
FILES = ['README.md','AGENTS.md','src/session.rs','src/state.rs','src/api.rs','src/lib.rs','src/history_retention.rs']
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def git(*args):
    return subprocess.check_output(['git','-C',str(SOURCE),*args],text=True).strip()
def save(name,value):
    with (OUT/name).open('x',encoding='utf-8') as f: json.dump(value,f,indent=2,sort_keys=True); f.write('\n')
def pins():
    return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain'),'binary_sha256':sha(BINARY),'source_sha256':{p:sha(SOURCE/p) for p in FILES}}
child=None; log=None; runtime=None; starts=0; data=None
calls=[]; processes=[]; observations={}; controls=[]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def check(name,condition):
    controls.append({'name':name,'pass':bool(condition)})
    assert condition, name

def request(path,payload=None):
    # Closed allowlist: synthetic session/scope metadata only. No generic URL input.
    allowed = path == '/api/sessions' or path == '/api/runtime' or path.startswith('/api/runtime?session_id=')
    assert allowed and runtime and runtime['pid']==child.pid
    method='POST' if payload is not None else 'GET'
    if method=='POST':
        if path=='/api/sessions': assert payload == {'name':'Scope control B'}
        else:
            assert path=='/api/runtime' and set(payload)=={'session_id','scope_patterns'}
            assert payload['session_id'] in observations['ids'].values()
            assert payload['scope_patterns'] in [['example.com'],['b.example.com']]
    if '?' in path:
        assert path=='/api/runtime?session_id='+observations['ids']['A']
    req=urllib.request.Request('http://'+runtime['ui_addr']+path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={'Content-Type':'application/json'},method=method)
    with opener.open(req,timeout=5) as res:
        status=res.status; body=json.loads(res.read())
    calls.append({'process':starts,'method':method,'path':path,'payload':payload,'status':status})
    return body

def start(data):
    global child,log,runtime,starts
    starts+=1
    env=dict(os.environ)
    for k in list(env):
        if k.lower().endswith('_proxy') or k.startswith('SNIPER_'): env.pop(k,None)
    env.update(SNIPER_DATA_DIR=str(data),SNIPER_UI_ADDR='127.0.0.1:0',SNIPER_PROXY_ADDR='127.0.0.1:0',RUST_LOG='off')
    log=(OUT/f'server-{starts}.log').open('xb')
    child=subprocess.Popen([str(BINARY)],env=env,stdout=log,stderr=subprocess.STDOUT,cwd=str(OUT))
    processes.append({'pid':child.pid,'start':starts})
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        assert child.poll() is None, 'owned server exited during setup'
        try:
            r=json.loads((data/'runtime-state.json').read_text())
            if r['pid']==child.pid:
                for key in ('ui_addr','proxy_addr'):
                    host,port=r[key].rsplit(':',1)
                    assert host=='127.0.0.1' and 0<int(port)<65536
                runtime={k:r[k] for k in ('pid','ui_addr','proxy_addr')}
                processes[-1]['runtime']=runtime
                return request('/api/sessions')
        except (FileNotFoundError, json.JSONDecodeError, urllib.error.URLError): pass
        time.sleep(.02)
    raise AssertionError('owned server did not become ready')

def stop():
    global child,log,runtime
    if child is not None:
        if child.poll() is None: child.send_signal(signal.SIGTERM)
        try: code=child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill(); code=child.wait(timeout=5)
            processes[-1]['forced_cleanup']=True
        processes[-1]['exit']=code
        child=None; runtime=None
        if log: log.close(); log=None
        check('owned graceful shutdown '+str(starts),code==0 and not processes[-1].get('forced_cleanup',False))

def list_summary(rows):
    return {k:{'id':r['id'],'active':r['active'],'request_count':r['request_count'],
                  'event_count':r['event_count'],'overview':r['overview'],'storage_bytes':r['storage_bytes']}
            for k,ident in observations['ids'].items() for r in rows if r['id']==ident}

def stored(data):
    registry_path=data/'sessions/registry.json'
    registry=json.loads(registry_path.read_text())
    result={}
    for name,ident in observations['ids'].items():
        state=json.loads((data/'sessions'/ident/'state.json').read_text())
        meta=next(m for m in registry['sessions'] if m['id']==ident)
        result[name]={'state_sha256':sha(data/'sessions'/ident/'state.json'),
                     'snapshot_sha256':sha(data/'sessions'/ident/'snapshot.json'),
                     'registry_sha256':sha(registry_path),'scope':state['runtime']['scope_patterns'],'finding_count':len(state.get('scanner_findings',[])),
                     'registry_overview':meta['overview'],'registry_request_count':meta['request_count'],
                     'registry_event_count':meta['event_count']}
    return result

status='SETUP_OR_FIXTURE_FAILURE'; exit_code=2; initial=None
try:
    initial=pins()
    check('sealed source pins',initial['head']==HEAD and initial['tree']==TREE and initial['status']=='')
    check('sealed server hash',initial['binary_sha256']==BINARY_SHA)
    data=pathlib.Path(tempfile.mkdtemp(prefix='sniper-session-overview-'))
    rows=start(data)
    check('one initial session',len(rows)==1 and rows[0]['active'])
    a=rows[0]['id']
    b=request('/api/sessions',{'name':'Scope control B'})['id']
    observations['ids']={'A':a,'B':b}
    observations['initial']=list_summary(request('/api/sessions'))
    check('B active and A inactive before pinned write',observations['initial']['B']['active'] and not observations['initial']['A']['active'])
    check('initial empty scope',all(v['overview']['scope']==[] for v in observations['initial'].values()))
    body_a=request('/api/runtime',{'session_id':a,'scope_patterns':['example.com']})
    body_b=request('/api/runtime',{'session_id':b,'scope_patterns':['b.example.com']})
    observations['acknowledged_scope']={'A':body_a['scope_patterns'],'B':body_b['scope_patterns']}
    check('inactive A acknowledged',body_a['scope_patterns']==['example.com'])
    check('active B acknowledged',body_b['scope_patterns']==['b.example.com'])
    observations['live']=list_summary(request('/api/sessions'))
    observations['stored_before_shutdown']=stored(data)
    check('loaded A listing current',observations['live']['A']['overview']['scope']==['example.com'])
    check('loaded B listing current',observations['live']['B']['overview']['scope']==['b.example.com'])
    check('A scope durably present',observations['stored_before_shutdown']['A']['scope']==['example.com'])
    stop()
    observations['stored_after_shutdown']=stored(data)
    observations['inactive_A_shutdown_fullsave_signal']={
        'snapshot_changed':observations['stored_before_shutdown']['A']['snapshot_sha256']!=observations['stored_after_shutdown']['A']['snapshot_sha256'],
        'registry_scope_before':observations['stored_before_shutdown']['A']['registry_overview']['scope'],
        'registry_scope_after':observations['stored_after_shutdown']['A']['registry_overview']['scope']}
    rows=start(data) # This is the unopened first listing: no read of A's context.
    observations['restarted_unopened']=list_summary(rows)
    observations['stored_after_restart']=stored(data)
    check('B remains active',observations['restarted_unopened']['B']['active'] and not observations['restarted_unopened']['A']['active'])
    check('active B survives restart',observations['restarted_unopened']['B']['overview']['scope']==['b.example.com'])
    check('A stored scope not lost',observations['stored_after_restart']['A']['scope']==['example.com'])
    read_a=request('/api/runtime?session_id='+a)
    observations['read_A_scope']=read_a['scope_patterns']
    observations['after_A_read']=list_summary(request('/api/sessions'))
    observations['stored_after_A_read']=stored(data)
    check('read A returns stored scope',read_a['scope_patterns']==['example.com'])
    check('A read repairs listing overlay',observations['after_A_read']['A']['overview']['scope']==['example.com'])
    for stage in ('initial','live','restarted_unopened','after_A_read'):
        check(stage+' exactly two sessions',len(observations[stage])==2)
        check(stage+' zero requests',all(v['request_count']==0 for v in observations[stage].values()))
        check(stage+' zero findings',all(sum(v['overview']['findings'].values())==0 for v in observations[stage].values()))
        check(stage+' apparent bytes positive',all(v['storage_bytes']>0 for v in observations[stage].values()))
    stop()
    final=pins(); check('source and binary unchanged',initial==final)
    freshness_checks={
        'ordinary_save_registry_current':observations['stored_before_shutdown']['A']['registry_overview']['scope']==['example.com'],
        'shutdown_did_not_rewrite_inactive_snapshot':not observations['inactive_A_shutdown_fullsave_signal']['snapshot_changed'],
        'unopened_restart_scope_current':observations['restarted_unopened']['A']['overview']['scope']==['example.com']}
    expected=all(freshness_checks.values())
    status='PASS' if expected else 'PRODUCT_EXPECTATION_RED'
    exit_code=0 if expected else 1
    observations['expectation']={'name':'ordinary save refreshes inactive Scope overview without relying on shutdown or read repair','checks':freshness_checks,'expected':['example.com'],
       'actual':observations['restarted_unopened']['A']['overview']['scope'],'pass':expected}
except BaseException:
    observations['error']=traceback.format_exc()
    print(observations['error'],flush=True)
finally:
    try:
        if child is not None: stop()
    except BaseException:
        observations['cleanup_error']=traceback.format_exc(); status='SETUP_OR_FIXTURE_FAILURE'; exit_code=2
    if data is not None:
        if child is None or child.poll() is not None:
            try:
                shutil.rmtree(data) # Only the exact root created above, after owned processes stop.
                observations['owned_data_removed']=not data.exists()
            except BaseException:
                observations['data_cleanup_error']=traceback.format_exc(); status='SETUP_OR_FIXTURE_FAILURE'; exit_code=2
        else:
            observations['data_cleanup_error']='owned process not confirmed stopped; temporary data retained'
            status='SETUP_OR_FIXTURE_FAILURE'; exit_code=2
    final=pins()
    if initial is not None and final!=initial:
        status='SOURCE_OR_BINARY_CHANGED'; exit_code=2
    save('runtime-observations.json',{'status':status,'exit':exit_code,'argv':sys.argv,'pins_before':initial,'pins_after':final,
        'script_sha256':sha(pathlib.Path(__file__)),'controls':controls,'observations':observations,'api_calls':calls,'processes':processes,
        'limits':['only explicit local metadata API requests','no proxy/capture/scanner/provider requests','no findings or nonzero request-count defect claim',
                  'apparent-byte positivity controls only, not exact/allocated disk usage','not browser QA; inactive context intentionally unread before first restarted listing']})
    print(json.dumps({'status':status,'exit':exit_code,'controls_passed':sum(c['pass'] for c in controls),'controls_total':len(controls),
                      'expectation':observations.get('expectation'),'server_starts':starts,'api_calls':len(calls)},sort_keys=True),flush=True)
    sys.exit(exit_code)
