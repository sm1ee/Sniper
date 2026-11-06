#!/usr/bin/env python3
"""Verify forwarding UI against real native socket backpressure; loopback only.

Build `cargo build --offline --locked --release --bins`, then run this file.
Uses disposable data, production JS, and unchanged backend networking.
"""
import hashlib, json, os, pathlib, socket, subprocess, tempfile, threading, time, urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'validation'/'forwarding-visibility';OUT.mkdir(parents=True,exist_ok=True)
DATA=pathlib.Path(tempfile.mkdtemp(prefix='tcp-forwarding-visibility-'))
(DATA/'templates').mkdir();(DATA/'templates/templates.json').write_text('{"auto_update":false}')
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
UI,PROXY,RELAY=port(),port(),port()
def api(p,b=None,m=None):
 req=urllib.request.Request(f'http://127.0.0.1:{UI}'+p,data=None if b is None else json.dumps(b).encode(),method=m,headers={'content-type':'application/json'})
 with urllib.request.urlopen(req,timeout=8) as r:
  raw=r.read();return json.loads(raw) if raw else None
def poll(fn,t=10):
 end=time.monotonic()+t
 while time.monotonic()<end:
  try:
   v=fn()
   if v:return v
  except OSError:pass
  time.sleep(.02)
 raise AssertionError('poll timeout')
up=socket.socket();up.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024);up.bind(('127.0.0.1',0));up.listen(8);up.settimeout(8)
log=(OUT/'native.log').open('w');env=dict(os.environ,SNIPER_DATA_DIR=str(DATA),SNIPER_UI_ADDR=f'127.0.0.1:{UI}',SNIPER_PROXY_ADDR=f'127.0.0.1:{PROXY}',SNIPER_INSTALL_AGENT_SKILLS='0',SNIPER_INSTALL_CLI_PATH='0',RUST_LOG='warn')
proc=subprocess.Popen([str(ROOT/'target/release/sniper')],env=env,stdout=log,stderr=log);clients=[];results={}
def pair():
 known={r['id'] for r in api('/api/tcp/connections')};c=socket.create_connection(('127.0.0.1',RELAY),timeout=8);s,_=up.accept();s.settimeout(8);clients.extend([c,s]);cid=poll(lambda:next((r['id'] for r in api('/api/tcp/connections') if r['id'] not in known),None));return c,s,cid
try:
 poll(lambda:api('/api/tcp/status'))
 for name in ['tcp-capture.js','index.html','styles.css']:
  route='/' if name=='index.html' else '/'+name
  with urllib.request.urlopen(f'http://127.0.0.1:{UI}'+route) as r:assert r.read()==(ROOT/'web'/name).read_bytes(),name
 results['embeddedAssetsMatch']=True;results['binarySha256']=hashlib.sha256((ROOT/'target/release/sniper').read_bytes()).hexdigest()
 api('/api/tcp/start',dict(local_port=RELAY,target_host='127.0.0.1',target_port=up.getsockname()[1]))
 policy=api('/api/tcp/intercept');api('/api/tcp/intercept',dict(enabled=True,direction='client_to_server',expected_revision=policy['revision']),'PUT')
 results['controller']=[]
 for mode in ['unchanged','edited','drop']:
  c,s,cid=pair()
  def flood(client):
   try:client.sendall(b'x'*(32*1024*1024))
   except OSError:pass
  if mode=='drop':c.sendall(b'drop')
  else:threading.Thread(target=flood,args=(c,),daemon=True).start()
  poll(lambda:api(f'/api/tcp/connections/{cid}/pending')['items'])
  checked=subprocess.run(['node',str(ROOT/'tests/tcp-forwarding-visibility-runtime.cjs'),f'http://127.0.0.1:{UI}',cid,mode],capture_output=True,text=True,timeout=90)
  assert checked.returncode==0,checked.stdout+checked.stderr
  results['controller'].append(json.loads(checked.stdout));print(checked.stdout.strip(),flush=True)
  if mode=='drop':
   s.settimeout(.15)
   try:s.recv(1);raise AssertionError('dropped bytes reached peer')
   except socket.timeout:pass
  api('/api/tcp/connections/'+cid+'/close',{},'POST');c.close();s.close()
  poll(lambda:api('/api/tcp/connections/'+cid)['status'] in ['closed','failed','stopped'])
 results['fixture']=str(DATA);(OUT/'native-results.json').write_text(json.dumps(results,indent=2));print('PASS unchanged, edited and Drop with real native backend',flush=True)
finally:
 for c in clients:c.close()
 try:api('/api/tcp/stop',{},'POST')
 except Exception:pass
 proc.terminate();proc.wait(timeout=20);up.close();log.close()
