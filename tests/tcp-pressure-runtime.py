#!/usr/bin/env python3
"""Loopback-only native TCP interception regression checks against a freshly built Sniper.

Run after `cargo build --locked --release --bin sniper`. All traffic and
session mutations use disposable fixture data; no real session is opened.
"""
import argparse, os, json, socket, subprocess, threading, time, pathlib, urllib.request, urllib.error, base64, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, default=ROOT/'target/release/sniper')
parser.add_argument('--data-dir', type=pathlib.Path, help='New, nonexistent fixture directory; kept for inspection')
args=parser.parse_args()
BINARY=args.binary.resolve()
if not BINARY.is_file():parser.error('Build the headless sniper binary first')
if args.data_dir:
 DATA=args.data_dir.resolve();DATA.mkdir(parents=True,exist_ok=False)
else:DATA=pathlib.Path(tempfile.mkdtemp(prefix='sniper-tcp-runtime-'))
(DATA/'templates').mkdir(); (DATA/'templates/templates.json').write_text('{"auto_update":false}')

def port():
 with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
UI,PROXY,RELAY=port(),port(),port()
proc=None; logs=[]; results=[]
def check(name,condition):
 assert condition,name
 results.append(name); print('PASS',name,flush=True)
def poll(fn,timeout=15):
 end=time.monotonic()+timeout; error=None
 while time.monotonic()<end:
  try:
   r=fn()
   if r:return r
  except (OSError,urllib.error.URLError) as e:error=e
  time.sleep(.02)
 raise AssertionError(('poll timeout',error))
def api(path,body=None,method=None):
 global last_status
 data=None if body is None else json.dumps(body).encode()
 req=urllib.request.Request(f'http://127.0.0.1:{UI}'+path,data=data,method=method,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=8) as r:
  last_status=r.status
  b=r.read(); return json.loads(b) if b else None

def launch():
 global proc
 env=os.environ.copy();env.update(SNIPER_DATA_DIR=str(DATA),SNIPER_UI_ADDR=f'127.0.0.1:{UI}',SNIPER_PROXY_ADDR=f'127.0.0.1:{PROXY}',RUST_LOG='warn')
 log=open(DATA/f'run-{len(logs)}.log','w');logs.append(log)
 proc=subprocess.Popen([str(BINARY)],env=env,stdout=log,stderr=log)
 poll(lambda:api('/api/tcp/status'))
def shutdown(kill=False):
 global proc
 if proc is not None:
  proc.kill() if kill else proc.terminate()
  proc.wait(timeout=20);proc=None

up=socket.socket();up.bind(('127.0.0.1',0));up.listen(64);up.settimeout(8)
clients=[]
def pending(cid,n=1):
 return poll(lambda: (r if len((r:=api(f'/api/tcp/connections/{cid}/pending'))['items'])==n else None))['items']
def decide(cid,item,action='forward',replacement=None):
 body={'action':action,'expected_revision':item['revision']}
 if replacement is not None:body['replacement_base64']=base64.b64encode(replacement).decode()
 return api(f"/api/tcp/connections/{cid}/pending/{item['pending_id']}/decision"+q,body)
def open_pair():
 before={r['id'] for r in api('/api/tcp/connections')}
 client=socket.create_connection(('127.0.0.1',RELAY),timeout=8);server,_=up.accept();server.settimeout(8);clients.extend([client,server])
 cid=poll(lambda:next((r['id'] for r in api('/api/tcp/connections') if r['id'] not in before),None))
 return client,server,cid
import struct
try:
 launch()
 with urllib.request.urlopen(f'http://127.0.0.1:{UI}/tcp-capture.js',timeout=8) as r:
  check('served TCP UI matches validated source',r.read()==(ROOT/'web/tcp-capture.js').read_bytes())
 sid=next(s['id'] for s in api('/api/sessions') if s['active']);q=f'?session_id={sid}&expected_active_session_id={sid}'
 up.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024)
 api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':'127.0.0.1','target_port':up.getsockname()[1]})
 policy=api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':0},'PUT')
 client,server,cid=open_pair()
 def flood():
  try:client.sendall(b'x'*(32*1024*1024))
  except OSError:pass
 thread=threading.Thread(target=flood,daemon=True);thread.start()
 blocked=None
 for i in range(500):
  item=pending(cid)[0]
  if item['state']=='pending':decide(cid,item)
  time.sleep(.01)
  after=api(f'/api/tcp/connections/{cid}/pending')['items']
  if after and after[0]['state']=='forwarding':
   time.sleep(.3)
   after=api(f'/api/tcp/connections/{cid}/pending')['items']
   if after and after[0]['state']=='forwarding':blocked=after[0];break
 assert blocked, 'did not reach backpressure'
 policy=api('/api/tcp/intercept'+q,{'enabled':False,'direction':'both','expected_revision':policy['revision']},'PUT')
 check('Off preserves approved forwarding aggregate', policy['pending_count']==1 and policy['paused_count']==0 and policy['forwarding_count']==1)
 print('BACKPRESSURE',json.dumps({'iteration':i,'policy':policy,'event':{k:v for k,v in blocked.items() if not k.endswith('base64')},'record':{k:v for k,v in api(f'/api/tcp/connections/{cid}').items() if k not in ['chunks','intercept_events']}}),flush=True)
 api(f'/api/tcp/connections/{cid}/close'+q,method='POST');poll(lambda:api(f'/api/tcp/connections/{cid}')['durable'])
 print('CLOSE_BACKPRESSURE',json.dumps({k:v for k,v in api(f'/api/tcp/connections/{cid}')['intercept_events'][-1].items() if not k.endswith('base64')}),flush=True)
 policy=api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':policy['revision']},'PUT')
 client2,server2,cid2=open_pair();client2.sendall(b'client held');server2.sendall(b'server held');pending(cid2,2)
 client2.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));client2.close()
 time.sleep(2)
 print('RST_BOTH_PENDING',json.dumps({k:v for k,v in api(f'/api/tcp/connections/{cid2}').items() if k not in ['chunks','intercept_events']}),flush=True)
 api(f'/api/tcp/connections/{cid2}/close'+q,method='POST');poll(lambda:api(f'/api/tcp/connections/{cid2}')['durable'])
 poll(lambda:api('/api/tcp/status')['active_count']==0)
 pairs=[]
 for _ in range(32):
  c,s,cid=open_pair();c.sendall(b'held');pending(cid);pairs.append((c,s,cid))
 status=api('/api/tcp/status')
 check('32 occupied admission slots reported',status['active_count']==32 and status['active_limit']==32)
 extra=socket.create_connection(('127.0.0.1',RELAY),timeout=8);extra.sendall(b'queued');clients.append(extra)
 up.settimeout(.2)
 try:
  up.accept();raise AssertionError('33rd connection accepted while full')
 except socket.timeout:pass
 check('extra connection waits, existing ranges preserved',api('/api/tcp/intercept')['paused_count']==32)
 api(f'/api/tcp/connections/{pairs[0][2]}/close'+q,method='POST')
 up.settimeout(8);extra_server,_=up.accept();clients.append(extra_server)
 poll(lambda:api('/api/tcp/intercept')['paused_count']==32)
 check('freeing one slot admits waiting connection',api('/api/tcp/status')['active_count']==32)
 api('/api/tcp/stop'+q,method='POST')
 check('Stop drains admission slots',api('/api/tcp/status')['active_count']==0 and api('/api/tcp/intercept')['pending_count']==0)
 for _,server,_ in pairs:
  check('Stop sends no held client bytes to upstream',server.recv(1)==b'')
 extra_server.settimeout(8)
 check('Stop sends no queued client bytes to upstream',extra_server.recv(1)==b'')
 print('DATA',str(DATA),flush=True)
finally:
 shutdown()
 for c in clients:c.close()
 up.close()
 for log in logs:log.close()
