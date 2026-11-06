#!/usr/bin/env python3
"""Loopback-only native TCP regression checks against a freshly built Sniper.

Run after `cargo build --locked --release --bin sniper`. All traffic and
session mutations use disposable fixture data; no real session is opened.
"""
import argparse, os, json, socket, subprocess, threading, time, pathlib, urllib.request, urllib.error, uuid, base64, tempfile
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
 data=None if body is None else json.dumps(body).encode()
 req=urllib.request.Request(f'http://127.0.0.1:{UI}'+path,data=data,method=method,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=8) as r:
  b=r.read(); return json.loads(b) if b else None

def launch():
 global proc
 env=os.environ.copy();env.update(SNIPER_INSTALL_AGENT_SKILLS='0',SNIPER_INSTALL_CLI_PATH='0',SNIPER_DATA_DIR=str(DATA),SNIPER_UI_ADDR=f'127.0.0.1:{UI}',SNIPER_PROXY_ADDR=f'127.0.0.1:{PROXY}',RUST_LOG='warn')
 log=open(DATA/f'run-{len(logs)}.log','w');logs.append(log)
 proc=subprocess.Popen([str(BINARY)],env=env,stdout=log,stderr=log)
 poll(lambda:api('/api/tcp/status'))
def shutdown(kill=False):
 global proc
 if proc is not None:
  proc.kill() if kill else proc.terminate()
  proc.wait(timeout=20);proc=None

def echo_listener():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen(64)
 def serve():
  while True:
   try:c,_=s.accept()
   except OSError:return
   def client(c):
    try:
     while True:
      b=c.recv(65536)
      if not b:break
      c.sendall(b)
     c.shutdown(socket.SHUT_WR)
    except OSError:pass
    finally:c.close()
   threading.Thread(target=client,args=(c,),daemon=True).start()
 threading.Thread(target=serve,daemon=True).start(); return s

def terminal(n):
 rows=api('/api/tcp/connections');return rows if len(rows)>=n and all(r['ended_at'] and r['durable'] for r in rows) else None

def exchange(payload):
 c=socket.create_connection(('127.0.0.1',RELAY),timeout=8)
 errors=[]
 def send():
  try:c.sendall(payload);c.shutdown(socket.SHUT_WR)
  except OSError as error:errors.append(error)
 t=threading.Thread(target=send);t.start();out=bytearray()
 try:
  while True:
   b=c.recv(65536)
   if not b:break
   out.extend(b)
 finally:t.join();c.close()
 if errors:raise errors[0]
 return bytes(out)

up=echo_listener();target=up.getsockname()[1]
try:
 launch()
 sid=next(s['id'] for s in api('/api/sessions') if s['active'])
 q=f'?session_id={sid}&expected_active_session_id={sid}'
 occupied=socket.socket();occupied.bind(('127.0.0.1',0));occupied.listen()
 conflict_port=occupied.getsockname()[1]
 try:
  api('/api/tcp/start'+q,{'local_port':conflict_port,'target_host':'127.0.0.1','target_port':1})
  raise AssertionError('occupied bind accepted')
 except urllib.error.HTTPError as e:
  text=e.read().decode()
  check('occupied bind returns actionable HTTP 400',e.code==400 and text==f'Local port {conflict_port} is already in use. Choose another Local port or stop the listener using it.')
 check('failed bind leaves listener off',not api('/api/tcp/status')['enabled'])
 occupied.close()
 for host in ['localhost:1234','127.0.0.1:80','[::1]:80','[localhost]','[::1','::1]']:
  try:
   api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':host,'target_port':1});raise AssertionError('invalid host accepted')
  except urllib.error.HTTPError as e:check('host syntax rejected: '+host,e.code==400)
 upstream=socket.socket(socket.AF_INET6);upstream.bind(('::1',0));upstream.listen()
 def echo6():
  c,_=upstream.accept()
  with c:
   data=c.recv(100);c.sendall(data);c.shutdown(socket.SHUT_WR)
 worker=threading.Thread(target=echo6,daemon=True);worker.start()
 target=upstream.getsockname()[1]
 result=api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':'[::1]','target_port':target})
 check('bracketed IPv6 normalized in listener status',result['settings']['target_host']=='::1')
 with socket.create_connection(('127.0.0.1',RELAY),timeout=5) as client:
  client.sendall(bytes([0,255,42]));client.shutdown(socket.SHUT_WR)
  check('actual IPv6 upstream bytes relayed',client.recv(10)==bytes([0,255,42]))
 worker.join(5);upstream.close()
 rows=poll(lambda:terminal(1))
 check('IPv6 target label is unambiguous',rows[0]['target']==f'[::1]:{target}')
 api('/api/tcp/stop'+q,method='POST')
 # A bound, non-listening port deterministically refuses loopback connects.
 refused=socket.socket();refused.bind(('127.0.0.1',0))
 api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':'127.0.0.1','target_port':refused.getsockname()[1]})
 check('start does not connect to target',len(api('/api/tcp/connections'))==1)
 with socket.create_connection(('127.0.0.1',RELAY),timeout=5) as client:
  try:client.recv(1)
  except ConnectionResetError:pass
 rows=poll(lambda:terminal(2));failed=next(r for r in rows if r['status']=='failed');fid=failed['id']
 check('refused summary has safe failure code and zero bytes',failed.get('failure')=='connection_refused' and failed['client_bytes']==0 and failed['server_bytes']==0)
 detail=api('/api/tcp/connections/'+fid)
 check('detail failure agrees with summary',detail.get('failure')=='connection_refused')
 disk=list(DATA.rglob(fid+'.json'))
 check('terminal disk record persists refusal',len(disk)==1 and json.loads(disk[0].read_text()).get('failure')=='connection_refused')
 check('successful IPv6 record has no failure',next(r for r in rows if r['status']=='closed').get('failure') is None)
 refused.close();api('/api/tcp/stop'+q,method='POST')
 shutdown();launch()
 reloaded=api('/api/tcp/connections/'+fid)
 check('restart retains safe refusal and saved status',reloaded.get('failure')=='connection_refused' and reloaded['durable'])
 print('RESULT',len(results),'checks passed',flush=True)
finally:
 shutdown()
 for log in logs:log.close()
