#!/usr/bin/env python3
"""Loopback-only native TCP regression checks against a freshly built Sniper.

Run after `cargo build --locked --release --bin sniper`. All traffic and
session mutations use disposable fixture data; no real session is opened.
"""
import argparse, os, json, socket, subprocess, threading, time, pathlib, urllib.request, urllib.error, uuid, base64, tempfile
from datetime import datetime, timezone
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
 env=os.environ.copy();env.update(SNIPER_DATA_DIR=str(DATA),SNIPER_UI_ADDR=f'127.0.0.1:{UI}',SNIPER_PROXY_ADDR=f'127.0.0.1:{PROXY}',RUST_LOG='warn')
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
 launch(); check('listener initially off',not api('/api/tcp/status')['enabled'])
 sid=next(s['id'] for s in api('/api/sessions') if s['active'])
 q=f'?session_id={sid}&expected_active_session_id={sid}'
 settings={'local_port':RELAY,'target_host':'127.0.0.1','target_port':target}
 api('/api/tcp/start'+q,settings)
 check('listener start',api('/api/tcp/status')['enabled'])
 payload=bytes(range(256))*2200
 check('563200-byte binary roundtrip with client half-close',exchange(payload)==payload)
 rows=poll(lambda:terminal(1)); detail=api('/api/tcp/connections/'+rows[0]['id'])
 check('capture cap does not truncate relay',detail['client_bytes']==len(payload) and detail['server_bytes']==len(payload) and detail['captured_bytes']==1048576 and detail['capture_truncated'])
 check('summary excludes payload',rows[0]['chunks']==[])
 api('/api/transactions'+q,method='DELETE')
 check('HTTP history clear leaves TCP detail unchanged',api('/api/tcp/connections/'+rows[0]['id'])==detail)
 listing=next(s for s in api('/api/sessions') if s['id']==sid)
 check('TCP-only session listing shows one connection and nonzero disk size',listing['tcp_connection_count']==1 and listing['request_count']==0 and listing['storage_bytes']>0)
 captured={d:bytearray() for d in ['client_to_server','server_to_client']}
 for chunk in detail['chunks']:
  dest=captured[chunk['direction']]; assert chunk['offset']==len(dest); dest.extend(base64.b64decode(chunk['data_base64']))
 check('captured prefixes preserve binary',all(payload.startswith(bytes(v)) for v in captured.values()))
 try:api('/api/tcp/stop?expected_active_session_id='+str(uuid.uuid4()),method='POST');raise AssertionError('stale write accepted')
 except urllib.error.HTTPError as e: check('stale session write is 409',e.code==409)
 try:api('/api/sessions/'+str(uuid.uuid4())+'/activate',method='POST');raise AssertionError('missing session accepted')
 except urllib.error.HTTPError as e:check('failed session activation preserves listener',api('/api/tcp/status')['enabled'])
 api('/api/tcp/stop'+q,method='POST');check('explicit stop',not api('/api/tcp/status')['enabled'])
 shutdown()
 storage=pathlib.Path(listing['storage_path']);assert storage.is_relative_to(DATA)
 history=storage/'tcp-history'
 durable_path=history/f"{detail['id']}.json";durable_bytes=durable_path.read_bytes()
 orphan_path=durable_path.with_suffix(f'.tmp-{uuid.uuid4()}')
 orphan_path.write_bytes(b'{"unfinished":')
 unpublished=dict(detail,id=str(uuid.uuid4()))
 unpublished_path=history/f"{unpublished['id']}.tmp-{uuid.uuid4()}"
 unpublished_bytes=json.dumps(unpublished).encode();unpublished_path.write_bytes(unpublished_bytes)
 launch();check('restart leaves listener disabled',not api('/api/tcp/status')['enabled'])
 check('orphan atomic writes do not flag history recovery',not api('/api/tcp/status')['load_error'])
 check('orphan atomic writes are preserved without publication',orphan_path.read_bytes()==b'{"unfinished":' and unpublished_path.read_bytes()==unpublished_bytes and not (history/f"{unpublished['id']}.json").exists())
 check('orphan recovery leaves durable record bytes unchanged',durable_path.read_bytes()==durable_bytes)
 check('TCP session count survives restart',next(s for s in api('/api/sessions') if s['id']==sid)['tcp_connection_count']==1)
 restored=api('/api/tcp/connections/'+rows[0]['id']);check('closed history and captured bytes survive process restart',restored==detail)
 api('/api/tcp/start'+q,settings)
 c=socket.create_connection(('127.0.0.1',RELAY));c.sendall(b'live-before-crash');assert c.recv(17)==b'live-before-crash'
 poll(lambda:len(api('/api/tcp/connections'))==2)
 live=next(r for r in api('/api/tcp/connections') if r['id']!=detail['id'])
 terminal_orphan=dict(api('/api/tcp/connections/'+live['id']),status='closed',durable=True,ended_at=datetime.now(timezone.utc).isoformat())
 shutdown(kill=True);c.close()
 admission_path=history/f"{live['id']}.json";admission_bytes=admission_path.read_bytes()
 terminal_orphan_path=admission_path.with_suffix(f'.tmp-{uuid.uuid4()}')
 terminal_orphan_bytes=json.dumps(terminal_orphan).encode();terminal_orphan_path.write_bytes(terminal_orphan_bytes)
 launch()
 interrupted=[r for r in api('/api/tcp/connections') if r['status']=='interrupted']
 check('crash recovery marked interrupted, partial and nondurable',len(interrupted)==1 and interrupted[0]['capture_truncated'] and not interrupted[0]['durable'] and interrupted[0]['ended_at'] is None)
 check('complete terminal orphan cannot replace admission snapshot',interrupted[0]['client_bytes']==0 and interrupted[0]['server_bytes']==0 and interrupted[0]['captured_bytes']==0 and admission_path.read_bytes()==admission_bytes and terminal_orphan_path.read_bytes()==terminal_orphan_bytes)
 # A restarted connection tests session switching with a live TCP stream.
 api('/api/tcp/start'+q,settings);c=socket.create_connection(('127.0.0.1',RELAY));c.sendall(b'switch');assert c.recv(6)==b'switch'
 poll(lambda:len(api('/api/tcp/connections'))==3)
 other=api('/api/sessions',{'name':'TCP runtime isolation'})
 api('/api/sessions/'+other['id']+'/activate',method='POST')
 check('successful switch disables listener in new session',not api('/api/tcp/status')['enabled'])
 check('new session has isolated history',api('/api/tcp/connections')==[])
 c.settimeout(5);check('successful switch closes old stream',c.recv(1)==b'');c.close()
 old=api('/api/tcp/connections?session_id='+sid)
 check('old session stop saved terminal history',len(old)==3 and any(r['status']=='stopped' and r['durable'] for r in old))
 # Exercise refusal and corrupt-history protections via fresh loopback-only sessions.
 api('/api/tcp/start',dict(settings,target_port=port()))
 try:exchange(b'refused')
 except OSError:pass
 failed=poll(lambda:terminal(1));check('unavailable upstream produces durable failed history',failed[0]['status']=='failed')
 api('/api/tcp/stop',method='POST')
 # Active budget is enforced on accepted relay work, not the kernel backlog.
 api('/api/tcp/start',settings)
 clients=[]
 for i in range(32):
  conn=socket.create_connection(('127.0.0.1',RELAY),timeout=5);conn.sendall(b'x');assert conn.recv(1)==b'x';clients.append(conn)
 extra=socket.create_connection(('127.0.0.1',RELAY),timeout=5);extra.sendall(b'y');extra.settimeout(.2)
 try:extra.recv(1);raise AssertionError('33rd stream forwarded over active limit')
 except socket.timeout:pass
 check('32 active relay limit preserves backlog without forwarding',len(api('/api/tcp/connections'))==33)
 clients.pop().close();extra.settimeout(5);check('queued connection admitted after capacity returns',extra.recv(1)==b'y');clients.append(extra)
 api('/api/tcp/stop',method='POST')
 for conn in clients:conn.close()
 check('stop drains all active records to durable terminal state',len(poll(lambda:terminal(34)))==34)
 capsession=api('/api/sessions',{'name':'TCP history cap'})
 api('/api/sessions/'+capsession['id']+'/activate',method='POST');api('/api/tcp/start',settings)
 for i in range(256):assert exchange(bytes([i]))==bytes([i])
 full=poll(lambda:terminal(256));ids={r['id'] for r in full}
 try:exchange(b'over-cap')
 except OSError:pass
 check('256 history cap refuses admission without eviction',{r['id'] for r in api('/api/tcp/connections')}==ids)
 api('/api/tcp/stop',method='POST')
 try:api('/api/tcp/start',settings);raise AssertionError('full history restart allowed')
 except urllib.error.HTTPError as e:check('full history start reports 400',e.code==400)
 graceful=api('/api/sessions',{'name':'TCP graceful shutdown'})
 api('/api/tcp/start',settings)
 conn=socket.create_connection(('127.0.0.1',RELAY));conn.sendall(b'graceful');assert conn.recv(8)==b'graceful'
 poll(lambda:len(api('/api/tcp/connections'))==1)
 shutdown();conn.close();launch()
 saved=api('/api/tcp/connections')
 check('graceful process shutdown persists active stream as stopped',len(saved)==1 and saved[0]['status']=='stopped' and saved[0]['durable'])
 check('inactive TCP session count survives restart without opening session',next(s for s in api('/api/sessions') if s['id']==sid)['tcp_connection_count']==3)
 corrupt=api('/api/sessions',{'name':'TCP corrupt history recovery'})
 storage=pathlib.Path(corrupt['storage_path']);assert storage.is_relative_to(DATA)
 shutdown();(storage/'tcp-history').mkdir(exist_ok=True)
 corrupt_id=str(uuid.uuid4())
 (storage/'tcp-history'/f'{corrupt_id}.json').write_text('invalid fixture')
 (storage/'tcp-history'/f'{corrupt_id}.tmp-{uuid.uuid4()}').write_text(json.dumps(dict(detail,id=corrupt_id)))
 launch();check('corrupt active session count is unknown',next(s for s in api('/api/sessions') if s['id']==corrupt['id'])['tcp_connection_count'] is None)
 check('corrupt history exposes recovery error',api('/api/tcp/status')['load_error'])
 try:api('/api/tcp/start',settings);raise AssertionError('corrupt history start allowed')
 except urllib.error.HTTPError as e:check('corrupt history safely blocks new capture',e.code==400)
 clean=api('/api/sessions',{'name':'TCP summary clean restart'})
 shutdown();launch()
 check('corrupt inactive count stays unknown across restart',next(s for s in api('/api/sessions') if s['id']==corrupt['id'])['tcp_connection_count'] is None)
 api('/api/sessions/'+graceful['id'],method='DELETE')
 check('whole-session deletion removes terminal TCP history',not pathlib.Path(graceful['storage_path']).exists())
 check('all runtime checks finished',True)
finally:
 shutdown();up.close()
 for log in logs:log.close()
 (DATA/'results.json').write_text(json.dumps({'passed':results},indent=2))
 print('DATA_DIR',DATA,flush=True)
