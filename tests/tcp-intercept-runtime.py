#!/usr/bin/env python3
"""Loopback-only native TCP interception regression checks against a freshly built Sniper.

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
try:
 launch();sid=next(s['id'] for s in api('/api/sessions') if s['active']);q=f'?session_id={sid}&expected_active_session_id={sid}'
 check('intercept defaults off',not api('/api/tcp/intercept')['enabled'])
 api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':'127.0.0.1','target_port':up.getsockname()[1]})
 policy=api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':0},'PUT')
 client,server,cid=open_pair();original=bytes([0,255,13,10,128]);client.sendall(original);item=pending(cid)[0]
 server.settimeout(.1)
 try:server.recv(1);raise AssertionError('unsent bytes arrived')
 except socket.timeout:check('pending bytes do not reach upstream',True)
 server.settimeout(8)
 check('pending binary is lossless',base64.b64decode(item['original_base64'])==original)
 check('pending excluded from delivered byte count',api(f'/api/tcp/connections/{cid}')['client_bytes']==0)
 edited=bytes([254,13,10,0,128,1,2]);receipt=decide(cid,item,replacement=edited)
 check('Forward response only acknowledges acceptance202',last_status==202 and receipt['state']=='forwarding')
 check('edited binary reaches upstream exactly',server.recv(64)==edited)
 try:decide(cid,item);raise AssertionError('duplicate accepted')
 except urllib.error.HTTPError as e:check('duplicate decision rejected409',e.code==409)
 client.sendall(b'drop');item=pending(cid)[0]
 policy=api('/api/tcp/intercept'+q,{'enabled':False,'direction':'both','expected_revision':policy['revision']},'PUT')
 check('Off retains held ranges',policy['pending_count']==1 and len(pending(cid))==1)
 decide(cid,item,'drop');client.sendall(b'next');check('Drop permits subsequent bytes without closing',server.recv(64)==b'next')
 client.shutdown(socket.SHUT_WR);check('client half-close forwarded after decision',server.recv(1)==b'')
 server.sendall(b'response');server.shutdown(socket.SHUT_WR);check('opposite direction survives half-close',client.recv(64)==b'response')
 poll(lambda:api(f'/api/tcp/connections/{cid}')['durable']);record=api(f'/api/tcp/connections/{cid}')
 check('received and delivered accounting differ correctly',record['client_received_bytes']==13 and record['client_bytes']==11)
 events=record['intercept_events'];check('history preserves original edited dropped outcomes',len(events)==2 and events[0]['edited'] and base64.b64decode(events[0]['original_base64'])==original and base64.b64decode(events[0]['selected_base64'])==edited and events[0]['written_bytes']==7 and events[1]['state']=='dropped')
 api('/api/tcp/stop'+q,method='POST');shutdown();launch()
 check('restart never re-enables interception',not api('/api/tcp/intercept')['enabled'])
 check('terminal event history restored unchanged',api(f'/api/tcp/connections/{cid}')==record)
 api('/api/tcp/start'+q,{'local_port':RELAY,'target_host':'127.0.0.1','target_port':up.getsockname()[1]})
 policy=api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':0},'PUT')
 client,server,cid2=open_pair();client.sendall(b'once');item=pending(cid2)[0]
 route=f"/api/tcp/connections/{cid2}/pending/{item['pending_id']}/decision"+q
 body=json.dumps({'action':'forward','expected_revision':item['revision']}).encode()
 # The transport response is deliberately abandoned; acceptance must not depend on it.
 wire=socket.create_connection(('127.0.0.1',UI));wire.sendall(f'POST {route} HTTP/1.1\r\nHost: 127.0.0.1:{UI}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()+body)
 check('accepted decision survives abandoned HTTP response',server.recv(64)==b'once');wire.close()
 client.sendall(b'held');server.sendall(b'held response');pending(cid2,2)
 api(f'/api/tcp/connections/{cid2}/close'+q,method='POST')
 poll(lambda:api(f'/api/tcp/connections/{cid2}')['durable']);closed=api(f'/api/tcp/connections/{cid2}')
 check('explicit Close cancels both pending directions',len(closed['intercept_events'])==3 and sum(e['state']=='cancelled' for e in closed['intercept_events'])==2 and api('/api/tcp/intercept')['pending_count']==0)
 client,server,switch_id=open_pair();client.sendall(b'switch pending');pending(switch_id)
 try:api('/api/sessions/'+str(uuid.uuid4())+'/activate',method='POST');raise AssertionError('missing session activated')
 except urllib.error.HTTPError:check('failed session activation preserves held original',len(pending(switch_id))==1)
 old_sid=sid;new=api('/api/sessions',{'name':'TCP intercept pending switch'})
 api('/api/sessions/'+new['id']+'/activate',method='POST')
 old=poll(lambda: (r if (r:=api(f'/api/tcp/connections/{switch_id}?session_id={old_sid}'))['durable'] else None))
 check('committed session switch cancels pending and persists original',old['status']=='stopped' and old['intercept_events'][0]['state']=='cancelled' and base64.b64decode(old['intercept_events'][0]['original_base64'])==b'switch pending')
 check('new session starts with no listener or interception',not api('/api/tcp/status')['enabled'] and not api('/api/tcp/intercept')['enabled'])
 sid=new['id'];q=f'?session_id={sid}&expected_active_session_id={sid}'
 settings={'local_port':RELAY,'target_host':'127.0.0.1','target_port':up.getsockname()[1]}
 api('/api/tcp/start'+q,settings);api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':0},'PUT')
 client,server,graceful_id=open_pair();client.sendall(b'shutdown pending');pending(graceful_id)
 shutdown();launch();graceful=api(f'/api/tcp/connections/{graceful_id}')
 check('graceful shutdown persists held range as cancelled',graceful['status']=='stopped' and graceful['durable'] and graceful['intercept_events'][0]['state']=='cancelled' and graceful['client_bytes']==0)
 api('/api/tcp/start'+q,settings);api('/api/tcp/intercept'+q,{'enabled':True,'direction':'both','expected_revision':0},'PUT')
 client,server,cid3=open_pair();client.sendall(b'crash pending');pending(cid3)
 shutdown(kill=True);launch();r=api(f'/api/tcp/connections/{cid3}')
 check('crash does not invent sent or dropped outcomes',r['status']=='interrupted' and r['capture_truncated'] and r['intercept_truncated'] and r['client_bytes']==0 and r['intercept_events']==[])
 check('crash restart keeps listener off',not api('/api/tcp/status')['enabled'])
 print(json.dumps({'passed':len(results),'checks':results,'data_dir':str(DATA)},indent=2))
finally:
 shutdown()
 for c in clients:c.close()
 up.close()
 for log in logs:log.close()
