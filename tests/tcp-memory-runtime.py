#!/usr/bin/env python3
"""Isolated loopback TCP memory, saved-detail, and restart regression.

Reports RSS before and after visiting three sessions containing 96 capped
captures. Verifies all detail JSON and saved file hashes after restart.
"""
import argparse,os,json,socket,subprocess,threading,time,pathlib,urllib.request,urllib.error,uuid,tempfile,hashlib
ROOT=pathlib.Path(os.environ.get('TCP_MEMORY_CANDIDATE', pathlib.Path(__file__).resolve().parents[1]))
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, default=ROOT/'target/release/sniper')
parser.add_argument('--connections-per-session', type=int, choices=range(1,257), default=32)
parser.add_argument('--sessions', type=int, choices=range(1,9), default=3)
args=parser.parse_args();BINARY=args.binary.resolve();CONNECTIONS=args.connections_per_session;SESSIONS=args.sessions
if not BINARY.is_file():parser.error('Build the release sniper binary first')
DATA=pathlib.Path(tempfile.mkdtemp(prefix='tcp-memory-runtime-'));(DATA/'templates').mkdir();(DATA/'templates/templates.json').write_text('{"auto_update":false}')
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
UI,PROXY,RELAY=port(),port(),port();proc=None;results={'sessions':SESSIONS,'connections_per_session':CONNECTIONS};logs=[]
def api(path,body=None,method=None):
 req=urllib.request.Request(f'http://127.0.0.1:{UI}'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=10) as r:
  b=r.read();return json.loads(b) if b else None
def poll(fn,timeout=20):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  try:
   value=fn()
   if value:return value
  except (OSError,urllib.error.URLError):pass
  time.sleep(.02)
 raise AssertionError('poll timeout')
def rss():
 return int(next(l.split()[1] for l in pathlib.Path(f'/proc/{proc.pid}/status').read_text().splitlines() if l.startswith('VmRSS:')))
def start():
 global proc
 env=os.environ.copy();env.update(SNIPER_DATA_DIR=str(DATA),SNIPER_UI_ADDR=f'127.0.0.1:{UI}',SNIPER_PROXY_ADDR=f'127.0.0.1:{PROXY}',RUST_LOG='warn');log=open(DATA/f'run-{len(logs)}.log','w');logs.append(log);proc=subprocess.Popen([str(BINARY)],env=env,stdout=log,stderr=log);poll(lambda:api('/api/tcp/status'))
def shutdown():
 global proc
 if proc:proc.terminate();proc.wait(timeout=20);proc=None
def echo():
 up=socket.socket();up.bind(('127.0.0.1',0));up.listen(64)
 def accept():
  while True:
   try:c,_=up.accept()
   except OSError:return
   def run(c):
    try:
     while True:
      b=c.recv(65536)
      if not b:break
      c.sendall(b)
     c.shutdown(socket.SHUT_WR)
    except OSError:pass
    finally:c.close()
   threading.Thread(target=run,args=(c,),daemon=True).start()
 threading.Thread(target=accept,daemon=True).start();return up
def exchange(size):
 c=socket.create_connection(('127.0.0.1',RELAY),timeout=10);block=bytes(range(256))*256;errors=[];expected=hashlib.sha256();actual=hashlib.sha256();total=0
 def send():
  try:
   for i in range(size//len(block)):c.sendall(block);expected.update(block)
   c.shutdown(socket.SHUT_WR)
  except OSError as e:errors.append(str(e))
 t=threading.Thread(target=send);t.start()
 while True:
  b=c.recv(65536)
  if not b:break
  total+=len(b);actual.update(b)
 t.join();c.close();assert not errors and total==size and actual.digest()==expected.digest()
def done(n):
 rows=api('/api/tcp/connections');return rows if len(rows)==n and all(r['durable'] for r in rows) else None
up=echo();sessions=[];saved_details={};disk_snapshots={}
try:
 start();results['baseline_rss_kib']=rss();settings={'local_port':RELAY,'target_host':'127.0.0.1','target_port':up.getsockname()[1]}
 api('/api/tcp/start',settings);exchange(32*1024*1024);row=poll(lambda:done(1))[0];results['large_transfer']={k:row[k] for k in ['client_bytes','server_bytes','captured_bytes','capture_truncated','durable']};results['large_transfer']['rss_kib']=rss();assert row['client_bytes']==row['server_bytes']==32*1024*1024 and row['captured_bytes']==1048576 and row['capture_truncated']
 api('/api/tcp/stop',method='POST')
 results['session_memory']=[]
 for i in range(SESSIONS):
  session=api('/api/sessions',{'name':f'Resource audit {i}'});sessions.append(session);api('/api/tcp/start',settings)
  for j in range(CONNECTIONS):exchange(256*1024)
  rows=poll(lambda:done(CONNECTIONS));api('/api/tcp/stop',method='POST')
  for row in rows:
   detail=api('/api/tcp/connections/'+row['id']);saved_details[(session['id'],row['id'])]=detail
   file=pathlib.Path(session['storage_path'])/'tcp-history'/(row['id']+'.json');assert file.is_relative_to(DATA);disk_snapshots[str(file)]=hashlib.sha256(file.read_bytes()).hexdigest()
  results['session_memory'].append({'filled_sessions':i+1,'rss_kib':rss()})
 empty=api('/api/sessions',{'name':'Resource audit empty'});results['empty_active_rss_kib']=rss();shutdown();start();results['empty_active_after_restart_rss_kib']=rss()
 for session in sessions:
  rows=api('/api/tcp/connections?session_id='+session['id']);assert len(rows)==CONNECTIONS
  results.setdefault('read_only_memory',[]).append({'opened_sessions':len(results.get('read_only_memory',[]))+1,'rss_kib':rss()})
 results['summary_read_growth_kib']=rss()-results['empty_active_after_restart_rss_kib']
 # Reopening every saved detail must return exactly its complete previous JSON,
 # including binary previews and all offsets, without growing the session cache.
 for _ in range(2):
  for (session_id,record_id),expected in saved_details.items():
   actual=api('/api/tcp/connections/'+record_id+'?session_id='+session_id);assert actual==expected
 results['reopened_details']=len(saved_details)*2;results['after_detail_reads_rss_kib']=rss()
 for file,digest in disk_snapshots.items():assert hashlib.sha256(pathlib.Path(file).read_bytes()).hexdigest()==digest
 results['unchanged_history_files']=len(disk_snapshots)
 # Saved payload errors are explicit, not an empty successful detail or 404.
 session_id,record_id=next(iter(saved_details));file=next(pathlib.Path(s['storage_path'])/'tcp-history'/(record_id+'.json') for s in sessions if s['id']==session_id);original=file.read_bytes();file.write_bytes(b'{')
 try:api('/api/tcp/connections/'+record_id+'?session_id='+session_id);raise AssertionError('corrupt saved detail was accepted')
 except urllib.error.HTTPError as e:assert e.code==500;results['corrupt_detail_http']=e.code
 assert api('/api/tcp/status?session_id='+session_id)['load_error'];assert len(api('/api/tcp/connections?session_id='+session_id))==CONNECTIONS
 file.write_bytes(original)
 print(json.dumps(results,indent=2),flush=True)
finally:
 shutdown();up.close();[log.close() for log in logs];(DATA/'resource-results.json').write_text(json.dumps(results,indent=2));print('DATA_DIR',DATA,flush=True)
