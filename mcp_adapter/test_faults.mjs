import test from 'node:test';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Worker,makeServer} from './server.mjs';
const fixture=fileURLToPath(new URL('./fault_child.mjs',import.meta.url));
function fault(mode,timeoutMs=1500){return new Worker(spawn(process.execPath,[fixture,mode],{stdio:['pipe','pipe','ignore']}),{timeoutMs});}
async function bounded(p,ms=8000){let timer;try{return await Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('test deadline exceeded')),ms);})]);}finally{clearTimeout(timer);}}
async function start(w){const s=makeServer(w);await new Promise(r=>s.http.listen(0,'127.0.0.1',r));return {...s,url:`http://127.0.0.1:${s.http.address().port}`};}
for(const mode of ['exit','stall','malformed','wrong-id','partial','oversize']){
 test(`worker ${mode}: all pending calls fail closed and timers clear`,async()=>{
  const w=fault(mode,mode==='oversize'?5000:1500);const pending=Array.from({length:8},(_,i)=>w.request({action:'health',marker:i}));
  const records=[...w.pending];
  try{
   assert.deepEqual(await bounded(Promise.all(pending)),Array(8).fill({status:503}));
   assert.equal(w.closed,true);assert.equal(w.pending.length,0);
   assert.ok(records.every(p=>p.timer._destroyed));
   assert.deepEqual(await w.request({action:'health'}),{status:503});
  }finally{await bounded(w.close());}
 });
}
test('malformed successful authentication response is not trusted',async()=>{
 const w=fault('bad-shape');try{assert.deepEqual(await bounded(w.request({action:'authenticate'})),{status:503});assert.equal(w.closed,true);}finally{await bounded(w.close());}
});
test('eight-request queue rejects excess without response misrouting',async()=>{
 const w=fault('echo');
 try{
  const requests=Array.from({length:8},(_,i)=>w.request({action:'health',marker:i}));
  const records=[...w.pending];
  assert.deepEqual(await w.request({action:'health',marker:'excess'}),{status:503});
  const replies=await bounded(Promise.all(requests));assert.deepEqual(replies.map(r=>r.marker),[0,1,2,3,4,5,6,7]);
  assert.equal(w.closed,false);assert.equal(w.pending.length,0);assert.ok(records.every(p=>p.timer._destroyed));
  assert.equal((await w.request({action:'health',marker:'later'})).marker,'later');
 }finally{await bounded(w.close());}
});
for(const mode of ['exit','stall','malformed']){
 test(`HTTP health and protected requests never succeed after worker ${mode}`,async()=>{
  const w=fault(mode);const s=await start(w);
  try{
   const requests=['/health','/healthz','/mcp'].map(path=>fetch(s.url+path,path==='/mcp'?{method:'POST',headers:{authorization:'Bearer synthetic'}}:{}));
   const responses=await bounded(Promise.all(requests));assert.deepEqual(responses.map(r=>r.status),[503,503,503]);
   for(const r of responses){const text=await r.text();assert.ok(!text.includes('synthetic'));}
   assert.equal((await fetch(s.url+'/health')).status,503);
  }finally{await bounded(s.close());}
 });
}
test('shutdown immediately settles requests and reaps SIGTERM-ignoring child',async()=>{
 const w=fault('shutdown',10000);const s=await start(w);
 const pending=w.request({action:'health'});
 const inflight=fetch(s.url+'/health').then(r=>r.status,()=>503);
 await bounded((async()=>{while(w.pending.length<2)await new Promise(r=>setTimeout(r,5));})());
 const records=[...w.pending];
 const close=s.close();assert.equal(close,s.close());
 await bounded(close,2000);assert.deepEqual(await pending,{status:503});assert.equal(await inflight,503);
 assert.equal(w.pending.length,0);assert.ok(records.every(p=>p.timer._destroyed));
 assert.ok(w.child.exitCode!==null || w.child.signalCode!==null);
});
test('spawn failure settles pending work without waiting for an exit event',async()=>{
 const child=spawn('/nonexistent-gptopia-synthetic-test-executable',[],{stdio:['pipe','pipe','ignore']});
 const w=new Worker(child);const result=w.request({action:'health'});
 assert.deepEqual(await bounded(result),{status:503});await bounded(w.close());assert.equal(w.pending.length,0);
});

for(const mode of ['worker','handler']) {
 test(`contradictory unavailable/success envelope denied by ${mode} layer`,async()=>{
  // Exercise IPC validation and, separately, the handler with a boundary
  // double bypassing IPC: neither layer may turn unavailable into success.
  const w=mode==='worker'?fault('contradictory'):{request:async m=>m.action==='authenticate'?{status:200,scopes:['world:discover']}:{status:503,result:{ok:true,result:{identities:[],protocol:'gptopia-kernel/0.2',limits:{content_bytes:8192,mutation_quota:100,objects_per_owner:10},operations:['discover']}}}};
  const s=await start(w);const c=new Client({name:'fault-client',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  try {
   await c.connect(new StreamableHTTPClientTransport(new URL(s.url+'/mcp'),{requestInit:{headers:{authorization:'Bearer synthetic'}}}));
   const result=await c.callTool({name:'world_discover',arguments:{space:'pilot'}});
   assert.equal(result.isError,true);assert.equal(result.structuredContent.ok,false);
   assert.equal(result.structuredContent.error.code,'unavailable');
   if(mode==='worker'){assert.equal(w.closed,true);assert.equal(w.pending.length,0);assert.equal((await fetch(s.url+'/health')).status,503);}
  }finally{await c.close();await bounded(s.close());}
 });
}

test('worker stderr logs fixed startup diagnostics and drops arbitrary output',async t=>{
 const logged=[];t.mock.method(console,'error',line=>logged.push(line));
 const script="process.stderr.write('SECRET_TOKEN\\nGPTOPIA_WORKER_STARTUP_ERROR:unknown-secret\\n'+ 'x'.repeat(1000)+'\\nGPTOPIA_WORKER_STARTUP_ERROR:admission_expiry_invalid\\n');";
 const w=new Worker(spawn(process.execPath,['-e',script],{stdio:['pipe','pipe','pipe']}));
 await bounded(w.exited);
 assert.deepEqual(logged,['GPTOPIA_WORKER_STARTUP_ERROR:admission_expiry_invalid']);
 await bounded(w.close());
});
