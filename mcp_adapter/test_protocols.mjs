// Synthetic protocol compatibility only: not the user's actual Muse or Pip.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {Worker,makeServer,protocolVersions,definitions} from './server.mjs';

async function setup(){
 const w=new Worker(spawn('python',['-u',fileURLToPath(new URL('./test_fixture.py',import.meta.url))],{stdio:['pipe','pipe','ignore']}));
 const tokens=await w.request({action:'test_setup'});
 const s=makeServer(w,{resource:'https://world.example',issuer:'https://issuer.example'});
 await new Promise(r=>s.http.listen(0,'127.0.0.1',r));
 return {...s,tokens,url:`http://127.0.0.1:${s.http.address().port}/mcp`};
}
async function rpcBody(response){
 const text=await response.text();
 if(!text)return null;
 if(response.headers.get('content-type')?.includes('text/event-stream')){
  const lines=text.split('\n').filter(l=>l.startsWith('data:'));
  return lines.map(l=>JSON.parse(l.slice(5))).find(m=>'result' in m || 'error' in m);
 }
 return JSON.parse(text);
}
async function legacyClient(s,version,token,record=[]){
 const client=new Client({name:'synthetic-legacy-client',version:'1'},{supportedProtocolVersions:[version],versionNegotiation:{mode:'legacy'}});
 const observedFetch=async(url,init)=>{
  const response=await fetch(url,{...init,redirect:'error'});
  assert.equal(response.headers.get('mcp-session-id'),null);
  if(init?.method==='POST'){
   const request=JSON.parse(init.body);
   assert.ok(new Headers(init.headers).get('authorization')?.startsWith('Bearer '));
   record.push({request,result:await rpcBody(response.clone()),status:response.status});
  }
  return response;
 };
 await client.connect(new StreamableHTTPClientTransport(new URL(s.url),{fetch:observedFetch,requestInit:{headers:{authorization:'Bearer '+token}}}));
 return client;
}
for(const version of protocolVersions.slice(1)){
 test(`official legacy client ${version}: exact negotiation, all nine tools and unchanged authorization`,async()=>{
  const s=await setup();const record=[];let a,b,reader;
  try {
   a=await legacyClient(s,version,s.tokens.a,record);b=await legacyClient(s,version,s.tokens.b);
   const init=record.find(r=>r.request.method==='initialize');assert.equal(init.result.result.protocolVersion,version);
   assert.ok(record.some(r=>r.request.method==='notifications/initialized' && r.status===202));
   const list=await a.listTools();assert.equal(list.tools.length,definitions.length);
   const seen=new Set();
   async function ok(c,name,args){seen.add(name);const r=await c.callTool({name,arguments:args});assert.equal(r.isError,false);assert.equal(r.structuredContent.ok,true);return r.structuredContent.result;}
   const space={space:'pilot'};
   await ok(a,'world_discover',space);
   const msg={...space,recipient:'test-b',content:'synthetic protocol probe',idempotency_key:'send'};
   const first=await ok(a,'world_send',msg);assert.deepEqual(await ok(a,'world_send',msg),first);
   await ok(b,'world_inbox',space);
   const created=await ok(a,'world_create',{...space,content:'one',readers:['test-a','test-b'],writers:['test-a','test-b'],idempotency_key:'create'});
   const object={...space,id:created.id};await ok(a,'world_get',object);
   const changed=await ok(b,'world_update',{...object,expected_version:1,content:'two',idempotency_key:'update'});
   await ok(a,'world_history',object);await ok(a,'world_events',space);
   await ok(a,'world_accept',{...object,version:2,content_sha256:changed.content_sha256,idempotency_key:'accept'});
   assert.equal(seen.size,9);
   for(const args of [{...object,actor:'test-b'},{...object,space:'outside'}])assert.equal((await a.callTool({name:'world_get',arguments:args})).isError,true);
   assert.equal((await a.callTool({name:'world_update',arguments:{...object,expected_version:1,content:'stale',idempotency_key:'stale'}})).isError,true);
   reader=await legacyClient(s,version,s.tokens.read);
   await assert.rejects(reader.callTool({name:'world_create',arguments:{...space,content:'denied',readers:[],writers:[],idempotency_key:'scope'}}),/scope/i);
   for(const token of [undefined,s.tokens.wrong,s.tokens.expired]){
    const r=await fetch(s.url,{method:'POST',headers:token?{authorization:'Bearer '+token}:{},body:'not-json'});assert.equal(r.status,401);
   }
  }finally{await a?.close();await b?.close();await reader?.close();await s.close();}
 });
}
test('raw Muse-shaped requests negotiate statelessly; unsupported versions cannot execute',async()=>{
 const s=await setup();let id=0;
 const post=async(body,version)=>fetch(s.url,{method:'POST',redirect:'error',headers:{authorization:'Bearer '+s.tokens.a,'content-type':'application/json',accept:'application/json, text/event-stream',...(version?{'mcp-protocol-version':version}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(5000)});
 try {
  for(const version of protocolVersions.slice(1)){
   const init=await post({jsonrpc:'2.0',id:++id,method:'initialize',params:{protocolVersion:version,capabilities:{},clientInfo:{name:'synthetic-muse-shape',version:'1'}}});
   assert.equal(init.status,200);assert.equal(init.headers.get('mcp-session-id'),null);assert.equal((await rpcBody(init)).result.protocolVersion,version);
   const notification=await post({jsonrpc:'2.0',method:'notifications/initialized'},version);assert.equal(notification.status,202);
   const listed=await post({jsonrpc:'2.0',id:++id,method:'tools/list'},version);assert.equal(listed.status,200);assert.equal((await rpcBody(listed)).result.tools.length,definitions.length);
   const called=await post({jsonrpc:'2.0',id:++id,method:'tools/call',params:{name:'world_discover',arguments:{space:'pilot'}}},version);
   const outcome=(await rpcBody(called)).result;assert.equal(outcome.isError,false);assert.equal(JSON.parse(outcome.content[0].text).ok,true);
  }
  // Legacy spec counter-offers a supported version; it does not adopt an
  // arbitrary initialization version or authorize calls under that version.
  const unknown=await post({jsonrpc:'2.0',id:++id,method:'initialize',params:{protocolVersion:'1900-01-01',capabilities:{},clientInfo:{name:'test',version:'1'}}});
  assert.equal((await rpcBody(unknown)).result.protocolVersion,'2025-11-25');
  for(const version of ['1900-01-01','2024-11-05','2024-10-07']){
   const rejected=await post({jsonrpc:'2.0',id:++id,method:'tools/call',params:{name:'world_discover',arguments:{space:'pilot'}}},version);
   assert.equal(rejected.status,400);assert.ok((await rpcBody(rejected)).error);
  }
  const noModernMeta=await post({jsonrpc:'2.0',id:++id,method:'tools/list'},'2026-07-28');assert.equal(noModernMeta.status,400);
  const mixed=await post({jsonrpc:'2.0',id:++id,method:'tools/list',params:{_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'test',version:'1'},'io.modelcontextprotocol/clientCapabilities':{}}}},'2025-11-25');assert.equal(mixed.status,400);
  const malformed=await post({jsonrpc:'2.0',id:++id,method:'initialize',params:{protocolVersion:23,capabilities:{},clientInfo:{name:'test',version:'1'}}});
  assert.ok((await rpcBody(malformed)).error);
  for(const method of ['GET','DELETE'])assert.equal((await fetch(s.url,{method,headers:{authorization:'Bearer '+s.tokens.a}})).status,405);
 }finally{await s.close();}
});
test('modern and legacy clients share durable state without sharing transport identity',async()=>{
 const s=await setup();let modern,legacy;
 try {
  modern=new Client({name:'synthetic-modern',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  await modern.connect(new StreamableHTTPClientTransport(new URL(s.url),{requestInit:{headers:{authorization:'Bearer '+s.tokens.a}}}));
  legacy=await legacyClient(s,'2025-11-25',s.tokens.b);
  assert.ok(JSON.stringify(await modern.discover()).includes('2026-07-28'));
  async function ok(c,name,args){const r=await c.callTool({name,arguments:args});assert.equal(r.isError,false);return r.structuredContent.result;}
  const created=await ok(modern,'world_create',{space:'pilot',content:'modern',readers:['test-a','test-b'],writers:['test-a','test-b'],idempotency_key:'mixed-create'});
  const object={space:'pilot',id:created.id};
  const updated=await ok(legacy,'world_update',{...object,expected_version:1,content:'legacy contribution',idempotency_key:'mixed-update'});
  for(const [c,key] of [[modern,'mixed-a'],[legacy,'mixed-b']])await ok(c,'world_accept',{...object,version:2,content_sha256:updated.content_sha256,idempotency_key:key});
  const got=await ok(modern,'world_get',object);assert.equal(got.content_sha256,updated.content_sha256);
  assert.deepEqual(got.acceptance.records.map(r=>r.actor).sort(),['test-a','test-b']);
  assert.equal(new Set(got.acceptance.records.map(r=>r.client_id)).size,2);
  // Scripted synthetic clients prove attribution plumbing, NOT independent agents.
 }finally{await modern?.close();await legacy?.close();await s.close();}
});
