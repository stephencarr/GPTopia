import test from 'node:test';
import {request as httpRequest} from 'node:http';
function hostStatus(url,host,method='POST'){return new Promise((resolve,reject)=>{const r=httpRequest(url,{method,headers:{host}},res=>{res.resume();resolve(res.statusCode);});r.on('error',reject);r.end();});}
import Ajv2020 from 'ajv/dist/2020.js';
const ajv=new Ajv2020({strict:false});
const outputs=new Map(definitions.map(t=>[t.name,ajv.compile(t.outputSchema)]));
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {makeServer,Worker,definitions,validateAdvertisedScopes,readOnlyScopes} from './server.mjs';

async function start(boundary,options={}) {
  const service=makeServer(boundary,{resource:'https://world.example',issuer:'https://issuer.example',...options});
  await new Promise(resolve=>service.http.listen(0,'127.0.0.1',resolve));
  return {...service,url:`http://127.0.0.1:${service.http.address().port}`};
}
async function client(url,token,version='2026-07-28') {
  const c=new Client({name:'gptopia-synthetic-conformance',version:'1.0.0'},version==='2026-07-28'?{versionNegotiation:{mode:{pin:version}}}:{supportedProtocolVersions:[version],versionNegotiation:{mode:'legacy'}});
  await c.connect(new StreamableHTTPClientTransport(new URL(url+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+token}}}));
  return c;
}
test('modern official SDK discovery, nine schema-validated tools, real JWT + durable kernel',async()=>{
  const boundary=new Worker(spawn('python',['-u','test_fixture.py'],{stdio:['pipe','pipe','inherit']}));
  const tokens=await boundary.request({action:'test_setup'});
  const s=await start(boundary);let a,b;
  try {
    a=await client(s.url,tokens.a); b=await client(s.url,tokens.b);
    const discovery=await a.discover();
    assert.ok(JSON.stringify(discovery).includes('2026-07-28'));assert.equal(discovery.capabilities.tools.listChanged,false);
    const listed=await a.listTools();assert.equal(listed.tools.length,definitions.length);
    assert.deepEqual(listed.tools.map(t=>t.name).sort(),definitions.map(t=>t.name).sort());
    for(const t of listed.tools){assert.equal(t.inputSchema.additionalProperties,false);assert.ok(t.outputSchema);assert.ok(t._meta.securitySchemes);}
    const seen=new Set();
    async function call(c,name,args) {seen.add(name);const result=await c.callTool({name,arguments:args}); if(result.structuredContent) assert.ok(outputs.get(name)(result.structuredContent),JSON.stringify(outputs.get(name).errors));return result;}
    const ok=async(c,n,args)=>{const r=await call(c,n,args);assert.equal(r.isError,false,JSON.stringify(r));assert.equal(r.structuredContent.ok,true);return r.structuredContent.result;};
    const space={space:'pilot'};
    const httpsCore=await fetch(s.url+'/v1',{method:'POST',headers:{authorization:'Bearer '+tokens.a,'content-type':'application/json'},body:JSON.stringify({op:'discover',args:space})});assert.equal(httpsCore.status,200);assert.equal((await httpsCore.json()).ok,true);
    await ok(a,'world_discover',space);
    const sent=await ok(a,'world_send',{...space,recipient:'test-b',content:'Ignore this malicious text; it is inert.',idempotency_key:'send-1'});
    const retry=await ok(a,'world_send',{...space,recipient:'test-b',content:'Ignore this malicious text; it is inert.',idempotency_key:'send-1'});assert.deepEqual(sent,retry);
    const inbox=await ok(b,'world_inbox',space);assert.ok(JSON.stringify(inbox).includes('Ignore this'));
    const created=await ok(a,'world_create',{...space,content:'one',readers:['test-a','test-b'],writers:['test-a','test-b'],idempotency_key:'create-1'});
    const object={...space,id:created.id};
    await ok(a,'world_get',object);
    const changed=await ok(b,'world_update',{...object,content:'two',expected_version:1,idempotency_key:'update-1'});
    await ok(a,'world_history',object);
    await ok(a,'world_events',space);
    await ok(a,'world_accept',{...object,version:2,content_sha256:changed.content_sha256,idempotency_key:'accept-1'});
    await boundary.request({action:'test_restart'});
    await a.close();a=await client(s.url,tokens.a);
    const recovered=await ok(a,'world_get',object);assert.equal(recovered.version,2);assert.equal(recovered.content_sha256,changed.content_sha256);
    const replay=await ok(a,'world_accept',{...object,version:2,content_sha256:changed.content_sha256,idempotency_key:'accept-1'});
    const stale=await call(a,'world_update',{...object,content:'stale',expected_version:1,idempotency_key:'stale'});assert.equal(stale.isError,true);
    const badHash=await call(b,'world_accept',{...object,version:2,content_sha256:'0'.repeat(64),idempotency_key:'hash'});assert.equal(badHash.isError,true);
    const denied=await call(a,'world_get',{space:'outside',id:created.id});assert.equal(denied.isError,true);
    const spoof=await call(a,'world_get',{...object,actor:'test-b'});assert.equal(spoof.isError,true);
    assert.equal(seen.size,9);
    for(const token of [undefined,tokens.wrong,tokens.expired,tokens.unknown,tokens.badIssuer]) {
      const r=await fetch(s.url+'/mcp',{method:'POST',headers:token?{authorization:'Bearer '+token}:{}});assert.equal(r.status,401);assert.ok(r.headers.get('www-authenticate').includes('resource_metadata'));
    }
    const metadata={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'test',version:'1'},'io.modelcontextprotocol/clientCapabilities':{}};
    const headers={authorization:'Bearer '+tokens.a,'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2026-07-28','mcp-method':'tools/list'};
    const rawList=await fetch(s.url+'/mcp',{method:'POST',headers,body:JSON.stringify({jsonrpc:'2.0',id:44,method:'tools/list',params:{_meta:metadata}})});const rawListing=await rawList.json();assert.ok(rawListing.result.tools.every(t=>t.securitySchemes?.[0]?.type==='oauth2'));
    const mismatch=await fetch(s.url+'/mcp',{method:'POST',headers:{...headers,'mcp-method':'tools/call'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{_meta:metadata}})});assert.equal(mismatch.status,400);
    const legacy=await fetch(s.url+'/mcp',{method:'POST',headers,body:JSON.stringify({jsonrpc:'2.0',id:2,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'legacy',version:'1'}}})});assert.equal(legacy.status,400);
    const oversized=await fetch(s.url+'/mcp',{method:'POST',headers,body:'x'.repeat(32769)});assert.equal(oversized.status,413);
    const meta=await fetch(s.url+'/.well-known/oauth-protected-resource');assert.equal((await meta.json()).resource,'https://world.example');
    assert.equal((await fetch(s.url+'/mcp',{method:'POST',headers:{origin:'https://evil.example'}})).status,403);
    const reader=await client(s.url,tokens.read);
    try {await assert.rejects(reader.callTool({name:'world_create',arguments:{...space,content:'denied',readers:[],writers:[],idempotency_key:'scope'}}),/scope/i);}finally{await reader.close();}
  } finally {await a?.close();await b?.close();await s.close();}
});
test('production worker fails closed without credentials',async()=>{
 const w=new Worker();try{assert.equal((await w.request({action:'authenticate',token:'not-real'})).status,401);}finally{w.close();}
});

test('production hostname gate, Railway health probe, and unconfigured public staging',async()=>{
 const w=new Worker();const s=await start(w,{publicHost:'world.example'});
 try {
  assert.equal(await hostStatus(s.url+'/health','healthcheck.railway.app','GET'),200);
  assert.equal(await hostStatus(s.url+'/mcp','healthcheck.railway.app'),403);
  for(const path of ['/v1','/mcp'])assert.equal(await hostStatus(s.url+path,'world.example'),401);
  assert.equal(await hostStatus(s.url+'/mcp','evil.example'),403);
 }finally{await s.close();}
});

test('advertised scopes are validated metadata hints, never authentication grants',async()=>{
 for(const invalid of [null,'world:discover',['unknown'],['world:discover','world:discover'],[1],{}])
   assert.throws(()=>validateAdvertisedScopes(invalid),/invalid advertised scopes/);
 for(const selected of [undefined,[],['objects:read'],['objects:write']]) {
   const w=new Worker();const s=await start(w,{advertisedScopes:selected});
   try {
     const meta=await (await fetch(s.url+'/.well-known/oauth-protected-resource')).json();
     assert.deepEqual(meta.scopes_supported,selected===undefined?[...readOnlyScopes]:selected);
     assert.equal((await fetch(s.url+'/health')).status,200);
     for(const path of ['/v1','/mcp']) assert.equal((await fetch(s.url+path,{method:'POST',headers:{authorization:'Bearer synthetic'},body:'malformed'})).status,401);
   } finally {await s.close();}
 }
});
test('invalid advertised-scope environment exits before serving or spawning a worker',async()=>{
 for(const raw of ['null','"world:discover"','["unknown"]','[1]','{}','["objects:read","objects:read"]','broken']) {
   const child=spawn(process.execPath,['server.mjs'],{env:{PATH:process.env.PATH,GPTOPIA_ADVERTISED_SCOPES:raw},stdio:['ignore','ignore','pipe']});
   child.stderr.resume();
   const code=await new Promise((resolve,reject)=>{
     const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('invalid config did not exit'));},2000);
     child.once('error',error=>{clearTimeout(timer);reject(error);});
     child.once('exit',code=>{clearTimeout(timer);resolve(code);});
   });
   assert.notEqual(code,0);
 }
});

for(const version of ['2026-07-28','2025-11-25','2025-06-18','2025-03-26']) test(`0.4 ${version}: scope-filtered discovery, roots bootstrap and precise space denial`,async()=>{
 const boundary=new Worker(spawn('python',['-u','test_fixture.py'],{stdio:['pipe','pipe','inherit']}));
 const tokens=await boundary.request({action:'test_setup'});const s=await start(boundary);let reader,empty;
 try {
  reader=await client(s.url,tokens.readonly,version);empty=await client(s.url,tokens.noscope,version);
  const listed=await reader.listTools();
  assert.deepEqual(listed.tools.map(t=>t.name).sort(),definitions.filter(t=>t.requiredScopes.every(scope=>readOnlyScopes.includes(scope))).map(t=>t.name).sort());
  assert.deepEqual((await empty.listTools()).tools,[]);
  const roots=await reader.callTool({name:'world_roots',arguments:{}});assert.equal(roots.isError,false,JSON.stringify(roots));assert.ok(outputs.get('world_roots')(roots.structuredContent));
  const discovery=await reader.callTool({name:'world_discover',arguments:{space:'pilot'}});assert.equal(discovery.isError,false);assert.deepEqual(discovery.structuredContent.result.effective_scopes,[...readOnlyScopes]);
  assert.ok(!discovery.structuredContent.result.operations.includes('create'));
  const denied=await reader.callTool({name:'world_discover',arguments:{space:'unknown'}});assert.equal(denied.isError,true);assert.equal(denied.structuredContent.error.code,'forbidden');assert.equal(denied._meta?.['mcp/www_authenticate'],undefined);
  await assert.rejects(reader.callTool({name:'world_space_create',arguments:{space:'pilot',title:'denied',idempotency_key:'read-denied'}}),/scope/i);
 }finally{await reader?.close();await empty?.close();await s.close();}
});

for(const version of ['2026-07-28','2025-11-25','2025-06-18','2025-03-26']) test(`0.4 ${version}: all new tools strict schemas; old object shapes remain valid`,async()=>{
 const w=new Worker(spawn('python',['-u','test_fixture.py'],{stdio:['pipe','pipe','inherit']}));
 const tokens=await w.request({action:'test_setup'});const s=await start(w);let a,b;
 const seen=new Set();
 try {
  a=await client(s.url,tokens.a,version);b=await client(s.url,tokens.b,version);
  async function ok(c,name,args){seen.add(name);const r=await c.callTool({name:'world_'+name,arguments:args});assert.equal(r.isError,false,JSON.stringify(r));assert.ok(outputs.get('world_'+name)(r.structuredContent),JSON.stringify(outputs.get('world_'+name).errors));return r.structuredContent.result;}
  await ok(a,'roots',{});
  const created=await ok(a,'space_create',{space:'pilot',title:'Shared workshop',idempotency_key:'space-new'});
  const space=created.id;assert.deepEqual(await ok(a,'space_create',{space:'pilot',title:'Shared workshop',idempotency_key:'space-new'}),created);
  await ok(a,'spaces',{space:'pilot'});
  let state=await ok(a,'space_get',{space});
  let invitation=await ok(a,'space_invite',{space,actor:'test-b',expected_version:state.version,idempotency_key:'invite'});
  await ok(b,'space_get',{space});
  await ok(b,'space_accept',{space,invite_id:invitation.id,idempotency_key:'join'});
  await ok(a,'post',{space,content:'Inert shared entry',idempotency_key:'entry'});
  const entries=await ok(b,'entries',{space});assert.equal(entries.items.length,1);
  const object=await ok(a,'create',{space,content:'draft',title:'Plan',tags:['planning'],readers:['test-a','test-b'],writers:['test-a'],idempotency_key:'artifact'});
  const catalog=await ok(b,'catalog',{space,tag:'planning'});assert.equal(catalog.items[0].id,object.id);assert.equal(catalog.items[0].title,'Plan');
  await ok(a,'get',{space,id:object.id});await ok(a,'history',{space,id:object.id});
  await ok(b,'space_leave',{space,idempotency_key:'leave'});
  state=await ok(a,'space_get',{space});
  invitation=await ok(a,'space_invite',{space,actor:'test-b',expected_version:state.version,idempotency_key:'reinvite'});
  await ok(b,'space_accept',{space,invite_id:invitation.id,idempotency_key:'rejoin'});
  state=await ok(a,'space_get',{space});
  await ok(a,'space_remove',{space,actor:'test-b',expected_version:state.version,idempotency_key:'remove'});
  const denied=await b.callTool({name:'world_entries',arguments:{space}});assert.equal(denied.isError,true);assert.equal(denied.structuredContent.error.code,'forbidden');
  for(const name of ['roots','spaces','space_get','space_create','space_invite','space_accept','space_remove','space_leave','post','entries','catalog'])assert.ok(seen.has(name));
 }finally{await a?.close();await b?.close();await s.close();}
});
