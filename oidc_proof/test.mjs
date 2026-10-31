import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {jwtVerify,createLocalJWKSet} from 'jose';
import {start,ephemeralKeys} from './server.mjs';

class Browser {
  cookies=new Map();
  async fetch(url,options={}){
    const response=await fetch(url,{...options,redirect:'manual',headers:{...options.headers,cookie:[...this.cookies].map(([k,v])=>`${k}=${v}`).join('; ')}});
    for(const value of response.headers.getSetCookie()){
      const [pair]=value.split(';');const i=pair.indexOf('=');const key=pair.slice(0,i),v=pair.slice(i+1);
      if(value.includes('Max-Age=0')||!v)this.cookies.delete(key);else this.cookies.set(key,v);
    }
    return response;
  }
}
async function form(url,data){const r=await fetch(url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)});const text=await r.text();return {status:r.status,body:text?JSON.parse(text):null};}
async function register(s,name){const r=await fetch(s.issuer+'/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:name,application_type:'native',redirect_uris:['http://127.0.0.1:9999/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:'openid offline_access world:discover messages:read'})});const body=await r.json();assert.equal(r.status,201,JSON.stringify(body));return body;}
async function code(s,c,{resource=s.resource,challenge=true,scope='openid offline_access world:discover messages:read'}={}){
  const verifier=randomBytes(32).toString('base64url');
  const params=new URLSearchParams({client_id:c.client_id,redirect_uri:c.redirect_uris[0],response_type:'code',scope,resource,state:'test-state',prompt:'consent'});
  if(challenge){params.set('code_challenge',createHash('sha256').update(verifier).digest('base64url'));params.set('code_challenge_method','S256');}
  const b=new Browser();let url=s.issuer+'/auth?'+params;
  for(let i=0;i<12;i++){
    if(url.startsWith(c.redirect_uris[0]))return {code:new URL(url).searchParams.get('code'),error:new URL(url).searchParams.get('error'),verifier};
    const interaction=new URL(url).pathname.startsWith('/interaction/');
    const r=await b.fetch(url,interaction?{method:'POST',headers:{'x-test-owner':s.testOwnerSecret}}:{});
    const location=r.headers.get('location');
    assert.ok(location,`authorization HTTP ${r.status}: ${await r.text()}`);
    url=new URL(location,s.issuer).href;
  }
  throw Error('authorization loop exceeded');
}
async function tokens(s,c,options){const a=await code(s,c,options);assert.ok(a.code,a.error);const t=await form(s.issuer+'/token',{grant_type:'authorization_code',client_id:c.client_id,redirect_uri:c.redirect_uris[0],code:a.code,code_verifier:a.verifier});assert.equal(t.status,200,JSON.stringify(t.body));assert.ok(t.body.refresh_token);return t.body;}
async function world(s,token){const r=await fetch(s.resource,{headers:{authorization:'Bearer '+token}});return {status:r.status,body:r.status===200?await r.json():await r.text()};}

 test('real local provider OAuth/DCR/PKCE/resource/refresh/replay/revocation/persistence proof',async()=>{
  const temp=await mkdtemp(join(tmpdir(),'gptopia-oidc-proof-'));const path=join(temp,'test.sqlite');
  const jwks=await ephemeralKeys();const cookieKeys=[randomBytes(32).toString('hex')];
  let s;const cpu=process.cpuUsage();const started=performance.now();
  try{
    s=await start({dbPath:path,jwks,cookieKeys});
    const prm=await (await fetch(s.issuer+'/.well-known/oauth-protected-resource')).json();assert.equal(prm.resource,s.resource);assert.deepEqual(prm.authorization_servers,[s.issuer]);
    const meta=await (await fetch(s.issuer+'/.well-known/openid-configuration')).json();assert.equal(meta.issuer,s.issuer);assert.ok(meta.code_challenge_methods_supported.includes('S256'));assert.ok(meta.registration_endpoint);
    const deniedRegistration=await fetch(s.issuer+'/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({application_type:'native',redirect_uris:['https://evil.example/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code'],response_types:['code']})});assert.equal(deniedRegistration.status,400);
    const client=await register(s,'Synthetic shared host');const client2=await register(s,'Synthetic second host');assert.notEqual(client.client_id,client2.client_id);
    const first=await tokens(s,client);const second=await tokens(s,client);const third=await tokens(s,client2);
    const a=await world(s,first.access_token),b=await world(s,second.access_token),c=await world(s,third.access_token);
    assert.equal(a.status,200);assert.equal(b.status,200);assert.equal(c.status,200);
    assert.equal(a.body.owner,b.body.owner);assert.equal(a.body.client_id,b.body.client_id);assert.notEqual(a.body.actor,b.body.actor);assert.notEqual(a.body.grant_id,b.body.grant_id);
    const {payload}=await jwtVerify(first.access_token,createLocalJWKSet(s.publicKeys),{issuer:s.issuer,audience:s.resource});assert.equal(payload.sub,'synthetic-owner');assert.equal(payload.gptopia_grant_id,a.body.grant_id);
    await assert.rejects(jwtVerify(first.access_token,createLocalJWKSet(s.publicKeys),{issuer:s.issuer,audience:s.issuer+'/wrong'}));
    assert.equal((await code(s,client,{resource:s.issuer+'/wrong'})).error,'invalid_target');
    assert.ok((await code(s,client,{challenge:false})).error);
    const bad=await code(s,client);assert.equal((await form(s.issuer+'/token',{grant_type:'authorization_code',client_id:client.client_id,redirect_uri:client.redirect_uris[0],code:bad.code,code_verifier:randomBytes(32).toString('base64url')})).status,400);
    const rotate=await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:first.refresh_token});assert.equal(rotate.status,200,JSON.stringify(rotate.body));assert.notEqual(rotate.body.refresh_token,first.refresh_token);assert.deepEqual((await world(s,rotate.body.access_token)).body,a.body);
    const replay=await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:first.refresh_token});assert.equal(replay.status,400);assert.equal(replay.body.error,'invalid_grant');
    assert.equal((await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:rotate.body.refresh_token})).status,400);
    assert.equal((await world(s,rotate.body.access_token)).status,401);
    const restricted=await tokens(s,client,{scope:'openid offline_access messages:read'});assert.equal((await world(s,restricted.access_token)).status,401);
    assert.equal((await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client2.client_id,refresh_token:second.refresh_token})).status,400);
    await form(s.issuer+'/token/revocation',{client_id:client2.client_id,token:second.refresh_token});assert.equal((await world(s,second.access_token)).status,200);
    const racing=await tokens(s,client);const race=await Promise.all([0,1].map(()=>form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:racing.refresh_token})));
    assert.ok(race.filter(x=>x.status===200).length<=1);assert.ok(race.some(x=>x.status===400));
    for(const result of race.filter(x=>x.status===200))assert.equal((await world(s,result.body.access_token)).status,401);
    const port=s.port;await s.close();s=await start({dbPath:path,jwks,cookieKeys,port});
    assert.deepEqual((await world(s,second.access_token)).body,b.body);
    const restored=await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:second.refresh_token});assert.equal(restored.status,200,JSON.stringify(restored.body));assert.deepEqual((await world(s,restored.body.access_token)).body,b.body);
    const revoke=await form(s.issuer+'/token/revocation',{client_id:client2.client_id,token:third.refresh_token,token_type_hint:'refresh_token'});assert.equal(revoke.status,200);
    assert.equal((await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client2.client_id,refresh_token:third.refresh_token})).status,400);
    assert.equal((await world(s,third.access_token)).status,401);
    console.log('PROOF_METRICS '+JSON.stringify({rss_bytes:process.memoryUsage().rss,cpu_microseconds:process.cpuUsage(cpu),wall_ms:performance.now()-started,database_bytes:(await stat(path)).size,identities:'same synthetic owner; distinct explicit grants, not host attestation',restart:'provider recreated with same temporary storage and ephemeral keys'}));
  }finally{if(s)await s.close();await rm(temp,{recursive:true,force:true});}
});

test('proof actor storage has its own connection page ceiling and lifetime row cap',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'gptopia-oidc-cap-'));let s;
 try{const path=join(temp,'test.sqlite');s=await start({dbPath:path,jwks:await ephemeralKeys(),cookieKeys:[randomBytes(32).toString('hex')]});assert.equal(s.stats().actor_connection_max_bytes,32*1024*1024);
 const db=new DatabaseSync(path);try{for(let i=0;i<100;i++)db.prepare('INSERT INTO proof_agents VALUES(?,?,?,?)').run('g'+i,'owner','client','actor'+i);assert.throws(()=>db.prepare('INSERT INTO proof_agents VALUES(?,?,?,?)').run('overflow','owner','client','overflow'),/quota/);assert.equal(s.stats().actor_rows,100);}finally{db.close();}
 }finally{if(s)await s.close();await rm(temp,{recursive:true,force:true});}
});

test('expired access token renews using refresh without another owner interaction',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'gptopia-oidc-expiry-'));let s;
 try{s=await start({dbPath:join(temp,'test.sqlite'),jwks:await ephemeralKeys(),cookieKeys:[randomBytes(32).toString('hex')],accessTokenTTL:1});const client=await register(s,'Expiry test');const initial=await tokens(s,client);
 const before=await world(s,initial.access_token);assert.equal(before.status,200);await new Promise(r=>setTimeout(r,1500));assert.equal((await world(s,initial.access_token)).status,401);
 const fresh=await form(s.issuer+'/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:initial.refresh_token});assert.equal(fresh.status,200);assert.deepEqual((await world(s,fresh.body.access_token)).body,before.body);
 }finally{if(s)await s.close();await rm(temp,{recursive:true,force:true});}
});
