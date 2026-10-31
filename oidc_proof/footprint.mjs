// Resource probe only: provider loaded beside synthetic 0.3 adapter, NOT auth integration.
import {spawn} from 'node:child_process';
import {mkdtemp,rm,readFile,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {start,ephemeralKeys} from './server.mjs';
import {Worker,makeServer} from '../mcp_adapter/server.mjs';
const temp=await mkdtemp(join(tmpdir(),'gptopia-oidc-footprint-'));
const child=spawn('python',['-u','test_fixture.py'],{cwd:new URL('../mcp_adapter/',import.meta.url),stdio:['pipe','pipe','ignore'],env:{PATH:process.env.PATH,TMPDIR:temp,PYTHONDONTWRITEBYTECODE:'1'}});
const worker=new Worker(child);let provider,service;let peak=0,samples=0;
async function sample(){try{const raw=await readFile(`/proc/${child.pid}/status`,'utf8');const rss=Number(raw.match(/^VmRSS:\s+(\d+)/m)[1])*1024;peak=Math.max(peak,process.memoryUsage().rss+rss);samples++;}catch{}}
const timer=setInterval(sample,10);const cpu=process.cpuUsage(),began=performance.now();
try{
  provider=await start({dbPath:join(temp,'provider.sqlite'),jwks:await ephemeralKeys(),cookieKeys:[randomBytes(32).toString('hex')]});
  service=makeServer(worker,{resource:'https://world.example',issuer:'https://issuer.example'});
  await new Promise(resolve=>service.http.listen(0,'127.0.0.1',resolve));
  const url=`http://127.0.0.1:${service.http.address().port}`;const tokens=await worker.request({action:'test_setup'});let n=0;
  async function call(op,args){const body={op,args};if(['send','create','update'].includes(op))body.idempotency_key=`probe-${++n}`;
    const r=await fetch(url+'/v1',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${tokens.a}`},body:JSON.stringify(body)});const out=await r.json();if(!out.ok)throw Error(JSON.stringify(out));return out.result;}
  for(let i=0;i<20;i++){await call('send',{space:'pilot',recipient:'test-b',content:'x'.repeat(8192)});await fetch(provider.issuer+'/.well-known/openid-configuration');}
  let object=await call('create',{space:'pilot',content:'x'.repeat(8192),readers:['test-a','test-b'],writers:['test-a','test-b']});
  for(let i=0;i<10;i++)object=await call('update',{space:'pilot',id:object.id,expected_version:object.version,content:String(i)+'x'.repeat(8191)});
  for(let i=0;i<3;i++){await Promise.all(Array.from({length:4},()=>call('get',{space:'pilot',id:object.id})));await new Promise(r=>setTimeout(r,50));}
  await sample();console.log(JSON.stringify({mode:'co-loaded provider and existing MCP Node modules plus synthetic Python worker; NOT integrated auth',peak_sampled_combined_rss_bytes:peak,samples,node_heap_limit_mib:96,node_cpu_microseconds:process.cpuUsage(cpu),wall_ms:performance.now()-began,provider_database_bytes:(await stat(join(temp,'provider.sqlite'))).size,limits:'10ms sample, initialization before sampling and brief peaks can be missed; not container/Railway measurement; provider discovery only alongside 31 kernel writes',synthetic:true},null,2));
}finally{clearInterval(timer);if(service)await service.close();else child.kill();if(provider)await provider.close();await rm(temp,{recursive:true,force:true});}
