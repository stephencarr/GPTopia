// Local synthetic runtime load probe, not a provider or independent-agent test.
import {spawn} from 'node:child_process';
import {Worker,makeServer} from './server.mjs';
const child=spawn('python',['-u','test_fixture.py'],{stdio:['pipe','pipe','ignore']});
const worker=new Worker(child);
const service=makeServer(worker,{resource:'https://world.example',issuer:'https://issuer.example'});
await new Promise(resolve=>service.http.listen(0,'127.0.0.1',resolve));
const url=`http://127.0.0.1:${service.http.address().port}`;
console.log(JSON.stringify({phase:'ready',node_pid:process.pid,worker_pid:child.pid}));
try {
  const tokens=await worker.request({action:'test_setup'}); let key=0;
  async function call(token,op,args){
    const body={op,args};if(['create','update','accept','space_create','space_invite','space_accept','post'].includes(op))body.idempotency_key=`probe-${++key}`;
    const r=await fetch(url+'/v1',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${token}`},body:JSON.stringify(body)});
    const result=await r.json();if(!r.ok||!result.ok)throw new Error(JSON.stringify({status:r.status,result}));return result.result;
  }
  const space=await call(tokens.a,'space_create',{space:'pilot',title:'Synthetic benchmark'});
  const invitation=await call(tokens.a,'space_invite',{space:space.id,actor:'test-b',expected_version:1});
  await call(tokens.b,'space_accept',{space:space.id,invite_id:invitation.id});
  for(let i=0;i<20;i++)await call(i%2?tokens.a:tokens.b,'post',{space:space.id,content:'x'.repeat(8192)});
  let object=await call(tokens.a,'create',{space:space.id,content:'x'.repeat(8192),title:'Benchmark artifact',tags:['probe'],readers:['test-a','test-b'],writers:['test-a','test-b']});
  for(let i=0;i<10;i++)object=await call(i%2?tokens.a:tokens.b,'update',{space:space.id,id:object.id,expected_version:object.version,content:String(i)+'x'.repeat(8191)});
  for(let batch=0;batch<3;batch++){
    await Promise.all(Array.from({length:4},()=>call(tokens.b,'entries',{space:space.id,limit:100})));
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  console.log(JSON.stringify({phase:'complete',synthetic:true,posts:20,revisions:11,concurrent_readers:4,read_calls:12,node_cpu:process.cpuUsage(),node_memory:process.memoryUsage()}));
} finally {await service.close();}
