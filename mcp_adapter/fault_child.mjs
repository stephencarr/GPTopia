// TEST ONLY: fixed synthetic subprocess modes, no tokens or external access.
import {createInterface} from 'node:readline';
const mode=process.argv[2];
if (mode==='stall' || mode==='shutdown') process.on('SIGTERM',()=>{});
const lines=createInterface({input:process.stdin});
lines.on('line',line=>{
 const m=JSON.parse(line);
 if(mode==='contradictory'){
  const response=m.action==='authenticate'?{status:200,scopes:['world:discover']}:{status:503,result:{ok:true,result:{identities:[],protocol:'gptopia-kernel/0.2',limits:{content_bytes:8192,mutation_quota:100,objects_per_owner:10},operations:['discover']}}};
  process.stdout.write(JSON.stringify({...response,id:m.id})+'\n');return;
 }
 if(mode==='exit'){process.exit(1);return;}
 if(mode==='stall' || mode==='shutdown')return;
 if(mode==='malformed'){process.stdout.write('not-json\n');return;}
 if(mode==='wrong-id'){process.stdout.write(JSON.stringify({id:'unrelated',status:200})+'\n');return;}
 if(mode==='bad-shape'){process.stdout.write(JSON.stringify({id:m.id,status:200,scopes:'not-an-array'})+'\n');return;}
 if(mode==='partial'){process.stdout.write('{"id":');process.stdout.end();return;}
 if(mode==='oversize'){process.stdout.write('x'.repeat(8*1024*1024+1));return;}
 if(mode==='echo')setTimeout(()=>process.stdout.write(JSON.stringify({id:m.id,status:200,marker:m.marker})+'\n'),100);
});
