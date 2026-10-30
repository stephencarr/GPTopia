"""Optional schema parity check; requires already-installed jsonschema, not kernel runtime."""
import json,sys,tempfile,dataclasses
from pathlib import Path
from jsonschema import Draft202012Validator
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel import Kernel
from identity import fixture
root=Path(__file__).resolve().parent
core=json.loads((root/'api-contract.json').read_text());adapter=json.loads((root/'adapter-contract.json').read_text())
for c in [core,adapter]:Draft202012Validator.check_schema(c)
checks=[]
def check(doc, name, sample):
 Draft202012Validator({'$schema':doc['$schema'],'$ref':'#/$defs/'+name,'$defs':doc['$defs']}).validate(sample)
 checks.append(name)
with tempfile.TemporaryDirectory() as d:
 k=Kernel(Path(d)/'test.sqlite3',allow_fixture=True);k.initialize()
 def run(actor,op,args,key=None):
  request={'op':op,'args':args}
  if key:request['idempotency_key']=key
  check(core,op+'Request',request)
  tool_input=dict(args)
  if key:tool_input['idempotency_key']=key
  check(adapter,op+'Input',tool_input)
  response=k.request(actor,request)
  assert response['ok'],response
  check(core,op+'Response',response);check(adapter,op+'Output',response)
  return response['result']
 run('alice','discover',{'space':'plaza'})
 created=run('alice','create',{'space':'plaza','content':'one','readers':['alice','bob'],'writers':['alice','bob']},'create')
 oid=created['id']
 run('alice','get',{'space':'plaza','id':oid})
 for actor in ['alice','bob']:
  run(actor,'accept',{'space':'plaza','id':oid,'version':1,'content_sha256':created['content_sha256']},'accept1-'+actor)
 jointly=run('alice','get',{'space':'plaza','id':oid})
 assert jointly['acceptance']['test_multi_party_attested'] and not jointly['acceptance']['multi_party_attested']
 updated=run('bob','update',{'space':'plaza','id':oid,'content':'two','expected_version':1},'update')
 run('alice','accept',{'space':'plaza','id':oid,'version':2,'content_sha256':updated['content_sha256']},'accept2')
 run('alice','history',{'space':'plaza','id':oid})
 run('alice','send',{'space':'plaza','recipient':'bob','content':'hi'},'send')
 run('bob','inbox',{'space':'plaza'})
 run('alice','events',{'space':'plaza'})
 run('alice','roots',{})
 child=run('alice','space_create',{'space':'plaza','title':'Workshop'},'new-space')
 space=child['id']
 run('alice','spaces',{'space':'plaza'})
 state=run('alice','space_get',{'space':space})
 invite=run('alice','space_invite',{'space':space,'actor':'bob','expected_version':state['version']},'invite')
 run('bob','space_accept',{'space':space,'invite_id':invite['id']},'join')
 run('alice','post',{'space':space,'content':'Inert log entry'},'post')
 run('bob','entries',{'space':space})
 artifact=run('alice','create',{'space':space,'content':'plan','title':'Plan','tags':['plan'],'readers':['alice','bob'],'writers':['alice']},'plan')
 run('bob','catalog',{'space':space,'tag':'plan'})
 run('alice','get',{'space':space,'id':artifact['id']})
 run('alice','history',{'space':space,'id':artifact['id']})
 run('bob','space_leave',{'space':space},'leave')
 state=run('alice','space_get',{'space':space})
 invite=run('alice','space_invite',{'space':space,'actor':'bob','expected_version':state['version']},'invite-again')
 run('bob','space_accept',{'space':space,'invite_id':invite['id']},'join-again')
 state=run('alice','space_get',{'space':space})
 run('alice','space_remove',{'space':space,'actor':'bob','expected_version':state['version']},'remove')
 failure=k.request(dataclasses.replace(fixture('alice'),expires_at=0),{'op':'get','args':{'space':'plaza','id':oid}})
 assert failure['error']['code']=='unauthenticated'
 check(core,'getResponse',failure);check(adapter,'getOutput',failure)
print(f'PASS: {len(checks)} validations across actual requests, tool inputs and kernel response envelopes; all 20 operations, acceptance history, error401 payload, both schemas checked.')
