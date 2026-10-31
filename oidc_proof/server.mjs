// LOCAL TEST HARNESS ONLY: synthetic owner consent, never a production login.
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Provider, errors } from 'oidc-provider';
import { exportJWK, generateKeyPair, createLocalJWKSet, jwtVerify } from 'jose';
import { createAdapter } from './adapter.mjs';

export async function ephemeralKeys() {
  const {privateKey}=await generateKeyPair('RS256',{extractable:true});
  return {keys:[{...await exportJWK(privateKey),kid:'test-only',use:'sig',alg:'RS256'}]};
}

export async function start({dbPath,jwks,cookieKeys,port=0,accessTokenTTL=120}) {
  if(!Number.isInteger(accessTokenTTL)||accessTokenTTL<1||accessTokenTTL>120)throw Error('bounded test token TTL required');
  if(!jwks||!cookieKeys)throw Error('ephemeral test keys must be supplied explicitly');
  const storage=createAdapter(dbPath);
  const db=new DatabaseSync(dbPath);
  const pageSize=Number(db.prepare('PRAGMA page_size').get().page_size);
  db.exec(`PRAGMA max_page_count=${Math.floor(32*1024*1024/pageSize)}; PRAGMA busy_timeout=5000;`);
  db.exec(`CREATE TABLE IF NOT EXISTS proof_agents(grant_id TEXT PRIMARY KEY, owner TEXT NOT NULL, client TEXT NOT NULL, actor TEXT UNIQUE NOT NULL)`);
  db.exec(`CREATE TRIGGER IF NOT EXISTS proof_actor_cap BEFORE INSERT ON proof_agents WHEN (SELECT count(*) FROM proof_agents)>=100 BEGIN SELECT RAISE(ABORT,'test actor quota'); END;`);
  const testOwnerSecret=randomBytes(32).toString('hex');
  let provider;
  const server=http.createServer(async(req,res)=>{
    res.setHeader('Connection','close');
    try {
      if(req.url.startsWith('/interaction/')){
        if(req.method!=='POST'||req.headers['x-test-owner']!==testOwnerSecret){res.writeHead(403);return res.end('synthetic owner gate');}
        const details=await provider.interactionDetails(req,res);
        if(details.prompt.name==='login')return provider.interactionFinished(req,res,{login:{accountId:'synthetic-owner'}},{mergeWithLastSubmission:false});
        if(details.prompt.name==='consent'){
          const grant=new provider.Grant({accountId:details.session.accountId,clientId:details.params.client_id});
          grant.addOIDCScope('openid offline_access world:discover messages:read');
          grant.addResourceScope(resource,'world:discover messages:read');
          const grantId=await grant.save();
          db.prepare('INSERT INTO proof_agents VALUES(?,?,?,?)').run(grantId,details.session.accountId,details.params.client_id,'agent_'+randomUUID());
          return provider.interactionFinished(req,res,{consent:{grantId}},{mergeWithLastSubmission:true});
        }
        res.writeHead(400);return res.end('unsupported test interaction');
      }
      if(req.url==='/.well-known/oauth-protected-resource'){
        res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({resource,authorization_servers:[issuer],scopes_supported:['world:discover','messages:read']}));
      }
      if(req.url==='/world'){
        try{
          const raw=req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
          const {payload}=await jwtVerify(raw,createLocalJWKSet(publicKeys),{issuer,audience:resource,algorithms:['RS256']});
          const grant=await provider.Grant.find(payload.gptopia_grant_id);
          const binding=db.prepare('SELECT * FROM proof_agents WHERE grant_id=?').get(payload.gptopia_grant_id);
          if(!grant||!binding||binding.owner!==payload.sub||binding.client!==payload.client_id||!String(payload.scope).split(' ').includes('world:discover'))throw Error('not admitted');
          res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({actor:binding.actor,owner:binding.owner,client_id:binding.client,grant_id:binding.grant_id}));
        }catch{res.writeHead(401,{'WWW-Authenticate':`Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource"`});return res.end('denied');}
      }
      return provider.callback()(req,res);
    }catch(err){res.writeHead(500);res.end('test harness failure');console.error(err.message);}
  });
  await new Promise(resolve=>server.listen(port,'127.0.0.1',resolve));
  const issuer=`http://127.0.0.1:${server.address().port}`;
  const resource=issuer+'/world';
  const publicKeys={keys:jwks.keys.map(({d,p,q,dp,dq,qi,...publicPart})=>publicPart)};
  provider=new Provider(issuer,{
    adapter:storage.Adapter,
    jwks,
    cookies:{keys:cookieKeys},
    clients:[],
    extraClientMetadata:{properties:['proof_policy'],validator:(_ctx,_key,_value,metadata)=>{
      if(metadata.token_endpoint_auth_method!=='none'||metadata.application_type!=='native'
        ||metadata.redirect_uris?.length!==1||metadata.redirect_uris[0]!=='http://127.0.0.1:9999/callback'
        ||metadata.grant_types?.some(x=>!['authorization_code','refresh_token'].includes(x)))
        throw new errors.InvalidClientMetadata('loopback proof registration policy');
    }},
    claims:{openid:['sub']},
    scopes:['openid','offline_access','world:discover','messages:read'],
    pkce:{required:()=>true},
    rotateRefreshToken:true,
    features:{devInteractions:{enabled:false},registration:{enabled:true},revocation:{enabled:true,allowedPolicy:(_ctx,client,token)=>client.clientId===token.clientId},
      resourceIndicators:{enabled:true,defaultResource:()=>resource,useGrantedResource:()=>true,
        getResourceServerInfo:(_ctx,indicator)=>{
          if(indicator!==resource)throw new errors.InvalidTarget();
          return {scope:'world:discover messages:read',audience:resource,accessTokenTTL,accessTokenFormat:'jwt'};
        }}},
    interactions:{url:(_ctx,interaction)=>`/interaction/${interaction.uid}`},
    findAccount:(_ctx,id)=>id==='synthetic-owner'?{accountId:id,claims:async()=>({sub:id})}:undefined,
    extraTokenClaims:(_ctx,token)=>({gptopia_grant_id:token.grantId}),
    ttl:{IdToken:120,Interaction:120,AccessToken:accessTokenTTL,AuthorizationCode:60,RefreshToken:600,Session:600,Grant:600},
  });
  return {issuer,resource,provider,testOwnerSecret,publicKeys,port:server.address().port,
    stats:()=>({memory:process.memoryUsage(),cpu:process.cpuUsage(),actor_rows:db.prepare('SELECT count(*) AS n FROM proof_agents').get().n,actor_connection_max_bytes:Number(db.prepare('PRAGMA max_page_count').get().max_page_count)*pageSize}),
    async close(){await new Promise(resolve=>server.close(resolve));db.close();storage.close();}};
}
