import test from 'node:test';
import assert from 'node:assert/strict';
import {loopbackOrigin,callbackURL,freshPasskey,begin,configuration,exchange,totp,totpSequence} from './protocol.mjs';
import * as oidc from 'openid-client';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';

// Protocol regression only: these synthetic signed responses are never
// acceptance evidence for a live provider or a browser WebAuthn ceremony.
test('OIDC exchange enforces requested freshness while allowing ordinary SSO without auth_time',async()=>{
 const {publicKey,privateKey}=await generateKeyPair('RS256');
 const jwk={...await exportJWK(publicKey),kid:'synthetic-key',alg:'RS256',use:'sig'};
 let issuer,nonce,authTime;
 const server=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json');
  if(req.url.endsWith('/.well-known/openid-configuration')){
   res.end(JSON.stringify({issuer,authorization_endpoint:issuer+'/auth',token_endpoint:issuer+'/token',
    jwks_uri:issuer+'/certs',code_challenge_methods_supported:['S256']}));
  }else if(req.url.endsWith('/certs'))res.end(JSON.stringify({keys:[jwk]}));
  else if(req.url.endsWith('/token')){
   const claims={sub:'synthetic-subject',nonce,acr:'1'};
   if(authTime!==undefined)claims.auth_time=authTime;
   const id_token=await new SignJWT(claims).setProtectedHeader({alg:'RS256',kid:jwk.kid})
    .setIssuer(issuer).setAudience('synthetic-client').setIssuedAt().setExpirationTime('60s').sign(privateKey);
   res.end(JSON.stringify({id_token,access_token:'synthetic-access-token',token_type:'Bearer',expires_in:60}));
  }else{res.statusCode=404;res.end('{}');}
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const origin='http://127.0.0.1:'+server.address().port;
 issuer=origin+'/realms/baobab';
 try{
  const protocol=await configuration(origin,'synthetic-client'),redirect='http://localhost:3003/passkey-qualification';
  for(const [fresh,age,accepted] of [[false,undefined,true],[true,undefined,false],[true,60,false],[true,0,true]]){
   const {transaction}=await begin(protocol.config,redirect,undefined,fresh);
   nonce=transaction.nonce;authTime=age===undefined?undefined:Math.floor(Date.now()/1000)-age;
   const result=exchange(protocol,redirect+'?'+new URLSearchParams({code:'synthetic-code',state:transaction.state}),transaction,redirect);
   if(accepted)assert.equal((await result).sub,'synthetic-subject');else await assert.rejects(result);
  }
 }finally{await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
});

test('successive ceremonies never reuse an OTP window or bypass a stalled clock',async()=>{
 let milliseconds=300001;const waits=[];
 const next=totpSequence({now:()=>milliseconds,wait:async ms=>{waits.push(ms);milliseconds+=ms;}});
 assert.equal(await next('synthetic-secret'),totp('synthetic-secret',300));
 assert.equal(await next('synthetic-secret'),totp('synthetic-secret',330));
 assert.deepEqual(waits,[29999]);
 const stalled=totpSequence({now:()=>300001,wait:async()=>{}});
 await stalled('synthetic-secret');await assert.rejects(stalled('synthetic-secret'));
});

test('qualification cannot target a live realm or non-loopback origin',()=>{
 assert.equal(loopbackOrigin('http://localhost:8080','ci'),'http://localhost:8080');
 for(const raw of ['https://iam.example.com','http://localhost:8080/path','http://user@localhost:8080',
  'http://localhost:8080?token=private','http://localhost:8080/#fragment','http://localhost:8080/'])
  assert.throws(()=>loopbackOrigin(raw,'ci'));
 assert.throws(()=>loopbackOrigin('http://localhost:8080','production'));
});

test('callback requires exact, bounded, single-use browser transaction',()=>{
 const redirect='http://localhost:3003/passkey-qualification';
 const transaction={state:'state',expires:100,used:false};
 assert.equal(callbackURL(redirect+'?code=opaque&state=state',transaction,redirect,50).searchParams.get('code'),'opaque');
 for(const suffix of ['?code=a&code=b&state=state','?code=a&state=state&state=state','?code=a&state=other',
  '?code=&state=state','?code=a&state=state&error=denied','?code=a&state=state#fragment'])
  assert.throws(()=>callbackURL(redirect+suffix,transaction,redirect,50));
 assert.throws(()=>callbackURL('http://foreign.invalid/callback?code=a&state=state',transaction,redirect,50));
 assert.throws(()=>callbackURL(redirect+'?code=a&state=state',{...transaction,used:true},redirect,50));
 assert.throws(()=>callbackURL(redirect+'?code=a&state=state',transaction,redirect,100));
});

test('enrollment, TOTP, stale and future authentication cannot become fresh passkey proof',()=>{
 assert.equal(freshPasskey({acr:'3',auth_time:100},100,100),true);
 for(const claims of [{acr:'1',auth_time:100},{acr:'2',auth_time:100},{acr:'gold',auth_time:100},
  {acr:'3'},{acr:'3',auth_time:101},{acr:'3',auth_time:0},{acr:'3',auth_time:1.5}])
  assert.equal(freshPasskey(claims,100,100),false);
 assert.equal(freshPasskey({acr:'3',auth_time:100},100,401),false);
});

// The provider uses acr_values to select a conditional LoA subflow. The OIDC
// claims parameter alone is not a substitute for this native requirement;
// acr_values alone is not an essential requirement and permits fallback.
test('passkey challenge requests Keycloak native raw LoA 3 and freshness',async()=>{
 const base='http://localhost:8080/realms/baobab';
 const config=new oidc.Configuration({issuer:base,
   authorization_endpoint:base+'/protocol/openid-connect/auth',
   token_endpoint:base+'/protocol/openid-connect/token',
   jwks_uri:base+'/protocol/openid-connect/certs'},'synthetic-client',{},oidc.None());
 oidc.allowInsecureRequests(config);
 const c=await begin(config,'http://localhost:3003/passkey-qualification',3,true);
 assert.equal(c.url.searchParams.get('acr_values'),'3');
 assert.equal(c.url.searchParams.get('max_age'),'0');
 assert.equal(c.url.searchParams.get('code_challenge_method'),'S256');
 assert.deepEqual(JSON.parse(c.url.searchParams.get('claims')),{id_token:{acr:{essential:true,values:['3']}}});
 assert.ok(c.transaction.verifier);
 assert.equal(c.transaction.fresh,true);
 const baseline=await begin(config,'http://localhost:3003/passkey-qualification');
 assert.equal(baseline.transaction.fresh,false);
 assert.equal(baseline.url.searchParams.has('max_age'),false);
});
