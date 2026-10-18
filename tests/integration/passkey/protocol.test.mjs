import test from 'node:test';
import assert from 'node:assert/strict';
import {loopbackOrigin,callbackURL,freshPasskey} from './protocol.mjs';

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
