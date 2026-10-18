import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {startCallbackReceiver} from './callback.mjs';

test('real redirect reaches the exact loopback callback; other paths and methods cannot supply a code',async()=>{
 let callback;
 const receiver=await startCallbackReceiver(raw=>{callback=raw;});
 const issuer=createServer((request,response)=>{
  response.writeHead(302,{Location:receiver.redirectUri+'?code=synthetic-code&state=synthetic-state'});response.end();
 });
 issuer.listen(0,'127.0.0.1');await once(issuer,'listening');
 try{
  assert.equal((await fetch(receiver.redirectUri+'/wrong?code=wrong')).status,404);
  assert.equal((await fetch(receiver.redirectUri,{method:'POST'})).status,404);
  assert.equal(callback,undefined);
  const response=await fetch('http://127.0.0.1:'+issuer.address().port+'/authorize');
  assert.equal(response.status,200);assert.equal(response.headers.get('Cache-Control'),'no-store');
  assert.equal(new URL(callback).searchParams.get('code'),'synthetic-code');
  assert.equal(new URL(callback).searchParams.get('state'),'synthetic-state');
 }finally{
  await receiver.close();await new Promise(resolve=>issuer.close(resolve));
 }
 await assert.rejects(fetch(receiver.redirectUri));
});
