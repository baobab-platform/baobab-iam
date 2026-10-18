import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {checkIds,receipt,publish} from './evidence.mjs';
const checks=()=>Object.fromEntries(checkIds.map(id=>[id,true]));
const make=(cases=checks(),failed=false,teardown=true)=>receipt(cases,failed,teardown,'a'.repeat(40),'passkey');

test('failed, incomplete and uncertain-cleanup runs never qualify',()=>{
 assert.equal(make().result,'PASS');
 assert.equal(make(checks(),true).result,'FAIL');assert.equal(make(checks(),false,false).result,'FAIL');
 for(const id of checkIds){const c=checks();c[id]=false;assert.equal(make(c).result,'FAIL');delete c[id];assert.throws(()=>make(c));}
 assert.throws(()=>make({...checks(),token:'private'}));
});

test('only complete synchronized bundles become visible with a verified digest',async()=>{
 const dir=await fs.mkdtemp(path.join(tmpdir(),'passkey-evidence-'));
 try{
  await publish(dir,make());const entries=await fs.readdir(dir);assert.equal(entries.length,1);assert.match(entries[0],/^run-/);
  const bytes=await fs.readFile(path.join(dir,entries[0],'receipt.json'));
  const digest=await fs.readFile(path.join(dir,entries[0],'receipt.sha256'),'utf8');
  assert.equal(digest,createHash('sha256').update(bytes).digest('hex')+'  receipt.json\n');
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('digest-write failure cannot leave a published PASS behind',async()=>{
 const dir=await fs.mkdtemp(path.join(tmpdir(),'passkey-failure-'));
 try{
  const fault={...fs,open:async(file,...args)=>{if(file.endsWith('receipt.sha256'))throw Error('synthetic write fault');return fs.open(file,...args);}};
  await assert.rejects(publish(dir,make(),fault));
  assert.equal((await fs.readdir(dir)).filter(name=>name.startsWith('run-')).length,0);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('diagnostics reject arbitrary page, exception and secret-bearing content',async()=>{
 const {observation}=await import('./evidence.mjs');
 for(const [field,value] of [['form','private HTML'],['error','exception with code'],['claim','private claim'],['last_action','https://issuer.invalid/?code=private']]){
  assert.throws(()=>receipt(checks(),true,true,'a'.repeat(40),'registration',{...observation(),[field]:value}));
 }
 assert.throws(()=>receipt(checks(),true,true,'a'.repeat(40),'registration',{...observation(),token:'private'}));
});
