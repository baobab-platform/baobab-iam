/** Closed, sanitized receipts. Publication is atomic and the final fallible
 * operation, so a digest-write failure cannot leave a visible PASS receipt.
 */
import * as fs from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import path from 'node:path';
export const checkIds=Object.freeze(['browser_registration','enrollment_is_not_step_up','ordinary_sso_not_step_up',
 'totp_not_passkey','signed_fresh_passkey','code_replay_denied','bad_signature_denied',
 'missing_uv_denied','missing_presence_denied','revoked_credential_denied']);
const stages=new Set(['configuration','synthetic_setup','registration','ordinary_sso','totp','passkey','code_replay',
 'bad_signature_denied','missing_uv_denied','missing_presence_denied','credential_revocation']);
// Diagnostics are restricted to a closed vocabulary, never an exception, HTML,
// credential, URL, cookie or form body. Phase identifies the failing boundary.
export const observation=()=>({form:'NONE',location:'NONE',error:'NONE',claim:'NONE',phase:'NONE',last_action:'NONE',last_status:0,registration_events:0,assertion_events:0});
const forms=new Set(['NONE','USERNAME_PASSWORD','PASSWORD','TOTP_SETUP','TOTP','PASSKEY_REGISTER','PASSKEY_AUTH','ERROR','OTHER']);
const errors=new Set(['NONE','TIMEOUT','CLAIM','OIDC','PROOF','UNSUPPORTED_PAGE','OTHER']);
const claims=new Set(['NONE','acr','auth_time','nonce','iss','aud','iat','exp','OTHER']);
const phases=new Set(['NONE','BOOTSTRAP','AUTH_BEGIN','PAGE_GOTO','PAGE_LOGIN','PAGE_TOTP','PAGE_REGISTER','PAGE_PASSKEY','CALLBACK','EXCHANGE','PROOF','RESET']);
export function receipt(checks,failed,teardown,source,stage,diagnostic=observation()){
 if(!/^[a-f0-9]{40}$/.test(source)||!stages.has(stage)||typeof failed!=='boolean'||typeof teardown!=='boolean'||
  Object.keys(checks).length!==checkIds.length||!checkIds.every(id=>typeof checks[id]==='boolean'))throw Error('evidence');
 if(Object.keys(diagnostic).length!==9||!forms.has(diagnostic.form)||!forms.has(diagnostic.last_action)||
  !['NONE','ISSUER','CALLBACK','OTHER'].includes(diagnostic.location)||!errors.has(diagnostic.error)||!claims.has(diagnostic.claim)||!phases.has(diagnostic.phase)||
  !Number.isInteger(diagnostic.last_status)||diagnostic.last_status<0||diagnostic.last_status>599||
  !['registration_events','assertion_events'].every(k=>Number.isInteger(diagnostic[k])&&diagnostic[k]>=0&&diagnostic[k]<=99))throw Error('diagnostic');
 const results=Object.fromEntries(checkIds.map(id=>[id,checks[id]]));
 return {schema:'baobab-passkey-browser-qualification/v1',result:!failed&&teardown&&Object.values(results).every(Boolean)?'PASS':'FAIL',
  source_commit:source,virtual_authenticator:true,physical_authenticator_qualified:false,critical_grant_accepted:false,
  checks:results,teardown,failure_stage:failed?stage:null,observation:{...diagnostic}};
}
export async function publish(output,result,operations=fs){
 await operations.mkdir(output,{recursive:true,mode:0o700});
 const pending=await operations.mkdtemp(path.join(output,'.pending-'));
 const bytes=Buffer.from(JSON.stringify(result,null,2)+'\n');
 const synced=async(file,data)=>{const handle=await operations.open(file,'wx',0o600);try{await handle.writeFile(data);await handle.sync();}finally{await handle.close();}};
 await synced(path.join(pending,'receipt.json'),bytes);
 await synced(path.join(pending,'receipt.sha256'),createHash('sha256').update(bytes).digest('hex')+'  receipt.json\n');
 for(const directory of [pending,output]){const handle=await operations.open(directory,'r');try{await handle.sync();}finally{await handle.close();}}
 // No code that can fail is scheduled after this atomic visibility boundary.
 await operations.rename(pending,path.join(output,'run-'+randomUUID()));
}
