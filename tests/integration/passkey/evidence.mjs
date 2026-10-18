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
export function receipt(checks,failed,teardown,source,stage){
 if(!/^[a-f0-9]{40}$/.test(source)||!stages.has(stage)||typeof failed!=='boolean'||typeof teardown!=='boolean'||
  Object.keys(checks).length!==checkIds.length||!checkIds.every(id=>typeof checks[id]==='boolean'))throw Error('evidence');
 const results=Object.fromEntries(checkIds.map(id=>[id,checks[id]]));
 return {schema:'baobab-passkey-browser-qualification/v1',result:!failed&&teardown&&Object.values(results).every(Boolean)?'PASS':'FAIL',
  source_commit:source,virtual_authenticator:true,physical_authenticator_qualified:false,critical_grant_accepted:false,
  checks:results,teardown,failure_stage:failed?stage:null};
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
