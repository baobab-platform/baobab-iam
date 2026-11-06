/** N06 real Kratos v26.2 browser/WebAuthn experiment, development only.
 * Pinned Ory Kratos renders the challenge; Chromium CTAP2 generates an
 * authentic ES256 assertion; Kratos (not the test) verifies credentials.
 * The disposable virtual authenticator DOES NOT prove hardware A4.
 * Never print tokens, codes, credential responses or private keys.
 */
import {chromium} from 'playwright';
import {randomBytes} from 'node:crypto';

const API = 'http://127.0.0.1:4433';
const ADMIN = 'http://127.0.0.1:4434';
const UI = 'http://127.0.0.1:4455';
const envOK = process.env.ORY_FOUNDATION === '1' &&
 process.env.GITHUB_ACTIONS === 'true' &&
 process.env.ORY_KRATOS_ADMIN_URL === ADMIN &&
 process.env.ORY_KRATOS_PUBLIC_URL === API;
if (!envOK) throw Error('N06 real-browser proof requires isolated original CI Ory Foundation');

const session = {browser:null, context:null, page:null, cdp:null, id:null};
const pass = (value, stage) => {if (!value) throw Error('N06_A3_HELD_' + stage);};
const nonce = () => randomBytes(24).toString('hex');
const privateEmail = 'a3-live-' + nonce() + '@baobab.invalid';
const privatePassword = 'Aa!9-' + nonce();
let identityID, added=0, asserted=0;
let qualificationPhase='INITIALIZING';

const timeout = AbortSignal.timeout(12000);
async function jsonRequest(url, method='GET', body) {
 const u = new URL(url);
 pass([API,ADMIN].includes(u.origin), 'ORIGIN');
 const r = await fetch(url, {method, redirect:'manual', signal:AbortSignal.timeout(12000),
  headers:{Accept:'application/json', ...(body===undefined?{}:{'Content-Type':'application/json'})},
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw = r.status===204?{}:await r.json().catch(()=>null);
 return {status:r.status, body:raw};
}
function nodes(flow) {
 pass(flow && flow.ui && Array.isArray(flow.ui.nodes), 'FLOW_NODES');
 return flow.ui.nodes.filter(x=>x && x.attributes && x.attributes.name);
}
function field(flow,name) {
 const x=nodes(flow).find(x=>x.attributes.name===name);
 return x && x.attributes.value;
}
function statusExact(r,expected,stage) {
 pass(r.status===expected,stage+'_HTTP_'+String(r.status));
 return r.body;
}
async function onPage(method, url, body) {
 return await session.page.evaluate(async ({url,method,body})=>{
  const r=await fetch(url,{method,credentials:'include',redirect:'manual',
   headers:{Accept:'application/json', ...(body===undefined?{}:{'Content-Type':'application/json'})},
   body:body===undefined?undefined:JSON.stringify(body)});
  let data=null;
  if (r.type!=='opaqueredirect') data=await r.json().catch(()=>null);
  return {status:r.status,body:data,redirect:r.type==='opaqueredirect'};
 }, {url,method,body});
}
async function browserFlow(kind,extra='') {
 await session.page.goto(API+'/self-service/'+kind+'/browser'+extra,{waitUntil:'domcontentloaded'});
 const u=new URL(session.page.url());
 pass(u.origin===UI && u.pathname==='/'+kind && /^[0-9a-f-]{36}$/.test(u.searchParams.get('flow')||''),kind+'_ORIGIN');
 const id=u.searchParams.get('flow');
 const r=await onPage('GET',API+'/self-service/'+kind+'/flows?id='+encodeURIComponent(id));
 statusExact(r,200,kind+'_READ');
 return {id,flow:r.body};
}
function decode(s) {
 return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
}
function encode(bytes) {
 return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function nativeCredential(operation, value, expectedRP) {
 // Run *only* in real Chromium secure loopback context, never node crypto.
 return await session.page.evaluate(async ({operation,value,expectedRP})=>{
  const options=JSON.parse(value);
  const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
  const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  if (!options.publicKey || !options.publicKey.challenge) throw Error('NO_NATIVE_CHALLENGE');
  const pk=options.publicKey;
  pk.challenge=decode(pk.challenge);
  if (operation==='create') {
    if (!pk.user || !pk.user.id || (pk.rp && pk.rp.id!==expectedRP)) throw Error('WRONG_RP_OR_USER');
    pk.user.id=decode(pk.user.id);
    if (pk.excludeCredentials) pk.excludeCredentials=pk.excludeCredentials.map(c=>({...c,id:decode(c.id)}));
    const c=await navigator.credentials.create(options);
    return {id:c.id,rawId:encode(c.rawId),type:c.type,
     response:{attestationObject:encode(c.response.attestationObject),clientDataJSON:encode(c.response.clientDataJSON)}};
  }
  if (pk.rpId && pk.rpId!==expectedRP) throw Error('WRONG_RP');
  if (pk.allowCredentials) pk.allowCredentials=pk.allowCredentials.map(c=>({...c,id:decode(c.id)}));
  const c=await navigator.credentials.get(options);
  return {id:c.id,rawId:encode(c.rawId),type:c.type,
   response:{authenticatorData:encode(c.response.authenticatorData),
     clientDataJSON:encode(c.response.clientDataJSON),signature:encode(c.response.signature),
     userHandle:c.response.userHandle?encode(c.response.userHandle):''}};
 }, {operation,value,expectedRP});
}
async function kratosIdentity() {
 const flow=statusExact(await jsonRequest(API+'/self-service/registration/api'),200,'REG_FLOW');
 pass(/^[0-9a-f-]{36}$/.test(flow.id),'REG_ID');
 const data=statusExact(await jsonRequest(API+'/self-service/registration?flow='+flow.id,'POST',
  {method:'password', password:privatePassword,traits:{email:privateEmail}}),200,'REG_CREATE');
 pass(data.identity?.id && data.session_token, 'REG_NATIVE_SESSION');
 identityID=data.identity.id;
}
async function getIdentity() {
 const data=statusExact(await jsonRequest(ADMIN+'/admin/identities/'+encodeURIComponent(identityID)),200,'CURRENT_IDENTITY');
 pass(data.id===identityID, 'SUBJECT_MISMATCH');
 return data;
}
async function browserLoginPassword() {
 const {id,flow}=await browserFlow('login');
 const csrf=field(flow,'csrf_token');
 pass(typeof csrf==='string' && csrf.length>20,'PASSWORD_CSRF');
 const result=await onPage('POST',API+'/self-service/login?flow='+id,
  {method:'password',identifier:privateEmail,password:privatePassword,csrf_token:csrf});
 pass(result.status===200 || result.redirect,'PASSWORD_LOGIN_'+result.status);
 const whoami=await onPage('GET',API+'/sessions/whoami');
 statusExact(whoami,200,'BROWSER_SESSION');
 pass(whoami.body.identity?.id===identityID,'BROWSER_SESSION_SUBJECT');
}
async function registerWebAuthn() {
 const {id,flow}=await browserFlow('settings');
 const challenge=field(flow,'webauthn_register_trigger');
 const csrf=field(flow,'csrf_token');
 pass(typeof challenge==='string' && challenge.startsWith('{') && typeof csrf==='string','SETTINGS_RP_CHALLENGE');
 const credential=await nativeCredential('create',challenge,'127.0.0.1');
 pass(typeof credential.id==='string' && credential.id.length>=16 && added>=1,'CHROMIUM_CREDENTIAL');
 const response=await onPage('POST',API+'/self-service/settings?flow='+id,
  {method:'webauthn',webauthn_register:JSON.stringify(credential),
   webauthn_register_displayname:'disposable-ci-ctap2',csrf_token:csrf});
 pass(response.status===200 || response.redirect, 'REGISTRATION_COMMIT_'+response.status);
 const after=await getIdentity();
 const configured=after.credentials?.webauthn?.config?.credentials;
 pass(Array.isArray(configured) && configured.length===1,'REGISTERED_PROVIDER_KEY_READBACK');
}
async function loginSecondFactor() {
 const {id,flow}=await browserFlow('login','?aal=aal2');
 const challenge=field(flow,'webauthn_login_trigger');
 const csrf=field(flow,'csrf_token');
 pass(typeof challenge==='string' && challenge.startsWith('{') && typeof csrf==='string','AAL2_CHALLENGE');
 const credential=await nativeCredential('get',challenge,'127.0.0.1');
 pass(credential.type==='public-key' && asserted>=1,'REAL_CREDENTIAL_ASSERTION');
 const success=await onPage('POST',API+'/self-service/login?flow='+id,
  {method:'webauthn',webauthn_login:JSON.stringify(credential),csrf_token:csrf});
 pass(success.status===200 || success.redirect,'AAL2_COMMIT_'+success.status);
 const active=statusExact(await onPage('GET',API+'/sessions/whoami'),200,'AAL2_SESSION');
 pass(active.identity?.id===identityID &&
  active.authenticator_assurance_level==='aal2' &&
  Array.isArray(active.authentication_methods) &&
  active.authentication_methods.some(x=>x.method==='webauthn'),'ACTUAL_AAL2_METHOD_READBACK');
 // Replaying the original assertion on the already-consumed server flow must
 // never produce a new authoritative Kratos successful login response.
 const replay=await onPage('POST',API+'/self-service/login?flow='+id,
  {method:'webauthn',webauthn_login:JSON.stringify(credential),csrf_token:csrf});
 pass(replay.status!==200,'REPLAY_REJECTED');
}
async function run() {
 try {
  qualificationPhase='KRATOS_NATIVE_IDENTITY';
  await kratosIdentity();
  qualificationPhase='CHROMIUM_LAUNCH';
  session.browser=await chromium.launch({headless:true});
  session.context=await session.browser.newContext({acceptDownloads:false});
  session.page=await session.context.newPage();
  session.page.setDefaultTimeout(18000);
  await session.page.route(UI+'/**', route=>route.fulfill({status:200,contentType:'text/html',
   body:'<!doctype html><html><meta charset="utf-8"><body>Disposable IAM WebAuthn browser</body></html>'}));
  session.page.on('dialog',dialog=>void dialog.dismiss().catch(()=>{}));
  qualificationPhase='CHROMIUM_AUTHENTICATOR';
  session.cdp=await session.context.newCDPSession(session.page);
  await session.cdp.send('WebAuthn.enable');
  const response=await session.cdp.send('WebAuthn.addVirtualAuthenticator',
   {options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,
    isUserVerified:true,automaticPresenceSimulation:true}});
  session.id=response.authenticatorId;
  session.cdp.on('WebAuthn.credentialAdded',({credential})=>{
   if(credential?.rpId==='127.0.0.1') added++;
  });
  session.cdp.on('WebAuthn.credentialAsserted',()=>{asserted++});
  qualificationPhase='KRATOS_BROWSER_LOGIN';
  await browserLoginPassword();
  qualificationPhase='KRATOS_PASSKEY_REGISTRATION';
  await registerWebAuthn();
  qualificationPhase='KRATOS_AAL2_ASSERTION';
  await loginSecondFactor();
  process.stdout.write('N06_KRATOS_CHROMIUM_CTAP2_A3_CEREMONY_AND_REPLAY_PASS_NOT_A4\n');
 } finally {
  // Preserve the failing protocol stage through mandatory cleanup;
  // cleanup must not conceal a real Kratos/Chromium qualification failure.
  if (session.cdp && session.id) {
   await session.cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:session.id}).catch(()=>{});
  }
  await session.browser?.close().catch(()=>{});
  if (identityID) {
   const r=await jsonRequest(ADMIN+'/admin/identities/'+encodeURIComponent(identityID),'DELETE').catch(()=>null);
   if (r?.status!==204) throw Error('N06_A3_DISPOSABLE_IDENTITY_TEARDOWN_UNVERIFIED');
  }
 }
}
await run().catch(error => {
 // Only bounded machine-readable gate labels may enter workflow logs.
 // Do not print native flow bodies, credentials, tokens or exception stacks.
 const message = String(error?.message ?? '');
 const safe = /^N06_A3_HELD_[A-Z0-9_]{1,96}$/.test(message)
  ? message : 'N06_A3_HELD_' + qualificationPhase + '_UNCLASSIFIED';
 process.stderr.write(safe + '\n');
 process.exitCode = 2;
});
