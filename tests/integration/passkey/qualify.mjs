/** Actual Keycloak + Chromium ceremonies with an ephemeral CTAP2 authenticator.
 * No imported private credential, modified realm policy, screenshot or trace.
 * Bootstrap users/clients exist only in the disposable loopback test realm.
 */
import {chromium} from 'playwright';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkIds,receipt,publish,observation} from './evidence.mjs';
import {loopbackOrigin, opaque, configuration, begin, exchange, freshPasskey, totp} from './protocol.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const checks=Object.fromEntries(checkIds.map(x=>[x,false]));
const diagnostic=observation();
let stage='configuration', teardown=false, failed=false;
const requireProof=(proof)=>{if(!proof)throw Error('proof');};

async function run(){
 const origin=loopbackOrigin(process.env.KC_URL??'http://localhost:8080',process.env.BAOBAB_ENVIRONMENT);
 const username=process.env.KEYCLOAK_ADMIN,password=process.env.KEYCLOAK_ADMIN_PASSWORD;
 delete process.env.KEYCLOAK_ADMIN;delete process.env.KEYCLOAK_ADMIN_PASSWORD;
 requireProof(username&&password);
 const issuer=origin+'/realms/baobab', redirectUri='http://localhost:3003/passkey-qualification';
 const clientId='passkey-qualification-'+opaque().slice(0,16), userName='passkey-'+opaque().slice(0,16);
 const userPassword=opaque();
 let userId,clientUuid,browser,context,page,authenticatorId,cdp,otpSecret,callback;
 let added=0,asserted=0,wrongRP=false;
 async function admin(endpoint,body,method='GET',absent=false){
  // Master credentials belong to this isolated fixture. Refresh through the
  // owning provider so long browser tests cannot strand cleanup on an expired
  // bearer. Neither credentials nor bearer responses are retained or logged.
  const response=await fetch(origin+'/realms/master/protocol/openid-connect/token',{method:'POST',redirect:'error',
   signal:AbortSignal.timeout(10000),body:new URLSearchParams({client_id:'admin-cli',grant_type:'password',username,password})});
  requireProof(response.ok);const token=await response.json();
  const r=await fetch(origin+'/admin/realms/baobab/'+endpoint,{method,redirect:'error',signal:AbortSignal.timeout(10000),
   headers:{Authorization:'Bearer '+token.access_token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
  if(absent){requireProof(r.status===404);return;}
  requireProof(r.ok);return r.status===204?undefined:await r.json();
 }
 async function create(endpoint,body){
  // Create returns 201 with an empty body. Get its independently queried exact
  // synthetic name below, rather than persisting a provider-selected URL.
  const tokenResponse=await fetch(origin+'/realms/master/protocol/openid-connect/token',{method:'POST',redirect:'error',
   signal:AbortSignal.timeout(10000),body:new URLSearchParams({client_id:'admin-cli',grant_type:'password',username,password})});
  requireProof(tokenResponse.ok);const token=await tokenResponse.json();
  const r=await fetch(origin+'/admin/realms/baobab/'+endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),
   headers:{Authorization:'Bearer '+token.access_token,'Content-Type':'application/json'},body:JSON.stringify(body)});
  requireProof(r.status===201);
  const location=new URL(r.headers.get('location'));
  const id=location.pathname.split('/').at(-1);
  requireProof(location.origin===origin&&location.pathname==='/admin/realms/baobab/'+endpoint+'/'+id&&/^[a-f0-9-]{36}$/.test(id));
  return id;
 }
 try{
  stage='synthetic_setup';diagnostic.phase='BOOTSTRAP';
  clientUuid=await create('clients',{clientId,enabled:true,protocol:'openid-connect',publicClient:true,standardFlowEnabled:true,
   directAccessGrantsEnabled:false,implicitFlowEnabled:false,serviceAccountsEnabled:false,fullScopeAllowed:false,
   defaultClientScopes:['acr'],optionalClientScopes:[],redirectUris:[redirectUri],
   attributes:{'pkce.code.challenge.method':'S256'}});
  const clients=await admin('clients?'+new URLSearchParams({clientId}));requireProof(clients.length===1);requireProof(clientUuid===clients[0].id);
  userId=await create('users',{username:userName,enabled:true,email:userName+'@example.invalid',emailVerified:true,
   firstName:'Synthetic',lastName:'Passkey',requiredActions:['CONFIGURE_TOTP','webauthn-register-passwordless'],
   credentials:[{type:'password',value:userPassword,temporary:false}]});
  const users=await admin('users?'+new URLSearchParams({username:userName,exact:'true'}));requireProof(users.length===1);requireProof(userId===users[0].id);
  const protocol=await configuration(origin,clientId);
  browser=await chromium.launch({headless:true});context=await browser.newContext({acceptDownloads:false});
  page=await context.newPage();page.setDefaultTimeout(15000);
  // Only the fixed issuer and synthetic callback are permitted browser origins.
  // Callback query/authorization codes stay in memory, with no callback server.
  await page.route('**/*',async route=>{
   const u=new URL(route.request().url());
   if(u.origin+u.pathname===redirectUri){callback=u.href;diagnostic.phase='CALLBACK';await route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Synthetic callback</title>'});}
   else if(u.origin===origin)await route.continue();else await route.abort();
  });
  page.on('dialog',dialog=>{void dialog.accept('Synthetic CI passkey').catch(()=>{});});
  cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
  ({authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',
   hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}}));
  // CDP events contain private credential material: retain counters/RP equality
  // only. Never query, serialize, clone or upload the credential objects.
  cdp.on('WebAuthn.credentialAdded',event=>{added++;wrongRP ||= event.credential.rpId!==new URL(origin).hostname;});
  cdp.on('WebAuthn.credentialAsserted',()=>{asserted++;});

  async function authorize(level,fresh=false){
   callback=undefined;diagnostic.phase='AUTH_BEGIN';const ceremony=await begin(protocol.config,redirectUri,level,fresh);
   diagnostic.phase='PAGE_GOTO';let response=await page.goto(ceremony.url.href,{waitUntil:'domcontentloaded'});diagnostic.last_status=response?.status()??0;
   async function navigate(action){[response]=await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded'}),action()]);diagnostic.last_status=response?.status()??0;}
   for(let step=0;step<12;step++){
    if(callback)return {ceremony,callback};
    // A provider error must be a real rendered 200/400 denial, not a network,
    // timeout, 500, unavailable browser or missing-authenticator environment.
    if(await page.locator('#kc-error-message, .alert-error, .pf-m-danger').count())
     return {denied:true,status:response?.status(),nativeACR:(await page.locator('body').innerText()).includes('Authentication requirements not fulfilled')};
    if(await page.locator('#username').isVisible().catch(()=>false)){
     diagnostic.phase='PAGE_LOGIN';diagnostic.last_action='USERNAME_PASSWORD';
     await page.locator('#username').fill(userName);await page.locator('#password').fill(userPassword);
     await navigate(()=>page.locator('#kc-login').click());continue;
    }
    if(await page.locator('#password').isVisible().catch(()=>false)){
     diagnostic.phase='PAGE_LOGIN';diagnostic.last_action='PASSWORD';
     await page.locator('#password').fill(userPassword);await navigate(()=>page.locator('#kc-login').click());continue;
    }
    if(await page.locator('#totpSecret').count()){ 
     diagnostic.phase='PAGE_TOTP';diagnostic.last_action='TOTP_SETUP';
     otpSecret=await page.locator('#totpSecret').inputValue();await page.locator('#totp').fill(totp(otpSecret));
     await page.locator('#userLabel').fill('Synthetic CI TOTP');await navigate(()=>page.locator('#saveTOTPBtn').click());continue;
    }
    if(await page.locator('#otp').isVisible().catch(()=>false)){
     diagnostic.phase='PAGE_TOTP';diagnostic.last_action='TOTP';
     requireProof(otpSecret);await page.locator('#otp').fill(totp(otpSecret));await navigate(()=>page.locator('#kc-login').click());continue;
    }
    if(await page.locator('#registerWebAuthn').isVisible().catch(()=>false)){
     diagnostic.phase='PAGE_REGISTER';diagnostic.last_action='PASSKEY_REGISTER';
     await navigate(()=>page.locator('#registerWebAuthn').click());continue;
    }
    if(await page.locator('#authenticateWebAuthnButton').isVisible().catch(()=>false)){
     diagnostic.phase='PAGE_PASSKEY';diagnostic.last_action='PASSKEY_AUTH';
     await navigate(()=>page.locator('#authenticateWebAuthnButton').click());continue;
    }
    throw Error('unsupported_page');
   }
   throw Error('ceremony_budget');
  }
  async function consume(result){diagnostic.phase='EXCHANGE';requireProof(result.callback);return exchange(protocol,result.callback,result.ceremony.transaction,redirectUri);}
  async function reset(){diagnostic.phase='RESET';await admin('users/'+userId+'/logout',undefined,'POST');await context.clearCookies();}

  stage='registration';const enrollment=await consume(await authorize());
  diagnostic.phase='PROOF';requireProof(added===1&&!wrongRP);checks.browser_registration=true;
  diagnostic.phase='PROOF';requireProof(String(enrollment.acr)!=='3');checks.enrollment_is_not_step_up=true;
  stage='ordinary_sso';const beforeSSO=asserted;const sso=await consume(await authorize());
  requireProof(String(sso.acr)!=='3'&&asserted===beforeSSO);checks.ordinary_sso_not_step_up=true;
  stage='totp';await reset();const beforeTOTP=asserted;const mfa=await consume(await authorize(2,true));
  requireProof(['2','gold'].includes(String(mfa.acr))&&asserted===beforeTOTP);checks.totp_not_passkey=true;
  stage='passkey';await reset();const started=Math.floor(Date.now()/1000),beforePasskey=asserted;
  const successful=await authorize(3,true),claims=await consume(successful);
  requireProof(asserted>beforePasskey&&freshPasskey(claims,started));checks.signed_fresh_passkey=true;
  stage='code_replay';
  const replay=await fetch(protocol.tokenEndpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),body:new URLSearchParams({
   grant_type:'authorization_code',client_id:clientId,code:new URL(successful.callback).searchParams.get('code'),
   redirect_uri:redirectUri,code_verifier:successful.ceremony.transaction.verifier})});
  requireProof(replay.status===400&&(await replay.json()).error==='invalid_grant');checks.code_replay_denied=true;
  for(const [name,override] of [['bad_signature_denied',{isBogusSignature:true}],['missing_uv_denied',{isBadUV:true}],['missing_presence_denied',{isBadUP:true}]]){
   stage=name;await reset();await cdp.send('WebAuthn.setResponseOverrideBits',{authenticatorId,...override});
   const before=asserted,result=await authorize(3,true);
   requireProof(asserted>before&&result.denied&&[200,400].includes(result.status)&&!callback);checks[name]=true;
   await cdp.send('WebAuthn.setResponseOverrideBits',{authenticatorId});
  }
  stage='credential_revocation';
  const credentials=await admin('users/'+userId+'/credentials');
  const passkeys=credentials.filter(c=>c.type==='webauthn-passwordless');requireProof(passkeys.length===1);
  await admin('users/'+userId+'/credentials/'+passkeys[0].id,undefined,'DELETE');await reset();
  const revoked=await authorize(3,true);
  requireProof(revoked.denied&&revoked.status===400&&revoked.nativeACR&&!callback);checks.revoked_credential_denied=true;
 }catch(error){
  diagnostic.registration_events=Math.min(99,added);diagnostic.assertion_events=Math.min(99,asserted);
  diagnostic.error=error.message?.includes('net::ERR_ABORTED')?'NAVIGATION_ABORTED':
   error.message?.includes('interrupted by another navigation')?'NAVIGATION_INTERRUPTED':
   error.message?.includes('Execution context was destroyed')?'DOCUMENT_CHANGED':
   error.message?.includes('Download is starting')?'DOWNLOAD':
   error.message?.includes('Target page, context or browser has been closed')?'PAGE_CLOSED':error.name==='TimeoutError'?'TIMEOUT':error.code==='ERR_JWT_CLAIM_VALIDATION_FAILED'?'CLAIM':
   ['ClientError','OperationProcessingError'].includes(error.name)?'OIDC':error.message==='proof'?'PROOF':error.message==='unsupported_page'?'UNSUPPORTED_PAGE':'OTHER';
  diagnostic.claim=['acr','auth_time','nonce','iss','aud','iat','exp'].includes(error.claim)?error.claim:'NONE';
  if(page)try{
   const current=new URL(page.url());diagnostic.location=current.origin===origin?'ISSUER':current.origin+current.pathname===redirectUri?'CALLBACK':'OTHER';
   diagnostic.form=await page.evaluate(()=>{
    const visible=s=>{const e=document.querySelector(s);return e&&e.getClientRects().length>0;};
    return document.querySelector('#kc-error-message, .alert-error, .pf-m-danger')?'ERROR':visible('#username')?'USERNAME_PASSWORD':
     visible('#password')?'PASSWORD':document.querySelector('#totpSecret')?'TOTP_SETUP':visible('#otp')?'TOTP':
     visible('#registerWebAuthn')?'PASSKEY_REGISTER':visible('#authenticateWebAuthnButton')?'PASSKEY_AUTH':'OTHER';
   });
  }catch{diagnostic.form='OTHER';}
  throw Error('qualification');
 }finally{
  diagnostic.registration_events=Math.min(99,added);diagnostic.assertion_events=Math.min(99,asserted);
  let cleaned=true;
  // Cleanup is independent: one failure must not skip the other resource.
  if(cdp&&authenticatorId)try{await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId});}catch{cleaned=false;}
  if(browser)try{await browser.close();}catch{cleaned=false;}
  if(userId)try{await admin('users/'+userId,undefined,'DELETE');await admin('users/'+userId,undefined,'GET',true);}catch{cleaned=false;}
  if(clientUuid)try{await admin('clients/'+clientUuid,undefined,'DELETE');await admin('clients/'+clientUuid,undefined,'GET',true);}catch{cleaned=false;}
  teardown=cleaned&&Boolean(userId&&clientUuid);
  if(!teardown)throw Error('cleanup');
 }
}
try{await run();}catch{failed=true;}
// Only fixed-vocabulary booleans and source provenance are retained. A failed,
// interrupted or incomplete case cannot produce PASS. No token/session data.
const result=receipt(checks,failed,teardown,execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),stage,diagnostic);
try{await publish(path.join(root,'tests/integration/.runtime/passkey-evidence'),result);}
catch{console.error('FAIL passkey evidence publication');process.exit(1);}
console.log(result.result+' passkey browser qualification; fixed evidence retained; no session details emitted');
if(result.result!=='PASS')process.exit(1);
