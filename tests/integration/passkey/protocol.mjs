/** Disposable browser qualification only; not a production relying party.
 * Keep protocol verification in maintained OIDC/JOSE libraries. No tokens,
 * credential private keys, form bodies, browser traces or exception text leave
 * memory. HTTP is accepted only on the exact loopback CI issuer.
 */
import {randomBytes, timingSafeEqual, createHmac} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import * as oidc from 'openid-client';
import {createRemoteJWKSet, customFetch, jwtVerify} from 'jose';

export const opaque = () => randomBytes(32).toString('base64url');
export function loopbackOrigin(raw, environment) {
  const u = new URL(raw);
  if (!['ci','test','local'].includes(environment) || !['localhost','127.0.0.1'].includes(u.hostname) ||
      !['http:','https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' ||
      u.search || u.hash || u.origin !== raw) throw Error('configuration');
  return u.origin;
}
const equal = (a,b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) &&
  timingSafeEqual(Buffer.from(a),Buffer.from(b));
export function callbackURL(raw, transaction, redirectUri, now = Date.now()) {
  const u = new URL(raw);
  if (!transaction || transaction.used || transaction.expires <= now || u.origin+u.pathname !== redirectUri || u.hash ||
      u.searchParams.getAll('code').length !== 1 || !u.searchParams.get('code') ||
      u.searchParams.getAll('state').length !== 1 || !equal(u.searchParams.get('state'),transaction.state) ||
      u.searchParams.has('error')) throw Error('callback');
  return u;
}
export async function configuration(origin, clientId) {
  const issuer = origin+'/realms/baobab';
  const response = await fetch(issuer+'/.well-known/openid-configuration',{redirect:'error',signal:AbortSignal.timeout(10000)});
  if (!response.ok) throw Error('discovery');
  const meta = await response.json();
  if (meta.issuer !== issuer || !meta.code_challenge_methods_supported?.includes('S256')) throw Error('discovery');
  for (const name of ['authorization_endpoint','token_endpoint','jwks_uri']) {
    const u = new URL(meta[name]);
    if (u.origin !== origin || u.username || u.password || u.hash) throw Error('discovery');
  }
  const config = new oidc.Configuration({issuer,authorization_endpoint:meta.authorization_endpoint,
    token_endpoint:meta.token_endpoint,jwks_uri:meta.jwks_uri},clientId,
    {id_token_signed_response_alg:'RS256'},oidc.None());
  if (origin.startsWith('http:')) oidc.allowInsecureRequests(config);
  oidc.enableNonRepudiationChecks(config);
  config.timeout = 10;
  const keys = createRemoteJWKSet(new URL(meta.jwks_uri),{[customFetch]: (url,init) => fetch(url,{...init,redirect:'error'})});
  return {config,keys,issuer,clientId,tokenEndpoint:meta.token_endpoint};
}
export async function begin(config, redirectUri, level, fresh = false) {
  const transaction = {state:opaque(),nonce:opaque(),verifier:oidc.randomPKCECodeVerifier(),expires:Date.now()+60000,used:false,fresh};
  const params = {scope:'openid',response_type:'code',redirect_uri:redirectUri,state:transaction.state,nonce:transaction.nonce,
    code_challenge:await oidc.calculatePKCECodeChallenge(transaction.verifier),code_challenge_method:'S256'};
  // Numeric acr_values is Keycloak's native LoA selector. A claims-only request
  // does not necessarily drive the conditional LoA-3 authenticator subflow.
  if (level) params.acr_values = String(level);
  if (fresh) params.max_age='0';
  return {transaction,url:oidc.buildAuthorizationUrl(config,params)};
}
export async function exchange(protocol, raw, transaction, redirectUri) {
  const callback = callbackURL(raw,transaction,redirectUri);
  transaction.used=true; // Uncertain exchange is never retried as a new proof.
  // OIDC makes auth_time conditional on the requested max_age. Retain that
  // request intent and give it to the maintained verifier; baseline SSO need
  // not emit auth_time, while every fresh step-up must prove it independently.
  const tokens = await oidc.authorizationCodeGrant(protocol.config,callback,{pkceCodeVerifier:transaction.verifier,
    expectedState:transaction.state,expectedNonce:transaction.nonce,idTokenExpected:true,...(transaction.fresh?{maxAge:0}:{})});
  const {payload} = await jwtVerify(tokens.id_token,protocol.keys,{issuer:protocol.issuer,audience:protocol.clientId,
    algorithms:['RS256'],requiredClaims:['iss','sub','aud','exp','iat','nonce','acr',...(transaction.fresh?['auth_time']:[])]});
  if (!equal(payload.nonce,transaction.nonce)) throw Error('nonce');
  return payload;
}
export function freshPasskey(claims, started, now = Math.floor(Date.now()/1000)) {
  return String(claims.acr)==='3' && Number.isSafeInteger(claims.auth_time) && claims.auth_time>=started-1 &&
    claims.auth_time<=now && now-claims.auth_time<=300;
}
export function totp(secret, seconds = Math.floor(Date.now()/1000)) {
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(seconds/30)));
  const digest=createHmac('sha1',Buffer.from(secret,'utf8')).update(counter).digest();
  return ((digest.readUInt32BE(digest[digest.length-1]&15)&0x7fffffff)%1000000).toString().padStart(6,'0');
}

// The fixture realm forbids OTP reuse. Each login, including a negative
// passkey ceremony, must advance past the last OTP window used for this user.
export function totpSequence({now=Date.now,wait=delay}={}) {
  let previous=-1;
  return async secret=>{
    let milliseconds=now(),window=Math.floor(milliseconds/30000);
    if(window<=previous){
      const remaining=(previous+1)*30000-milliseconds;
      if(remaining<1||remaining>30000)throw Error('otp_clock');
      await wait(remaining);
      milliseconds=now();window=Math.floor(milliseconds/30000);
      if(window<=previous)throw Error('otp_clock');
    }
    previous=window;
    return totp(secret,Math.floor(milliseconds/1000));
  };
}
