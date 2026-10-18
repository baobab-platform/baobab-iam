// C4-03C: real Kratos session / governed Hydra authorization-code journey.
// The pre-enrolled user and registered OAuth client are fixture-only. No new
// human identity, client, grant or canonical membership is minted here.
package main

import (
 "context"
 "crypto/tls"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/baobab-platform/baobab-iam/internal/federation"
 "github.com/baobab-platform/baobab-iam/internal/humanauth"
 "github.com/baobab-platform/baobab-iam/internal/provider"
 "github.com/baobab-platform/baobab-iam/internal/provider/ory"
 "github.com/coreos/go-oidc/v3/oidc"
)

// The browser receives a Location but the qualifier does NOT visit login or
// consent frontend URLs. Only the pinned Hydra issuer may be contacted.
func oauthRedirect(ctx context.Context,client *http.Client,issuer,raw string)(*url.URL,error){
 target,e:=url.Parse(raw);if e!=nil{return nil,errors.New("invalid OAuth URL")}
 origin,e:=url.Parse(issuer);if e!=nil||target.Scheme!=origin.Scheme||target.Host!=origin.Host||target.User!=nil{return nil,errors.New("unapproved OAuth request")}
 req,e:=http.NewRequestWithContext(ctx,"GET",target.String(),nil);if e!=nil{return nil,errors.New("invalid OAuth request")}
 resp,e:=client.Do(req);if e!=nil{return nil,errors.New("Hydra authorization unavailable")}
 defer resp.Body.Close()
 if resp.StatusCode!=302&&resp.StatusCode!=303{return nil,errors.New("Hydra did not redirect")}
 location,e:=resp.Location()
 if e!=nil||location.User!=nil||location.Fragment!=""{return nil,errors.New("invalid OAuth redirect")}
 return location,nil
}
func nativeCodeExchange(ctx context.Context,client *http.Client,c liveConfig,code,verifier string)(int,[]byte,error){
 values:=url.Values{"grant_type":{"authorization_code"},"client_id":{c.NativeClientID},
   "redirect_uri":{c.NativeCallback},"code":{code},"code_verifier":{verifier}}
 req,e:=http.NewRequestWithContext(ctx,"POST",strings.TrimRight(c.HydraIssuer,"/")+"/oauth2/token",strings.NewReader(values.Encode()))
 if e!=nil{return 0,nil,errors.New("invalid native code request")}
 req.Header.Set("Content-Type","application/x-www-form-urlencoded")
 resp,e:=client.Do(req);if e!=nil{return 0,nil,errors.New("native token provider unavailable")}
 defer resp.Body.Close()
 body,e:=io.ReadAll(io.LimitReader(resp.Body,65537))
 if e!=nil||len(body)>65536{return 0,nil,errors.New("native response too large")}
 return resp.StatusCode,body,nil
}
func qualifyNative(ctx context.Context,c liveConfig,client *http.Client,tlsConfig *tls.Config,ledgerDir string)(map[string]bool,error){
 checks:=map[string]bool{"kratos_synthetic_session_verified":false,"governed_login_consent":false,
  "signed_nonce_bound_oidc":false,"code_replay_denied":false,"synthetic_session_revoked":false}
 if os.Getenv("BAOBAB_C403_DISPOSABLE")!="1"{return checks,errors.New("disposable native fixture not approved")}
 session,e:=protectedToken(ctx,c.NativeSessionFile);if e!=nil{return checks,errors.New("synthetic native credential unavailable")}
 // Identity equality is a mandatory safeguard before the destructive revoke.
 status,_,body,e:=requestJSON(ctx,client,"GET",strings.TrimRight(c.KratosPublic,"/")+"/sessions/whoami","",nil)
 _=status;_=body;_=e // Kratos requires X-Session-Token; checked below with its own request.
 sessionRequest,e:=http.NewRequestWithContext(ctx,"GET",strings.TrimRight(c.KratosPublic,"/")+"/sessions/whoami",nil)
 if e!=nil{return checks,errors.New("Kratos whoami request invalid")}
 sessionRequest.Header.Set("X-Session-Token",session)
 reply,e:=client.Do(sessionRequest);if e!=nil{return checks,errors.New("Kratos whoami unreachable")}
 var identity struct{Active bool `json:"active"`;ExpiresAt time.Time `json:"expires_at"`;Identity struct{ID string `json:"id"`;State string `json:"state"`} `json:"identity"`}
 if reply.StatusCode!=200||json.NewDecoder(io.LimitReader(reply.Body,65536)).Decode(&identity)!=nil{
  reply.Body.Close();return checks,errors.New("Kratos session not verified")
 }
 reply.Body.Close()
 if !identity.Active||identity.Identity.ID!=c.NativeIdentityID||identity.Identity.State!="active"||!time.Now().Before(identity.ExpiresAt){
  return checks,errors.New("synthetic identity not proven")
 }
 checks["kratos_synthetic_session_verified"]=true
 if e=os.MkdirAll(ledgerDir,0700);e!=nil{return checks,errors.New("private challenge-fence storage unavailable")}
 ledger,e:=federation.OpenNativeChallengeLedger(filepath.Join(ledgerDir,"native-c4-03-fence.db"))
 if e!=nil{return checks,errors.New("native persistent challenge fence unavailable")}
 defer ledger.Close()
 service,stopService:=context.WithCancel(ctx);defer stopService()
 handoff,supervisor,e:=ory.StartNativeHumanRuntime(service,ory.NativeHumanConfig{
  KratosPublicURL:c.KratosPublic,HydraAdminURL:c.HydraAdmin,Issuer:c.HydraIssuer,
  Client:client,Now:time.Now,Fence:ledger},c.Human,c.NativeIssuer,tlsConfig)
 if e!=nil{return checks,errors.New("native CP composition denied")}
 defer func(){stopService();<-supervisor.Done()}()
 verifier,e:=randomOpaque();if e!=nil{return checks,errors.New("random source unavailable")}
 state,e:=randomOpaque();if e!=nil{return checks,errors.New("random source unavailable")}
 nonce,e:=randomOpaque();if e!=nil{return checks,errors.New("random source unavailable")}
 hash:=sha256.Sum256([]byte(verifier))
 challenge:=base64.RawURLEncoding.EncodeToString(hash[:])
 intent:=humanauth.Request{GrantType:"authorization_code",ClientID:c.NativeClientID,
  RedirectURI:c.NativeCallback,Scope:"openid",CodeChallenge:challenge,CodeChallengeMethod:"S256",
  State:state,Nonce:nonce}
 params:=url.Values{"response_type":{"code"},"client_id":{c.NativeClientID},
  "redirect_uri":{c.NativeCallback},"scope":{"openid"},"state":{state},"nonce":{nonce},
  "code_challenge":{challenge},"code_challenge_method":{"S256"}}
 redirect,e:=oauthRedirect(ctx,client,c.HydraIssuer,strings.TrimRight(c.HydraIssuer,"/")+"/oauth2/auth?"+params.Encode())
 if e!=nil||redirect.Query().Get("login_challenge")==""{return checks,errors.New("real Hydra login challenge unavailable")}
 credential:=ory.NativeSessionCredential{SessionToken:session}
 accepted,e:=handoff.AcceptLogin(ctx,redirect.Query().Get("login_challenge"),credential,intent)
 if e!=nil{return checks,errors.New("current CP native login denied")}
 redirect,e=oauthRedirect(ctx,client,c.HydraIssuer,accepted)
 if e!=nil||redirect.Query().Get("consent_challenge")==""{return checks,errors.New("real Hydra consent challenge unavailable")}
 accepted,e=handoff.AcceptConsent(ctx,redirect.Query().Get("consent_challenge"),credential,intent,true)
 if e!=nil{return checks,errors.New("current CP native consent denied")}
 redirect,e=oauthRedirect(ctx,client,c.HydraIssuer,accepted)
 callback,_:=url.Parse(c.NativeCallback)
 if e!=nil||redirect.Scheme!=callback.Scheme||redirect.Host!=callback.Host||redirect.Path!=callback.Path||
  redirect.Query().Get("state")!=state||redirect.Query().Get("code")==""{return checks,errors.New("native callback binding denied")}
 checks["governed_login_consent"]=true
 code:=redirect.Query().Get("code")
 status,raw,e:=nativeCodeExchange(ctx,client,c,code,verifier)
 if e!=nil||status!=200{return checks,errors.New("Hydra code exchange denied")}
 canonical,e:=humanauth.ProjectOAuthResponse(raw)
 if e!=nil||canonical.IDToken==""{return checks,errors.New("invalid canonical OIDC envelope")}
 verifierOIDC:=oidc.NewVerifier(c.HydraIssuer,
  oidc.NewRemoteKeySet(ctx,strings.TrimRight(c.HydraIssuer,"/")+"/.well-known/jwks.json"),
  &oidc.Config{ClientID:c.NativeClientID,SupportedSigningAlgs:[]string{"RS256"}})
 signed,e:=verifierOIDC.Verify(ctx,canonical.IDToken)
 if e!=nil||signed.Subject!=c.NativeIdentityID||signed.Nonce!=nonce{return checks,errors.New("invalid signed identity binding")}
 checks["signed_nonce_bound_oidc"]=true
 status,_,e=nativeCodeExchange(ctx,client,c,code,verifier)
 checks["code_replay_denied"]=e==nil&&(status==400||status==401)
 if !checks["code_replay_denied"]{return checks,errors.New("authorization code replay accepted")}
 // This operation revokes ONLY the exact synthetic identity attested above.
 // A real account MUST NEVER be supplied to this qualification environment.
 providerAdapter,e:=ory.NewAdapter(ory.Config{KratosAdminURL:c.KratosAdmin,
  HydraAdminURL:c.HydraAdmin,PublicIssuer:c.HydraIssuer,HTTPClient:client})
 if e!=nil{return checks,errors.New("Kratos revoker unavailable")}
 if e=providerAdapter.RevokeSessions(ctx,provider.ExternalSubject{Issuer:c.HydraIssuer,Subject:c.NativeIdentityID});e!=nil{
  return checks,errors.New("synthetic Kratos session revocation failed")
 }
 // The SAME session token, not an unrelated bad credential, must now deny.
 request,e:=http.NewRequestWithContext(ctx,"GET",strings.TrimRight(c.KratosPublic,"/")+"/sessions/whoami",nil)
 if e!=nil{return checks,errors.New("revocation verification invalid")}
 request.Header.Set("X-Session-Token",session)
 resp,e:=client.Do(request)
 if e!=nil{return checks,errors.New("Kratos revocation verification unavailable")}
 io.Copy(io.Discard,io.LimitReader(resp.Body,1024));resp.Body.Close()
 checks["synthetic_session_revoked"]=resp.StatusCode==401
 if !checks["synthetic_session_revoked"]{return checks,errors.New("previously active Kratos session remains valid")}
 return checks,nil
}
