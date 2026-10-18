// C4-03B/D: registered live Hydra issuance and CP resource qualification.
// This is NOT a provider bootstrap tool. All principals, grants, runtime
// bindings and audiences must be independently approved before invocation.
package main

import (
 "bytes"
 "context"
 "crypto"
 "crypto/rand"
 "crypto/rsa"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "math/big"
 "os"
 "net/http"
 "net/url"
 "strings"
 "time"

 "github.com/baobab-platform/baobab-iam/internal/federation"
 "github.com/baobab-platform/baobab-iam/internal/provider"
)

type liveTarget struct {
 ClientID string `json:"client_id"`
 SecretFile string `json:"client_secret_file"`
 TenantID string `json:"tenant_id"`
 OrganisationID string `json:"organisation_id"`
 CountryCode string `json:"country_code"`
}
type liveConfig struct {
 Workload federation.RuntimeComposition `json:"workload_runtime"`
 Human federation.RuntimeComposition `json:"human_runtime"`
 NativeIssuer federation.RuntimeComposition `json:"native_issuer_runtime"`
 HydraIssuer string `json:"hydra_issuer"`
 HydraAdmin string `json:"hydra_admin"`
 KratosPublic string `json:"kratos_public"`
 KratosAdmin string `json:"kratos_admin"`
 Primary liveTarget `json:"primary"`
 Foreign liveTarget `json:"foreign"`
 ResourceAudience string `json:"resource_audience"`
 ResourceScope string `json:"resource_scope"`
 ValidatorTokenFile string `json:"validator_token_file"`
 NativeSessionFile string `json:"native_session_file"`
 NativeIdentityID string `json:"native_identity_id"`
 NativeClientID string `json:"native_client_id"`
 NativeCallback string `json:"native_callback"`
}
type accessProof struct {
 raw string // bearer held in memory only; NEVER serialize this struct
 claims accessClaims
}
type accessClaims struct {
 Issuer string `json:"iss"`
 Subject string `json:"sub"`
 ClientID string `json:"client_id"`
 AuthorizedParty string `json:"azp"`
 ActorType string `json:"actor_type"`
 Audience []string
 Scope string `json:"scope"`
 IssuedAt int64 `json:"iat"`
 Expires int64 `json:"exp"`
}
func parseOrigin(s string) (*url.URL,error) {
 u,e:=url.Parse(s)
 if e!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!=""&&u.Path!="/"||u.ForceQuery {return nil,errors.New("verified HTTPS origin required")}
 return u,nil
}
func validLiveConfig(c liveConfig) bool {
 if _,e:=parseOrigin(c.HydraIssuer);e!=nil{return false}
 if _,e:=parseOrigin(c.HydraAdmin);e!=nil{return false}
 if _,e:=parseOrigin(c.KratosPublic);e!=nil{return false}
 if _,e:=parseOrigin(c.KratosAdmin);e!=nil{return false}
 if c.ResourceAudience==""||c.ResourceScope==""||strings.ContainsAny(c.ResourceAudience+c.ResourceScope," \n\r\t")||c.ValidatorTokenFile=="" {return false}
 if c.Primary.ClientID==""||c.Primary.SecretFile==""||c.Foreign.ClientID==""||c.Foreign.SecretFile==""||c.Primary.ClientID==c.Foreign.ClientID||c.Primary.TenantID==c.Foreign.TenantID{return false}
 for _,p:=range []liveTarget{c.Primary,c.Foreign} {
  if p.TenantID==""||p.OrganisationID==""||len(p.CountryCode)!=2||p.CountryCode[0]<'A'||p.CountryCode[0]>'Z'||p.CountryCode[1]<'A'||p.CountryCode[1]>'Z'{return false}
 }
 if c.NativeSessionFile==""||c.NativeIdentityID==""||c.NativeClientID==""||c.NativeCallback==""{return false}
 u,e:=url.Parse(c.NativeCallback)
 return e==nil&&u.Scheme=="https"&&u.Hostname()!=""&&u.User==nil&&u.Fragment==""&&u.RawQuery==""
}
func protectedToken(ctx context.Context,path string)(string,error) {
 return (federation.FileAuthorityTokens{Path:path}).Token(ctx)
}
func verifiedClient(caPath string)(*http.Client,*tls.Config,error) {
 tc:=&tls.Config{MinVersion:tls.VersionTLS12}
 if caPath!="" {
  pem,e:=readTrustRoots(caPath);if e!=nil{return nil,nil,e}
  roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(pem){return nil,nil,errors.New("invalid TLS trust roots")}
  tc.RootCAs=roots
 }
 return &http.Client{Timeout:10*time.Second,Transport:&http.Transport{TLSClientConfig:tc,Proxy:nil},
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},tc,nil
}
// Trust-root files are deployment-owned; no fallback to an empty trust bundle.
func readTrustRoots(path string)([]byte,error){
 info,e:=os.Lstat(path)
 if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0022!=0||info.Size()>1<<20{return nil,errors.New("unsafe trust-root file")}
 return os.ReadFile(path)
}
func requestJSON(ctx context.Context,client *http.Client,method,target,bearer string,body any)(int,http.Header,[]byte,error) {
 var input io.Reader
 if body!=nil {raw,e:=json.Marshal(body);if e!=nil{return 0,nil,nil,e};input=bytes.NewReader(raw)}
 req,e:=http.NewRequestWithContext(ctx,method,target,input);if e!=nil{return 0,nil,nil,e}
 req.Header.Set("Accept","application/json");req.Header.Set("Cache-Control","no-store")
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 if bearer!=""{req.Header.Set("Authorization","Bearer "+bearer)}
 resp,e:=client.Do(req);if e!=nil{return 0,nil,nil,errors.New("verified resource unavailable")}
 defer resp.Body.Close()
 raw,e:=io.ReadAll(io.LimitReader(resp.Body,65537));if e!=nil||len(raw)>65536{return 0,nil,nil,errors.New("bounded response required")}
 return resp.StatusCode,resp.Header,raw,nil
}
func issuedJWT(ctx context.Context,client *http.Client,c liveConfig,target liveTarget,audience,scope string)(accessProof,error) {
 var out accessProof
 secret,e:=protectedToken(ctx,target.SecretFile);if e!=nil{return out,errors.New("protected client secret unavailable")}
 form:=url.Values{"grant_type":{"client_credentials"},"client_id":{target.ClientID},"client_secret":{secret},"audience":{audience},"scope":{scope}}
 r,e:=http.NewRequestWithContext(ctx,"POST",strings.TrimRight(c.HydraIssuer,"/")+"/oauth2/token",strings.NewReader(form.Encode()))
 if e!=nil{return out,errors.New("invalid token request")}
 r.Header.Set("Content-Type","application/x-www-form-urlencoded")
 resp,e:=client.Do(r);if e!=nil{return out,errors.New("Hydra token transport failed")}
 defer resp.Body.Close()
 if resp.StatusCode!=200||!strings.HasPrefix(resp.Header.Get("Content-Type"),"application/json"){return out,errors.New("Hydra denied or non-JSON token response")}
 var token struct{ AccessToken string `json:"access_token"`; TokenType string `json:"token_type"`; ExpiresIn int `json:"expires_in"`; Scope string `json:"scope"` }
 if json.NewDecoder(io.LimitReader(resp.Body,65537)).Decode(&token)!=nil||token.AccessToken==""||!strings.EqualFold(token.TokenType,"bearer")||token.ExpiresIn<1||token.ExpiresIn>900||token.Scope!=scope{return out,errors.New("Hydra token profile invalid")}
 claims,e:=verifyHydraJWT(ctx,client,strings.TrimRight(c.HydraIssuer,"/"),token.AccessToken,target.ClientID,audience,scope)
 if e!=nil{return out,e}
 return accessProof{raw:token.AccessToken,claims:claims},nil
}
// Cryptographically verify the actual Hydra access token against its fixed,
// trusted issuer's JWKS. Neither kid nor any JWT URL chooses the remote host.
func verifyHydraJWT(ctx context.Context,client *http.Client,issuer,raw,expectedClient,audience,scope string)(accessClaims,error) {
 var out accessClaims
 parts:=strings.Split(raw,".");if len(parts)!=3{return out,errors.New("signed JWT required")}
 decode:=func(s string,v any)error{b,e:=base64.RawURLEncoding.DecodeString(s);if e!=nil{return e};return json.Unmarshal(b,v)}
 var head struct{Alg string `json:"alg"`; Kid string `json:"kid"`; Crit []string `json:"crit"`}
 if decode(parts[0],&head)!=nil||head.Alg!="RS256"||head.Kid==""||len(head.Crit)!=0{return out,errors.New("unsupported JWT header")}
 status,_,body,e:=requestJSON(ctx,client,"GET",issuer+"/.well-known/jwks.json","",nil)
 if e!=nil||status!=200{return out,errors.New("issuer signing keys unavailable")}
 var keys struct{Keys []struct{Kty string `json:"kty"`;Kid string `json:"kid"`;N string `json:"n"`;E string `json:"e"`} `json:"keys"`}
 if json.Unmarshal(body,&keys)!=nil||len(keys.Keys)>32{return out,errors.New("invalid issuer JWKS")}
 var public *rsa.PublicKey
 for _,k:=range keys.Keys{if k.Kid!=head.Kid{continue}
  if public!=nil||k.Kty!="RSA"{return out,errors.New("ambiguous signing key")}
  n,en:=base64.RawURLEncoding.DecodeString(k.N);ex,ee:=base64.RawURLEncoding.DecodeString(k.E)
  if en!=nil||ee!=nil||len(ex)<1||len(ex)>4{return out,errors.New("invalid public key")}
  exponent:=new(big.Int).SetBytes(ex).Int64()
  public=&rsa.PublicKey{N:new(big.Int).SetBytes(n),E:int(exponent)}
  if public.N.BitLen()<2048||exponent<3||exponent%2==0{return out,errors.New("weak signing key")}
 }
 if public==nil{return out,errors.New("signing key not found")}
 sig,e:=base64.RawURLEncoding.DecodeString(parts[2]);if e!=nil{return out,errors.New("invalid JWT signature encoding")}
 digest:=sha256.Sum256([]byte(parts[0]+"."+parts[1]))
 if rsa.VerifyPKCS1v15(public,crypto.SHA256,digest[:],sig)!=nil{return out,errors.New("invalid JWT signature")}
 var claims struct{Issuer string `json:"iss"`;Subject string `json:"sub"`;ClientID string `json:"client_id"`;AZP string `json:"azp"`;Actor string `json:"actor_type"`;AUD any `json:"aud"`;Scope string `json:"scope"`;IssuedAt int64 `json:"iat"`;Expires int64 `json:"exp"`;NotBefore int64 `json:"nbf"`;JWTID string `json:"jti"`}
 if decode(parts[1],&claims)!=nil{return out,errors.New("invalid signed claims")}
 aud:=[]string{}
 switch v:=claims.AUD.(type){case string:aud=append(aud,v);case []any:for _,a:=range v{s,ok:=a.(string);if !ok{return out,errors.New("invalid signed audience")};aud=append(aud,s)}}
 now:=time.Now().Unix()
 // A valid signature alone is insufficient: require one exact audience, a
 // bounded identifier and a presently valid workload session profile.
 if len(aud)!=1||aud[0]!=audience||claims.JWTID==""||len(claims.JWTID)>255||claims.NotBefore>now+5||
  claims.Issuer!=issuer&&claims.Issuer!=issuer+"/"||claims.ClientID!=expectedClient||claims.AZP!=expectedClient||
  claims.Subject!=expectedClient||claims.Actor!="workload"||claims.Scope!=scope||claims.IssuedAt>now+5||
  claims.Expires<=now+120||claims.Expires-claims.IssuedAt>900||claims.Expires<=claims.IssuedAt{
  return out,errors.New("signed workload claims not eligible for live qualification")
 }
 return accessClaims{Issuer:claims.Issuer,Subject:claims.Subject,ClientID:claims.ClientID,AuthorizedParty:claims.AZP,
  ActorType:claims.Actor,Audience:aud,Scope:claims.Scope,IssuedAt:claims.IssuedAt,Expires:claims.Expires},nil
}
func cpContext(ctx context.Context,client *http.Client,c liveConfig,target liveTarget,token string)(string,error){
 body:=map[string]string{"tenant_id":target.TenantID,"organisation_id":target.OrganisationID,"country_code":target.CountryCode}
 status,_,raw,e:=requestJSON(ctx,client,"POST",strings.TrimRight(c.Workload.CPOrigin,"/")+"/v1/platform-context/resolve",token,body)
 if e!=nil||status!=200{return "",errors.New("CP context resolution denied")}
 var v struct{ContextID string `json:"context_id"`; TenantID string `json:"tenant_id"`;OrganisationID string `json:"organisation_id"`;ExpiresAt time.Time `json:"expires_at"`}
 if json.Unmarshal(raw,&v)!=nil||v.ContextID==""||v.TenantID!=target.TenantID||v.OrganisationID!=target.OrganisationID||!time.Now().Before(v.ExpiresAt){return "",errors.New("CP returned incorrect context")}
 return v.ContextID,nil
}
type validation struct{ContextID string `json:"context_id"`;TenantID string `json:"tenant_id"`;OrganisationID string `json:"organisation_id"`;AuthorityPurpose string `json:"authority_purpose"`;ExpiresAt time.Time `json:"expires_at"`}
type cpDecision struct{status int; code string; value validation}
func validateCP(ctx context.Context,client *http.Client,c liveConfig,validator,subject,contextID string)(cpDecision,error){
 var out cpDecision
 status,headers,raw,e:=requestJSON(ctx,client,"POST",strings.TrimRight(c.Workload.CPOrigin,"/")+"/v1/platform-context/validate",validator,
  map[string]string{"context_id":contextID,"subject_token":subject})
 if e!=nil{return out,e}
 out.status=status
 if status==200{
  if headers.Get("Cache-Control")!="no-store"||json.Unmarshal(raw,&out.value)!=nil||out.value.ContextID!=contextID||
   out.value.AuthorityPurpose!="RUNTIME"||!time.Now().Before(out.value.ExpiresAt){return cpDecision{},errors.New("untrusted protected response")}
  return out,nil
 }
 var problem struct{Code string `json:"code"`}
 if json.Unmarshal(raw,&problem)!=nil{return cpDecision{},errors.New("CP denial without structured code")}
 out.code=problem.Code
 return out,nil
}
func randomOpaque() (string,error){b:=make([]byte,32);_,e:=rand.Read(b);return base64.RawURLEncoding.EncodeToString(b),e}
func checkCurrent(ctx context.Context,d *federation.RuntimeDispatch)error{
 if d==nil{return errors.New("missing current dispatch")}
 check,stop:=context.WithTimeout(ctx,8*time.Second);defer stop()
 return d.CheckCapability(check,provider.CapabilityWorkloadTokenIssue)
}
func requireDecision(d cpDecision,status int,code string)error{
 if d.status!=status||d.code!=code{return fmt.Errorf("unexpected protected CP decision")}
 return nil
}
