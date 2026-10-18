// C4-03B-E: orchestrate registered providers, an actual CP resource and an
// explicitly operator-approved synthetic CP withdrawal. No mocked positive
// responses or self-issued CP grants can satisfy this acceptance path.
package main

import (
 "bufio"
 "context"
 "encoding/base64"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/baobab-platform/baobab-iam/internal/federation"
 "github.com/baobab-platform/baobab-iam/internal/provider"
)

const fullSchema="baobab-c4-03-registered-integration/v1"
var fullRequired=[]string{
 "real_hydra_workload_issuance","signed_scoped_audience_token","current_cp_runtime_after_issuance",
 "kratos_synthetic_session_verified","governed_login_consent","signed_nonce_bound_oidc",
 "code_replay_denied","synthetic_session_revoked","protected_cp_resource_accepted",
 "foreign_tenant_context_denied","tampered_subject_token_denied",
 "real_cp_withdrawal_denied_unexpired_token","evidence_closed",
}
type fullEvidence struct{
 Schema string `json:"schema"`
 SourceCommit string `json:"source_commit"`
 Result string `json:"result"`
 Checks map[string]bool `json:"checks"`
 ProviderAndCPActuallyContacted bool `json:"registered_live_services_contacted"`
 CPGrantWithdrawalObserved bool `json:"cp_withdrawal_observed"`
 PhysicalPasskey bool `json:"physical_passkey_qualified"`
 ProductionReady bool `json:"production_ready"`
}
func newFullEvidence(sha string)fullEvidence{
 r:=fullEvidence{Schema:fullSchema,SourceCommit:sha,Result:"FAIL",Checks:map[string]bool{}}
 for _,id:=range fullRequired{r.Checks[id]=false}
 return r
}
func (r *fullEvidence)close(){
 r.Result="FAIL";r.ProductionReady=false;r.PhysicalPasskey=false
 if !shaPattern.MatchString(r.SourceCommit)||r.Schema!=fullSchema||!r.ProviderAndCPActuallyContacted||
  !r.CPGrantWithdrawalObserved||len(r.Checks)!=len(fullRequired){return}
 for _,id:=range fullRequired{if !r.Checks[id]{return}}
 r.Result="PASS"
}
// publishFull writes all evidence files privately, fsyncs both contents,
// then atomically exposes the complete bundle; no token, session or CP
// document is ever retained.
func publishFull(dir string,r fullEvidence)error{
 if dir==""||r.Schema!=fullSchema||!shaPattern.MatchString(r.SourceCommit){return errors.New("invalid full evidence")}
 r.close()
 if e:=os.MkdirAll(dir,0700);e!=nil{return e}
 pending,e:=os.MkdirTemp(dir,".pending-");if e!=nil{return e}
 defer os.RemoveAll(pending)
 data,e:=json.MarshalIndent(r,"","  ");if e!=nil{return e};data=append(data,'\n')
 write:=func(name string,b []byte)error{
  f,e:=os.OpenFile(filepath.Join(pending,name),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return e}
  if _,e=f.Write(b);e!=nil{f.Close();return e}
  if e=f.Sync();e!=nil{f.Close();return e}
  return f.Close()
 }
 if e=write("receipt.json",data);e!=nil{return e}
 sum:=sha256.Sum256(data)
 if e=write("receipt.sha256",[]byte(hex.EncodeToString(sum[:])+"  receipt.json\n"));e!=nil{return e}
 fd,e:=os.Open(pending);if e!=nil{return e}
 if e=fd.Sync();e!=nil{fd.Close();return e};if e=fd.Close();e!=nil{return e}
 nonce:=make([]byte,12);if _,e=rand.Read(nonce);e!=nil{return e}
 return os.Rename(pending,filepath.Join(dir,"run-"+hex.EncodeToString(nonce)))
}
// Operator confirmation is intentionally NOT considered withdrawal evidence.
// Only subsequent denial from the live CP for the same still-unexpired token
// qualifies; this instruction is only a safe synchronization checkpoint.
func operatorWithdrawal(ctx context.Context,in io.Reader,out io.Writer)error{
 if os.Getenv("BAOBAB_C403_DISPOSABLE")!="1"{return errors.New("destructive fixture gate not enabled")}
 fmt.Fprintln(out,"C4-03: withdraw ONLY the approved synthetic primary tenant or owner in the running CP, then enter REVOKED")
 completed:=make(chan bool,1)
 go func(){r:=bufio.NewReader(io.LimitReader(in,64));line,e:=r.ReadString('\n');completed<-e==nil&&strings.TrimSpace(line)=="REVOKED"}()
 limit,stop:=context.WithTimeout(ctx,90*time.Second);defer stop()
 select{case ok:=<-completed:if !ok{return errors.New("operator confirmation missing")}
 case <-limit.Done():return errors.New("operator withdrawal checkpoint expired")}
 return nil
}
func qualifyFull(parent context.Context,c liveConfig,caFile,sha,artifactDir string,in io.Reader,out io.Writer)fullEvidence{
 r:=newFullEvidence(sha)
 if !validLiveConfig(c)||os.Getenv("BAOBAB_C403_DISPOSABLE")!="1" {return r}
 client,tlsConfig,e:=verifiedClient(caFile);if e!=nil{return r}
 ctx,cancel:=context.WithCancel(parent);defer cancel()
 // Reuse live C4-02 composition, including the real CP-issued context and
 // current runtime capabilities. A disabled or unregistered binding denies.
 dispatch,supervisor,e:=federation.StartRuntimeComposition(ctx,c.Workload,provider.CapabilityWorkloadTokenIssue,tlsConfig)
 if e!=nil{return r}
 defer func(){cancel();<-supervisor.Done()}()
 if checkCurrent(ctx,dispatch)!=nil{return r}
 // Hydra is the ONLY token issuer; no local JWT fabrication or bypass hook.
 issuerPrimary,e:=issuedJWT(ctx,client,c,c.Primary,"baobab-control-plane","context:resolve")
 if e!=nil{return r}
 resourcePrimary,e:=issuedJWT(ctx,client,c,c.Primary,c.ResourceAudience,c.ResourceScope)
 if e!=nil{return r}
 issuerForeign,e:=issuedJWT(ctx,client,c,c.Foreign,"baobab-control-plane","context:resolve")
 if e!=nil{return r}
 r.Checks["real_hydra_workload_issuance"]=true
 r.Checks["signed_scoped_audience_token"]=resourcePrimary.claims.ActorType=="workload"
 if checkCurrent(ctx,dispatch)!=nil{return r}
 r.Checks["current_cp_runtime_after_issuance"]=true
 // The CP subject's context is minted by the running CP for its verified
 // canonical owner. The resource validator must be independently registered.
 own,e:=cpContext(ctx,client,c,c.Primary,issuerPrimary.raw);if e!=nil{return r}
 foreign,e:=cpContext(ctx,client,c,c.Foreign,issuerForeign.raw);if e!=nil||foreign==own{return r}
 validator,e:=protectedToken(ctx,c.ValidatorTokenFile);if e!=nil{return r}
 accepted,e:=validateCP(ctx,client,c,validator,resourcePrimary.raw,own)
 if e!=nil||accepted.status!=200||accepted.value.TenantID!=c.Primary.TenantID||
  accepted.value.OrganisationID!=c.Primary.OrganisationID{return r}
 r.Checks["protected_cp_resource_accepted"]=true
 foreignDecision,e:=validateCP(ctx,client,c,validator,resourcePrimary.raw,foreign)
 if e!=nil||requireDecision(foreignDecision,404,"CONTEXT_NOT_FOUND")!=nil{return r}
 r.Checks["foreign_tenant_context_denied"]=true
 // Flip a bit in the SIGNATURE of the already issued JWT, rather than
 // asserting rejection of a fabricated unrelated string or expired token.
 parts:=strings.Split(resourcePrimary.raw,".");if len(parts)!=3{return r}
 sig,e:=base64.RawURLEncoding.DecodeString(parts[2]);if e!=nil||len(sig)<1{return r}
 sig[0]^=1;parts[2]=base64.RawURLEncoding.EncodeToString(sig)
 invalid,e:=validateCP(ctx,client,c,validator,strings.Join(parts,"."),own)
 if e!=nil||requireDecision(invalid,401,"SUBJECT_TOKEN_INVALID")!=nil{return r}
 r.Checks["tampered_subject_token_denied"]=true
 r.ProviderAndCPActuallyContacted=true
 // C4-03C: actual pre-enrolled synthetic Kratos session, governed CP native
 // acceptance, Hydra consent/code, signed OIDC, and real session revocation.
 native,e:=qualifyNative(ctx,c,client,tlsConfig,filepath.Join(artifactDir,"fence"))
 if e!=nil{return r}
 for k,v:=range native {if _,ok:=r.Checks[k];ok{r.Checks[k]=v}}
 // C4-03D: require an OUT-OF-BAND authorised withdrawal of the approved
 // synthetic CP tenant. A mere 'REVOKED' acknowledgment does not count.
 if e=operatorWithdrawal(ctx,in,out);e!=nil{return r}
 // Must be the same cryptographically sound bearer while still unexpired.
 if resourcePrimary.claims.Expires<=time.Now().Unix()+10{return r}
 after,e:=validateCP(ctx,client,c,validator,resourcePrimary.raw,own)
 if e!=nil{return r}
 if after.status==403&&after.code=="TENANT_NOT_ACTIVE"||after.status==404&&after.code=="CONTEXT_NOT_FOUND"{
  r.Checks["real_cp_withdrawal_denied_unexpired_token"]=true
  r.CPGrantWithdrawalObserved=true
 }
 // Evidence is closed only after every substantive check succeeds; E itself
 // is not established by a source-only fixture or a manually signed statement.
 r.Checks["evidence_closed"]=true
 r.close()
 return r
}
