package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "sync"
 "testing"
 "time"

 "github.com/baobab-platform/baobab-iam/internal/provider"
 "github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type fakeIssuer struct {
 mu sync.Mutex
 clients map[string]map[string]any
 writes int
 deletes int
}
func fixtureIssuer(t *testing.T) (*native,*fakeIssuer,func()) {
 t.Helper()
 state:=&fakeIssuer{clients:map[string]map[string]any{}}
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  const prefix="/admin/clients/"
  state.mu.Lock();defer state.mu.Unlock()
  if r.Method=="POST" && r.URL.Path=="/admin/clients" {
   var row map[string]any
   if err:=json.NewDecoder(r.Body).Decode(&row);err!=nil {w.WriteHeader(400);return}
   id,_:=row["client_id"].(string)
   if id=="" {w.WriteHeader(400);return}
   if _,ok:=state.clients[id];ok {w.WriteHeader(http.StatusConflict);return}
   state.clients[id]=row
   state.writes++
   w.WriteHeader(http.StatusCreated)
   json.NewEncoder(w).Encode(row)
   return
  }
  if len(r.URL.Path)<=len(prefix) ||r.URL.Path[:len(prefix)]!=prefix {http.NotFound(w,r);return}
  id:=r.URL.Path[len(prefix):]
  row,ok:=state.clients[id]
  switch r.Method {
  case "GET":
   if !ok {http.NotFound(w,r);return}
   json.NewEncoder(w).Encode(row)
  case "PUT":
   if !ok {http.NotFound(w,r);return}
   if err:=json.NewDecoder(r.Body).Decode(&row);err!=nil {w.WriteHeader(400);return}
   state.clients[id]=row;state.writes++
   json.NewEncoder(w).Encode(row)
  case "DELETE":
   if !ok {http.NotFound(w,r);return}
   delete(state.clients,id);state.deletes++
   w.WriteHeader(204)
  default: w.WriteHeader(405)
  }
 }))
 a,err:=ory.NewAdapter(ory.Config{HydraAdminURL:srv.URL,KratosAdminURL:srv.URL,PublicIssuer:srv.URL,HTTPClient:srv.Client()})
 if err!=nil {t.Fatal(err)}
 return &native{adapter:a,client:srv.Client(),admin:srv.URL,runID:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},state,srv.Close
}
func spec(name string) provider.WorkloadProvisioningSpec {
 scopes:=[]string{"context:validate"}
 audience:=[]string{"baobab-control-plane"}
 owner:="baobab-platform/baobab-cms"
 if name==consumer {scopes=[]string{"context:resolve","content:entry:resolve"};audience=[]string{"baobab-control-plane","baobab-cms"};owner="baobab-platform/infrastructure"}
 return provider.WorkloadProvisioningSpec{LogicalClientID:name,AllowedScopes:scopes,Audiences:audience,
  AccessTokenTTLSeconds:60,RequireNew:true,AuthMethod:provider.WorkloadAuthClientSecret,LifecycleStatus:provider.WorkloadStatusProvisioned,
  Metadata:map[string]string{"environment":"development","owner":owner}}
}
func TestExactNativeBoundary(t *testing.T) {
 for _,name:=range []string{consumer,validator} {
  if !requiredSpec(spec(name)) {t.Fatalf("refused %s",name)}
 }
 wrong:=spec(consumer);wrong.AllowedScopes=append(wrong.AllowedScopes,"admin:*")
 if requiredSpec(wrong) {t.Fatal("widened scope accepted")}
 wrong=spec(validator);wrong.Metadata["extra"]="danger"
 if requiredSpec(wrong) {t.Fatal("unreviewed metadata accepted")}
 wrong=spec(consumer);wrong.RequireNew=false
 if requiredSpec(wrong) {t.Fatal("existing clients may be reused")}
}
func TestRealAdapterProvisionAndOwnedRecovery(t *testing.T) {
 n,state,closeServer:=fixtureIssuer(t);defer closeServer()
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil {t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 // The IAM adapter performs a separate GET of fresh authority, and this
 // bridge performs a second independent GET before publishing a secret.
 if err:=n.create(ctx,spec(consumer),dir);err!=nil {t.Fatal(err)}
 raw,err:=os.ReadFile(filepath.Join(dir,consumer+".secret"))
 if err!=nil||len(raw)<32 {t.Fatal("secret handoff missing")}
 if err:=n.create(ctx,spec(consumer),dir);err==nil {t.Fatal("existing client reused")}
 state.mu.Lock();writes:=state.writes;state.mu.Unlock()
 if writes!=1 {t.Fatal("refused create mutated client")}
 if err:=n.revoke(ctx,consumer);err!=nil {t.Fatal(err)}
 if err:=n.destroy(ctx,consumer);err!=nil {t.Fatal(err)}
 if err:=n.destroy(ctx,consumer);err!=nil {t.Fatal("idempotent crash recovery refused")}
 state.mu.Lock();deletes:=state.deletes;state.mu.Unlock()
 if deletes!=1 {t.Fatalf("deleted %d clients",deletes)}
}
func TestCannotDeleteOtherRun(t *testing.T) {
 n,state,closeServer:=fixtureIssuer(t);defer closeServer()
 dir:=t.TempDir();_ = os.Chmod(dir,0700)
 ctx:=context.Background()
 if err:=n.create(ctx,spec(validator),dir);err!=nil {t.Fatal(err)}
 state.mu.Lock();state.clients[validator]["metadata"]=map[string]any{"int03_run_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};state.mu.Unlock()
 if err:=n.destroy(ctx,validator);err==nil {t.Fatal("foreign run erased")}
 state.mu.Lock();remaining:=len(state.clients);deletes:=state.deletes;state.mu.Unlock()
 if remaining!=1||deletes!=0 {t.Fatal("foreign client was mutated")}
}
func TestAcceptedPostThenFaultRecoverable(t *testing.T) {
 n,state,closeServer:=fixtureIssuer(t);defer closeServer()
 // A response can be lost after accepted POST. Recovery must use the
 // persisted marker, not a successful CLI exit or locally stored secret.
 state.mu.Lock()
 state.clients[consumer]=map[string]any{"client_id":consumer,"metadata":map[string]any{
  "int03_run_id":n.runID,"owner":"baobab-platform/infrastructure","environment":"development"},
  "grant_types":[]string{"client_credentials"}}
 state.mu.Unlock()
 if err:=n.destroy(context.Background(),consumer);err!=nil {t.Fatal(err)}
 state.mu.Lock();deletes:=state.deletes;state.mu.Unlock()
 if deletes!=1 {t.Fatal("ambiguous POST not recovered")}
}

func TestPrivateNativeOriginsOnly(t *testing.T) {
 goodAdmin:="https://hydra.int03.test"
 goodIssuer:="https://hydra.int03.test"
 goodKratos:="http://kratos:4434"
 nonce:="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 if err:=validateOrigins(goodAdmin,goodKratos,goodIssuer);err!=nil {
  t.Fatal("valid private issuer/companion origins refused",err)
 }
 for _,tc:=range []struct{admin,kratos,issuer,run string}{
  {"https://real.example.org",goodKratos,goodIssuer,nonce},
  {"http://hydra.int03.test",goodKratos,goodIssuer,nonce},
  {goodAdmin,goodKratos,"https://production.example.org",nonce},
  {goodAdmin,"https://foreign.example.org",goodIssuer,nonce},
  {goodAdmin,goodKratos,goodIssuer,"short"},
 } {
  if err:=validateOrigins(tc.admin,tc.kratos,tc.issuer);err==nil && tc.run==nonce {
   t.Fatal("non-disposable IAM origin accepted")
  }
  if _,err:=makeNative(tc.admin,tc.kratos,tc.issuer,"/no-disposable-ca.pem",tc.run);err==nil {
   t.Fatal("untrusted native provisioning accepted")
  }
 }
}
