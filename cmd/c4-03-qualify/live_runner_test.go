package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestC403FullReceiptMustHaveEveryRealGate(t *testing.T){
 r:=newFullEvidence(strings.Repeat("a",40))
 for _,id:=range fullRequired{r.Checks[id]=true}
 r.close()
 if r.Result!="FAIL"{t.Fatal("uncontacted live services accepted")}
 r.ProviderAndCPActuallyContacted=true
 r.close()
 if r.Result!="FAIL"{t.Fatal("missing CP withdrawal accepted")}
 r.CPGrantWithdrawalObserved=true
 for _,id:=range fullRequired{
  r.Checks[id]=false;r.close()
  if r.Result!="FAIL"{t.Fatalf("missing gate %s accepted",id)}
  r.Checks[id]=true
 }
 r.Checks["unregistered_mock_passed"]=true;r.close()
 if r.Result!="FAIL"{t.Fatal("unexpected evidence property accepted")}
 delete(r.Checks,"unregistered_mock_passed");r.close()
 if r.Result!="PASS"||r.ProductionReady||r.PhysicalPasskey{
  t.Fatal("readiness overclaim or invalid closed result")
 }
}

func TestC403FullReceiptPrivateAtomicAndNoCredentialFields(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"full")
 r:=newFullEvidence(strings.Repeat("b",40))
 r.ProviderAndCPActuallyContacted=true;r.CPGrantWithdrawalObserved=true
 for _,id:=range fullRequired{r.Checks[id]=true}
 if err:=publishFull(dir,r);err!=nil{t.Fatal(err)}
 entries,err:=os.ReadDir(dir);if err!=nil||len(entries)!=1||!strings.HasPrefix(entries[0].Name(),"run-"){t.Fatal("partial bundle")}
 a:=filepath.Join(dir,entries[0].Name(),"receipt.json")
 b:=filepath.Join(dir,entries[0].Name(),"receipt.sha256")
 bytesData,err:=os.ReadFile(a);if err!=nil{t.Fatal(err)}
 digest,err:=os.ReadFile(b);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(bytesData)
 if string(digest)!=hex.EncodeToString(sum[:])+"  receipt.json\n"{t.Fatal("receipt digest mismatch")}
 var got fullEvidence
 if json.Unmarshal(bytesData,&got)!=nil||got.Result!="PASS"||got.ProductionReady||got.PhysicalPasskey{
  t.Fatal("receipt scope invalid")
 }
 for _,p:=range []string{a,b}{
  info,err:=os.Stat(p)
  if err!=nil||info.Mode().Perm()!=0600{t.Fatal("receipt not private")}
 }
 var object map[string]json.RawMessage
 if json.Unmarshal(bytesData,&object)!=nil{t.Fatal("invalid receipt object")}
 for _,forbidden:=range []string{"access_token","client_secret","session_token","subject_token","cookie","private_key"}{
  if _,exists:=object[forbidden];exists{t.Fatal("credential-bearing top-level evidence field")}
 }
}

func TestC403InvalidLiveTargetNeverStarts(t *testing.T){
 good:=liveConfig{
  HydraIssuer:"https://hydra.example.invalid",HydraAdmin:"https://hydra-admin.example.invalid",
  KratosPublic:"https://kratos.example.invalid",KratosAdmin:"https://kratos-admin.example.invalid",
  Primary:liveTarget{ClientID:"synthetic-primary",SecretFile:"/private/primary",TenantID:"tenant-primary",OrganisationID:"org-primary",CountryCode:"ZA"},
  Foreign:liveTarget{ClientID:"synthetic-foreign",SecretFile:"/private/foreign",TenantID:"tenant-foreign",OrganisationID:"org-foreign",CountryCode:"UG"},
  ResourceAudience:"baobab-erp",ResourceScope:"context:resolve",ValidatorTokenFile:"/private/validator",
  NativeSessionFile:"/private/native",NativeIdentityID:"synthetic-identity",NativeClientID:"synthetic-native",NativeCallback:"https://callback.example.invalid/oidc",
 }
 if !validLiveConfig(good){t.Fatal("valid config rejected")}
 for _,tc:=range []struct{name string;mutate func(*liveConfig)}{
  {"HTTP Hydra",func(c *liveConfig){c.HydraIssuer="http://127.0.0.1:4444"}},
  {"URL injection",func(c *liveConfig){c.HydraIssuer="https://user:secret@hydra.invalid"}},
  {"duplicate client",func(c *liveConfig){c.Foreign.ClientID=c.Primary.ClientID}},
  {"same tenant",func(c *liveConfig){c.Foreign.TenantID=c.Primary.TenantID}},
  {"unbounded scope",func(c *liveConfig){c.ResourceScope="context:resolve erp:write"}},
  {"missing session",func(c *liveConfig){c.NativeSessionFile=""}},
  {"invalid country",func(c *liveConfig){c.Primary.CountryCode="za"}},
  {"HTTP callback",func(c *liveConfig){c.NativeCallback="http://localhost/callback"}},
 }{
  t.Run(tc.name,func(t *testing.T){candidate:=good;tc.mutate(&candidate);if validLiveConfig(candidate){t.Fatal("invalid live config accepted")}})
 }
}

func TestC403OperatorTextIsNotRevocationEvidence(t *testing.T){
 t.Setenv("BAOBAB_C403_DISPOSABLE","1")
 if err:=operatorWithdrawal(context.Background(),strings.NewReader("ACK\n"),&bytes.Buffer{});err==nil{t.Fatal("arbitrary reply accepted")}
 if err:=operatorWithdrawal(context.Background(),strings.NewReader("REVOKED\n"),&bytes.Buffer{});err!=nil{t.Fatal(err)}
 // The boolean is set exclusively by the post-withdrawal live CP request.
 r:=newFullEvidence(strings.Repeat("c",40))
 for _,id:=range fullRequired{r.Checks[id]=true}
 r.ProviderAndCPActuallyContacted=true
 r.close()
 if r.Result!="FAIL"{t.Fatal("operator acknowledgment equated to authoritative revocation")}
}

func TestC403NoUnsignedJWTOrTransportSubstitution(t *testing.T){
 if _,err:=parseOrigin("https://hydra.invalid/issuer?access_token=private");err==nil{t.Fatal("issuer query accepted")}
 if _,err:=parseOrigin("http://localhost:4444");err==nil{t.Fatal("insecure issuer accepted")}
 client:=&http.Client{}
 for _,raw:=range []string{"opaque", "eyJhbGciOiJub25lIn0.e30.signature", "a.b.c.d"}{
  if _,err:=verifyHydraJWT(context.Background(),client,"https://hydra.invalid",raw,"id","aud","scope");err==nil{
   t.Fatal("unsigned or invalid signed token accepted")
  }
 }
 if requireDecision(cpDecision{status:401,code:"SUBJECT_TOKEN_INVALID"},401,"SUBJECT_TOKEN_INVALID")!=nil{t.Fatal("expected CP problem refused")}
 if requireDecision(cpDecision{status:503,code:"SUBJECT_TOKEN_INVALID"},401,"SUBJECT_TOKEN_INVALID")==nil{t.Fatal("outage treated as rejection proof")}
}
