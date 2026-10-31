package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/pkg/workloadresource"
)

func testPrivate(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validN04Config() config {
	return config{
		Schema:"baobab.iam.n04.dev-read-config.v1",
		Environment:"development",
		RunID: strings.Repeat("a",32),
		IAMSourceSHA: strings.Repeat("b",40),
		SharedSourceSHA: strings.Repeat("c",40),
		CPSourceSHA: strings.Repeat("d",40),
		CPOrigin:"https://cp.invalid",
		CARootFile:"/private/ca.pem", TokenFile:"/private/client.token",
		Target:workloadresource.CPBindingTarget{
			ProviderID:"provider_aaaabbbb",EngineInstanceID:"ei_aaaabbbb",
			OrganisationID:"org_dev",EstateID:"estate_nabhold",
			ConfigurationReference:"ref_config1234",
			SecurityDomainReference:"ref_security1234",
		},
	}
}

func TestN04DevelopmentReaderExactPrivateConfig(t *testing.T) {
	c := validN04Config()
	raw, err := json.Marshal(c)
	if err != nil {t.Fatal(err)}
	configFile := testPrivate(t,"settings.json",raw)
	observed, err := checkedConfig(configFile)
	if err != nil || observed.Environment != "development" ||
		observed.Target.ProviderID != c.Target.ProviderID ||
		observed.Target.ConfigurationReference != c.Target.ConfigurationReference {
		t.Fatal("valid exact canonical development config refused",err)
	}
	for _, bad := range []string{
		`{"schema":"a","schema":"b"}`,
		`{"target":{"provider_id":"provider_aaaabbbb","provider_id":"provider_foreign"}}`,
		string(raw)+`{"unexpected":true}`,
		string(raw)+"garbage",
		"[]",
	} {
		p := testPrivate(t,"malformed.json",[]byte(bad))
		if _,err:=checkedConfig(p);err==nil {
			t.Fatal("ambiguous or trailing operator source accepted")
		}
	}
	c.Environment = "production"
	raw, _ = json.Marshal(c)
	if _,err:=checkedConfig(testPrivate(t,"protected.json",raw));err==nil {
		t.Fatal("protected deployment was admitted by N04 development-only CLI")
	}
}

func TestN04DevelopmentReaderPrivateFilesCannotBeSymlinksOrWorldReadable(t *testing.T) {
	path:=testPrivate(t,"source",[]byte("private"))
	if _,err:=privateFile(path,128);err!=nil {t.Fatal(err)}
	if err:=os.Chmod(path,0644);err!=nil {t.Fatal(err)}
	if _,err:=privateFile(path,128);err==nil {t.Fatal("world-readable source accepted")}
	if err:=os.Chmod(path,0600);err!=nil {t.Fatal(err)}
	symlink:=filepath.Join(t.TempDir(),"attacker-link")
	if err:=os.Symlink(path,symlink);err!=nil{t.Fatal(err)}
	if _,err:=privateFile(symlink,128);err==nil {t.Fatal("symlink private credential accepted")}
}

func TestN04DevelopmentReaderContactsActualTLSCPResourceNotFixtureSuccessFlag(t *testing.T) {
	c := validN04Config()
	const token="actual-bounded-development-cp-reader-bearer"
	calls:=0
	status:=http.StatusOK
	server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls++
		if r.URL.Path!="/internal/identity-runtime/v1/binding" ||
			r.Header.Get("Authorization")!="Bearer "+token ||
			r.Method!=http.MethodPost {
			w.WriteHeader(http.StatusForbidden);return
		}
		var query map[string]string
		if json.NewDecoder(r.Body).Decode(&query)!=nil||
			query["provider_id"]!=c.Target.ProviderID||
			query["runtime_capability"]!="WORKLOAD_TOKEN_ISSUANCE"{
			w.WriteHeader(http.StatusForbidden);return
		}
		if status!=200{w.WriteHeader(status);return}
		w.Header().Set("Cache-Control","no-store")
		data:=map[string]any{
			"provider_id":c.Target.ProviderID,
			"engine_instance_id":c.Target.EngineInstanceID,
			"scope":map[string]string{"organisation_id":c.Target.OrganisationID,"estate_id":c.Target.EstateID},
			"provider_status":"ACTIVE", "instance_status":"ACTIVE",
			"binding_status":"ACTIVE","runtime_capability":"WORKLOAD_TOKEN_ISSUANCE",
			"support_status":"VERIFIED","artifact_digest":"sha256:"+strings.Repeat("a",64),
			"deployed_artifact_digest":"sha256:"+strings.Repeat("a",64),
			"profile_revision":1,"evidence_expires_at":time.Now().Add(time.Minute),
			"configuration_reference":c.Target.ConfigurationReference,
			"security_domain_reference":c.Target.SecurityDomainReference,
		}
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer server.Close()
	c.CPOrigin=server.URL
	leaf:=server.Certificate()
	ca:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:leaf.Raw})
	c.CARootFile=testPrivate(t,"ca.pem",ca)
	c.TokenFile=testPrivate(t,"reader.token",[]byte(token))
	if err:=probe(context.Background(),c);err!=nil{t.Fatal("correct TLS CP binding refused",err)}
	if calls!=1 {t.Fatal("real TLS CP endpoint not actually contacted")}
	status=http.StatusForbidden
	if err:=probe(context.Background(),c);err==nil {t.Fatal("revoked CP caller accepted")}
	if calls!=2 {t.Fatal("CP registration unexpectedly cached")}
	// TLS roots must originate from the exact private operator file.
	otherRoot:=x509.NewCertPool()
	_ = otherRoot
	c.CARootFile=testPrivate(t,"invalid-ca.pem",[]byte("not a certificate"))
	if err:=probe(context.Background(),c);err==nil {t.Fatal("invalid TLS roots accepted")}
}
