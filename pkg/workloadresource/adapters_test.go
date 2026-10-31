package workloadresource

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type nativeFixture struct{ deny bool; calls int }
func (n *nativeFixture) AuthorizeOperation(_ context.Context, c Claims, o Operation) error {
	n.calls++
	if n.deny || c.ClientID == "" || o.ResourceOperation != "search" { return ErrDenied }
	return nil
}
func TestCPContextAuthorityChecksCurrentHTTPAndNativeVeto(t *testing.T) {
	subject := "signed-original-provider-workload-bearer"
	validator := "independent-CP-validator-issuer-credential"
	var status int = http.StatusOK
	var badTenant bool
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/platform-context/validate" ||
			r.Header.Get("Authorization") != "Bearer "+validator {
			t.Error("CP validator credential or exact route changed")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil ||
			body["context_id"] != "cp-context-123" || body["subject_token"] != subject {
			t.Error("CP did not receive exact issuer bearer and context")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			tenant := "tn_own"
			if badTenant { tenant = "tn_other" }
			_ = json.NewEncoder(w).Encode(map[string]any{
				"context_id": body["context_id"], "tenant_id": tenant,
				"expires_at": time.Now().Add(time.Minute),
			})
		}
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	native := &nativeFixture{}
	authority, err := NewCPContextAuthority(srv.URL, roots,
		func(context.Context) (string, error) { return validator, nil }, native)
	if err != nil { t.Fatal(err) }
	op := Operation{ContextID:"cp-context-123", TenantID:"tn_own",ResourceOperation:"search"}
	claims := Claims{ClientID:"pulse-workload"}
	if err := authority.AuthorizeCurrent(context.Background(), subject, claims, op); err != nil || native.calls != 1 {
		t.Fatal("fresh CP + native authorization rejected")
	}
	status = http.StatusForbidden
	if err := authority.AuthorizeCurrent(context.Background(), subject, claims, op); err == nil {
		t.Fatal("CP withdrawal did not veto resource")
	}
	status = http.StatusOK
	badTenant = true
	if err := authority.AuthorizeCurrent(context.Background(), subject, claims, op); err == nil {
		t.Fatal("wrong-tenant CP response accepted")
	}
	badTenant = false
	native.deny = true
	if err := authority.AuthorizeCurrent(context.Background(), subject, claims, op); err == nil {
		t.Fatal("domain engine native veto bypassed")
	}
	if hits != 4 || native.calls != 2 { t.Fatalf("CP/native checks not independent: %d/%d", hits,native.calls) }
}

func TestCPContextRequiresSeparateCallerAndVerifiedTLS(t *testing.T) {
	native := &nativeFixture{}
	issuer := "https://cp.invalid"
	if _, err := NewCPContextAuthority("http://127.0.0.1:3000", nil,
		func(context.Context)(string,error){return strings.Repeat("x",24),nil},native);err == nil {
		t.Fatal("insecure CP route configured")
	}
	if _, err := NewCPContextAuthority(issuer,nil,nil,native);err == nil {
		t.Fatal("missing registered CP validator admitted")
	}
	authority, err := NewCPContextAuthority(issuer,nil,
		func(context.Context)(string,error){return "signed-original-provider-workload-bearer",nil},native)
	if err != nil {t.Fatal(err)}
	if err := authority.AuthorizeCurrent(context.Background(),
		"signed-original-provider-workload-bearer",Claims{ClientID:"ci"},
		Operation{ContextID:"cp-context",TenantID:"tn",ResourceOperation:"search"});err==nil {
		t.Fatal("same subject token reused as CP validator bearer")
	}
}

func TestRFC7662CurrentIntrospectionAndNegativeResponses(t *testing.T) {
	var mode string
	var calls int
	expires := time.Now().Add(5*time.Minute).UTC().Truncate(time.Second).Unix()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		client, secret, ok := r.BasicAuth()
		if !ok || client != "resource-validator" || secret != strings.Repeat("k", 32) ||
			r.Method != http.MethodPost || r.URL.Path != "/introspect" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err:=r.ParseForm();err!=nil||r.PostForm.Get("token")!="opaque-real-provider-workload-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type","application/json")
		switch mode {
		case "inactive":w.Write([]byte(`{"active":false}`))
		case "duplicate":w.Write([]byte(`{"active":true,"active":false}`))
		case "redirect":http.Redirect(w,r,"https://untrusted.invalid",http.StatusFound)
		case "error":w.WriteHeader(http.StatusServiceUnavailable)
		default: _ = json.NewEncoder(w).Encode(map[string]any{
			"active":true, "iss":"https://issuer.invalid","sub":"federated-sub",
			"client_id":"pulse-workload","aud":[]string{"baobab-pulse"},
			"scope":"intelligence:read","exp":expires,
		})
		}
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	reader,err:=NewRFC7662Introspector(srv.URL+"/introspect","resource-validator",strings.Repeat("k",32),roots)
	if err!=nil{t.Fatal(err)}
	raw:="opaque-real-provider-workload-token"
	status,err:=reader.ReadCurrent(context.Background(),raw)
	if err!=nil||!status.Active||status.Subject!="federated-sub"||status.ExpiresAt.Unix()!=expires{
		t.Fatal("valid real TLS issuer-status response rejected")
	}
	for _,bad:=range []string{"inactive","duplicate","redirect","error"}{
		mode=bad
		if _,err=reader.ReadCurrent(context.Background(),raw);err==nil{
			t.Fatal("invalid current-state response accepted:",bad)
		}
	}
	if calls!=5{t.Fatal("current issuer state cached")}
	if _,err=NewRFC7662Introspector("http://issuer.invalid/introspect","client",strings.Repeat("k",32),roots);err==nil{
		t.Fatal("insecure live issuer accepted")
	}
	_ = bytes.Equal
	_ = errors.New
}
