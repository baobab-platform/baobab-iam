package nativebff

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHydraSubjectWideLogoutUsesPrivateTLSAndExactSubject(t *testing.T){
	subject:="11111111-1111-4111-8111-111111111111"
	seen:=[]string{}
	failure:=false
	srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method!=http.MethodDelete || r.URL.Query().Get("subject")!=subject{
			t.Error("Hydra subject unbound")
			w.WriteHeader(http.StatusForbidden);return
		}
		if r.URL.Path=="/admin/oauth2/auth/sessions/consent"{
			if r.URL.Query().Get("all")!="true"{t.Error("global consent withdrawal missing")}
		}else if r.URL.Path!="/admin/oauth2/auth/sessions/login"{
			t.Error("unapproved Hydra admin route")
			w.WriteHeader(http.StatusForbidden);return
		}
		seen=append(seen,r.URL.Path)
		if failure{w.WriteHeader(http.StatusServiceUnavailable);return}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	roots:=x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	h,err:=NewHydraSubjectSessionsRevoker(HydraSubjectSessionsConfig{AdminOrigin:srv.URL,Roots:roots})
	if err!=nil{t.Fatal(err)}
	if err=h.RevokeSubjectSessions(context.Background(),subject);err!=nil||len(seen)!=2{
		t.Fatalf("real TLS Hydra session revocation not performed: %v",err)
	}
	if seen[0]!="/admin/oauth2/auth/sessions/consent"||
		seen[1]!="/admin/oauth2/auth/sessions/login"{
		t.Fatal("wrong global consent/login revocation order")
	}
	if h.RevokeSubjectSessions(context.Background(),"not-an-oidc-subject")==nil{
		t.Fatal("invalid client-selected subject accepted")
	}
	failure=true
	if h.RevokeSubjectSessions(context.Background(),subject)==nil{
		t.Fatal("Hydra subject-session 503 counted as confirmed")
	}
	if _,err=NewHydraSubjectSessionsRevoker(HydraSubjectSessionsConfig{
		AdminOrigin:"http://127.0.0.1:4445",Roots:roots});err==nil{
		t.Fatal("private Hydra insecure transport admitted")
	}
	foreign:=url.URL{Scheme:"https",Host:"hydra.example.invalid"}
	if _,err=NewHydraSubjectSessionsRevoker(HydraSubjectSessionsConfig{AdminOrigin:foreign.String()});err==nil{
		t.Fatal("unverified Hydra root accepted")
	}
}
