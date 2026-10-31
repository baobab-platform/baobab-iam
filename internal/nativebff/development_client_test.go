package nativebff

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func devLease(t *testing.T)DevelopmentEstateClient{
	t.Helper()
	var run [16]byte
	var key [32]byte
	if _,err:=rand.Read(run[:]);err!=nil{t.Fatal(err)}
	if _,err:=rand.Read(key[:]);err!=nil{t.Fatal(err)}
	return DevelopmentEstateClient{
		Environment:"development",Estate:"zuribeans",RunID:hex.EncodeToString(run[:]),
		RedirectURI:"http://127.0.0.1:3000/auth/callback",
        PublicOrigin:"http://127.0.0.1:3000",
		ClientSecret:base64.RawURLEncoding.EncodeToString(key[:]),
		ExpiresAt:time.Now().Add(15*time.Minute),
	}
}
func TestDevClientRegistrationRefusesNonDevelopmentAndUnsafeOrigins(t *testing.T){
	lease:=devLease(t)
	for _,origin:=range []string{"https://hydra.example.invalid","http://hydra.example.invalid","http://localhost:4445","http://127.0.0.1.evil.invalid"}{
		if _,err:=NewDevelopmentClientRegistry(origin,nil,time.Now);err==nil{
			t.Fatal("non-loopback issuer admission",origin)
		}
	}
	r,err:=NewDevelopmentClientRegistry("http://127.0.0.1:4445",nil,time.Now)
	if err!=nil{t.Fatal(err)}
	for _,kind:=range []string{"production","late","redirect","wrong-estate","wildcard","wrong-run","wrong-origin"}{
		c:=lease
		switch kind{
		case "production":c.Environment="production"
		case "late":c.ExpiresAt=time.Now().Add(-time.Second)
		case "redirect":c.RedirectURI="https://other.invalid/auth/callback"
		case "wrong-estate":c.Estate="nabhold"
		case "wildcard":c.RedirectURI="http://127.0.0.1:3000/*"
		case "wrong-run":c.RunID="test"
        case "wrong-origin":c.PublicOrigin="https://foreign.example.invalid"
		}
		if _,err=r.name(c);err==nil{t.Fatal("unapproved client accepted",kind)}
	}
	// Current HTTPS estates must use their exact reviewed public first-party
    // origin. Go cannot silently rewrite to the older Next buyer BFF callback.
    httpsLease:=lease
    httpsLease.PublicOrigin="https://zuribeans.dev.example.test"
    httpsLease.RedirectURI=httpsLease.PublicOrigin+"/auth/callback"
    if id,err:=r.name(httpsLease);err!=nil||id!="baobab-dev-zuribeans-native-browser-bff"{
        t.Fatal("reviewed native HTTPS first-party client rejected")
    }
    httpsLease.RedirectURI="https://zuribeans.dev.example.test/api/iam/callback"
    if _,err:=r.name(httpsLease);err==nil{
        t.Fatal("Next buyer-BFF callback treated as native IAM browser callback")
    }
    if err=r.DeleteDevelopment(context.Background(),"production-nabhold-client",lease.RunID);err==nil{
		t.Fatal("protected client teardown accepted")
	}
}

// This test actually provisions a confidential OAuth client in the disposable
// Ory Foundation, inspects Hydra Admin's returned registration, denies an
// unapproved client scope, deletes it and independently observes 404.
// It does NOT create a CP Principal, CP scope grant, canonical provider binding,
// user or protected estate. No client secret enters a CI artifact/log.
func TestLiveDevelopmentHydraEstateClientRegistration(t *testing.T){
	if os.Getenv("ORY_FOUNDATION")!="1"||os.Getenv("ORY_HYDRA_ADMIN_URL")==""{
		t.Skip("requires disposable real Hydra foundation")
	}
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
	defer cancel()
	r,err:=NewDevelopmentClientRegistry(os.Getenv("ORY_HYDRA_ADMIN_URL"),nil,time.Now)
	if err!=nil{t.Fatal("invalid actual development Hydra admin",err)}
	lease:=devLease(t)
	id,err:=r.CreateDevelopment(ctx,lease)
	if err!=nil{t.Fatal("live Hydra refused scoped BFF client",err)}
	// A failed test cannot quietly leave an authorized confidential client.
	t.Cleanup(func(){
		cleanCtx,stop:=context.WithTimeout(context.Background(),10*time.Second)
		defer stop()
		if err:=r.DeleteDevelopment(cleanCtx,id,lease.RunID);err!=nil{
			t.Error("Hydra client teardown unverified")
		}
	})
	if err:=r.Readback(ctx,id,lease.RedirectURI,lease.RunID);err!=nil{
		t.Fatal("live Hydra readback drift",err)
	}
	if err:=r.Readback(ctx,id,"http://127.0.0.1:3000/unapproved",lease.RunID);err==nil{
		t.Fatal("Hydra unapproved redirect mistakenly qualified")
	}
	if id!="baobab-dev-zuribeans-native-browser-bff" {t.Fatal("actual client differs from Shared identity")}
	if err:=r.Readback(ctx,id,lease.RedirectURI,strings.Repeat("f",32));err==nil {
		t.Fatal("foreign development lease adopted canonical client")
	}
	if err:=r.DeleteDevelopment(ctx,id,strings.Repeat("f",32));err==nil {
		t.Fatal("foreign development lease deleted canonical client")
	}
	// Readback only proves a provider's registration, never current CP client
	// binding or a valid human subject token at Trade's resource.
}

func TestKratosGlobalLogoutBoundaryUsesVerifiedTLSAndExactSubject(t *testing.T){
	identity:="11111111-1111-4111-8111-111111111111"
	calls:=0
	status:=http.StatusNoContent
	srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls++
		if r.Method!=http.MethodDelete||r.URL.Path!="/admin/identities/"+identity+"/sessions"{
			t.Error("Kratos admin operation escaped exact identity")
			w.WriteHeader(http.StatusForbidden);return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	roots:=x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	client,err:=NewKratosAdminSessionRevoker(KratosAdminRevokeConfig{Origin:srv.URL,TrustedRoots:roots})
	if err!=nil{t.Fatal(err)}
	if client.RevokeNativeSessions(context.Background(),identity)!=nil||calls!=1{
		t.Fatal("live TLS Kratos session revocation rejected")
	}
	for _,bad:=range []string{"","../","not-an-identity",strings.Repeat("a",400)}{
		if client.RevokeNativeSessions(context.Background(),bad)==nil{t.Fatal("unsafe Kratos subject accepted")}
	}
	status=http.StatusServiceUnavailable
	if client.RevokeNativeSessions(context.Background(),identity)==nil{
		t.Fatal("unknown Kratos admin status declared logout")
	}
	if _,err=NewKratosAdminSessionRevoker(KratosAdminRevokeConfig{Origin:"http://127.0.0.1:4434",TrustedRoots:roots});err==nil{
		t.Fatal("insecure production Kratos admin origin accepted")
	}
	if _,err=NewKratosAdminSessionRevoker(KratosAdminRevokeConfig{Origin:srv.URL});err==nil{
		t.Fatal("unverified Kratos admin trust accepted")
	}
}
var _ = errors.New
