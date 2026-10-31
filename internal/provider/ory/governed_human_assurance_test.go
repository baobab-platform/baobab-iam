package ory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type n02CurrentDispatch struct{ deny atomic.Bool }
func (a *n02CurrentDispatch) CheckCapability(context.Context,string)error{
	if a.deny.Load(){return errors.New("CP dispatch withdrawn")}
	return nil
}
func TestGovernedNativeAAL2ReadsCurrentKratosAndCP(t *testing.T){
	var reads atomic.Int32
	var active atomic.Bool
	active.Store(true)
	aal:="aal2"
	srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		reads.Add(1)
		if r.URL.Path!="/sessions/whoami" || r.Header.Get("Cookie")!="ory_kratos_session=synthetic" ||
			r.Header.Get("X-Session-Token")!=""{
			w.WriteHeader(http.StatusUnauthorized);return
		}
		now:=time.Now()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":"synthetic-session","active":active.Load(),"expires_at":now.Add(time.Minute),
			"authenticated_at":now.Add(-time.Second),"authenticator_assurance_level":aal,
			"identity":map[string]string{"id":"synthetic-kratos-subject","state":"active"},
		})
	}))
	defer srv.Close()
	cp:=&n02CurrentDispatch{}
	h,err:=NewGovernedNativeHumanHandoff(NativeHumanConfig{
		KratosPublicURL:srv.URL,HydraAdminURL:srv.URL,Issuer:srv.URL,
		Client:srv.Client(),Now:time.Now,Fence:openNativeTestFence(t),
	},cp)
	if err!=nil{t.Fatal(err)}
	credential:=NativeSessionCredential{Cookie:"ory_kratos_session=synthetic"}
	observed,err:=h.AuthenticatorAAL(context.Background(),credential)
	if err!=nil||observed!="aal2"||reads.Load()!=1{t.Fatal("current Kratos AAL2 not observed")}
	aal="aal1"
	observed,err=h.AuthenticatorAAL(context.Background(),credential)
	if err!=nil||observed!="aal1"{t.Fatal("AAL downgrade not detected")}
	cp.deny.Store(true)
	before:=reads.Load()
	if _,err=h.AuthenticatorAAL(context.Background(),credential);err==nil||reads.Load()!=before{
		t.Fatal("withdrawn CP binding still disclosed assurance")
	}
	cp.deny.Store(false)
	active.Store(false)
	if _,err=h.AuthenticatorAAL(context.Background(),credential);err==nil{
		t.Fatal("revoked Kratos session still supplied AAL")
	}
}
