package workloadresource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type operationFixture struct { calls int; deny bool }
func (p *operationFixture) ResolveOperation(_ context.Context, r *http.Request)(Operation,error){
	p.calls++
	if p.deny||r.URL.Path!="/resource/search"{
		return Operation{},errors.New("resource operation absent")
	}
	return op(),nil
}
func TestResourceMiddlewareNeverForwardsUnverifiedOrRawCredentials(t *testing.T){
	g,_,status,cp:=fixture(t)
	resolver:=&operationFixture{}
	forwarded:=0
	downstream:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		forwarded++
		if r.Header.Get("Authorization")!=""||r.Header.Get("Cookie")!=""{
			t.Fatal("original bearer/cookie leaked into engine application handler")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	bridge,err:=NewMiddleware(g,resolver,downstream)
	if err!=nil{t.Fatal(err)}
	probe:=func(auth string,cookies bool)int{
		req:=httptest.NewRequest(http.MethodPost,"http://resource.invalid/resource/search",nil)
		if auth!=""{req.Header.Add("Authorization",auth)}
		if cookies{req.Header.Add("Cookie","ory_session=must-not-forward")}
		out:=httptest.NewRecorder()
		bridge.ServeHTTP(out,req)
		if out.Header().Get("Cache-Control")!="no-store"{
			t.Fatal("resource response may be cached")
		}
		return out.Code
	}
	if status:=probe("Bearer "+bearer(),true);status!=http.StatusNoContent{
		t.Fatalf("fresh authorized bearer refused HTTP status %d",status)
	}
	for _,raw:=range []string{
		"",bearer(),"Basic "+bearer(),"Bearer "+bearer()+",Bearer duplicate",
		"Bearer "+bearer()+" ","Bearer not-enough",
	}{
		if code:=probe(raw,false);code==http.StatusNoContent{
			t.Fatal("malformed bearer bypassed HTTP resource boundary")
		}
	}
	if forwarded!=1||cp.calls!=1||status.calls!=2{
		t.Fatal("HTTP middleware forwarded rejected request to resource PEP")
	}
	cp.err=errors.New("current CP grant withdrawn")
	if code:=probe("Bearer "+bearer(),true);code!=http.StatusForbidden || forwarded!=1{
		t.Fatal("current CP withdrawal not enforced at HTTP resource")
	}
	cp.err=nil
	status.active.Active=false
	if code:=probe("Bearer "+bearer(),false);code!=http.StatusForbidden || forwarded!=1{
		t.Fatal("revoked issuer allowed resource HTTP action")
	}
	if resolver.calls==0{t.Fatal("owner-owned trusted operation lookup skipped")}
}
func TestResourceMiddlewareRequiresExplicitOwnerOperation(t *testing.T){
	g,_,_,_:=fixture(t)
	if _,err:=NewMiddleware(g,nil,http.HandlerFunc(func(http.ResponseWriter,*http.Request){}));err==nil{
		t.Fatal("no native operation source admitted")
	}
	if _,err:=NewMiddleware(g,&operationFixture{},nil);err==nil{
		t.Fatal("missing resource PEP admitted")
	}
}
