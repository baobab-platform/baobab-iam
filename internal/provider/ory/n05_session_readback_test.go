package ory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func TestN05KratosSessionReadbackIsCurrentAndExact(t *testing.T) {
	const issuer = "https://native-iam.example.test"
	const id = "11111111-1111-4111-8111-111111111111"
	type reply struct {
		status int
		body string
		media string
	}
	result := reply{status:200,body:"[]",media:"application/json; charset=utf-8"}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		if r.URL.Path != "/admin/identities/"+id+"/sessions" ||
			r.URL.Query().Get("active") != "true" ||
			r.URL.Query().Get("page_size") != "2" ||
			r.Method != http.MethodGet {
			http.Error(w,"unsafe session scan",400)
			return
		}
		w.Header().Set("Content-Type", result.media)
		w.WriteHeader(result.status)
		_,_ = w.Write([]byte(result.body))
	}))
	defer api.Close()
	adapter,err:=ory.NewAdapter(ory.Config{
		KratosAdminURL:api.URL,
		HydraAdminURL:"http://127.0.0.1:4445",
		PublicIssuer:issuer,
		HTTPClient:api.Client(),
	})
	if err!=nil{t.Fatal(err)}
	subject:=provider.ExternalSubject{Issuer:issuer,Subject:id}
	count,err:=adapter.ActiveSessionCount(context.Background(),subject)
	if err!=nil||count!=0 {t.Fatalf("empty active session readback %d %v",count,err)}
	samples:=[]reply{
		{200,`[{"id":"s1","identity_id":"`+id+`","active":true}]`,"application/json"},
		{200,`[{"id":"s1","identity_id":"different","active":true}]`,"application/json"},
		{200,`[{"id":"s1","identity_id":"`+id+`","active":false}]`,"application/json"},
		{200,`[{"id":"s1","identity_id":"`+id+`"}]`,"application/json"},
		{200,"null","application/json"},
		{200,"{}","application/json"},
		{200,"[]{}","application/json"},
		{200,"[]","text/plain"},
		{204,"[]","application/json"},
		{302,"[]","application/json"},
		{500,"[]","application/json"},
	}
	for _,sample:=range samples{
		result=sample
		withCount,readErr:=adapter.ActiveSessionCount(context.Background(),subject)
		if sample.body==`[{"id":"s1","identity_id":"`+id+`","active":true}]`{
			if readErr!=nil||withCount!=1{t.Fatalf("active session ignored: %d %v",withCount,readErr)}
		}else if readErr==nil{
			t.Fatalf("unsafe Kratos response was accepted: status=%d body=%s",sample.status,sample.body)
		}
	}
	result=reply{200,"[]","application/json"}
	if _,err:=adapter.ActiveSessionCount(context.Background(),provider.ExternalSubject{
		Issuer:"https://other-issuer.example.test",Subject:id,
	});err==nil||!strings.Contains(err.Error(),"issuer"){
		t.Fatalf("foreign issuer not refused: %v",err)
	}
}
