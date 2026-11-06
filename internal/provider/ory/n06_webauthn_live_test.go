package ory_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// A real Kratos API capability/negative check, NOT a completed browser
// authenticator ceremony. The Chrome CTAP2 verifier and real sign count
// mutation must be separately exercised to qualify A3.
func TestLiveN06KratosWebAuthnRegistrationChallenge(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION")!="1" {
		t.Skip("real pinned Kratos Foundation required")
	}
	ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second)
	defer cancel()
	seed:=make([]byte,20)
	if _,err:=rand.Read(seed);err!=nil { t.Fatal("fixture randomness unavailable") }
	email:="a3-native-"+hex.EncodeToString(seed)+"@baobab.invalid"
	passwordSeed:=make([]byte,32)
	if _,err:=rand.Read(passwordSeed);err!=nil {t.Fatal("independent credential fixture entropy unavailable")}
	password:="Aa!9-"+hex.EncodeToString(passwordSeed)
	pub:=envOr("ORY_KRATOS_PUBLIC_URL","http://127.0.0.1:4433")
	admin:=envOr("ORY_KRATOS_ADMIN_URL","http://127.0.0.1:4434")
	client:=&http.Client{Timeout:10*time.Second}
	var start struct{ID string `json:"id"`}
	foundationRequest(t,ctx,client,http.MethodGet,pub+"/self-service/registration/api",nil,"",200,&start)
	var created struct{
		SessionToken string `json:"session_token"`
		Identity struct{ID string `json:"id"`} `json:"identity"`
	}
	foundationRequest(t,ctx,client,http.MethodPost,pub+"/self-service/registration?flow="+url.QueryEscape(start.ID),
		map[string]any{"method":"password","password":password,"traits":map[string]any{"email":email}},
		"",200,&created)
	if created.Identity.ID=="" || created.SessionToken=="" {t.Fatal("real native identity/session not provisioned")}
	t.Cleanup(func(){
		cleanup,done:=context.WithTimeout(context.Background(),10*time.Second)
		defer done()
		foundationRequest(t,cleanup,client,http.MethodDelete,admin+"/admin/identities/"+url.PathEscape(created.Identity.ID),
			nil,"",204,nil)
	})
	var settings struct{
		ID string `json:"id"`
		UI struct {
			Nodes []struct{
				Group string `json:"group"`
				Attributes struct{Name string `json:"name"`} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}
	foundationRequest(t,ctx,client,http.MethodGet,pub+"/self-service/settings/api",
		nil,created.SessionToken,200,&settings)
	if settings.ID=="" {t.Fatal("real Kratos native settings challenge not created")}
	found:=false
	for _,node:=range settings.UI.Nodes {
		if node.Group=="webauthn" || node.Attributes.Name=="webauthn_register" {
			found=true
		}
	}
	if !found {
		var password, passkey, totp int
		for _, node := range settings.UI.Nodes {
			switch node.Group {
			case "password":
				password++
			case "passkey":
				passkey++
			case "totp":
				totp++
			}
		}
		t.Fatalf("real Kratos WebAuthn challenge missing: webauthn=0 password=%d passkey=%d totp=%d",password,passkey,totp)
	}
	fields:=map[string]any{"method":"webauthn","webauthn_register":"tampered-assertion-without-browser-uv"}
	payload,err:=json.Marshal(fields)
	if err!=nil {t.Fatal(err)}
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,pub+"/self-service/settings?flow="+url.QueryEscape(settings.ID),bytes.NewReader(payload))
	if err!=nil {t.Fatal("invalid settings route")}
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Accept","application/json")
	req.Header.Set("X-Session-Token",created.SessionToken)
	res,err:=client.Do(req)
	if err!=nil {t.Fatal("native Kratos WebAuthn negative request failed")}
	defer res.Body.Close()
	_,_=io.Copy(io.Discard,io.LimitReader(res.Body,65536))
	if res.StatusCode!=http.StatusBadRequest && res.StatusCode!=http.StatusUnprocessableEntity {
		t.Fatalf("invalid WebAuthn registration response not explicitly rejected: HTTP %d",res.StatusCode)
	}
	var current struct {
		Credentials map[string]json.RawMessage `json:"credentials"`
	}
	foundationRequest(t,ctx,client,http.MethodGet,admin+"/admin/identities/"+url.PathEscape(created.Identity.ID),
		nil,"",http.StatusOK,&current)
	if _,exists:=current.Credentials["webauthn"];exists {
		t.Fatal("forged WebAuthn registration created a Kratos credential")
	}
	t.Log("real pinned Kratos WebAuthn settings challenge, invalid assertion denial and original credential absence verified; A3 positive not claimed")
}
