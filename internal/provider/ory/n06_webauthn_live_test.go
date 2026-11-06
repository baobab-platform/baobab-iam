package ory_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
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
	// WebAuthn is not offered as a native API flow in this Ory release.
	// Establish an ACTUAL Kratos browser cookie via password login, keep the
	// host-only cookie and anti-CSRF cookie, then inspect the browser settings.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("browser cookie jar unavailable")
	}
	browser := &http.Client{Jar: jar, Timeout: 10*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	loginID := n06BrowserFlowID(t, ctx, browser, pub, "login")
	var login struct {
		UI struct {
			Nodes []struct {
				Attributes struct {
					Name string `json:"name"`
					Value string `json:"value"`
				} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}
	n06BrowserReadFlow(t, ctx, browser, pub, "login", loginID, &login)
	csrf := ""
	for _, node := range login.UI.Nodes {
		if node.Attributes.Name == "csrf_token" {
			csrf = node.Attributes.Value
		}
	}
	if len(csrf) < 20 {
		t.Fatal("real browser CSRF form field not observed")
	}
	form := url.Values{
		"method":{"password"}, "identifier":{email},
		"password":{password}, "csrf_token":{csrf},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pub+"/self-service/login?flow="+url.QueryEscape(loginID), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal("real browser login form invalid")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := browser.Do(req)
	if err != nil {
		t.Fatal("real browser Kratos password login transport unavailable")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther && response.StatusCode != http.StatusOK {
		t.Fatalf("real browser Kratos password login refused: HTTP %d", response.StatusCode)
	}
	// Readback via browser cookies, NEVER the earlier API session token.
	read, err := http.NewRequestWithContext(ctx, http.MethodGet, pub+"/sessions/whoami", nil)
	if err != nil {
		t.Fatal("read browser Kratos session")
	}
	alive, err := browser.Do(read)
	if err != nil {
		t.Fatal("browser Kratos session not reachable")
	}
	defer alive.Body.Close()
	if alive.StatusCode != http.StatusOK {
		t.Fatal("browser cookie did not establish a real Kratos session")
	}
	settingsID := n06BrowserFlowID(t, ctx, browser, pub, "settings")
	var settings struct {
		UI struct {
			Nodes []struct {
				Group string `json:"group"`
				Attributes struct {
					Name string `json:"name"`
					Value string `json:"value"`
				} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}
	n06BrowserReadFlow(t, ctx, browser, pub, "settings", settingsID, &settings)
	found := false
	settingsCSRF := ""
	var passwordNodes, passkeyNodes, totpNodes int
	for _, node := range settings.UI.Nodes {
		if node.Attributes.Name == "csrf_token" {
			settingsCSRF = node.Attributes.Value
		}
		if node.Group=="webauthn" || strings.HasPrefix(node.Attributes.Name,"webauthn_") {
			found = true
		}
		switch node.Group {
		case "password":
			passwordNodes++
		case "passkey":
			passkeyNodes++
		case "totp":
			totpNodes++
		}
	}
	if !found {
		t.Fatalf("real Kratos browser WebAuthn challenge missing: password=%d passkey=%d totp=%d",
			passwordNodes,passkeyNodes,totpNodes)
	}
	if len(settingsCSRF) < 20 { t.Fatal("current settings flow CSRF absent") }
	// A browser must generate real WebAuthn attestation, not a form string.
	// Invalid registration is refused; the native provider must remain
	// credential-free under independent Admin API readback below.
	fields := url.Values{
		"method":{"webauthn"}, "webauthn_register":{"forged-no-authenticator"},
		"csrf_token":{settingsCSRF},
	}
	negative, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pub+"/self-service/settings?flow="+url.QueryEscape(settingsID),
		strings.NewReader(fields.Encode()))
	if err != nil { t.Fatal("invalid browser negative construction") }
	negative.Header.Set("Content-Type","application/x-www-form-urlencoded")
	reply, err := browser.Do(negative)
	if err != nil { t.Fatal("real browser WebAuthn negative transport failed") }
	reply.Body.Close()
	if reply.StatusCode < 300 && reply.StatusCode != http.StatusOK {
		t.Fatal("unexpected Kratos malformed WebAuthn protocol response")
	}
	if reply.StatusCode == http.StatusOK {
		t.Fatal("forged browser registration returned a success status")
	}
	var current struct {
		Credentials map[string]json.RawMessage `json:"credentials"`
	}
	foundationRequest(t,ctx,client,http.MethodGet,admin+"/admin/identities/"+url.PathEscape(created.Identity.ID),
		nil,"",http.StatusOK,&current)
	if _, exists:=current.Credentials["webauthn"];exists {
		t.Fatal("forged browser WebAuthn registration persisted a credential")
	}
	t.Log("real pinned Kratos browser settings WebAuthn challenge, forged browser denial and credential absence verified; A3 positive not claimed")
}

func n06BrowserFlowID(t *testing.T, ctx context.Context, client *http.Client, origin, name string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx,http.MethodGet,
		origin+"/self-service/"+name+"/browser",nil)
	if err != nil { t.Fatal("Kratos browser flow request invalid") }
	res, err := client.Do(req)
	if err != nil { t.Fatal("Kratos browser flow not reachable") }
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("Kratos did not issue browser flow redirect for %s: %d",name,res.StatusCode)
	}
	redirect,err:=url.Parse(res.Header.Get("Location"))
	if err!=nil || redirect==nil ||
		redirect.Scheme!="http" || redirect.Host!="127.0.0.1:4455" ||
		redirect.Path!="/"+name || redirect.User!=nil || redirect.Fragment!="" {
		t.Fatal("Kratos browser flow redirected to unreviewed UI")
	}
	id:=redirect.Query().Get("flow")
	if len(id)!=36 {t.Fatal("Kratos browser flow missing bounded ID")}
	return id
}
func n06BrowserReadFlow(t *testing.T,ctx context.Context,client *http.Client,
	origin,name,id string,out any) {
	t.Helper()
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,
		origin+"/self-service/"+name+"/flows?id="+url.QueryEscape(id),nil)
	if err!=nil{t.Fatal("invalid Kratos browser readback")}
	req.Header.Set("Accept","application/json")
	resp,err:=client.Do(req)
	if err!=nil{t.Fatal("browser Kratos CSRF-bound flow readback unavailable")}
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK {
		t.Fatalf("Kratos browser flow not current: HTTP %d",resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body,128*1024)).Decode(out)!=nil {
		t.Fatal("Kratos browser form was not valid JSON")
	}
}
