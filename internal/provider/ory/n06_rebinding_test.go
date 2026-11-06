package ory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

const n06RebindUser = "11000000-2200-4300-8400-550000000000"

type n06RebindReviewer struct{
	approved bool
	oldHold bool
}
func (r n06RebindReviewer) CurrentWebAuthnRebind(_ context.Context, s provider.ExternalSubject) (ory.NativeCredentialRebindEvidence,error) {
	if !r.approved{return ory.NativeCredentialRebindEvidence{},errors.New("not approved")}
	hold:=time.Now().UTC().Add(25*time.Hour)
	if r.oldHold{hold=time.Now().UTC().Add(2*time.Hour)}
	return ory.NativeCredentialRebindEvidence{
		OriginalRecoveryReference:"ref_actualrecoveryproof",
		RequestedByReference:"ref_currentrequester",
		IndependentReviewerReference:"ref_differentreviewer",
		CurrentSecurityDecisionReference:"ref_governedriskdecision",
		Issuer:s.Issuer,Subject:s.Subject,
		ObservedAt:time.Now().UTC().Add(-time.Second),
		HoldUntil:hold,
		Approved:true,DistinctReviewer:true,CurrentSecurityHold:true,
	},nil
}

func TestN06KratosRebindRequiresTwoPersonHoldAndActualCredentialWithdrawal(t *testing.T){
	for _,tc:=range []struct{
		name string
		reviewer n06RebindReviewer
		credential bool
		passkey bool
		refuseDelete bool
		stillWebAuthn bool
		sessionSurvives bool
		expectSuccess bool
	}{
		{name:"governed-native-rebinding",reviewer:n06RebindReviewer{approved:true},credential:true,expectSuccess:true},
		{name:"review-missing",reviewer:n06RebindReviewer{},credential:true},
		{name:"recovery-hold-too-short",reviewer:n06RebindReviewer{approved:true,oldHold:true},credential:true},
		{name:"no-old-credential",reviewer:n06RebindReviewer{approved:true}},
		{name:"provider-passkey-not-deletable",reviewer:n06RebindReviewer{approved:true},credential:true,passkey:true},
		{name:"revoke-sessions-not-effective",reviewer:n06RebindReviewer{approved:true},credential:true,sessionSurvives:true},
		{name:"provider-delete-rejected",reviewer:n06RebindReviewer{approved:true},credential:true,refuseDelete:true},
		{name:"deletion-not-persisted",reviewer:n06RebindReviewer{approved:true},credential:true,stillWebAuthn:true},
	} {
		t.Run(tc.name,func(t *testing.T){
			state:="active"
			hasCredential:=tc.credential
			deleteCount:=0
			revokeCount:=0
			server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
				base:="/admin/identities/"+n06RebindUser
				var response any
				switch {
				case r.Method==http.MethodGet && r.URL.Path==base:
					type credential struct{Config map[string]any `json:"config"`}
					creds:=map[string]credential{}
					if hasCredential {
						creds["webauthn"]=credential{Config:map[string]any{
							"credentials":[]any{map[string]any{"id":"test-kratos-credential"}},
						}}
					}
					if tc.passkey {
						creds["passkey"]=credential{Config:map[string]any{
							"credentials":[]any{map[string]any{"id":"untouched-passkey"}},
						}}
					}
					response=map[string]any{"id":n06RebindUser,"state":state,"credentials":creds}
				case r.Method==http.MethodPatch && r.URL.Path==base:
					state="inactive"
					w.WriteHeader(http.StatusNoContent)
					return
				case r.Method==http.MethodDelete && r.URL.Path==base+"/sessions":
					revokeCount++
					w.WriteHeader(http.StatusNoContent)
					return
				case r.Method==http.MethodGet && r.URL.Path==base+"/sessions":
					if tc.sessionSurvives {response=[]map[string]any{{"active":true,"id":"session-still-active"}}} else {response=[]any{}}
				case r.Method==http.MethodDelete && r.URL.Path==base+"/credentials/webauthn":
					deleteCount++
					if tc.refuseDelete {w.WriteHeader(http.StatusServiceUnavailable);return}
					if !tc.stillWebAuthn {hasCredential=false}
					w.WriteHeader(http.StatusNoContent)
					return
				default:
					http.NotFound(w,r)
					return
				}
				w.Header().Set("Content-Type","application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			a,err:=ory.NewAdapter(ory.Config{
				KratosAdminURL:server.URL,HydraAdminURL:server.URL,
				PublicIssuer:"https://issuer.example.test",HTTPClient:server.Client(),
			})
			if err!=nil{t.Fatal(err)}
			result,err:=a.BeginNativeWebAuthnRebind(context.Background(),
				provider.ExternalSubject{Issuer:"https://issuer.example.test",Subject:n06RebindUser},
				tc.reviewer,time.Now)
			if (err==nil)!=tc.expectSuccess {
				t.Fatalf("rebinding accepted insecure outcome or rejected complete provider state: %v",err)
			}
			if tc.expectSuccess {
				if !result.IdentityDisabled||!result.AllSessionsRevoked||!result.OldWebAuthnRemoved||
					!result.RecoveryHoldObserved||!result.NativeReenrolmentRequired||
					state!="inactive"||hasCredential||deleteCount!=1||revokeCount!=1 {
					t.Fatal("native rebinding did not fully invalidate old credentials/sessions")
				}
			}
			if !tc.reviewer.approved||tc.reviewer.oldHold||!tc.credential||tc.passkey {
				if deleteCount!=0 || revokeCount!=0 || state!="active" {
					t.Fatal("unsupported/missing review already mutated native account")
				}
			}
		})
	}
}
