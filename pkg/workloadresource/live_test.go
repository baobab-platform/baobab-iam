package workloadresource

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// n03ConsumerFixture invokes the real, immutable CP production router via
// Infrastructure's existing pinned CP consumer probe binary. That binary
// supplies synthetic in-memory CP fixture state: this proves source-level
// resource behavior, NOT a deployed/protected CP/Trade service.
type n03ConsumerFixture struct {
	probe string
	validator string
	scenario string
}
func (a *n03ConsumerFixture) AuthorizeCurrent(ctx context.Context, raw string, claim Claims, op Operation) error {
	if a == nil || claim.ActorType != "workload" || claim.ClientID == "" ||
		op.TenantID != "tn_m4fixture" || op.ResourceOperation != "context.validate" {
		return ErrDenied
	}
	payload,err:=json.Marshal(map[string]string{
		"validator":a.validator, "subject":raw, "scenario":a.scenario,
	})
	if err!=nil{return ErrDenied}
	command:=exec.CommandContext(ctx,a.probe)
	command.Stdin=bytes.NewReader(payload)
	output,err:=command.Output()
	if err!=nil||len(output)>16384{return ErrDenied}
	var decision struct {
		Status int `json:"status"`
		ContextMatches bool `json:"context_matches"`
		CredentialsAbsent bool `json:"credentials_absent"`
		NoStore bool `json:"no_store"`
	}
	if json.Unmarshal(output,&decision)!=nil||decision.Status!=200||
		!decision.ContextMatches||!decision.CredentialsAbsent||!decision.NoStore {
		return ErrDenied
	}
	return nil
}

// TestLiveN03HydraCPResourceAcceptance is deliberately opt-in, with no mock
// issuer fallback. It runs *only* in the disposable Ory Foundation hook with
// a real signed Hydra token and the CP consumer's actual API implementation.
// The pure-source tests cannot count it as an executed L4 case.
func TestLiveN03HydraCPResourceAcceptance(t *testing.T) {
	if os.Getenv("ORY_TOKEN_PROFILE")!="1" || os.Getenv("ORY_WORKLOAD")!="1" ||
		os.Getenv("ORY_CP_ROUTE_PROBE")=="" {
		t.Skip("requires actual disposable Hydra and CP current-route consumer")
	}
	const issuer="http://127.0.0.1:4444"
	const admin="http://127.0.0.1:4445"
	if os.Getenv("ORY_PUBLIC_ISSUER")!=issuer ||
		os.Getenv("ORY_HYDRA_ADMIN_URL")!=admin {
		t.Fatal("N03 live fixture issuer/admin is not disposable loopback")
	}
	ctx,cancel:=context.WithTimeout(context.Background(),110*time.Second)
	defer cancel()
	client:=&http.Client{Timeout:8*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
	adapter,err:=ory.NewAdapter(ory.Config{
		KratosAdminURL:"http://127.0.0.1:4434",HydraAdminURL:admin,
		PublicIssuer:issuer,HTTPClient:client,
	})
	if err!=nil{t.Fatal("N03 provider fixture unavailable")}
	provision:=func(id,scope string,aud []string)string{
		t.Helper()
		w,err:=adapter.ProvisionWorkload(ctx,provider.WorkloadProvisioningSpec{
			LogicalClientID:id,AllowedScopes:[]string{scope},Audiences:aud,
			AuthMethod:provider.WorkloadAuthClientSecret,
		})
		if err!=nil{t.Fatal("Hydra real fixture workload not provisioned")}
		t.Cleanup(func(){
			deleteCtx,stop:=context.WithTimeout(context.Background(),8*time.Second)
			defer stop()
			req,_:=http.NewRequestWithContext(deleteCtx,http.MethodDelete,admin+"/admin/clients/"+url.PathEscape(id),nil)
			resp,err:=client.Do(req)
			if err!=nil||resp.StatusCode!=204{
				t.Error("real Hydra client teardown failed")
				if resp!=nil{resp.Body.Close()}
				return
			}
			resp.Body.Close()
			get,_:=http.NewRequestWithContext(deleteCtx,http.MethodGet,admin+"/admin/clients/"+url.PathEscape(id),nil)
			resp,err=client.Do(get)
			if err!=nil||resp.StatusCode!=404{t.Error("real Hydra client remained after teardown")}
			if resp!=nil{resp.Body.Close()}
		})
		if len(w.ClientSecret)<32{t.Fatal("short Hydra confidential client credential")}
		return w.ClientSecret
	}
	subjectSecret:=provision("m4-ci-subject","context:resolve",[]string{"baobab-erp","baobab-control-plane"})
	validatorSecret:=provision("m4-ci-validator","context:validate",[]string{"baobab-control-plane"})
	exchange:=func(id,secret,scope,audience string)string{
		t.Helper()
		form:=url.Values{"grant_type":{"client_credentials"},"client_id":{id},
			"client_secret":{secret},"scope":{scope},"audience":{audience}}
		request,err:=http.NewRequestWithContext(ctx,"POST",issuer+"/oauth2/token",strings.NewReader(form.Encode()))
		if err!=nil{t.Fatal("cannot form issuer request")}
		request.Header.Set("Content-Type","application/x-www-form-urlencoded")
		response,err:=client.Do(request)
		if err!=nil{t.Fatal("Hydra real token endpoint unavailable")}
		defer response.Body.Close()
		var result struct {
			AccessToken string `json:"access_token"`
			ExpiresIn int `json:"expires_in"`
			TokenType string `json:"token_type"`
		}
		if response.StatusCode!=200||json.NewDecoder(io.LimitReader(response.Body,1<<16)).Decode(&result)!=nil||
			result.AccessToken==""||result.ExpiresIn<30||result.ExpiresIn>900||!strings.EqualFold(result.TokenType,"bearer"){
			t.Fatal("Hydra did not issue correctly bounded real workload bearer")
		}
		return result.AccessToken
	}
	validatorToken:=exchange("m4-ci-validator",validatorSecret,"context:validate","baobab-control-plane")
	raw:=exchange("m4-ci-subject",subjectSecret,"context:resolve","baobab-erp")
	verifier,err:=newSignedVerifier(issuer,"baobab-erp",client,true)
	if err!=nil{t.Fatal("real signed verifier could not be constructed")}
	// This issuer fixture uses the trusted local admin endpoint. The
	// protected constructor separately refuses HTTP and unapproved clients.
	status:=&RFC7662Introspector{endpoint:admin+"/admin/oauth2/introspect",
		clientID:"m4-ci-validator",secret:validatorSecret,client:client}
	current:=&n03ConsumerFixture{probe:os.Getenv("ORY_CP_ROUTE_PROBE"),
		validator:validatorToken,scenario:"owned"}
	gate,err:=newGate(Profile{Issuer:issuer,Audience:"baobab-erp",
		RequiredScopes:[]string{"context:resolve"},AllowedClients:[]string{"m4-ci-subject"},
		MaxTokenAge:15*time.Minute},verifier,status,current,true)
	if err!=nil{t.Fatal("real resource verifier profile refused")}
	operation:=Operation{ContextID:"cp-generated-by-pinned-probe",
		TenantID:"tn_m4fixture",ResourceOperation:"context.validate"}
	claims,err:=verifier.VerifySigned(ctx,raw)
	if err!=nil||claims.ActorType!="workload"||claims.Issuer!=issuer||
		claims.ClientID!="m4-ci-subject"||claims.ExpiresAt.Before(time.Now()){
		t.Fatal("real issuer signature/claims not verified")
	}
	t.Run("real-issued-token-and-CP-current-route-accepted",func(t *testing.T){
		if err:=gate.Authorize(ctx,raw,operation);err!=nil{
			t.Fatal("real signed active Hydra token denied by CP current resource fixture")
		}
	})
	t.Run("real-wrong-audience-refused",func(t *testing.T){
		other:=exchange("m4-ci-subject",subjectSecret,"context:resolve","baobab-control-plane")
		if gate.Authorize(ctx,other,operation)==nil{t.Fatal("real foreign audience admitted")}
	})
	t.Run("CP-other-owner-denied-with-unexpired-bearer",func(t *testing.T){
		current.scenario="other-owner"
		if gate.Authorize(ctx,raw,operation)==nil{t.Fatal("CP foreign-owner resource admitted")}
		current.scenario="owned"
	})
	t.Run("CP-revoked-external-link-denied-while-issuer-active",func(t *testing.T){
		current.scenario="revoked-external-link"
		if gate.Authorize(ctx,raw,operation)==nil{t.Fatal("revoked CP identity link admitted")}
		current.scenario="owned"
		if _,err:=status.ReadCurrent(ctx,raw);err!=nil{t.Fatal("CP-only revocation misattributed to issuer")}
	})
	t.Run("CP-suspended-tenant-denied",func(t *testing.T){
		current.scenario="suspended-tenant"
		if gate.Authorize(ctx,raw,operation)==nil{t.Fatal("suspended CP tenant admitted")}
		current.scenario="owned"
	})
	t.Run("real-issuer-revocation-before-expiry",func(t *testing.T){
		if !time.Now().Before(claims.ExpiresAt){t.Fatal("fixture expired before revocation")}
		form:=url.Values{"token":{raw},"token_type_hint":{"access_token"}}
		request,err:=http.NewRequestWithContext(ctx,http.MethodPost,issuer+"/oauth2/revoke",strings.NewReader(form.Encode()))
		if err!=nil{t.Fatal("invalid real revocation request")}
		request.SetBasicAuth("m4-ci-subject",subjectSecret)
		request.Header.Set("Content-Type","application/x-www-form-urlencoded")
		response,err:=client.Do(request)
		if err!=nil{t.Fatal("Hydra real revocation unavailable")}
		_,_=io.Copy(io.Discard,io.LimitReader(response.Body,1024))
		response.Body.Close()
		if response.StatusCode!=200&&response.StatusCode!=204{
			t.Fatal("Hydra did not confirm real token revocation")
		}
		if _,err:=status.ReadCurrent(ctx,raw);err==nil{t.Fatal("revoked token still active at issuer")}
		if gate.Authorize(ctx,raw,operation)==nil{t.Fatal("revoked unexpired token accepted by resource")}
		if !time.Now().Before(claims.ExpiresAt){t.Fatal("natural expiry substituted for revocation")}
	})
	t.Run("fresh-token-after-specific-revocation-accepted",func(t *testing.T){
		fresh:=exchange("m4-ci-subject",subjectSecret,"context:resolve","baobab-erp")
		if fresh==raw{t.Fatal("new provider token replayed same bearer")}
		if err:=gate.Authorize(ctx,fresh,operation);err!=nil{t.Fatal("fresh issuer/CP control denied")}
	})
	if t.Failed(){return}
	var marker [32]byte
	if _,err:=rand.Read(marker[:]);err!=nil{t.Fatal("evidence nonce unavailable")}
	report:=map[string]any{
		"classification":"REAL_COMPONENT_SYNTHETIC_DATA",
		"scope":"N03_NATIVE_HYDRA_CP_SOURCE_FIXTURE",
		"actual_provider_issuer":true,
		"actual_cp_router_from_immutable_consumer":true,
		"deployed_resource_tested":false,
		"protected_accepted":false,
		"canonical_provider_support_promoted":false,
		"issuer_revocation_before_expiry":true,
		"cross_tenant_cp_denial_observed":true,
		"credentials_absent":true,
		"run_nonce_digest":base64.RawURLEncoding.EncodeToString(marker[:]),
	}
	if root:=os.Getenv("ORY_M4_EVIDENCE_DIR");root!=""{
		payload,err:=json.MarshalIndent(report,"","  ")
		if err!=nil{t.Fatal("safe evidence encoding failed")}
		if err:=os.WriteFile(filepath.Join(root,"n03-resource-acceptance.json"),append(payload,'\n'),0600);err!=nil{
			t.Fatal("safe evidence write failed")
		}
	}
}
var _ = errors.New
