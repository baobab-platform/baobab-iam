package workloadresource

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

type n03LiveOperation struct{operation Operation}
func (r n03LiveOperation) ResolveOperation(_ context.Context,_ *http.Request)(Operation,error){
	return r.operation,nil
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
	// This is a real HTTP resource-server boundary in an isolated test,
	// *not* a separately deployed engine or a native business consequence.
	middleware,err:=NewMiddleware(gate,n03LiveOperation{operation},
		http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
			if r.Header.Get("Authorization")!=""||r.Header.Get("Cookie")!=""{
				w.WriteHeader(http.StatusForbidden);return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	if err!=nil{t.Fatal("cannot construct actual resource HTTP boundary")}
	resource:=httptest.NewServer(middleware)
	defer resource.Close()
	sendToResource:=func(token string)int{
		t.Helper()
		req,err:=http.NewRequestWithContext(ctx,http.MethodPost,resource.URL+"/protected",nil)
		if err!=nil{t.Fatal("cannot make resource request")}
		req.Header.Set("Authorization","Bearer "+token)
		response,err:=client.Do(req)
		if err!=nil{t.Fatal("actual resource transport refused")}
		defer response.Body.Close()
		_,_=io.Copy(io.Discard,io.LimitReader(response.Body,512))
		return response.StatusCode
	}
	claims,err:=verifier.VerifySigned(ctx,raw)
	if err!=nil||claims.ActorType!="workload"||claims.Issuer!=issuer||
		claims.ClientID!="m4-ci-subject"||claims.ExpiresAt.Before(time.Now()){
		t.Fatal("real issuer signature/claims not verified")
	}
	t.Run("real-issued-token-HTTP-resource-accepted",func(t *testing.T){
		if code:=sendToResource(raw);code!=http.StatusNoContent{
			t.Fatalf("actual HTTP resource denied current Hydra/CP token: %d",code)
		}
	})
	t.Run("real-issued-token-and-CP-current-route-accepted",func(t *testing.T){
		if err:=gate.Authorize(ctx,raw,operation);err!=nil{
			t.Fatal("real signed active Hydra token denied by CP current resource fixture")
		}
	})
	t.Run("real-wrong-audience-refused",func(t *testing.T){
		other:=exchange("m4-ci-subject",subjectSecret,"context:resolve","baobab-control-plane")
		if gate.Authorize(ctx,other,operation)==nil||sendToResource(other)!=http.StatusForbidden{t.Fatal("real foreign audience admitted")}
	})
	t.Run("real-tampered-signature-denied-by-resource",func(t *testing.T){
		parts:=strings.Split(raw,".")
		if len(parts)!=3{t.Fatal("real provider JWT shape invalid")}
		sig,err:=base64.RawURLEncoding.DecodeString(parts[2])
		if err!=nil||len(sig)==0{t.Fatal("provider token signature absent")}
		sig[0]^=1
		parts[2]=base64.RawURLEncoding.EncodeToString(sig)
		altered:=strings.Join(parts,".")
		if gate.Authorize(ctx,altered,operation)==nil||sendToResource(altered)!=http.StatusForbidden{
			t.Fatal("tampered original provider signature accepted")
		}
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
	// N04 adds genuine Hydra/CP-source-composed token admission over local TLS.
	// The registration endpoint remains a fixture, NOT a CP PostgreSQL proof.
	n04LiveProviderComponentFixture(t, ctx, raw, validatorToken, issuer, gate, operation, client)
	t.Run("real-issuer-revocation-before-expiry",func(t *testing.T){
		if !time.Now().Before(claims.ExpiresAt){t.Fatal("fixture expired before revocation")}
		form:=url.Values{"token":{raw},"token_type_hint":{"access_token"},
			"client_id":{"m4-ci-subject"},"client_secret":{subjectSecret}}
		request,err:=http.NewRequestWithContext(ctx,http.MethodPost,issuer+"/oauth2/revoke",strings.NewReader(form.Encode()))
		if err!=nil{t.Fatal("invalid real revocation request")}
		request.Header.Set("Content-Type","application/x-www-form-urlencoded")
		response,err:=client.Do(request)
		if err!=nil{t.Fatal("Hydra real revocation unavailable")}
		_,_=io.Copy(io.Discard,io.LimitReader(response.Body,1024))
		response.Body.Close()
		if response.StatusCode!=200&&response.StatusCode!=204{
			t.Fatal("Hydra did not confirm real token revocation")
		}
		// Independently observe the provider's actual inactive=true/false value.
		// A generic issuer 5xx or network failure is NOT revocation proof.
		introspect:=url.Values{"token":{raw}}
		introspectionRequest,err:=http.NewRequestWithContext(ctx,http.MethodPost,
			admin+"/admin/oauth2/introspect",strings.NewReader(introspect.Encode()))
		if err!=nil{t.Fatal("independent issuer readback unavailable")}
		introspectionRequest.Header.Set("Content-Type","application/x-www-form-urlencoded")
		introspectionRequest.SetBasicAuth("m4-ci-validator",validatorSecret)
		readback,err:=client.Do(introspectionRequest)
		if err!=nil{t.Fatal("issuer status readback transport unavailable")}
		var observation struct {Active *bool `json:"active"`}
		e:=json.NewDecoder(io.LimitReader(readback.Body,4096)).Decode(&observation)
		readback.Body.Close()
		if readback.StatusCode!=200||e!=nil||observation.Active==nil||*observation.Active{
			t.Fatal("exact real issuer inactive readback missing")
		}
		if _,err:=status.ReadCurrent(ctx,raw);err==nil{t.Fatal("revoked token still admitted as active issuer status")}
		if gate.Authorize(ctx,raw,operation)==nil{t.Fatal("revoked unexpired token accepted by resource")}
		if code:=sendToResource(raw);code!=http.StatusForbidden{t.Fatal("revoked unexpired token accepted by HTTP resource")}
		if !time.Now().Before(claims.ExpiresAt){t.Fatal("natural expiry substituted for revocation")}
	})
	t.Run("fresh-token-after-specific-revocation-accepted",func(t *testing.T){
		fresh:=exchange("m4-ci-subject",subjectSecret,"context:resolve","baobab-erp")
		if fresh==raw{t.Fatal("new provider token replayed same bearer")}
		if err:=gate.Authorize(ctx,fresh,operation);err!=nil{t.Fatal("fresh issuer/CP control denied")}
	})
	if t.Failed(){return}
	// Record the exact executed checkout, not the requested branch or an
	// invented run identifier. CI pull_request may check out a merge SHA.
	currentSource:=strings.TrimSpace(os.Getenv("GITHUB_SHA"))
	if currentSource=="" {
		actual,err:=exec.Command("git","rev-parse","HEAD").Output()
		if err!=nil{t.Fatal("actual executed source cannot be determined")}
		currentSource=strings.TrimSpace(string(actual))
	}
	if !regexp.MustCompile("^[a-f0-9]{40}$").MatchString(currentSource){
		t.Fatal("immutable executed source SHA unavailable")
	}
	report:=map[string]any{
		"executed_source_sha":currentSource,
		"cp_consumer_source_sha":"c84063cb07dce76e1ffac4b12fa29c5e4e5ec855",
		"fixture_only":true,
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
	}
	if root:=os.Getenv("ORY_M4_EVIDENCE_DIR");root!=""{
		payload,err:=json.MarshalIndent(report,"","  ")
		if err!=nil{t.Fatal("safe evidence encoding failed")}
		if err:=os.WriteFile(filepath.Join(root,"n03-resource-acceptance.json"),append(payload,'\n'),0600);err!=nil{
			t.Fatal("safe evidence write failed")
		}
	}
}
