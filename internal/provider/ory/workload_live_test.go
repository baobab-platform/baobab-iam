package ory_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

const bearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type workloadProfile struct {
	CredentialType string `json:"credential_type"`
	Status string `json:"status"`
	Scopes []string `json:"allowed_scopes"`
	Audiences []string `json:"allowed_audiences"`
}

type workloadFixture struct {
	ctx context.Context
	client *http.Client
	adapter *ory.Adapter
	issuer, admin string
	profiles map[string]workloadProfile
}

func newWorkloadFixture(t *testing.T) *workloadFixture {
	t.Helper()
	if os.Getenv("ORY_WORKLOAD") != "1" { t.Skip("set ORY_WORKLOAD=1 with the isolated pinned Ory stack") }
	file, err := os.Open(os.Getenv("ORY_M4_PROFILES_FILE"))
	if err != nil { t.Fatal("load pinned Shared workload fixture profiles") }
	defer file.Close()
	var profiles struct { SharedCommit string `json:"shared_commit"`; Workloads map[string]workloadProfile `json:"workloads"` }
	if err := json.NewDecoder(file).Decode(&profiles); err != nil || len(profiles.SharedCommit) != 40 { t.Fatal("invalid pinned workload fixture profiles") }
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	f := &workloadFixture{ctx:ctx, client:&http.Client{Timeout:10*time.Second}, issuer:envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444"), admin:envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445"), profiles:profiles.Workloads}
	f.adapter, err = ory.NewAdapter(ory.Config{KratosAdminURL:envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434"), HydraAdminURL:f.admin, PublicIssuer:f.issuer, HTTPClient:f.client})
	if err != nil { t.Fatal("construct Ory workload adapter") }
	return f
}

func (f *workloadFixture) profile(t *testing.T, id, credentialType string) workloadProfile {
	t.Helper()
	p, ok := f.profiles[id]
	if !ok || p.CredentialType != credentialType || len(p.Scopes) == 0 || len(p.Audiences) == 0 { t.Fatal("workload fixture differs from pinned Shared profile") }
	return p
}

func (f *workloadFixture) cleanup(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		foundationRequest(t, ctx, f.client, http.MethodDelete, f.admin+path, nil, "", http.StatusNoContent, nil)
	})
}

type workloadToken struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int `json:"expires_in"`
	Scope string `json:"scope"`
	Error string `json:"error"`
}

// Only OAuth status/error codes are logged. Bodies may carry live credentials.
func (f *workloadFixture) exchange(t *testing.T, form url.Values, denied bool) workloadToken {
	t.Helper()
	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil { t.Fatal("construct workload exchange") }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil { t.Fatal("workload exchange transport failure") }
	defer resp.Body.Close()
	var token workloadToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil { t.Fatal("decode OAuth exchange response") }
	if denied {
		// A server failure, malformed response or HTTP 200 is not rejection proof.
		if (resp.StatusCode != 400 && resp.StatusCode != 401) || token.Error == "" || token.AccessToken != "" { t.Fatalf("expected OAuth rejection, received HTTP %d", resp.StatusCode) }
	} else if resp.StatusCode != 200 || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 3600 {
		t.Fatalf("expected bounded bearer token, received HTTP %d", resp.StatusCode)
	}
	return token
}

func secretForm(id, secret, scope string) url.Values {
	return url.Values{"grant_type":{"client_credentials"}, "client_id":{id}, "client_secret":{secret}, "scope":{scope}}
}

func TestLiveWorkloadClientCredentials(t *testing.T) {
	f := newWorkloadFixture(t)
	const id = "baobab-trade-workload"
	p := f.profile(t, id, "client_credentials")
	// These IDs exist only inside the disposable issuer. No registry is changed.
	w, err := f.adapter.ProvisionWorkload(f.ctx, provider.WorkloadProvisioningSpec{LogicalClientID:id, AllowedScopes:p.Scopes, Audiences:p.Audiences, AuthMethod:provider.WorkloadAuthClientSecret})
	if err != nil { t.Fatal("provision client-credentials fixture") }
	f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
	if w.ClientSecret == "" || w.AuthMethod != provider.WorkloadAuthClientSecret || w.LifecycleStatus != provider.WorkloadStatusProvisioned { t.Fatal("incorrect provider workload result") }
	ref := provider.ProviderWorkloadReference{LogicalClientID:id}
	t.Run("signed-token-and-shared-scopes", func(t *testing.T) {
		token := f.exchange(t, secretForm(id, w.ClientSecret, strings.Join(p.Scopes," ")), false)
		claims := f.verify(t, token, p.Scopes, id)
		if claims["sub"] != id { t.Fatal("client-credentials subject is not stable client ID") }
		f.recordProfile(t, id, p, claims)
	})
	t.Run("invalid-credential-and-scope", func(t *testing.T) {
		f.exchange(t, secretForm(id, "invalid-ci-credential", p.Scopes[0]), true)
		f.exchange(t, secretForm(id, w.ClientSecret, "billing:manage"), true)
	})
	t.Run("rotation-invalidates-old-credential", func(t *testing.T) {
		rotated, err := f.adapter.RotateWorkloadCredentials(f.ctx, ref)
		if err != nil || rotated.ClientSecret == "" || rotated.ClientSecret == w.ClientSecret { t.Fatal("rotate workload credential") }
		f.exchange(t, secretForm(id, w.ClientSecret, p.Scopes[0]), true)
		f.verify(t, f.exchange(t, secretForm(id, rotated.ClientSecret, p.Scopes[0]), false), []string{p.Scopes[0]}, id)
		w = rotated
	})
	t.Run("suspend-denies-future-issuance", func(t *testing.T) {
		if err := f.adapter.SuspendWorkload(f.ctx, ref); err != nil { t.Fatal("suspend provider issuance") }
		f.exchange(t, secretForm(id, w.ClientSecret, p.Scopes[0]), true)
	})
}

func TestLiveWorkloadFederated(t *testing.T) {
	f := newWorkloadFixture(t)
	for _, id := range []string{"baobab-cp-workload", "baobab-subscriptions-workload"} {
		t.Run(id, func(t *testing.T) {
			p := f.profile(t, id, "federated_workload_token")
			if p.Status != "PROVISIONED" { t.Fatal("federated fixture is no longer PROVISIONED at Shared pin; review activation evidence") }
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil { t.Fatal("generate disposable projected-assertion signer") }
			kid := "m4-ci-"+randomFixtureID(t)
			assertionIssuer := "https://projected.m4-ci.invalid/"+id
			subject := "system:serviceaccount:m4-ci:"+id
			jwk := map[string]any{"kty":"RSA", "use":"sig", "alg":"RS256", "kid":kid, "n":base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e":base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
			spec := provider.FederatedWorkloadTrustSpec{LogicalClientID:id, AllowedScopes:p.Scopes, IntendedAudiences:p.Audiences, AssertionIssuer:assertionIssuer, AssertionSubject:subject, AssertionJWK:jwk, TrustExpiresAt:time.Now().UTC().Add(15*time.Minute).Truncate(time.Second)}
			trust, err := f.adapter.ProvisionFederatedWorkload(f.ctx, spec)
			if err != nil { t.Fatal("provision exact issuer/subject federation trust") }
			f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
			if trust.TrustID == "" || trust.AuthMethod != provider.WorkloadAuthFederatedJWTBearer || trust.LifecycleStatus != provider.WorkloadStatusProvisioned { t.Fatal("incorrect provider trust result") }
			f.cleanup(t, "/admin/trust/grants/jwt-bearer/issuers/"+url.PathEscape(trust.TrustID))
			var observed struct { AuthMethod string `json:"token_endpoint_auth_method"`; Secret string `json:"client_secret"`; Grants []string `json:"grant_types"` }
			foundationRequest(t, f.ctx, f.client, http.MethodGet, f.admin+"/admin/clients/"+id, nil,"",200,&observed)
			if observed.AuthMethod != "none" || observed.Secret != "" || !reflect.DeepEqual(observed.Grants, []string{bearerGrant}) { t.Fatal("federated client has a credential downgrade") }
			newClaims := func() map[string]any {
				now := time.Now().Unix()
				return map[string]any{"iss":assertionIssuer, "sub":subject, "aud":[]string{f.issuer+"/oauth2/token"}, "iat":now-5, "nbf":now-5, "exp":now+120, "jti":randomFixtureID(t)}
			}
			form := func(assertion, scope string) url.Values { return url.Values{"grant_type":{bearerGrant}, "client_id":{id}, "assertion":{assertion}, "scope":{scope}} }
			t.Run("signed-exchange-and-replay-rejected", func(t *testing.T) {
				assertion := signAssertion(t,key,kid,newClaims())
				token := f.exchange(t, form(assertion,strings.Join(p.Scopes," ")), false)
				claims := f.verify(t,token,p.Scopes,id)
				if claims["sub"] != subject { t.Fatal("federated token lost exact assertion subject") }
				f.recordProfile(t,id,p,claims)
				f.exchange(t, form(assertion,p.Scopes[0]),true)
			})
			for _, name := range []string{"issuer", "subject", "audience", "expired", "not-yet-valid", "signature", "scope"} {
				t.Run("reject-"+name, func(t *testing.T) {
					claims := newClaims(); signer := key; scope := p.Scopes[0]
					switch name {
					case "issuer": claims["iss"] = "https://untrusted.invalid"
					case "subject": claims["sub"] = "wrong-service-account"
					case "audience": claims["aud"] = []string{"https://wrong-token-endpoint.invalid"}
					case "expired": claims["exp"] = time.Now().Unix()-120
					case "not-yet-valid": claims["nbf"] = time.Now().Unix()+120
					case "signature": signer, err = rsa.GenerateKey(rand.Reader,2048); if err != nil { t.Fatal("generate invalid assertion signer") }
					case "scope": scope = "context:resolve"
					}
					f.exchange(t,form(signAssertion(t,signer,kid,claims),scope),true)
				})
			}
			t.Run("no-static-secret-downgrade", func(t *testing.T) {
				if _, err := f.adapter.RotateWorkloadCredentials(f.ctx,provider.ProviderWorkloadReference{LogicalClientID:id}); err == nil { t.Fatal("federated secret rotation accepted") }
				f.exchange(t,secretForm(id,"invalid-ci-credential",p.Scopes[0]),true)
			})
			t.Run("revoke-denies-future-exchange", func(t *testing.T) {
				if err := f.adapter.RevokeWorkload(f.ctx,provider.ProviderWorkloadReference{LogicalClientID:id}); err != nil { t.Fatal("revoke provider issuance") }
				f.exchange(t,form(signAssertion(t,key,kid,newClaims()),p.Scopes[0]),true)
			})
		})
	}
}

func randomFixtureID(t *testing.T) string {
	t.Helper(); b := make([]byte,16)
	if _, err := rand.Read(b); err != nil { t.Fatal("generate fixture entropy") }
	return hex.EncodeToString(b)
}

func signAssertion(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg":"RS256", "typ":"JWT", "kid":kid})
	if err != nil { t.Fatal("encode assertion header") }
	body, err := json.Marshal(claims)
	if err != nil { t.Fatal("encode assertion claims") }
	unsigned := base64.RawURLEncoding.EncodeToString(header)+"."+base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader,key,crypto.SHA256,digest[:])
	if err != nil { t.Fatal("sign fixture assertion") }
	return unsigned+"."+base64.RawURLEncoding.EncodeToString(sig)
}

// This verifier is a test oracle only, never an IAM authorization endpoint.
// The issuer/JWKS origin is fixed by the fixture, not an untrusted JWT header.
func (f *workloadFixture) verify(t *testing.T, token workloadToken, scopes []string, id string) map[string]any {
	t.Helper()
	parts := strings.Split(token.AccessToken,".")
	if len(parts) != 3 { t.Fatal("access token is not a signed JWT") }
	decode := func(part string, target any) {
		b, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || json.Unmarshal(b,target) != nil { t.Fatal("invalid JWT encoding") }
	}
	var header struct { Alg string `json:"alg"`; KID string `json:"kid"`; Crit []string `json:"crit"` }
	decode(parts[0],&header)
	if header.Alg != "RS256" || header.KID == "" || len(header.Crit) != 0 { t.Fatal("unexpected JWT signing header") }
	var jwks struct { Keys []struct { KTY string `json:"kty"`; KID string `json:"kid"`; N string `json:"n"`; E string `json:"e"` } `json:"keys"` }
	foundationRequest(t,f.ctx,f.client,http.MethodGet,f.issuer+"/.well-known/jwks.json",nil,"",200,&jwks)
	var publicKey *rsa.PublicKey
	for _, key := range jwks.Keys {
		if key.KID != header.KID { continue }
		if publicKey != nil || key.KTY != "RSA" { t.Fatal("ambiguous or unsupported signing key") }
		n, errN := base64.RawURLEncoding.DecodeString(key.N); e, errE := base64.RawURLEncoding.DecodeString(key.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 { t.Fatal("invalid public signing key") }
		exponent := new(big.Int).SetBytes(e).Int64()
		publicKey = &rsa.PublicKey{N:new(big.Int).SetBytes(n),E:int(exponent)}
		if publicKey.N.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 { t.Fatal("weak public signing key") }
	}
	if publicKey == nil { t.Fatal("access-token signing key absent from public JWKS") }
	sig, err := base64.RawURLEncoding.DecodeString(parts[2]); digest := sha256.Sum256([]byte(parts[0]+"."+parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(publicKey,crypto.SHA256,digest[:],sig) != nil { t.Fatal("invalid access-token signature") }
	var claims map[string]any; decode(parts[1],&claims)
	if claims["iss"] != f.issuer+"/" && claims["iss"] != f.issuer { t.Fatal("wrong token issuer") }
	if claims["client_id"] != id { t.Fatal("token lost stable workload client ID") }
	exp, okExp := claims["exp"].(float64); iat, okIat := claims["iat"].(float64); now := float64(time.Now().Unix())
	if !okExp || !okIat || exp <= now || iat > now+5 || exp-iat > 3605 || exp <= iat { t.Fatal("invalid token lifetime") }
	if nbf, ok := claims["nbf"].(float64); ok && nbf > now+5 { t.Fatal("token is not yet valid") }
	if !sameScopes(strings.Fields(token.Scope),scopes) { t.Fatal("OAuth response scope exceeds or loses requested Shared scopes") }
	if !sameScopes(claimStrings(claims["scp"]),scopes) && !sameScopes(claimStrings(claims["scope"]),scopes) { t.Fatal("signed token scopes differ from requested Shared scopes") }
	return claims
}

func claimStrings(value any) []string {
	switch value := value.(type) {
	case string: return strings.Fields(value)
	case []any:
		result := make([]string,0,len(value)); for _, item := range value { s, ok := item.(string); if !ok { return nil }; result = append(result,s) }; return result
	default: return nil
	}
}

func sameScopes(a,b []string) bool {
	a = append([]string(nil),a...); b = append([]string(nil),b...); sort.Strings(a); sort.Strings(b); return reflect.DeepEqual(a,b)
}

func (f *workloadFixture) recordProfile(t *testing.T, id string, p workloadProfile, claims map[string]any) {
	t.Helper()
	dir := os.Getenv("ORY_M4_EVIDENCE_DIR")
	if dir == "" { t.Fatal("workload profile evidence directory is required") }
	actor := claims["actor_type"]
	if actor == nil { if ext, ok := claims["ext"].(map[string]any); ok { actor = ext["actor_type"] } }
	audiences := claimStrings(claims["aud"])
	logicalAudience := sameScopes(audiences,p.Audiences)
	// Record an allowlist of observed non-sensitive claims, never the raw JWT.
	evidence := map[string]any{"fixture_only":true,"logical_client_id":id,"credential_type":p.CredentialType,"shared_status":p.Status,"expected_audiences":p.Audiences,"observed_audiences":audiences,"actor_type_is_workload":actor=="workload","logical_audience_matches":logicalAudience,"signature_verified":true,"requested_shared_scopes_verified":true,"canonical_activation_proven":false,"actual_consumer_tested":false}
	data, err := json.MarshalIndent(evidence,"","  ")
	if err != nil { t.Fatal("encode safe workload profile evidence") }
	if err := os.WriteFile(filepath.Join(dir,id+".json"),append(data,'\n'),0600); err != nil { t.Fatal("write workload profile evidence") }
	t.Logf("Verified provider token; Shared audience match=%t, actor_type=workload=%t; canonical activation remains unproven",logicalAudience,actor=="workload")
}
