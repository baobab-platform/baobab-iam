package ory_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// The pinned provider copies the assertion audience into the access token.
// A governed policy must deny this mismatch, never relabel a reserved aud claim.
func TestLiveTokenProfileFederatedAudienceBlocked(t *testing.T) {
	if os.Getenv("ORY_TOKEN_PROFILE") != "1" {
		t.Skip("requires private token-profile hook fixture")
	}
	f := newWorkloadFixture(t)
	for _, id := range []string{"baobab-cp-workload", "baobab-subscriptions-workload"} {
		t.Run(id, func(t *testing.T) {
			p := f.profile(t, id, "federated_workload_token")
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal("generate disposable assertion signer")
			}
			kid := "profile-ci-" + randomFixtureID(t)
			issuer := "https://projected.m4-ci.invalid/" + id
			subject := "system:serviceaccount:m4-ci:" + id
			jwk := map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
			trust, err := f.adapter.ProvisionFederatedWorkload(f.ctx, provider.FederatedWorkloadTrustSpec{LogicalClientID: id, AllowedScopes: p.Scopes, IntendedAudiences: p.Audiences, AssertionIssuer: issuer, AssertionSubject: subject, AssertionJWK: jwk, TrustExpiresAt: time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)})
			if err != nil {
				t.Fatal("provision federated profile fixture")
			}
			f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
			f.cleanup(t, "/admin/trust/grants/jwt-bearer/issuers/"+url.PathEscape(trust.TrustID))
			now := time.Now().Unix()
			assertion := signAssertion(t, key, kid, map[string]any{"iss": issuer, "sub": subject, "aud": []string{f.issuer + "/oauth2/token"}, "iat": now - 5, "nbf": now - 5, "exp": now + 120, "jti": randomFixtureID(t)})
			response := f.exchange(t, url.Values{"grant_type": {bearerGrant}, "client_id": {id}, "assertion": {assertion}, "scope": {p.Scopes[0]}}, true)
			if response.Error != "access_denied" {
				t.Fatal("federated mismatch was not denied by the governed profile hook")
			}
		})
	}
}
