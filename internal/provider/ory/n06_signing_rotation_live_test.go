package ory_test

// Real disposable Hydra issuer-signing rotation, not a fake local JWK
// simulator. A signed access token is minted before and after rotation and
// cryptographically verified from the actual public issuer JWKS. Tokens,
// private JWKs and client secrets are never logged or written to artifacts.
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func n06KID(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatal("actual Hydra JWT access token required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal("invalid signed token header encoding")
	}
	var header struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &header) != nil || header.KID == "" || header.Alg != "RS256" {
		t.Fatal("unexpected Hydra issuer signing key")
	}
	return header.KID
}

// TestLiveN06HydraIssuerSigningKeyOverlap exercises the signing set actually
// used for a fresh signed Hydra workload JWT, not a disposable unused keyset.
// It holds the old key until its original token expiry, requires two native
// signed JWTs, denies premature retirement and verifies current JWKS removal.
// The approval in this test is a disposable securityops fixture, not CP.
func TestLiveN06HydraIssuerSigningKeyOverlap(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" {
		t.Skip("real pinned Hydra and disposable Ory Foundation required")
	}
	f := newWorkloadFixture(t)
	id := "n06-signing-" + randomFixtureID(t)
	p := workloadProfile{Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-control-plane"}}
	w, err := f.adapter.ProvisionWorkload(f.ctx, provider.WorkloadProvisioningSpec{
		LogicalClientID: id, AllowedScopes: p.Scopes, Audiences: p.Audiences,
		AuthMethod: provider.WorkloadAuthClientSecret, AccessTokenTTLSeconds: 60, RequireNew: true,
	})
	if err != nil || w == nil || w.ClientSecret == "" {
		t.Fatal("actual issuer client registration for signing rotation failed")
	}
	f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
	form := secretForm(id, w.ClientSecret, p.Scopes[0])
	if os.Getenv("ORY_TOKEN_PROFILE") == "1" {
		form.Set("audience", p.Audiences[0])
	}
	original := f.exchange(t, form, false)
	claims := f.verify(t, original, p.Scopes, id)
	oldKID := n06KID(t, original.AccessToken)
	oldExpiry, ok := claims["exp"].(float64)
	if !ok || oldExpiry <= float64(time.Now().Unix()) || oldExpiry > float64(time.Now().Add(65*time.Second).Unix()) {
		t.Fatal("old issuer token expiry not bounded before key operation")
	}
	// Independent current Hydra Admin original keyset readback identifies
	// which official signing key set actually emitted this token.
	var chosen string
	for _, set := range []string{"hydra.jwt.access-token", "hydra.openid.id-token"} {
		var observed struct {
			Keys []struct {
				KID string `json:"kid"`
			} `json:"keys"`
		}
		req, err := http.NewRequestWithContext(f.ctx, http.MethodGet,
			f.admin+"/admin/keys/"+url.PathEscape(set), nil)
		if err != nil {
			t.Fatal("invalid native keyset route")
		}
		res, err := f.client.Do(req)
		if err != nil {
			t.Fatal("Hydra admin keyset not reachable")
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			continue
		}
		parsed := json.NewDecoder(res.Body).Decode(&observed)
		res.Body.Close()
		if parsed != nil {
			t.Fatal("invalid actual signing-key readback")
		}
		for _, item := range observed.Keys {
			if item.KID == oldKID {
				if chosen != "" {
					t.Fatal("ambiguous live issuer signing keyset")
				}
				chosen = set
			}
		}
	}
	if chosen == "" {
		t.Fatal("real JWT signing set not found in Hydra Admin")
	}
	newKID := "n06-next-" + randomFixtureID(t)
	plan := ory.HydraSigningRotationPlan{
		SetID: chosen, OldKID: oldKID, NewKID: newKID,
		ReviewedChangeReference: "ref_disposablesigningtest",
	}
	reviewer := &n06ReviewedJWKS{}
	observation, err := f.adapter.AddHydraSigningKey(f.ctx, plan, reviewer)
	if err != nil || !observation.OldStillPublished || !observation.NewPublished ||
		!observation.IssuerJWKSObserved {
		t.Fatal("native Hydra signing rotation did not preserve both public KIDs")
	}
	// The old (still unexpired) signed token must verify through the live
	// issuer's current public JWKS during the overlap.
	f.verify(t, original, p.Scopes, id)
	newToken := f.exchange(t, form, false)
	f.verify(t, newToken, p.Scopes, id)
	if kid := n06KID(t, newToken.AccessToken); kid != newKID {
		t.Fatal("real issuer did not select freshly rotated signing key")
	}
	if f.adapter.RetireHydraSigningKey(f.ctx, plan, reviewer) == nil {
		t.Fatal("premature signing key retirement accepted")
	}
	// Do not guess that all old tokens expired merely because an API wrote a
	// key. The recorded original token expiry is mandatory before deleting.
	deadline := time.Unix(int64(oldExpiry), 0).Add(time.Second)
	if time.Until(deadline) > 70*time.Second {
		t.Fatal("unbounded old-token overlap")
	}
	if wait := time.Until(deadline); wait > 0 {
		select {
		case <-time.After(wait):
		case <-f.ctx.Done():
			t.Fatal("old-token overlap not completed")
		}
	}
	fresh := f.exchange(t, form, false)
	f.verify(t, fresh, p.Scopes, id)
	if n06KID(t, fresh.AccessToken) != newKID {
		t.Fatal("issuer signing key reverted during old-token overlap")
	}
	reviewer.retirement = true // synthetic evidence AFTER actual old token expiry
	if err := f.adapter.RetireHydraSigningKey(f.ctx, plan, reviewer); err != nil {
		t.Fatal("Hydra did not retire old key after witnessed original expiry")
	}
	f.verify(t, fresh, p.Scopes, id)
	t.Log("real Hydra signing-key selection, old+new JWKS overlap, bounded expiry and retired KID denial PASS; external securityops approval still required")
}
