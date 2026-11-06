package ory

// Governed provider-native Hydra JWK mutation. No unreviewed direct key
// replacement, no private JWK serialization in Baobab responses, and no
// inferred token validity from a successful admin HTTP status.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var errJWKSUnverified = errors.New("hydra: original signing key mutation or independent witness unverified")
var approvedKID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var approvedChange = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

type HydraSigningRotationPlan struct {
	SetID string
	OldKID string
	NewKID string
	ReviewedChangeReference string
}

// An external securityops/approval reader MUST check the exact reviewed
// source/runtime/change, the actor, independent approver and, for retirement,
// old signed token expiry + downstream consumer JWKS verification. Merely
// supplying a plan or a Go bool does NOT satisfy this boundary.
type HydraSigningRotationAuthority interface {
	ApproveSigningKeyOperation(context.Context, HydraSigningRotationPlan, string) error
}
type HydraSigningRotationObservation struct {
	OldKID string
	NewKID string
	OldStillPublished bool
	NewPublished bool
	// The authoritative issuer JWKS is only applicable to actual signing
	// sets; a disposable custom set proves only native JWK-admin mechanics.
	IssuerJWKSObserved bool
}

func verifySigningPlan(p HydraSigningRotationPlan) error {
	if !approvedKID.MatchString(p.OldKID) || !approvedKID.MatchString(p.NewKID) ||
		p.OldKID == p.NewKID || !approvedChange.MatchString(p.ReviewedChangeReference) {
		return errJWKSUnverified
	}
	switch p.SetID {
	case "hydra.openid.id-token", "hydra.jwt.access-token":
		return nil
	default:
		// Custom sandbox sets are only for a disposable real Hydra instance.
		// They MUST NOT be reported as issuer signing-key rotation.
		if os.Getenv("ORY_FOUNDATION") == "1" &&
			strings.HasPrefix(p.SetID, "baobab-development-") &&
			approvedKID.MatchString(p.SetID) {
			return nil
		}
		return errJWKSUnverified
	}
}

func secureKeyOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.User != nil || u.Fragment != "" ||
		u.RawQuery != "" || u.Path != "" || u.Host == "" {
		return false
	}
	if u.Scheme == "https" { return true }
	return os.Getenv("ORY_FOUNDATION") == "1" && u.Scheme == "http" &&
		u.Hostname() == "127.0.0.1"
}
func (a *Adapter) keyHTTP(ctx context.Context, method, endpoint string, body any) ([]byte, int, error) {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil { return nil, 0, errJWKSUnverified }
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil { return nil, 0, errJWKSUnverified }
	req.Header.Set("Accept", "application/json")
	if body != nil { req.Header.Set("Content-Type", "application/json") }
	client := *a.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil { return nil, 0, errJWKSUnverified }
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 128*1024+1))
	if err != nil || len(raw) > 128*1024 { return nil, 0, errJWKSUnverified }
	if res.StatusCode != 200 && res.StatusCode != 201 && res.StatusCode != 204 {
		return nil, res.StatusCode, errJWKSUnverified
	}
	if res.StatusCode != 204 {
		media, _, e := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if e != nil || media != "application/json" {
			return nil, res.StatusCode, errJWKSUnverified
		}
	}
	return raw, res.StatusCode, nil
}

type jwksReadback struct {
	Keys []struct {
		KID string `json:"kid"`
		Algorithm string `json:"alg"`
		Use string `json:"use"`
	} `json:"keys"`
}
func (a *Adapter) inspectKeySet(ctx context.Context, endpoint string) (map[string]bool,error) {
	raw, status, err := a.keyHTTP(ctx, "GET", endpoint, nil)
	if err != nil || status != http.StatusOK { return nil, errJWKSUnverified }
	var response jwksReadback
	if json.Unmarshal(raw, &response) != nil || len(response.Keys) > 50 {
		return nil, errJWKSUnverified
	}
	found := make(map[string]bool, len(response.Keys))
	for _, item := range response.Keys {
		if !approvedKID.MatchString(item.KID) || found[item.KID] ||
			(item.Algorithm != "" && item.Algorithm != "RS256") ||
			(item.Use != "" && item.Use != "sig") {
			return nil, errJWKSUnverified
		}
		found[item.KID] = true
	}
	return found, nil
}
func (a *Adapter) keySetURL(set string) string {
	return strings.TrimRight(a.cfg.HydraAdminURL, "/") + "/admin/keys/" + url.PathEscape(set)
}
func (a *Adapter) issuerJWKSURL() string {
	return strings.TrimRight(a.cfg.PublicIssuer, "/") + "/.well-known/jwks.json"
}
func isSigningSet(set string) bool {
	return set == "hydra.openid.id-token" || set == "hydra.jwt.access-token"
}

// AddHydraSigningKey performs the actual Hydra POST key generation and then
// rereads original admin + issuer JWKS. It intentionally NEVER deletes old
// keys or treats a 201 as qualification. A pre-existing old KID is mandatory.
func (a *Adapter) AddHydraSigningKey(ctx context.Context,
	plan HydraSigningRotationPlan, authority HydraSigningRotationAuthority,
) (HydraSigningRotationObservation, error) {
	none := HydraSigningRotationObservation{}
	if a == nil || ctx == nil || ctx.Err() != nil || authority == nil ||
		verifySigningPlan(plan) != nil || !secureKeyOrigin(a.cfg.HydraAdminURL) ||
		!secureKeyOrigin(a.cfg.PublicIssuer) {
		return none, errJWKSUnverified
	}
	before, err := a.inspectKeySet(ctx, a.keySetURL(plan.SetID))
	if err != nil || !before[plan.OldKID] || before[plan.NewKID] {
		return none, errJWKSUnverified
	}
	if isSigningSet(plan.SetID) {
		public, err := a.inspectKeySet(ctx, a.issuerJWKSURL())
		if err != nil || !public[plan.OldKID] || public[plan.NewKID] {
			return none, errJWKSUnverified
		}
	}
	if authority.ApproveSigningKeyOperation(ctx, plan, "ADD") != nil {
		return none, errJWKSUnverified
	}
	_, status, err := a.keyHTTP(ctx, http.MethodPost, a.keySetURL(plan.SetID),
		map[string]string{"alg":"RS256","use":"sig","kid":plan.NewKID})
	if err != nil || (status != 200 && status != 201) {
		return none, errJWKSUnverified
	}
	after, err := a.inspectKeySet(ctx, a.keySetURL(plan.SetID))
	if err != nil || !after[plan.OldKID] || !after[plan.NewKID] {
		return none, errJWKSUnverified
	}
	out := HydraSigningRotationObservation{
		OldKID:plan.OldKID,NewKID:plan.NewKID,
		OldStillPublished:true,NewPublished:true,
	}
	if isSigningSet(plan.SetID) {
		public, err := a.inspectKeySet(ctx, a.issuerJWKSURL())
		if err != nil || !public[plan.OldKID] || !public[plan.NewKID] {
			return none, errJWKSUnverified
		}
		out.IssuerJWKSObserved = true
	}
	return out, nil
}

// RetireHydraSigningKey never deletes a signing key before its independently
// reviewed old JWT expiry/consumer overlap witness. A real provider readback
// after the DELETE must still show the new key and absence of the old one.
func (a *Adapter) RetireHydraSigningKey(ctx context.Context,
	plan HydraSigningRotationPlan, authority HydraSigningRotationAuthority,
) error {
	if a == nil || ctx == nil || ctx.Err() != nil || authority == nil ||
		verifySigningPlan(plan) != nil || !secureKeyOrigin(a.cfg.HydraAdminURL) ||
		!secureKeyOrigin(a.cfg.PublicIssuer) {
		return errJWKSUnverified
	}
	before, err := a.inspectKeySet(ctx, a.keySetURL(plan.SetID))
	if err != nil || !before[plan.OldKID] || !before[plan.NewKID] {
		return errJWKSUnverified
	}
	if authority.ApproveSigningKeyOperation(ctx, plan, "RETIRE_AFTER_OLD_TOKEN_EXPIRY") != nil {
		return errJWKSUnverified
	}
	_, status, err := a.keyHTTP(ctx, http.MethodDelete,
		a.keySetURL(plan.SetID)+"/"+url.PathEscape(plan.OldKID), nil)
	if err != nil || (status != 200 && status != 204) { return errJWKSUnverified }
	after, err := a.inspectKeySet(ctx, a.keySetURL(plan.SetID))
	if err != nil || after[plan.OldKID] || !after[plan.NewKID] {
		return errJWKSUnverified
	}
	if isSigningSet(plan.SetID) {
		public, err := a.inspectKeySet(ctx, a.issuerJWKSURL())
		if err != nil || public[plan.OldKID] || !public[plan.NewKID] {
			return errJWKSUnverified
		}
	}
	return nil
}
