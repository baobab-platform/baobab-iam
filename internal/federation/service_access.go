package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// WorkloadAdmission is an operator-protected, current admission snapshot.
// Certificate fingerprints bind permission to a verified workload, never a CN.
type WorkloadAdmission struct {
	CertificateSHA256 string
	Issuer            string
	Subject           string
	Active            bool
	ValidUntil        time.Time
	Actions           []string
	Scopes            []Scope
}

type ServiceAccess struct {
	RegistryPath string
	Governance   *GovernanceComposition
	Platform     PlatformAuthority
	Verifier     *oidc.IDTokenVerifier
}

func privateDocument(path string) ([]byte, error) {
	f, err := privateLedgerFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return nil, ErrUnavailable
	}
	return b, nil
}

// LoadServiceDocument enforces the same protected inode and strict JSON
// rules as service admission. Non-Linux execution fails closed.
func LoadServiceDocument(path string, out any) error {
	data, err := privateDocument(path)
	if err != nil {
		return err
	}
	return decodeAuthority(data, out)
}

func (a *ServiceAccess) AuthorizeAuthorityRequest(ctx context.Context, r *http.Request, action string, want ReferenceExpectation) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrDenied
	}
	d := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	now := time.Now()
	if now.Before(r.TLS.PeerCertificates[0].NotBefore) || !now.Before(r.TLS.PeerCertificates[0].NotAfter) {
		return nil, ErrDenied
	}
	fingerprint := "sha256:" + hex.EncodeToString(d[:])
	b, err := privateDocument(a.RegistryPath)
	if err != nil {
		return nil, err
	}
	var registry []WorkloadAdmission
	if decodeAuthority(b, &registry) != nil {
		return nil, ErrInvalid
	}
	var admission *WorkloadAdmission
	for i := range registry {
		if registry[i].CertificateSHA256 == fingerprint {
			if admission != nil {
				return nil, ErrDenied
			}
			admission = &registry[i]
		}
	}
	if admission == nil || !admission.Active || !now.Before(admission.ValidUntil) {
		return nil, ErrDenied
	}
	parts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > 16384 || a.Verifier == nil {
		return nil, ErrDenied
	}
	token, err := a.Verifier.Verify(ctx, parts[1])
	if err != nil || token.Issuer != admission.Issuer || token.Subject != admission.Subject || len(token.Audience) != 1 {
		return nil, ErrDenied
	}
	var claims struct {
		ActorType string `json:"actor_type"`
		Scope     string `json:"scope"`
		IssuedAt  int64  `json:"iat"`
		NotBefore int64  `json:"nbf"`
	}
	if token.Claims(&claims) != nil || claims.ActorType != "workload" || claims.IssuedAt <= 0 || claims.IssuedAt > now.Unix() || claims.NotBefore > now.Unix() {
		return nil, ErrDenied
	}
	hasScope := false
	for _, scope := range strings.Fields(claims.Scope) {
		if scope == "federation-authority:read" {
			hasScope = true
		}
	}
	if !hasScope {
		return nil, ErrDenied
	}
	if action == "AUTHENTICATE" {
		return ctx, nil
	}
	allowed := false
	for _, v := range admission.Actions {
		if v == action {
			allowed = true
		}
	}
	if !allowed || a.Governance == nil || a.Platform == nil {
		return nil, ErrDenied
	}
	// ID-only routes derive scope from persisted governance, never the caller.
	if !validScope(want.Scope) {
		v, err := a.Governance.Trusts.read(ctx, want.TrustID)
		if err != nil {
			return nil, authorityError(err)
		}
		want.Scope = v.Scope
	}
	allowed = false
	for _, v := range admission.Scopes {
		if v == want.Scope {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrDenied
	}
	if strings.HasPrefix(action, "APPROVAL_") {
		token := r.Header.Get("X-Baobab-Governance-Subject")
		return WithGovernanceSubjectToken(ctx, token)
	}
	// Read admission is additionally fenced by current CP platform authority.
	v, err := a.Governance.Trusts.Trust(ctx, want.TrustID)
	if err != nil {
		return nil, authorityError(err)
	}
	facet := RuntimeOIDCFederation
	if v.Trust.Protocol == "SAML2" {
		facet = RuntimeSAMLFederation
	}
	if _, err = a.Platform.FederationBinding(ctx, v.Trust.ProviderBinding, want.Scope, facet); err != nil {
		return nil, authorityError(err)
	}
	return ctx, nil
}
