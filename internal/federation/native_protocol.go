package federation

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

// NativeOIDCSettings contains no keys or credentials. Public keys are resolved
// separately through the approved trust-material reference.
type NativeOIDCSettings struct{ ClientID, SigningAlgorithm string }
type NativeOIDCTrustMaterial struct{ JWKS json.RawMessage }

// NativeAssurancePolicy selects exact, separately approved event decisions.
// A rule or a signed token cannot manufacture an approval receipt.
type NativeAssurancePolicy struct{ Rules []NativeAssuranceRule }
type NativeAssuranceRule struct {
	ACR, Level string
	AMR        []string `json:"AMR,omitempty"`
}
type NativeAssuranceDecision struct {
	Evidence UpstreamEvidence
	Level    string
}

type NativeProtocol struct {
	Native     *NativeTargetLedger
	Governance GovernanceAuthority
	Scope      Scope
	Now        func() time.Time
}

func (p *NativeProtocol) base(ctx context.Context, s TrustSnapshot) (ReferenceExpectation, error) {
	if p == nil || p.Native == nil || absent(p.Governance) || p.Now == nil || !validScope(p.Scope) || ctx == nil || ctx.Err() != nil {
		return ReferenceExpectation{}, ErrInvalid
	}
	current, err := p.Governance.Trust(ctx, s.Trust.ID)
	if err != nil {
		return ReferenceExpectation{}, authorityError(err)
	}
	if TrustSnapshotDigest(current) != TrustSnapshotDigest(s) || ValidateTrust(s.Trust) != nil || s.Trust.Status != "ACTIVE" || s.Trust.Revision != s.ApprovedRevision || !p.Now().Before(s.ValidUntil) || !member(s.Trust.OrganisationIDs, p.Scope.OrganisationID) || !member(s.Trust.EstateIDs, p.Scope.EstateID) {
		return ReferenceExpectation{}, ErrUnverified
	}
	return ReferenceExpectation{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, TrustRevision: s.ApprovedRevision, ProviderID: s.Trust.ProviderBinding.ProviderID, EngineInstanceID: s.Trust.ProviderBinding.EngineInstanceID, Scope: p.Scope}, nil
}

func (p *NativeProtocol) read(ctx context.Context, w ReferenceExpectation, out any) (time.Time, error) {
	before, err := p.Governance.Reference(ctx, w)
	if err != nil {
		return time.Time{}, authorityError(err)
	}
	if before.Expectation != w || before.Status != "APPROVED" || !before.NonSecret || !fresh(before.ValidFrom, before.ExpiresAt, p.Now()) {
		return time.Time{}, ErrUnverified
	}
	content, err := p.Native.NativeTargetContent(ctx, w)
	if err != nil {
		return time.Time{}, err
	}
	if decodeAuthority(content, out) != nil {
		return time.Time{}, ErrInvalid
	}
	after, err := p.Governance.Reference(ctx, w)
	if err != nil {
		return time.Time{}, authorityError(err)
	}
	if before != after || ctx.Err() != nil || !fresh(after.ValidFrom, after.ExpiresAt, p.Now()) {
		return time.Time{}, ErrUnverified
	}
	return before.ExpiresAt, nil
}

func (p *NativeProtocol) OIDCConfiguration(ctx context.Context, s TrustSnapshot) (OIDCConfiguration, error) {
	w, err := p.base(ctx, s)
	if err != nil {
		return OIDCConfiguration{}, err
	}
	if s.Trust.Protocol != "OIDC" {
		return OIDCConfiguration{}, ErrUnsupported
	}
	w.ID = s.Trust.ProviderBinding.ConfigurationReference
	w.Kind = "federation_configuration"
	var settings NativeOIDCSettings
	expiry, err := p.read(ctx, w, &settings)
	if err != nil {
		return OIDCConfiguration{}, err
	}
	w.ID = s.Trust.ProviderBinding.TrustMaterialReference
	w.Kind = "federation_trust_material"
	var material NativeOIDCTrustMaterial
	keysExpiry, err := p.read(ctx, w, &material)
	if err != nil {
		return OIDCConfiguration{}, err
	}
	c := OIDCConfiguration{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, Revision: s.ApprovedRevision, Binding: s.Trust.ProviderBinding, ClientID: settings.ClientID, SigningAlgorithm: settings.SigningAlgorithm, JWKS: material.JWKS, ValidUntil: minimum(s.ValidUntil, minimum(expiry, keysExpiry))}
	if !exact(c.ClientID) {
		return OIDCConfiguration{}, ErrInvalid
	}
	if _, err = publicOIDCKeys(c); err != nil {
		return OIDCConfiguration{}, err
	}
	w.ID = s.Trust.ProviderBinding.ConfigurationReference
	w.Kind = "federation_configuration"
	if check, e := p.read(ctx, w, &settings); e != nil || check != expiry {
		err = ErrUnverified
		return OIDCConfiguration{}, err
	}
	w.ID = s.Trust.ProviderBinding.TrustMaterialReference
	w.Kind = "federation_trust_material"
	if check, e := p.read(ctx, w, &material); e != nil || check != keysExpiry {
		err = ErrUnverified
		return OIDCConfiguration{}, err
	}
	if _, err = p.base(ctx, s); err != nil {
		return OIDCConfiguration{}, err
	}
	return c, nil
}

func (p *NativeProtocol) MapAssurance(ctx context.Context, s TrustSnapshot, principal ExternalPrincipal, a Assurance) (Assurance, error) {
	w, err := p.base(ctx, s)
	if err != nil {
		return Assurance{}, err
	}
	if a.MappingStatus != "UNKNOWN" || ValidateBundle(Bundle{Trust: s.Trust, ExternalPrincipal: principal, Assurance: a}) != nil {
		return Assurance{}, ErrInvalid
	}
	w.ID = s.Trust.AssurancePolicyReference
	w.Kind = "assurance_policy"
	var policy NativeAssurancePolicy
	expiry, err := p.read(ctx, w, &policy)
	if err != nil {
		return Assurance{}, err
	}
	encoded, _ := json.Marshal(a.UpstreamEvidence)
	if a.Protocol != "OIDC" || a.UpstreamEvidence.OIDC == nil {
		return Assurance{}, ErrUnsupported
	}
	var level string
	if len(policy.Rules) == 0 || len(policy.Rules) > 64 {
		return Assurance{}, ErrInvalid
	}
	for _, rule := range policy.Rules {
		if !exact(rule.ACR) || (rule.Level != "BAOBAB-A1" && rule.Level != "BAOBAB-A2" && rule.Level != "BAOBAB-A3") || len(rule.AMR) > 16 {
			return Assurance{}, ErrInvalid
		}
		for _, method := range rule.AMR {
			if !exact(method) {
				return Assurance{}, ErrInvalid
			}
		}

		if rule.ACR != a.UpstreamEvidence.OIDC.ACR {
			continue
		}
		match := true
		for _, method := range rule.AMR {
			if !slices.Contains(a.UpstreamEvidence.OIDC.AMR, method) {
				match = false
			}
		}
		if match {
			if level != "" {
				return Assurance{}, ErrUnverified
			}
			level = rule.Level
		}
	}
	if level == "" {
		return Assurance{}, ErrUnverified
	}
	want := w
	want.ID = ""
	want.Kind = "assurance_mapping_decision"
	want.EventID = principal.AuthenticationEventID
	want.Issuer = principal.Issuer
	want.Subject = principal.Subject
	want.Level = level
	want.EvidenceDigest = nativeTargetDigest(encoded)
	selected, err := p.Native.FindAssuranceDecision(ctx, want)
	if err != nil {
		return Assurance{}, err
	}
	var decision NativeAssuranceDecision
	decisionExpiry, err := p.read(ctx, selected, &decision)
	if err != nil {
		return Assurance{}, err
	}
	bytes, _ := json.Marshal(decision.Evidence)
	if nativeTargetDigest(bytes) != selected.EvidenceDigest || decision.Level != selected.Level {
		return Assurance{}, ErrUnverified
	}
	a.MappingStatus = "MAPPED"
	a.Level = decision.Level
	a.MappingEvidenceReference = selected.ID
	a.ExpiresAt = minimum(a.ExpiresAt, minimum(s.ValidUntil, minimum(expiry, decisionExpiry)))
	if ValidateBundle(Bundle{Trust: s.Trust, ExternalPrincipal: principal, Assurance: a}) != nil {
		return Assurance{}, ErrUnverified
	}
	if check, e := p.read(ctx, w, &policy); e != nil || check != expiry {
		err = ErrUnverified
		return Assurance{}, err
	}
	if check, e := p.read(ctx, selected, &decision); e != nil || check != decisionExpiry {
		err = ErrUnverified
		return Assurance{}, err
	}
	if _, err = p.base(ctx, s); err != nil {
		return Assurance{}, err
	}
	return a, nil
}

var _ OIDCConfigurationAuthority = (*NativeProtocol)(nil)
var _ AssuranceMapper = (*NativeProtocol)(nil)
