package federation

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	uuidPattern     = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	refPattern      = regexp.MustCompile(`^ref_[a-z0-9]+$`)
	providerPattern = regexp.MustCompile(`^provider_[a-z0-9]+$`)
	instancePattern = regexp.MustCompile(`^ei_[a-z0-9]+$`)
	entityPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	estatePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func validRef(s string) bool { return len(s) >= 8 && len(s) <= 63 && refPattern.MatchString(s) }
func exact(s string) bool    { return s != "" && len(s) <= 512 && strings.TrimSpace(s) == s }
func validBinding(b Binding) bool {
	return len(b.ProviderID) >= 10 && len(b.ProviderID) <= 63 && providerPattern.MatchString(b.ProviderID) && len(b.EngineInstanceID) >= 6 && len(b.EngineInstanceID) <= 63 && instancePattern.MatchString(b.EngineInstanceID) && validRef(b.ConfigurationReference) && validRef(b.TrustMaterialReference)
}
func validScope(s Scope) bool {
	return len(s.OrganisationID) > 0 && len(s.OrganisationID) <= 128 && entityPattern.MatchString(s.OrganisationID) && len(s.EstateID) >= 3 && len(s.EstateID) <= 63 && estatePattern.MatchString(s.EstateID)
}
func uniqueScope(ids []string, estate bool) bool {
	if len(ids) < 1 || len(ids) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return false
		}
		seen[id] = true
		if estate {
			if !validScope(Scope{"org", id}) {
				return false
			}
		} else if !validScope(Scope{id, "estate"}) {
			return false
		}
	}
	return true
}
func member(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// DecodeBundle rejects duplicate/unknown JSON fields, nulls and trailing data.
// It is structural validation only and cannot authenticate a record.
func DecodeBundle(data []byte) (Bundle, error) {
	var b Bundle
	if len(data) > 65536 {
		return b, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(d); err != nil {
		return b, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return b, ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return Bundle{}, ErrInvalid
	}

	var raw struct {
		Trust     map[string]json.RawMessage `json:"trust"`
		Principal struct {
			Resolution map[string]json.RawMessage `json:"resolution"`
		} `json:"external_principal"`
		Assurance map[string]json.RawMessage `json:"assurance"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return Bundle{}, ErrInvalid
	}
	if b.ExternalPrincipal.Resolution.Status == "UNRESOLVED" {
		for _, field := range []string{"principal_id", "external_identity_id", "mapping_reference", "mapping_basis", "resolved_at"} {
			if _, present := raw.Principal.Resolution[field]; present {
				return Bundle{}, ErrInvalid
			}
		}
	}
	if b.Assurance.MappingStatus == "UNKNOWN" {
		for _, field := range []string{"level", "mapping_evidence_reference"} {
			if _, present := raw.Assurance[field]; present {
				return Bundle{}, ErrInvalid
			}
		}
	}
	if _, present := raw.Trust["activation_evidence_reference"]; present && !validRef(b.Trust.ActivationEvidenceReference) {
		return Bundle{}, ErrInvalid
	}
	if err := ValidateBundle(b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}
func uniqueJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil || token == nil {
		return ErrInvalid
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return ErrInvalid
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
		if _, err := d.Token(); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

// ValidateBundle mirrors Shared schema and cross-record publication invariants.
// Current approval/freshness is enforced independently by Consumer.Consume.
func ValidateBundle(b Bundle) error {
	t, p, a := b.Trust, b.ExternalPrincipal, b.Assurance
	if err := ValidateTrust(t); err != nil {
		return err
	}
	if !uuidPattern.MatchString(p.AuthenticationEventID) || p.TrustID != t.ID || p.Protocol != t.Protocol || p.Issuer != t.UpstreamIssuer || !exact(p.Subject) || p.ActorType != "human" || p.ProviderID != t.ProviderBinding.ProviderID || p.EngineInstanceID != t.ProviderBinding.EngineInstanceID || p.ObservedAt.IsZero() || !p.ExpiresAt.After(p.ObservedAt) {
		return ErrInvalid
	}
	if a.AuthenticationEventID != p.AuthenticationEventID || a.TrustID != p.TrustID || a.ProviderID != p.ProviderID || a.EngineInstanceID != p.EngineInstanceID || a.Protocol != p.Protocol || a.Issuer != p.Issuer || a.Subject != p.Subject || a.AssurancePolicyReference != t.AssurancePolicyReference || a.EvaluatedAt.Before(p.ObservedAt) || !a.ExpiresAt.After(a.EvaluatedAt) || a.ExpiresAt.After(p.ExpiresAt) {
		return ErrInvalid
	}
	r := p.Resolution
	switch r.Status {
	case "UNRESOLVED":
		if r.PrincipalID != "" || r.ExternalIdentityID != "" || r.MappingReference != "" || r.MappingBasis != "" || r.ResolvedAt != nil {
			return ErrInvalid
		}
	case "RESOLVED":
		if !uuidPattern.MatchString(r.PrincipalID) || !uuidPattern.MatchString(r.ExternalIdentityID) || !validRef(r.MappingReference) || r.MappingBasis != "ISSUER_SUBJECT" || r.ResolvedAt == nil || r.ResolvedAt.Before(p.ObservedAt) || !r.ResolvedAt.Before(p.ExpiresAt) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	switch a.MappingStatus {
	case "UNKNOWN":
		if a.Level != "" || a.MappingEvidenceReference != "" {
			return ErrInvalid
		}
	case "MAPPED":
		if (a.Level != "BAOBAB-A1" && a.Level != "BAOBAB-A2" && a.Level != "BAOBAB-A3") || !validRef(a.MappingEvidenceReference) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if t.Protocol == "OIDC" {
		e := a.UpstreamEvidence.OIDC
		if e == nil || a.UpstreamEvidence.SAML != nil || e.ActorType != "human" || e.Issuer != p.Issuer || !exact(e.ACR) || !exact(e.ClientID) || e.AuthenticatedAt.IsZero() || e.AuthenticatedAt.After(p.ObservedAt) || (e.StepUpAt != nil && (e.StepUpAt.Before(e.AuthenticatedAt) || e.StepUpAt.After(a.EvaluatedAt))) {
			return ErrInvalid
		}
		if e.AMR != nil && len(e.AMR) == 0 {
			return ErrInvalid
		}
		for _, method := range e.AMR {
			if !exact(method) {
				return ErrInvalid
			}
		}
	} else {
		e := a.UpstreamEvidence.SAML
		if e == nil || a.UpstreamEvidence.OIDC != nil || !exact(e.AuthnContextClassRef) || e.AuthenticatedAt.IsZero() || e.AuthenticatedAt.After(p.ObservedAt) || e.SessionExpiresAt.Before(a.ExpiresAt) {
			return ErrInvalid
		}
	}
	return nil
}
func fresh(from, until, now time.Time) bool {
	return !from.IsZero() && !until.IsZero() && !now.Before(from) && now.Before(until)
}

// ValidateTrust checks the pinned Shared structural and lifecycle record invariants.
// Approval, scope authority and technical activation proof remain separate.
func ValidateTrust(t Trust) error {
	if !uuidPattern.MatchString(t.ID) || !validBinding(t.ProviderBinding) || t.Revision < 1 || !uniqueScope(t.OrganisationIDs, false) || !uniqueScope(t.EstateIDs, true) || !validRef(t.AssurancePolicyReference) || !validRef(t.AttributeMappingReference) || !validRef(t.ProvisioningPolicyReference) {
		return ErrInvalid
	}
	u, err := url.Parse(t.UpstreamIssuer)
	if err != nil || u.Scheme == "" || len(t.UpstreamIssuer) > 2048 || strings.ContainsAny(t.UpstreamIssuer, " \t\r\n") {
		return ErrInvalid
	}
	switch t.Protocol {
	case "OIDC":
		if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return ErrInvalid
		}
	case "SAML2":
	default:
		return ErrInvalid
	}
	switch t.Status {
	case "REQUESTED", "CONFIGURING", "VERIFYING", "ACTIVE", "SUSPENDED", "ROTATING", "REVOKED":
	default:
		return ErrInvalid
	}
	if t.CreatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return ErrInvalid
	}
	if t.ActivatedAt != nil && (t.ActivatedAt.Before(t.CreatedAt) || t.ActivatedAt.After(t.UpdatedAt)) {
		return ErrInvalid
	}
	if t.Status == "ACTIVE" && (t.ActivatedAt == nil || !validRef(t.ActivationEvidenceReference)) {
		return ErrInvalid
	}
	if t.ActivationEvidenceReference != "" && !validRef(t.ActivationEvidenceReference) {
		return ErrInvalid
	}
	if t.Status == "REVOKED" {
		if t.RevokedAt == nil || t.RevokedAt.Before(t.CreatedAt) || t.RevokedAt.After(t.UpdatedAt) || (t.ActivatedAt != nil && t.RevokedAt.Before(*t.ActivatedAt)) {
			return ErrInvalid
		}
	} else if t.RevokedAt != nil {
		return ErrInvalid
	}
	return nil
}
