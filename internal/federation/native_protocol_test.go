package federation

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func nativeProtocolSetup(t *testing.T) (*NativeProtocol, *fakeAuthority, TrustSnapshot, OIDCConfiguration) {
	t.Helper()
	e, of, s, _, _ := oidcSetup(t)
	e.Close()
	_, authority := setup(t, "oidc")
	ledger, err := OpenNativeTargetLedger(filepath.Join(t.TempDir(), "native.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ledger.Close() })
	p := &NativeProtocol{Native: ledger, Governance: authority, Scope: Scope{"org_cisynthetic", "estate_ci"}, Now: func() time.Time { return authority.clock }}
	w, err := p.base(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range []struct {
		id, kind string
		content  any
	}{
		{s.Trust.ProviderBinding.ConfigurationReference, "federation_configuration", NativeOIDCSettings{of.config.ClientID, of.config.SigningAlgorithm}},
		{s.Trust.ProviderBinding.TrustMaterialReference, "federation_trust_material", NativeOIDCTrustMaterial{of.config.JWKS}},
	} {
		w.ID = doc.id
		w.Kind = doc.kind
		b, _ := json.Marshal(doc.content)
		if _, err = ledger.RegisterNonSecretTarget(context.Background(), w, b); err != nil {
			t.Fatal(err)
		}
	}
	return p, authority, s, of.config
}

func TestNativeProtocolConfigurationCurrentApprovals(t *testing.T) {
	p, a, s, c := nativeProtocolSetup(t)
	got, err := p.OIDCConfiguration(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != c.ClientID || string(got.JWKS) != string(c.JWKS) || got.Binding != s.Trust.ProviderBinding {
		t.Fatal("configuration changed binding")
	}
	// Revocation after the byte read must fail, including a subsequent read.
	calls := 0
	a.mutateReceipt = func(r *ApprovedReference) {
		calls++
		if calls%2 == 0 {
			r.Status = "REVOKED"
		}
	}
	if _, err = p.OIDCConfiguration(context.Background(), s); err == nil {
		t.Fatal("approval drift accepted")
	}
	a.mutateReceipt = nil
	a.snapshot.Trust.Status = "SUSPENDED"
	if _, err = p.OIDCConfiguration(context.Background(), s); err == nil {
		t.Fatal("suspended trust accepted")
	}
}

func TestNativeProtocolExactEventDecision(t *testing.T) {
	p, a, s, _ := nativeProtocolSetup(t)
	ctx := context.Background()
	principal := a.bundle.ExternalPrincipal
	assurance := a.bundle.Assurance
	assurance.MappingStatus = "UNKNOWN"
	assurance.Level = ""
	assurance.MappingEvidenceReference = ""
	w, _ := p.base(ctx, s)
	w.Kind = "assurance_mapping_decision"
	w.ID = "ref_cidecision"
	w.EventID = principal.AuthenticationEventID
	w.Issuer = principal.Issuer
	w.Subject = principal.Subject
	w.Level = "BAOBAB-A1"
	evidence, _ := json.Marshal(assurance.UpstreamEvidence)
	w.EvidenceDigest = nativeTargetDigest(evidence)
	b, _ := json.Marshal(NativeAssuranceDecision{assurance.UpstreamEvidence, w.Level})
	if _, err := p.Native.RegisterNonSecretTarget(ctx, w, b); err != nil {
		t.Fatal(err)
	}
	policyWant, _ := p.base(ctx, s)
	policyWant.Kind = "assurance_policy"
	policyWant.ID = s.Trust.AssurancePolicyReference
	b, _ = json.Marshal(NativeAssurancePolicy{Rules: []NativeAssuranceRule{{ACR: assurance.UpstreamEvidence.OIDC.ACR, Level: w.Level, AMR: assurance.UpstreamEvidence.OIDC.AMR}}})
	if _, err := p.Native.RegisterNonSecretTarget(ctx, policyWant, b); err != nil {
		t.Fatal(err)
	}
	got, err := p.MapAssurance(ctx, s, principal, assurance)
	if err != nil {
		t.Fatal(err)
	}
	if got.Level != w.Level || got.MappingEvidenceReference != w.ID {
		t.Fatal("decision not bound")
	}
	principal.Subject = "another-human"
	assurance.Subject = principal.Subject
	if _, err = p.MapAssurance(ctx, s, principal, assurance); err == nil {
		t.Fatal("another human reused approved decision")
	}
}

func TestNativeTargetContentDetached(t *testing.T) {
	p, _, s, _ := nativeProtocolSetup(t)
	w, _ := p.base(context.Background(), s)
	w.Kind = "federation_configuration"
	w.ID = s.Trust.ProviderBinding.ConfigurationReference
	bytes, err := p.Native.NativeTargetContent(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	bytes[0] = '!'
	if _, err = p.Native.NativeTargetContent(context.Background(), w); err != nil {
		t.Fatal("caller mutated ledger")
	}
	w.SnapshotID = "another-snapshot"
	if _, err = p.Native.NativeTargetContent(context.Background(), w); err == nil {
		t.Fatal("cross snapshot bytes accepted")
	}
}

func TestNativeProtocolRefreshFailureDeniesPersistedTargets(t *testing.T) {
	p, _, s, _ := nativeProtocolSetup(t)
	calls := 0
	p.Refresh = func(context.Context) error { calls++; return ErrUnavailable }
	if _, err := p.OIDCConfiguration(context.Background(), s); err == nil || calls != 1 {
		t.Fatalf("persisted targets bypassed failed publisher: calls=%d err=%v", calls, err)
	}
}
