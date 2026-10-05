package federation

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type targetRegistrationFixture struct {
	digest         string
	err            error
	calls          int
	mutateOnSecond bool
}

func (f *targetRegistrationFixture) TargetRegistration(context.Context, ReferenceExpectation) (TargetRegistration, error) {
	f.calls++
	if f.err != nil {
		return TargetRegistration{}, f.err
	}
	digest := f.digest
	if f.mutateOnSecond && f.calls > 1 {
		digest = "sha256:" + strings.Repeat("f", 64)
	}
	return TargetRegistration{Digest: digest}, nil
}

func nativeTargetExpectation(t *testing.T) (ReferenceExpectation, *fakeAuthority) {
	t.Helper()
	_, f := setup(t, "oidc")
	return ReferenceExpectation{
		ID:               f.bundle.Trust.ProviderBinding.ConfigurationReference,
		Kind:             "federation_configuration",
		TrustID:          f.bundle.Trust.ID,
		SnapshotID:       f.snapshot.SnapshotID,
		TrustRevision:    f.snapshot.ApprovedRevision,
		ProviderID:       f.platform.ProviderID,
		EngineInstanceID: f.platform.EngineInstanceID,
		Scope:            f.platform.Scope,
	}, f
}

func TestNativeTargetLedgerIsImmutableAndRestartSafe(t *testing.T) {
	ctx := context.Background()
	want, f := nativeTargetExpectation(t)
	path := filepath.Join(t.TempDir(), "native-targets.db")
	ledger, err := OpenNativeTargetLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"client_id":"ci-client","issuer":"https://idp.example.test","signing_algorithm":"RS256"}`)
	digest, err := ledger.RegisterNonSecretTarget(ctx, want, content)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ledger.NativeTargetDigest(ctx, want); err != nil || got != digest {
		t.Fatalf("digest=%q err=%v", got, err)
	}
	if _, err := ledger.RegisterNonSecretTarget(ctx, want, []byte(`{"client_id":"changed"}`)); !errors.Is(err, ErrDenied) {
		t.Fatalf("mutable ref accepted: %v", err)
	}

	cpOwned := want
	cpOwned.ID = "ref_runtimeprofile"
	cpOwned.Kind = "identity_runtime_profile"
	if _, err := ledger.RegisterNonSecretTarget(ctx, cpOwned, []byte(`{"revision":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CP-owned target stored by IAM: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenNativeTargetLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if got, err := ledger.NativeTargetDigest(ctx, want); err != nil || got != digest {
		t.Fatalf("restart digest=%q err=%v", got, err)
	}

	activation := ReferenceExpectation{
		ID:               f.snapshot.Trust.ActivationEvidenceReference,
		Kind:             "federation_activation",
		TrustID:          f.snapshot.Trust.ID,
		SnapshotID:       f.snapshot.SnapshotID,
		TrustRevision:    f.snapshot.ApprovedRevision,
		ProviderID:       f.snapshot.Trust.ProviderBinding.ProviderID,
		EngineInstanceID: f.snapshot.Trust.ProviderBinding.EngineInstanceID,
		Scope:            f.platform.Scope,
	}
	if got, err := ledger.RegisterTrustSnapshotTarget(ctx, activation, f.snapshot); err != nil || got != TrustSnapshotDigest(f.snapshot) {
		t.Fatalf("snapshot digest=%q err=%v", got, err)
	}
}

func TestCompositeApprovalTargetsRejectsCPOwnedNativeTarget(t *testing.T) {
	ctx := context.Background()
	want, _ := nativeTargetExpectation(t)
	want.ID = "ref_runtimeprofile"
	want.Kind = "identity_runtime_profile"
	registration := &targetRegistrationFixture{digest: "sha256:" + strings.Repeat("a", 64)}
	native, err := OpenNativeTargetLedger(filepath.Join(t.TempDir(), "native-targets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	targets, err := NewCompositeApprovalTargets(registration, native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targets.ResolveApprovedTarget(ctx, want); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CP-owned native target result=%v", err)
	}
	if registration.calls != 0 {
		t.Fatalf("CP registration consulted for unsupported owner-native target: calls=%d", registration.calls)
	}
}

func TestIAMOwnedNativeTargetKindMatchesSharedOwnership(t *testing.T) {
	for kind, want := range map[string]bool{
		"federation_configuration":   true,
		"federation_trust_material":  true,
		"assurance_policy":           true,
		"attribute_mapping":          true,
		"provisioning_policy":        true,
		"federation_activation":      true,
		"assurance_mapping_decision": true,
		"identity_security_domain":   true,
		"canonical_identity_mapping": false,
		"identity_runtime_profile":   false,
		"identity_runtime_support":   false,
	} {
		if got := iamOwnedNativeTargetKind(kind); got != want {
			t.Fatalf("%s IAM-owned=%v want=%v", kind, got, want)
		}
	}
}

func TestCompositeApprovalTargetsRequiresBothAuthorities(t *testing.T) {
	ctx := context.Background()
	want, _ := nativeTargetExpectation(t)
	ledger, err := OpenNativeTargetLedger(filepath.Join(t.TempDir(), "native-targets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	content := []byte(`{"client_id":"ci-client","issuer":"https://idp.example.test"}`)
	digest, err := ledger.RegisterNonSecretTarget(ctx, want, content)
	if err != nil {
		t.Fatal(err)
	}
	registration := &targetRegistrationFixture{digest: digest}
	targets, err := NewCompositeApprovalTargets(registration, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := targets.ResolveApprovedTarget(ctx, want); err != nil || got != digest || registration.calls != 2 {
		t.Fatalf("digest=%q calls=%d err=%v", got, registration.calls, err)
	}

	registration.calls = 0
	registration.digest = "sha256:" + strings.Repeat("e", 64)
	if _, err := targets.ResolveApprovedTarget(ctx, want); !errors.Is(err, ErrUnverified) {
		t.Fatalf("CP/native mismatch accepted: %v", err)
	}

	registration.calls = 0
	registration.digest = digest
	registration.mutateOnSecond = true
	if _, err := targets.ResolveApprovedTarget(ctx, want); !errors.Is(err, ErrUnverified) {
		t.Fatalf("CP drift accepted: %v", err)
	}
}

func TestCompositeTargetsGateApprovalProposalDecisionAndUse(t *testing.T) {
	ctx := context.Background()
	want, f := nativeTargetExpectation(t)
	native, err := OpenNativeTargetLedger(filepath.Join(t.TempDir(), "native-targets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	digest, err := native.RegisterNonSecretTarget(ctx, want, []byte(`{"client_id":"ci-client","issuer":"https://idp.example.test"}`))
	if err != nil {
		t.Fatal(err)
	}
	cp := &targetRegistrationFixture{digest: digest}
	targets, err := NewCompositeApprovalTargets(cp, native)
	if err != nil {
		t.Fatal(err)
	}
	actors := &approvalFixture{
		actor: "33333333-3333-4333-8333-333333333333",
		clock: f.clock,
	}
	ledger, err := OpenApprovalLedger(filepath.Join(t.TempDir(), "approvals.db"), actors, targets, func() time.Time { return actors.clock })
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	receipt := ApprovedReference{
		Expectation: want,
		Status:      "APPROVED",
		NonSecret:   true,
		ValidFrom:   actors.clock.Add(-time.Minute),
		ExpiresAt:   actors.clock.Add(10 * time.Minute),
	}
	proposal, err := ledger.Propose(ctx, proposalID, receipt)
	if err != nil || proposal.TargetDigest != digest {
		t.Fatalf("proposal=%#v err=%v", proposal, err)
	}
	if _, err := ledger.Decide(ctx, proposal.ID, proposal.TargetDigest, true); !errors.Is(err, ErrDenied) {
		t.Fatalf("self approval accepted: %v", err)
	}
	actors.actor = "44444444-4444-4444-8444-444444444444"
	if _, err := ledger.Decide(ctx, proposal.ID, proposal.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reference(ctx, want); err != nil {
		t.Fatal(err)
	}
	cp.digest = "sha256:" + strings.Repeat("e", 64)
	if _, err := ledger.Reference(ctx, want); !errors.Is(err, ErrUnverified) {
		t.Fatalf("drifted CP registration accepted at use: %v", err)
	}
}

func TestCompositeTargetsGateTrustProposalAndDecision(t *testing.T) {
	ctx := context.Background()
	_, source := setup(t, "oidc")
	snapshot := source.snapshot
	snapshot.Trust.Status = "REQUESTED"
	snapshot.Trust.ActivatedAt = nil
	snapshot.Trust.ActivationEvidenceReference = ""

	want := ReferenceExpectation{
		ID:               "ref_ciactivation",
		Kind:             "federation_activation",
		TrustID:          snapshot.Trust.ID,
		SnapshotID:       snapshot.SnapshotID,
		TrustRevision:    snapshot.ApprovedRevision,
		ProviderID:       snapshot.Trust.ProviderBinding.ProviderID,
		EngineInstanceID: snapshot.Trust.ProviderBinding.EngineInstanceID,
		Scope:            source.platform.Scope,
	}
	native, err := OpenNativeTargetLedger(filepath.Join(t.TempDir(), "native-targets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	digest, err := native.RegisterTrustSnapshotTarget(ctx, want, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	cp := &targetRegistrationFixture{digest: digest}
	targets, err := NewCompositeApprovalTargets(cp, native)
	if err != nil {
		t.Fatal(err)
	}
	actors := &approvalFixture{
		actor: "33333333-3333-4333-8333-333333333333",
		clock: source.clock,
	}
	ledger, err := OpenTrustLedger(
		filepath.Join(t.TempDir(), "trusts.db"),
		actors,
		targets,
		source,
		func() time.Time { return actors.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	proposal, err := ledger.Propose(ctx, proposalID, snapshot, want)
	if err != nil || proposal.TargetDigest != TrustSnapshotDigest(snapshot) {
		t.Fatalf("proposal=%#v err=%v", proposal, err)
	}
	actors.actor = "44444444-4444-4444-8444-444444444444"
	if _, err := ledger.Decide(ctx, proposal.ID, proposal.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	got, err := ledger.Trust(ctx, snapshot.Trust.ID)
	if err != nil || !sameSnapshot(got, snapshot) {
		t.Fatalf("trust=%#v err=%v", got, err)
	}
	cp.digest = "sha256:" + strings.Repeat("e", 64)
	if _, err := ledger.Propose(ctx, "66666666-6666-4666-8666-666666666666", snapshot, want); err == nil {
		t.Fatal("trust proposal ignored CP/native drift")
	}
}

func TestHTTPAuthorityReadsTargetRegistration(t *testing.T) {
	want, _ := nativeTargetExpectation(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	client, server := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/federation/v1/target-registration" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"digest":"` + digest + `"}`))
	})
	defer server.Close()
	client.tokens = &testAuthorityToken{value: "isolated-service-token"}
	got, err := client.TargetRegistration(context.Background(), want)
	if err != nil || got.Digest != digest {
		t.Fatalf("registration=%#v err=%v", got, err)
	}
}
