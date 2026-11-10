package ory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// The CP grant for interactive login cannot authorize a separately catalogued
// assurance evaluation, even when it concerns the same native human subject.
type assuranceCurrentDispatch struct {
	deny           atomic.Bool
	onlyHumanLogin atomic.Bool
	checks         atomic.Int32
}

func (a *assuranceCurrentDispatch) CheckCapability(_ context.Context, capability string) error {
	a.checks.Add(1)
	if a.deny.Load() || a.onlyHumanLogin.Load() && capability != provider.CapabilityHumanAuthentication ||
		capability != provider.CapabilityAuthenticationAssurance {
		return errors.New("CP assurance support not currently granted")
	}
	return nil
}
func TestGovernedNativeAssuranceUsesRealCurrentProviderAndCPChecks(t *testing.T) {
	authenticated := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var reads atomic.Int32
	var active atomic.Bool
	active.Store(true)
	var substituted atomic.Bool
	var lowered atomic.Bool
	var changeBetweenReads atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.URL.Path != "/sessions/whoami" || r.Header.Get("Cookie") != "ory_kratos_session=synthetic" || r.Header.Get("X-Session-Token") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := "current-session"
		if substituted.Load() {
			id = "substituted-session"
		}
		aal := "aal2"
		if lowered.Load() || (changeBetweenReads.Load() && reads.Load() >= 3) {
			aal = "aal1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "active": active.Load(), "expires_at": expires,
			"authenticated_at": authenticated, "authenticator_assurance_level": aal,
			"identity":               map[string]any{"id": "verified-subject", "state": "active"},
			"authentication_methods": []map[string]string{{"method": "password"}, {"method": "totp"}, {"method": "passkey"}},
		})
	}))
	defer srv.Close()
	cp := &assuranceCurrentDispatch{}
	h, err := NewGovernedNativeHumanHandoff(NativeHumanConfig{
		KratosPublicURL: srv.URL, HydraAdminURL: srv.URL, Issuer: srv.URL,
		Client: srv.Client(), Now: time.Now, Fence: openNativeTestFence(t),
	}, cp)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	credential := NativeSessionCredential{Cookie: "ory_kratos_session=synthetic"}
	event, session, err := h.CurrentAssuranceReferences(ctx, credential)
	if err != nil || !strings.HasPrefix(event, "ref_") || !strings.HasPrefix(session, "ref_") {
		t.Fatalf("server-owned references: %q %q %v", event, session, err)
	}
	req := assurance.Request{Schema: assurance.RequestSchema, AuthenticationEventReference: event, SessionReference: session, OperationClass: assurance.Login}
	res, err := h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.MetNotAuthorization || res.ObservedLevel != assurance.A2 || res.RequiredLevel != assurance.A1 ||
		res.EvidenceReference == "" || res.AuthenticatedAt == nil || reads.Load() != 3 {
		t.Fatalf("live current login qualification: %+v, reads=%d, err=%v", res, reads.Load(), err)
	}
	req.OperationClass = assurance.BuyerCommit
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied || res.Reason != assurance.CurrentRiskUnknown || res.EvidenceReference != "" {
		t.Fatalf("unsupported risk status incorrectly qualified buyer commit: %+v %v", res, err)
	}
	req.OperationClass = assurance.HighValueApproval
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied {
		t.Fatalf("generic passkey was elevated: %+v %v", res, err)
	}
	req.OperationClass = assurance.Login
	cp.deny.Store(true)
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied {
		t.Fatalf("CP dispatch revoked: %+v %v", res, err)
	}
	if _, _, err = h.CurrentAssuranceReferences(ctx, credential); err == nil {
		t.Fatal("CP withdrawal returned new references")
	}
	cp.deny.Store(false)
	cp.onlyHumanLogin.Store(true)
	before := reads.Load()
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied || reads.Load() != before {
		t.Fatalf("native login grant substituted for canonical assurance grant: %+v %v", res, err)
	}
	cp.onlyHumanLogin.Store(false)
	active.Store(false)
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied || res.Reason != assurance.AssuranceUnavailable {
		t.Fatalf("provider revocation: %+v %v", res, err)
	}
	active.Store(true)
	substituted.Store(true)
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied {
		t.Fatalf("replaced session: %+v %v", res, err)
	}
	substituted.Store(false)
	lowered.Store(true)
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.MetNotAuthorization || res.ObservedLevel != assurance.A1 {
		t.Fatalf("AAL downgrade not reflected: %+v %v", res, err)
	}
	lowered.Store(false)
	// The first proof read is followed by a second independent read. A
	// change to current AAL between those reads must kill success.
	reads.Store(1)
	changeBetweenReads.Store(true)
	res, err = h.EvaluateAssurance(ctx, credential, req)
	if err != nil || res.Outcome != assurance.Denied || res.Reason != assurance.CurrentSessionMissing {
		t.Fatalf("change between reads: %+v %v", res, err)
	}
	changeBetweenReads.Store(false)
	res, err = h.EvaluateAssurance(ctx, NativeSessionCredential{}, req)
	if err != nil || res.Outcome != assurance.Denied {
		t.Fatalf("missing native credential: %+v %v", res, err)
	}
}
