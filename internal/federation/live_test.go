package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// Only this isolated test authorizer uses a fixture credential. Production
// must verify token/mTLS, registered workload state and canonical permissions.
type isolatedAccess struct {
	err   error
	calls int
}

func (a *isolatedAccess) AuthorizeAuthorityRequest(ctx context.Context, r *http.Request, _ string, _ ReferenceExpectation) (context.Context, error) {
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	if r.Header.Get("Authorization") != "Bearer isolated-service-token" {
		return nil, ErrDenied
	}
	return ctx, nil
}
func TestLiveCompositionActualTLSOIDCReplayAndConsumer(t *testing.T) {
	e, policy, s, key, _ := oidcSetup(t)
	defer e.Close()
	_, facts := setup(t, "oidc")
	facts.canonical.Subject = "issuer-local-human-123"
	access := &isolatedAccess{}
	h, err := NewAuthorityHandler(AuthoritySources{Access: access, Governance: facts, Platform: facts, Canonical: facts, Configuration: policy, Assurance: policy})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a, err := NewHTTPAuthority(server.URL, &testAuthorityToken{value: "isolated-service-token"}, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	live, err := NewLive(LiveConfig{Governance: a, Platform: a, Canonical: a, ProtocolPolicy: a, EventLedgerPath: filepath.Join(t.TempDir(), "live-events.db"), Policy: Policy{Scope: facts.platform.Scope, MaxEventLifetime: 10 * time.Minute, MaxAuthenticationAge: 5 * time.Minute, MaxDecisionLifetime: time.Minute, Now: func() time.Time { return policy.clock }}})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	r, err := live.Events.Begin(context.Background(), s, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err = live.Events.Complete(context.Background(), r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(policy, s, r)), s); err != nil {
		t.Fatal(err)
	}
	d, err := live.Consumer.Consume(context.Background(), s.Trust.ID, r.ID)
	if err != nil || d.PrincipalID != facts.canonical.PrincipalID || d.AssuranceLevel != "BAOBAB-A1" {
		t.Fatal(d, err)
	}
	if _, err = live.Consumer.Consume(context.Background(), s.Trust.ID, r.ID); err == nil {
		t.Fatal("replay accepted")
	}
	if access.calls < 12 {
		t.Fatal("authority calls bypassed", access.calls)
	}
	access.err = ErrUnavailable
	if _, err = a.Resolve(context.Background(), facts.canonical.Issuer, facts.canonical.Subject); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestAuthorityHandlerRequiresAccessAndRefusesUnconfiguredSource(t *testing.T) {
	if _, err := NewAuthorityHandler(AuthoritySources{}); err == nil {
		t.Fatal("unauthenticated source handler")
	}
	access := &isolatedAccess{}
	h, err := NewAuthorityHandler(AuthoritySources{Access: access})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) })
	a.tokens = &testAuthorityToken{value: "isolated-service-token"}
	if _, err = a.Trust(context.Background(), proposalID); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	a.tokens = &testAuthorityToken{value: "incorrect"}
	if _, err = a.Trust(context.Background(), proposalID); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}

func TestPrivateApprovalWorkflowUsesDurableLedger(t *testing.T) {
	l, actor, receipt, _ := approvalSetup(t)
	defer l.Close()
	h, err := NewAuthorityHandler(AuthoritySources{Access: &isolatedAccess{}, Ledger: l, Approvals: actor, Targets: actor})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) })
	client.tokens = &testAuthorityToken{value: "isolated-service-token"}
	ctx := context.Background()
	p, err := client.ProposeReferenceApproval(ctx, proposalID, receipt)
	if err != nil || p.Status != "PENDING" {
		t.Fatal(p, err)
	}
	if _, err = client.DecideReferenceApproval(ctx, p.ID, p.TargetDigest, true); !errors.Is(err, ErrDenied) {
		t.Fatal("remote self approval", err)
	}
	actor.actor = "44444444-4444-4444-8444-444444444444"
	p, err = client.DecideReferenceApproval(ctx, p.ID, p.TargetDigest, true)
	if err != nil || p.Status != "APPROVED" {
		t.Fatal(p, err)
	}
	if _, err = l.Reference(ctx, receipt.Expectation); err != nil {
		t.Fatal(err)
	}
	if err = client.RevokeReferenceApproval(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Reference(ctx, receipt.Expectation); err == nil {
		t.Fatal("remote revocation ignored")
	}
}
