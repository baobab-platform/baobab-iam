package federation

import (
	"context"
)

// LiveConfig uses separately authenticated sources. Deployments must wire CP
// platform/canonical authority, IAM governance and approved protocol policy,
// never four aliases to an identity provider's admin endpoint.
type LiveConfig struct {
	Governance      *HTTPAuthority
	Platform        *HTTPAuthority
	Canonical       *HTTPAuthority
	ProtocolPolicy  *HTTPAuthority
	EventLedgerPath string
	Policy          Policy
}
type LiveConsumer struct {
	Consumer *Consumer
	Events   *OIDCEvents
}

// NewLive wires a persistent, actual signature verifier into the existing
// consumer. It does not mount a public browser callback or enable production.
// SAML is explicitly unsupported until a separately reviewed verifier exists.
func NewLive(cfg LiveConfig) (*LiveConsumer, error) {
	if cfg.Governance == nil || cfg.Platform == nil || cfg.Canonical == nil || cfg.ProtocolPolicy == nil || cfg.Policy.Now == nil {
		return nil, ErrInvalid
	}
	events, err := OpenOIDCEvents(cfg.EventLedgerPath, cfg.ProtocolPolicy, cfg.ProtocolPolicy, cfg.Policy.Now, cfg.Policy.MaxEventLifetime)
	if err != nil {
		return nil, err
	}
	c, err := New(Authorities{cfg.Governance, cfg.Platform, events, cfg.Canonical}, cfg.Policy)
	if err != nil {
		events.Close()
		return nil, err
	}
	return &LiveConsumer{c, events}, nil
}
func (c *LiveConsumer) Close() error {
	if c == nil || c.Events == nil {
		return ErrUnavailable
	}
	return c.Events.Close()
}

func (a *HTTPAuthority) AuthorizeApproval(ctx context.Context, action string, want ReferenceExpectation) (ApprovalActor, error) {
	var out approvalActorWire
	if !validExpectation(want) || action != "PROPOSE" && action != "DECIDE" && action != "REVOKE" {
		return ApprovalActor{}, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/approval-authority", approvalAuthorityWire{
		Action: action,
		Target: newReferenceExpectationWire(want),
	}, &out)
	if err != nil {
		return ApprovalActor{}, err
	}
	return ApprovalActor{PrincipalID: out.PrincipalID, ValidUntil: out.ValidUntil}, nil
}
func (a *HTTPAuthority) ResolveApprovedTarget(ctx context.Context, want ReferenceExpectation) (string, error) {
	var out digestWire
	if !validExpectation(want) {
		return "", ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/target", newReferenceExpectationWire(want), &out)
	if err != nil {
		return "", err
	}
	if !digestPattern.MatchString(out.Digest) {
		return "", ErrInvalid
	}
	return out.Digest, nil
}
func (a *HTTPAuthority) OIDCConfiguration(ctx context.Context, s TrustSnapshot) (OIDCConfiguration, error) {
	var out OIDCConfiguration
	err := a.call(ctx, "/internal/federation/v1/oidc-configuration", s, &out)
	if err != nil {
		return OIDCConfiguration{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) MapAssurance(ctx context.Context, s TrustSnapshot, p ExternalPrincipal, evidence Assurance) (Assurance, error) {
	var out Assurance
	err := a.call(ctx, "/internal/federation/v1/map-assurance", struct {
		Snapshot  TrustSnapshot
		Principal ExternalPrincipal
		Evidence  Assurance
	}{s, p, evidence}, &out)
	if err != nil {
		return Assurance{}, err
	}
	return out, nil
}

func (a *HTTPAuthority) ProposeReferenceApproval(ctx context.Context, id string, receipt ApprovedReference) (ApprovalProposal, error) {
	var out ApprovalProposal
	if !uuidPattern.MatchString(id) || !validExpectation(receipt.Expectation) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/approvals/propose", struct {
		ID      string
		Receipt ApprovedReference
	}{id, receipt}, &out)
	if err != nil {
		return ApprovalProposal{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) DecideReferenceApproval(ctx context.Context, id, digest string, approve bool) (ApprovalProposal, error) {
	var out ApprovalProposal
	if !uuidPattern.MatchString(id) || !digestPattern.MatchString(digest) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/approvals/decide", struct {
		ID, TargetDigest string
		Approve          bool
	}{id, digest, approve}, &out)
	if err != nil {
		return ApprovalProposal{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) RevokeReferenceApproval(ctx context.Context, id string) error {
	var out struct{ Status string }
	if !uuidPattern.MatchString(id) {
		return ErrInvalid
	}
	if err := a.call(ctx, "/internal/federation/v1/approvals/revoke", struct{ ID string }{id}, &out); err != nil {
		return err
	}
	if out.Status != "REVOKED" {
		return ErrUnverified
	}
	return nil
}

var _ ApprovalAuthority = (*HTTPAuthority)(nil)
var _ ApprovalTargets = (*HTTPAuthority)(nil)
var _ OIDCConfigurationAuthority = (*HTTPAuthority)(nil)
var _ AssuranceMapper = (*HTTPAuthority)(nil)

func (a *HTTPAuthority) ProposeTrust(ctx context.Context, id string, snapshot TrustSnapshot, target ReferenceExpectation) (TrustProposal, error) {
	var out TrustProposal
	if !uuidPattern.MatchString(id) || ValidateTrust(snapshot.Trust) != nil || !validExpectation(target) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/trusts/propose", struct {
		ID       string
		Snapshot TrustSnapshot
		Target   ReferenceExpectation
	}{id, snapshot, target}, &out)
	if err != nil {
		return TrustProposal{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) DecideTrust(ctx context.Context, id, digest string, approve bool) (TrustProposal, error) {
	var out TrustProposal
	if !uuidPattern.MatchString(id) || !digestPattern.MatchString(digest) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/trusts/decide", struct {
		ID, TargetDigest string
		Approve          bool
	}{id, digest, approve}, &out)
	if err != nil {
		return TrustProposal{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) ContainTrust(ctx context.Context, id string, revision uint64, status string) error {
	if !uuidPattern.MatchString(id) || revision == 0 || status != "SUSPENDED" && status != "REVOKED" {
		return ErrInvalid
	}
	var out struct{ Status string }
	if err := a.call(ctx, "/internal/federation/v1/trusts/contain", struct {
		ID       string
		Revision uint64
		Status   string
	}{id, revision, status}, &out); err != nil {
		return err
	}
	if out.Status != status {
		return ErrUnverified
	}
	return nil
}
