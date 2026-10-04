package federation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// AuthorityAccess authenticates the inbound service credential and evaluates
// CURRENT permission and target scope. The returned context carries verified
// actor identity for approval decisions. It must also enforce workload lifecycle
// and service audience; a TLS connection or possession of a ref is insufficient.
// No default, role-only fallback or effective-authority display adapter exists.
type AuthorityAccess interface {
	AuthorizeAuthorityRequest(context.Context, *http.Request, string, ReferenceExpectation) (context.Context, error)
}
type AuthoritySources struct {
	Access        AuthorityAccess
	Governance    GovernanceAuthority
	Platform      PlatformAuthority
	Canonical     CanonicalAuthority
	Approvals     ApprovalAuthority
	Targets       ApprovalTargets
	Configuration OIDCConfigurationAuthority
	Assurance     AssuranceMapper
	Ledger        *ApprovalLedger
	TrustLedger   *TrustLedger
}

// NewAuthorityHandler exposes the fixed private transport with mandatory
// request-time authorization. Unconfigured source operations fail closed as
// unsupported. CP and IAM mount only the source operations they own, behind
// their verified token/mTLS and canonical authorization composition roots.
// It does not create platform facts, approval permissions or canonical mappings.
func NewAuthorityHandler(s AuthoritySources) (http.Handler, error) {
	if absent(s.Access) {
		return nil, ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func(err error) {
			status := http.StatusServiceUnavailable
			switch {
			case errors.Is(err, ErrInvalid):
				status = http.StatusBadRequest
			case errors.Is(err, ErrDenied):
				status = http.StatusForbidden
			case errors.Is(err, ErrUnverified):
				status = http.StatusConflict
			case errors.Is(err, ErrUnsupported):
				status = http.StatusNotImplemented
			}
			w.WriteHeader(status)
			io.WriteString(w, `{"error":"authority request denied"}`)
		}
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			fail(ErrDenied)
			return
		}
		// Authenticate before parsing or looking up any proposal. Scoped
		// authorization follows after its target has been decoded/resolved.
		ctx, err := s.Access.AuthorizeAuthorityRequest(r.Context(), r, "AUTHENTICATE", ReferenceExpectation{})
		if err != nil {
			fail(authorityError(err))
			return
		}
		if ctx == nil || ctx.Err() != nil {
			fail(ErrUnavailable)
			return
		}
		r = r.WithContext(ctx)
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(ErrInvalid)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			fail(ErrInvalid)
			return
		}
		authorize := func(action string, want ReferenceExpectation) (context.Context, error) {
			ctx, err := s.Access.AuthorizeAuthorityRequest(r.Context(), r, action, want)
			if err != nil {
				return nil, authorityError(err)
			}
			if ctx == nil || ctx.Err() != nil {
				return nil, ErrUnavailable
			}
			return ctx, nil
		}
		var out any
		checkSnapshot := func(ctx context.Context, want TrustSnapshot) error {
			if absent(s.Governance) {
				return ErrUnsupported
			}
			current, err := s.Governance.Trust(ctx, want.Trust.ID)
			if err != nil {
				return authorityError(err)
			}
			if !sameSnapshot(current, want) {
				return ErrUnverified
			}
			return nil
		}
		switch r.URL.Path {
		case "/internal/federation/v1/trust":
			var req struct{ ID string }
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("TRUST_READ", ReferenceExpectation{TrustID: req.ID})
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Governance) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Governance.Trust(ctx, req.ID)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/reference":
			var req ReferenceExpectation
			if decodeAuthority(data, &req) != nil || !validExpectation(req) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("REFERENCE_READ", req)
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Governance) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Governance.Reference(ctx, req)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/target":
			var wire referenceExpectationWire
			if decodeAuthority(data, &wire) != nil {
				fail(ErrInvalid)
				return
			}
			req := wire.expectation()
			if !validExpectation(req) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("TARGET_READ", req)
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Targets) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Targets.ResolveApprovedTarget(ctx, req)
			if err != nil {
				fail(err)
				return
			}
			out = digestWire{Digest: value}
		case "/internal/federation/v1/binding":
			var req platformBindingWire
			if decodeAuthority(data, &req) != nil {
				fail(ErrInvalid)
				return
			}
			scope := req.platformScope()
			if !validBinding(req.Binding) || !validScope(scope) || !validFederationRuntimeCapability(req.RuntimeCapability) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("PLATFORM_READ", ReferenceExpectation{ProviderID: req.Binding.ProviderID, EngineInstanceID: req.Binding.EngineInstanceID, Scope: scope})
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Platform) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Platform.FederationBinding(ctx, req.Binding, scope, req.RuntimeCapability)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/identity":
			var req struct{ Issuer, Subject string }
			if decodeAuthority(data, &req) != nil || req.Issuer == "" || len(req.Issuer) > 2048 || !exact(req.Subject) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("CANONICAL_READ", ReferenceExpectation{Issuer: req.Issuer, Subject: req.Subject})
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Canonical) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Canonical.Resolve(ctx, req.Issuer, req.Subject)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/approval-authority":
			var req approvalAuthorityWire
			if decodeAuthority(data, &req) != nil {
				fail(ErrInvalid)
				return
			}
			target := req.Target.expectation()
			if !validExpectation(target) || req.SubjectToken == "" || len(req.SubjectToken) > 16384 || req.Action != "PROPOSE" && req.Action != "DECIDE" && req.Action != "REVOKE" {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("APPROVAL_"+req.Action, target)
			if err == nil {
				ctx, err = WithGovernanceSubjectToken(ctx, req.SubjectToken)
			}
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Approvals) {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Approvals.AuthorizeApproval(ctx, req.Action, target)
			if err != nil {
				fail(err)
				return
			}
			out = approvalActorWire{PrincipalID: value.PrincipalID, ValidUntil: value.ValidUntil}
		case "/internal/federation/v1/approvals/propose":
			var req struct {
				ID      string
				Receipt ApprovedReference
			}
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) || !validExpectation(req.Receipt.Expectation) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("APPROVAL_PROPOSE", req.Receipt.Expectation)
			if err != nil {
				fail(err)
				return
			}
			if s.Ledger == nil {
				fail(ErrUnsupported)
				return
			}
			value, err := s.Ledger.Propose(ctx, req.ID, req.Receipt)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/approvals/decide":
			var req struct {
				ID, TargetDigest string
				Approve          bool
			}
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) || !digestPattern.MatchString(req.TargetDigest) {
				fail(ErrInvalid)
				return
			}
			if s.Ledger == nil {
				fail(ErrUnsupported)
				return
			}
			p, err := s.Ledger.proposal(r.Context(), req.ID)
			if err != nil {
				fail(err)
				return
			}
			ctx, err := authorize("APPROVAL_DECIDE", p.Receipt.Expectation)
			if err != nil {
				fail(err)
				return
			}
			value, err := s.Ledger.Decide(ctx, req.ID, req.TargetDigest, req.Approve)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/approvals/revoke":
			var req struct{ ID string }
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) {
				fail(ErrInvalid)
				return
			}
			if s.Ledger == nil {
				fail(ErrUnsupported)
				return
			}
			p, err := s.Ledger.proposal(r.Context(), req.ID)
			if err != nil {
				fail(err)
				return
			}
			ctx, err := authorize("APPROVAL_REVOKE", p.Receipt.Expectation)
			if err != nil {
				fail(err)
				return
			}
			if err = s.Ledger.Revoke(ctx, req.ID); err != nil {
				fail(err)
				return
			}
			out = struct{ Status string }{"REVOKED"}

		case "/internal/federation/v1/trusts/propose":
			var req struct {
				ID       string
				Snapshot TrustSnapshot
				Target   ReferenceExpectation
			}
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) || !validExpectation(req.Target) {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("APPROVAL_PROPOSE", req.Target)
			if err != nil {
				fail(err)
				return
			}
			if s.TrustLedger == nil {
				fail(ErrUnsupported)
				return
			}
			value, err := s.TrustLedger.Propose(ctx, req.ID, req.Snapshot, req.Target)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/trusts/decide":
			var req struct {
				ID, TargetDigest string
				Approve          bool
			}
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) || !digestPattern.MatchString(req.TargetDigest) {
				fail(ErrInvalid)
				return
			}
			if s.TrustLedger == nil {
				fail(ErrUnsupported)
				return
			}
			p, err := s.TrustLedger.proposal(r.Context(), req.ID)
			if err != nil {
				fail(err)
				return
			}
			ctx, err := authorize("APPROVAL_DECIDE", p.Target)
			if err != nil {
				fail(err)
				return
			}
			value, err := s.TrustLedger.Decide(ctx, req.ID, req.TargetDigest, req.Approve)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/trusts/contain":
			var req struct {
				ID       string
				Revision uint64
				Status   string
			}
			if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.ID) || req.Revision == 0 || req.Status != "SUSPENDED" && req.Status != "REVOKED" {
				fail(ErrInvalid)
				return
			}
			if s.TrustLedger == nil {
				fail(ErrUnsupported)
				return
			}
			value, err := s.TrustLedger.read(r.Context(), req.ID)
			if err != nil {
				fail(err)
				return
			}
			current := value.Snapshot
			want := ReferenceExpectation{ID: current.Trust.ProviderBinding.ConfigurationReference, Kind: "federation_configuration", TrustID: req.ID, SnapshotID: current.SnapshotID, TrustRevision: current.ApprovedRevision, ProviderID: current.Trust.ProviderBinding.ProviderID, EngineInstanceID: current.Trust.ProviderBinding.EngineInstanceID, Scope: value.Scope}
			ctx, err := authorize("APPROVAL_REVOKE", want)
			if err != nil {
				fail(err)
				return
			}
			if err = s.TrustLedger.Contain(ctx, req.ID, req.Revision, req.Status); err != nil {
				fail(err)
				return
			}
			out = struct{ Status string }{req.Status}
		case "/internal/federation/v1/oidc-configuration":
			var req TrustSnapshot
			if decodeAuthority(data, &req) != nil {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("CONFIGURATION_READ", ReferenceExpectation{TrustID: req.Trust.ID, SnapshotID: req.SnapshotID, TrustRevision: req.ApprovedRevision})
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Configuration) {
				fail(ErrUnsupported)
				return
			}
			if err = checkSnapshot(ctx, req); err != nil {
				fail(err)
				return
			}
			value, err := s.Configuration.OIDCConfiguration(ctx, req)
			if err != nil {
				fail(err)
				return
			}
			out = value
		case "/internal/federation/v1/map-assurance":
			var req struct {
				Snapshot  TrustSnapshot
				Principal ExternalPrincipal
				Evidence  Assurance
			}
			if decodeAuthority(data, &req) != nil || ValidateBundle(Bundle{req.Snapshot.Trust, req.Principal, req.Evidence}) != nil {
				fail(ErrInvalid)
				return
			}
			ctx, err := authorize("ASSURANCE_MAP", ReferenceExpectation{TrustID: req.Snapshot.Trust.ID, EventID: req.Principal.AuthenticationEventID, Issuer: req.Principal.Issuer, Subject: req.Principal.Subject})
			if err != nil {
				fail(err)
				return
			}
			if absent(s.Assurance) {
				fail(ErrUnsupported)
				return
			}
			if err = checkSnapshot(ctx, req.Snapshot); err != nil {
				fail(err)
				return
			}
			value, err := s.Assurance.MapAssurance(ctx, req.Snapshot, req.Principal, req.Evidence)
			if err != nil {
				fail(err)
				return
			}
			out = value
		default:
			fail(ErrUnsupported)
			return
		}
		data, err = json.Marshal(out)
		if err != nil || len(data) > 65536 {
			fail(ErrUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}), nil
}
