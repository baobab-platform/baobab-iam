package federation

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// NewServiceBrokerHandler is a private BFF/provider-bridge boundary. Distinct
// admitted workloads must have minimum actions; capture is never browser-facing.
func NewServiceBrokerHandler(access AuthorityAccess, g GovernanceAuthority, adapter provider.EnterpriseFederationProvider, events *BrokerEvents, consumer *Consumer) (http.Handler, error) {
	if absent(access) || absent(g) || absent(adapter) || events == nil || consumer == nil {
		return nil, ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func() {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":"enterprise federation denied"}`)
		}
		if r.Method != "POST" || r.URL.RawQuery != "" {
			fail()
			return
		}
		ctx, err := access.AuthorizeAuthorityRequest(r.Context(), r, "AUTHENTICATE", ReferenceExpectation{})
		if err != nil {
			fail()
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail()
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 131072))
		if err != nil {
			fail()
			return
		}
		var input struct{ TrustID, EventID, SessionDigest, State, BrowserSecret, PKCEVerifier, Code, Issuer, Nonce, ProviderRoute, UpstreamCorrelation, Assertion string }
		if decodeAuthority(raw, &input) != nil || !uuidPattern.MatchString(input.TrustID) {
			fail()
			return
		}
		action := ""
		allowed := map[string]bool{"TrustID": true}
		add := func(fields ...string) {
			for _, field := range fields {
				allowed[field] = true
			}
		}
		switch r.URL.Path {
		case "/internal/enterprise-federation/v1/begin":
			action = "BROKER_BEGIN"
			add("SessionDigest")
		case "/internal/enterprise-federation/v1/complete":
			action = "BROKER_COMPLETE"
			add("EventID", "State", "BrowserSecret", "PKCEVerifier", "Code", "Issuer")
		case "/internal/enterprise-federation/v1/capture":
			action = "BROKER_EVIDENCE"
			add("Nonce", "ProviderRoute", "UpstreamCorrelation", "Assertion")
		case "/internal/enterprise-federation/v1/evidence":
			action = "BROKER_EVIDENCE_READ"
			add("EventID")
		case "/internal/enterprise-federation/v1/consume":
			action = "EVENT_CONSUME"
			add("EventID")
		default:
			fail()
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			fail()
			return
		}
		for key := range fields {
			if !allowed[key] {
				fail()
				return
			}
		}
		ctx, err = access.AuthorizeAuthorityRequest(ctx, r, action, ReferenceExpectation{TrustID: input.TrustID})
		if err != nil {
			fail()
			return
		}
		s, err := g.Trust(ctx, input.TrustID)
		if err != nil {
			fail()
			return
		}
		var out any
		switch action {
		case "BROKER_BEGIN":
			out, err = adapter.BeginFederation(ctx, provider.EnterpriseLogin{TrustID: input.TrustID, SessionDigest: input.SessionDigest})
		case "BROKER_COMPLETE":
			out, err = adapter.CompleteFederation(ctx, provider.EnterpriseCallback{TrustID: input.TrustID, EventID: input.EventID, State: input.State, BrowserSecret: input.BrowserSecret, PKCEVerifier: input.PKCEVerifier, Code: input.Code, Issuer: input.Issuer})
		case "BROKER_EVIDENCE":
			err = events.Capture(ctx, s, BrokerEvidence{TrustID: input.TrustID, Nonce: input.Nonce, ProviderRoute: input.ProviderRoute, UpstreamCorrelation: input.UpstreamCorrelation, Assertion: input.Assertion})
			out = struct{ Status string }{"VERIFIED"}
		case "BROKER_EVIDENCE_READ":
			var p ExternalPrincipal
			var a Assurance
			p, a, err = events.Preview(ctx, input.EventID, s)
			out = struct {
				Principal ExternalPrincipal
				Assurance Assurance
			}{p, a}
		case "EVENT_CONSUME":
			out, err = consumer.Consume(ctx, input.TrustID, input.EventID)
		}
		if err != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(out)
	}), nil
}
