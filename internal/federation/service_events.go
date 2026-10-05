package federation

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
)

// Ready validates the same pinned public configuration used by completion.
// A successful transport response alone must not make the service ready.
func (e *OIDCEvents) Ready(ctx context.Context, s TrustSnapshot) error {
	if e == nil || e.now == nil || !activeSnapshot(s, e.now()) || s.Trust.Protocol != "OIDC" {
		return ErrUnverified
	}
	c, err := e.config.OIDCConfiguration(ctx, s)
	if err != nil {
		return authorityError(err)
	}
	if c.TrustID != s.Trust.ID || c.SnapshotID != s.SnapshotID || c.Revision != s.ApprovedRevision || c.Binding != s.Trust.ProviderBinding || !exact(c.ClientID) || !e.now().Before(c.ValidUntil) {
		return ErrUnverified
	}
	_, err = publicOIDCKeys(c)
	return err
}

// NewServiceEventHandler is private BFF-to-IAM transport. The registered BFF
// must perform authorization-code/PKCE and supply its own server-created
// browser binding. This handler never claims upstream SAML verification.
func NewServiceEventHandler(access AuthorityAccess, g GovernanceAuthority, events *OIDCEvents, consumer *Consumer) (http.Handler, error) {
	if absent(access) || absent(g) || events == nil || consumer == nil {
		return nil, ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func() { w.WriteHeader(http.StatusForbidden); io.WriteString(w, `{"error":"federation event denied"}`) }
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
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if err != nil {
			fail()
			return
		}
		var req struct{ TrustID, EventID, SessionDigest, State, BrowserSecret, IDToken string }
		if decodeAuthority(data, &req) != nil || !uuidPattern.MatchString(req.TrustID) {
			fail()
			return
		}
		action := ""
		switch r.URL.Path {
		case "/internal/federation-events/v1/begin":
			action = "EVENT_BEGIN"
			if req.EventID != "" || req.State != "" || req.BrowserSecret != "" || req.IDToken != "" {
				fail()
				return
			}
		case "/internal/federation-events/v1/complete":
			action = "EVENT_COMPLETE"
			if req.SessionDigest != "" {
				fail()
				return
			}
		case "/internal/federation-events/v1/consume":
			action = "EVENT_CONSUME"
			if req.SessionDigest != "" || req.State != "" || req.BrowserSecret != "" || req.IDToken != "" {
				fail()
				return
			}
		default:
			fail()
			return
		}
		ctx, err = access.AuthorizeAuthorityRequest(ctx, r, action, ReferenceExpectation{TrustID: req.TrustID})
		if err != nil {
			fail()
			return
		}
		snapshot, err := g.Trust(ctx, req.TrustID)
		if err != nil {
			fail()
			return
		}
		var out any
		switch action {
		case "EVENT_BEGIN":
			out, err = events.Begin(ctx, snapshot, req.SessionDigest)
		case "EVENT_COMPLETE":
			err = events.Complete(ctx, req.EventID, req.State, req.BrowserSecret, req.IDToken, snapshot)
			out = struct{ Status string }{"VERIFIED"}
		case "EVENT_CONSUME":
			out, err = consumer.Consume(ctx, req.TrustID, req.EventID)
		}
		if err != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(out)
	}), nil
}
