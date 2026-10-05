package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type serviceTestAccess struct{ denied bool }

func (a serviceTestAccess) AuthorizeAuthorityRequest(ctx context.Context, _ *http.Request, _ string, _ ReferenceExpectation) (context.Context, error) {
	if a.denied {
		return nil, ErrDenied
	}
	return ctx, nil
}

func TestPrivateEventFlowUsesRealVerifierAndReplayFence(t *testing.T) {
	e, of, s, key, _ := oidcSetup(t)
	defer e.Close()
	if err := e.Ready(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	original := of.config.SnapshotID
	of.config.SnapshotID = "different-snapshot"
	if err := e.Ready(context.Background(), s); err == nil {
		t.Fatal("configuration drift made service ready")
	}
	of.config.SnapshotID = original
	c, f := setup(t, "oidc")
	f.canonical.Subject = "issuer-local-human-123"
	c.authorities.Events = e
	h, err := NewServiceEventHandler(serviceTestAccess{}, f, e, c)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string, value any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(value)
		r := httptest.NewRequest("POST", "https://iam.example/internal/federation-events/v1/"+path, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post("begin", map[string]string{"TrustID": s.Trust.ID, "SessionDigest": secretDigest(browserSecret)})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var request AuthenticationRequest
	if json.Unmarshal(w.Body.Bytes(), &request) != nil {
		t.Fatal("invalid begin response")
	}
	token := signOIDC(t, key, oidcClaims(of, s, request))
	w = post("complete", map[string]string{"TrustID": s.Trust.ID, "EventID": request.ID, "State": request.State, "BrowserSecret": browserSecret, "IDToken": token})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = post("consume", map[string]string{"TrustID": s.Trust.ID, "EventID": request.ID})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = post("consume", map[string]string{"TrustID": s.Trust.ID, "EventID": request.ID})
	if w.Code != 403 {
		t.Fatal("replayed evidence accepted", w.Code)
	}
	w = post("begin", map[string]string{"TrustID": s.Trust.ID, "SessionDigest": secretDigest(browserSecret), "IDToken": token})
	if w.Code != 403 {
		t.Fatal("cross-operation input accepted")
	}
	h, err = NewServiceEventHandler(serviceTestAccess{denied: true}, f, e, c)
	if err != nil {
		t.Fatal(err)
	}
	w = post("begin", map[string]string{"TrustID": s.Trust.ID, "SessionDigest": secretDigest(browserSecret)})
	if w.Code != 403 {
		t.Fatal("unauthorized event creation")
	}
}
