package nativebff

import (
	"errors"
	"net/http"
	"testing"
)

// ADR-0009: an authenticated workforce principal with an earlier AAL2
// callback has no enduring privileged session when Kratos loses step-up,
// changes the native subject or becomes unavailable. CP still supplies fresh
// canonical Principal evidence AFTER the independent assurance check.
// All evidence here uses disposable local fixtures, not a real provider.
func TestWorkforceSessionRequiresCurrentAAL2AndSameSubject(t *testing.T) {
	f := makeFixture(t)
	assurance := &fixtureAAL{aal: "aal2"}
	conf := f.h.c
	conf.RequireAAL2 = true
	conf.Assurance = assurance
	h, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	txn, state := startFlow(t, f)
	kratos := &http.Cookie{Name: "ory_kratos_session", Value: "kratos-browser-session"}
	callback := request(h, "GET", "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+state, "", txn, kratos)
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("AAL2 signed callback refused: %d", callback.Code)
	}
	sess := findCookie(callback, sessionCookie)
	if sess == nil {
		t.Fatal("verified callback did not create session")
	}
	check := func() int {
		return request(h, "GET", "http://127.0.0.1:3000/auth/session", "", sess, kratos).Code
	}
	if code := check(); code != http.StatusOK {
		t.Fatalf("current privileged workforce session rejected: %d", code)
	}
	alreadyReadCP := f.cp.calls
	assurance.aal = "aal1"
	if code := check(); code != http.StatusUnauthorized || f.cp.calls != alreadyReadCP {
		t.Fatal("downgraded AAL was treated as privileged workforce authentication")
	}
	assurance.aal = "aal2"
	assurance.subject = "substituted-person"
	if code := check(); code != http.StatusUnauthorized || f.cp.calls != alreadyReadCP {
		t.Fatal("a different Kratos human was accepted for stored workforce session")
	}
	assurance.subject = ""
	assurance.err = errors.New("Kratos assurance unavailable")
	if code := check(); code != http.StatusUnauthorized || f.cp.calls != alreadyReadCP {
		t.Fatal("Kratos outage permitted stale privilege")
	}
	assurance.err = nil
	if code := request(h, "GET", "http://127.0.0.1:3000/auth/session", "", sess).Code; code != http.StatusUnauthorized || f.cp.calls != alreadyReadCP {
		t.Fatal("missing current Kratos session permitted AAL2")
	}
	if code := check(); code != http.StatusOK || f.cp.calls != alreadyReadCP+1 {
		t.Fatal("restored verified AAL2 must still recheck CP current Principal")
	}
}
