package nativebff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type memoryStore struct {
	mu       sync.Mutex
	tx       map[string]Transaction
	sessions map[string]Session
}

func newMemoryStore() *memoryStore {
	return &memoryStore{tx: map[string]Transaction{}, sessions: map[string]Session{}}
}
func (m *memoryStore) PutTransaction(_ context.Context, id string, tx Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tx[id]; ok {
		return errors.New("duplicate")
	}
	m.tx[id] = tx
	return nil
}
func (m *memoryStore) ReadTransaction(_ context.Context, id string) (Transaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.tx[id]
	if !ok {
		return Transaction{}, errors.New("missing")
	}
	return v, nil
}
func (m *memoryStore) TakeTransaction(_ context.Context, id string) (Transaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.tx[id]
	if !ok {
		return Transaction{}, errors.New("consumed")
	}
	delete(m.tx, id)
	return v, nil
}
func (m *memoryStore) PutSession(_ context.Context, id string, v Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = v
	return nil
}
func (m *memoryStore) ReadSession(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.sessions[id]
	if !ok {
		return Session{}, errors.New("missing")
	}
	return v, nil
}
func (m *memoryStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

type allowAdmission struct {
	reject error
	calls  int
}

func (a *allowAdmission) Admit(_ context.Context, operation, remote string) error {
	a.calls++
	if remote == "" || operation == "" {
		return errors.New("invalid admission target")
	}
	return a.reject
}

type fixtureHandoff struct {
	accepted int
	intent   humanauth.Request
}

func (f *fixtureHandoff) AcceptLogin(_ context.Context, id string, _ ory.NativeSessionCredential, intent humanauth.Request) (string, error) {
	f.accepted++
	f.intent = intent
	return "http://127.0.0.1:4444/oauth2/auth?login_verifier=test", nil
}
func (f *fixtureHandoff) AcceptConsent(_ context.Context, id string, _ ory.NativeSessionCredential, intent humanauth.Request, approved bool) (string, error) {
	if !approved {
		return "", errors.New("consent denied")
	}
	f.accepted++
	f.intent = intent
	return "http://127.0.0.1:4444/oauth2/auth?consent_verifier=test", nil
}

type fixtureVerifier struct {
	subject string
	fail    bool
}

func (f fixtureVerifier) Verify(_ context.Context, raw, nonce string) (string, error) {
	if f.fail || raw == "" || nonce == "" {
		return "", errors.New("unverified")
	}
	return f.subject, nil
}

type fixturePrincipal struct {
	deny   bool
	calls  int
	access string
}

func (p *fixturePrincipal) ResolveHuman(_ context.Context, iss, sub, access string) (Principal, error) {
	p.calls++
	p.access = access
	if p.deny || iss != "http://127.0.0.1:4444" || sub != "synthetic-subject" {
		return Principal{}, errors.New("CP refused")
	}
	return Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
}

type fixtureRevoke struct {
	calls int
	fail  bool
}

func (p *fixtureRevoke) Revoke(_ context.Context, t humanauth.Response) error {
	p.calls++
	if p.fail {
		return errors.New("issuer unavailable")
	}
	return nil
}

type fixture struct {
	h       *Handler
	store   *memoryStore
	cp      *fixturePrincipal
	revoker *fixtureRevoke
	hand    *fixtureHandoff
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	store := newMemoryStore()
	cp := &fixturePrincipal{}
	revoker := &fixtureRevoke{}
	handoff := &fixtureHandoff{}
	h, err := New(Config{
		PublicOrigin: "http://127.0.0.1:3000", Issuer: "http://127.0.0.1:4444",
		ClientID: "synthetic-estate-bff", ClientSecret: strings.Repeat("s", 32),
		RedirectURI: "http://127.0.0.1:3000/auth/callback", Scope: "openid trade:buy",
		KratosSessionCookieName: "ory_kratos_session", AccessAudience: "baobab-trade", AccessScope: "trade:buy", Now: time.Now, Handoff: handoff,
		CP: cp, Revoker: revoker, Store: store, Limiter: &allowAdmission{}, AllowTestLoopback: true,
		Verifier:       fixtureVerifier{subject: "synthetic-subject"},
		AccessVerifier: fixtureVerifier{subject: "synthetic-subject"},
		HTTPClient: &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/oauth2/token" {
				return nil, errors.New("unexpected provider path")
			}
			w := httptest.NewRecorder()
			_ = json.NewEncoder(w).Encode(humanauth.Response{
				AccessToken: strings.Repeat("a", 40), TokenType: "Bearer", ExpiresIn: 300,
				IDToken: strings.Repeat("i", 40), Scope: "openid trade:buy",
			})
			return w.Result(), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{h, store, cp, revoker, handoff}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func request(h *Handler, method, path, origin string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
func startFlow(t *testing.T, f fixture) (*http.Cookie, string) {
	t.Helper()
	w := request(f.h, "POST", "http://127.0.0.1:3000/auth/start", "http://127.0.0.1:3000")
	if w.Code != 303 {
		t.Fatalf("start %d %s", w.Code, w.Body.String())
	}
	c := findCookie(w, transactionCookie)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatal("unprotected transaction cookie")
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Host != "127.0.0.1:4444" {
		t.Fatal("unsafe OAuth redirect")
	}
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("state") == "" || loc.Query().Get("nonce") == "" {
		t.Fatal("missing PKCE/state/nonce")
	}
	return c, loc.Query().Get("state")
}
func TestOAuthStartCallbackCPAndReplay(t *testing.T) {
	f := makeFixture(t)
	c, state := startFlow(t, f)
	callback := "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state=" + state
	w := request(f.h, "GET", callback, "", c)
	if w.Code != 303 {
		t.Fatalf("callback %d %s", w.Code, w.Body.String())
	}
	session := findCookie(w, sessionCookie)
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatal("BFF session not protected")
	}
	if f.cp.calls != 1 || f.cp.access != strings.Repeat("a", 40) {
		t.Fatal("CP did not receive real subject-token evidence")
	}
	w = request(f.h, "GET", callback, "", c)
	if w.Code == 303 {
		t.Fatal("authorization code callback replay accepted")
	}
	w = request(f.h, "GET", "http://127.0.0.1:3000/auth/session", "", session)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "authenticated") {
		t.Fatal("current CP session rejected")
	}
	f.cp.deny = true
	w = request(f.h, "GET", "http://127.0.0.1:3000/auth/session", "", session)
	if w.Code != 401 {
		t.Fatal("CP revocation did not deny existing session")
	}
}
func TestStateSubstitutionAndCPUnavailableFailClosed(t *testing.T) {
	f := makeFixture(t)
	c, state := startFlow(t, f)
	w := request(f.h, "GET", "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+strings.Repeat("x", len(state)), "", c)
	if w.Code == 303 {
		t.Fatal("state substitution accepted")
	}
	f.cp.deny = true
	w = request(f.h, "GET", "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+state, "", c)
	if w.Code == 303 || len(f.store.sessions) != 0 {
		t.Fatal("CP failure issued session")
	}
}

// failSessionStore simulates a vault failure after a real code exchange.
type failSessionStore struct{ Store }

func (f failSessionStore) PutSession(context.Context, string, Session) error {
	return errors.New("disposable vault unavailable")
}

func TestCallbackFailuresRevokeExchangedTokens(t *testing.T) {
	for _, tc := range []struct {
		name               string
		breakAfterExchange func(f *fixture)
	}{
		{"ID token verification", func(f *fixture) {
			f.h.verify = fixtureVerifier{subject: "synthetic-subject", fail: true}
		}},
		{"human access token binding", func(f *fixture) {
			f.h.access = fixtureVerifier{subject: "synthetic-subject", fail: true}
		}},
		{"CP canonical Principal denial", func(f *fixture) {
			f.cp.deny = true
		}},
		{"PostgreSQL session write failure", func(f *fixture) {
			f.h.c.Store = failSessionStore{Store: f.store}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			c, state := startFlow(t, f)
			tc.breakAfterExchange(&f)
			path := "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state=" + state
			w := request(f.h, "GET", path, "", c)
			if w.Code == http.StatusSeeOther || f.revoker.calls != 1 || len(f.store.sessions) != 0 {
				t.Fatalf("callback failure did not attempt credential cleanup: status=%d revocations=%d sessions=%d",
					w.Code, f.revoker.calls, len(f.store.sessions))
			}
			if replay := request(f.h, "GET", path, "", c); replay.Code == http.StatusSeeOther ||
				f.revoker.calls != 1 {
				t.Fatal("failed callback replay unexpectedly succeeded or exchanged tokens again")
			}
		})
	}
}

func TestCallbackCleanupFailureStillRefusesSession(t *testing.T) {
	f := makeFixture(t)
	c, state := startFlow(t, f)
	f.cp.deny = true
	f.revoker.fail = true
	w := request(f.h, "GET",
		"http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+state, "", c)
	if w.Code == http.StatusSeeOther || f.revoker.calls != 1 || len(f.store.sessions) != 0 {
		t.Fatal("uncertain issuer cleanup must not authorize a browser session")
	}
}

func TestFailedCodeExchangeDoesNotClaimTokenRevocation(t *testing.T) {
	f := makeFixture(t)
	c, state := startFlow(t, f)
	f.h.client = &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("issuer unreachable")
	})}
	w := request(f.h, "GET",
		"http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+state, "", c)
	if w.Code == http.StatusSeeOther || f.revoker.calls != 0 || len(f.store.sessions) != 0 {
		t.Fatal("failed exchange cannot mint session or pretend issuer revocation was observed")
	}
}

func TestAuthenticationAdmissionRejectsBeforeProviderOrVault(t *testing.T) {
	f := makeFixture(t)
	gate := &allowAdmission{reject: ErrRateLimited}
	f.h.c.Limiter = gate
	w := request(f.h, "POST", "http://127.0.0.1:3000/auth/start", "http://127.0.0.1:3000")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" ||
		gate.calls != 1 || len(f.store.tx) != 0 {
		t.Fatal("rate-limited start performed browser transaction or returned wrong status")
	}
	gate.reject = errors.New("database unavailable")
	w = request(f.h, "POST", "http://127.0.0.1:3000/auth/start", "http://127.0.0.1:3000")
	if w.Code != http.StatusServiceUnavailable || len(f.store.tx) != 0 {
		t.Fatal("unavailable admission ledger must fail closed")
	}
}

func TestConsentRequiresExplicitPOSTAndBoundCSRF(t *testing.T) {
	f := makeFixture(t)
	c, _ := startFlow(t, f)
	k := &http.Cookie{Name: "ory_kratos_session", Value: "verified-kratos-cookie"}
	loc := "http://127.0.0.1:3000/auth/consent?consent_challenge=trusted"
	w := request(f.h, "GET", loc, "", c, k)
	if w.Code != 200 || f.hand.accepted != 0 {
		t.Fatal("consent page autoaccepted")
	}
	r := httptest.NewRequest("POST", loc, strings.NewReader("approve=yes&csrf=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:3000")
	r.AddCookie(c)
	r.AddCookie(k)
	resp := httptest.NewRecorder()
	f.h.ServeHTTP(resp, r)
	if resp.Code != 403 || f.hand.accepted != 0 {
		t.Fatal("invalid consent CSRF accepted")
	}
	txn, err := f.store.ReadTransaction(context.Background(), c.Value)
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", loc, strings.NewReader(url.Values{"approve": {"yes"}, "csrf": {txn.CSRF}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:3000")
	r.AddCookie(c)
	r.AddCookie(k)
	resp = httptest.NewRecorder()
	f.h.ServeHTTP(resp, r)
	if resp.Code != 303 || f.hand.accepted != 1 || f.hand.intent.State != txn.Intent.State {
		t.Fatal("bound consent not accepted")
	}
}
func TestLogoutRequiresCSRFAndReportsRemoteRevocationUnknown(t *testing.T) {
	f := makeFixture(t)
	c, state := startFlow(t, f)
	w := request(f.h, "GET", "http://127.0.0.1:3000/auth/callback?code=legitimate-code-1234&state="+state, "", c)
	session := findCookie(w, sessionCookie)
	if session == nil {
		t.Fatal("setup failed")
	}
	stored, err := f.store.ReadSession(context.Background(), session.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ origin, csrf string }{{"", ""}, {"http://evil.invalid", stored.CSRF}, {"http://127.0.0.1:3000", "wrong"}} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:3000/auth/logout", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-CSRF-Token", tc.csrf)
		r.AddCookie(session)
		out := httptest.NewRecorder()
		f.h.ServeHTTP(out, r)
		if out.Code != 403 {
			t.Fatalf("logout CSRF did not deny %q", tc.origin)
		}
	}
	// A Principal deactivation or CP outage cannot prevent local sign-out.
	f.cp.deny = true
	f.revoker.fail = true
	r := httptest.NewRequest("POST", "http://127.0.0.1:3000/auth/logout", nil)
	r.Header.Set("Origin", "http://127.0.0.1:3000")
	r.Header.Set("X-CSRF-Token", stored.CSRF)
	r.AddCookie(session)
	out := httptest.NewRecorder()
	f.h.ServeHTTP(out, r)
	if out.Code != 503 || f.revoker.calls != 1 {
		t.Fatalf("unconfirmed token revocation not reported %d", out.Code)
	}
	if _, err = f.store.ReadSession(context.Background(), session.Value); err == nil {
		t.Fatal("unknown revocation resurrected session")
	}
}
func TestProductionRejectsInjectedVerificationAndMissingAuthorities(t *testing.T) {
	f := makeFixture(t)
	config := f.h.c
	config.AllowTestLoopback = false
	if _, err := New(config); err == nil {
		t.Fatal("plain HTTP allowed in production")
	}
	config.PublicOrigin = "https://estate.example.invalid"
	config.Issuer = "https://issuer.example.invalid"
	config.RedirectURI = "https://estate.example.invalid/auth/callback"
	if _, err := New(config); err == nil {
		t.Fatal("test verifier injected into production")
	}
	config.Verifier = nil
	config.AccessVerifier = nil
	config.HTTPClient = nil
	config.CP = nil
	if _, err := New(config); err == nil {
		t.Fatal("native host without CP admitted")
	}
}
func TestAtomicTestTransactionConsumption(t *testing.T) {
	s := newMemoryStore()
	id := strings.Repeat("x", 43)
	tx := Transaction{ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.PutTransaction(context.Background(), id, tx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	good := make(chan bool, 25)
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.TakeTransaction(context.Background(), id); good <- err == nil }()
	}
	wg.Wait()
	close(good)
	n := 0
	for ok := range good {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("transaction consumed %d times", n)
	}
}
