package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testAuthorityToken struct {
	value string
	err   error
}

func (t *testAuthorityToken) Token(context.Context) (string, error) { return t.value, t.err }
func tlsAuthority(t *testing.T, h http.HandlerFunc) (*HTTPAuthority, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a, err := NewHTTPAuthority(server.URL, &testAuthorityToken{value: "service-token"}, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return a, server
}
func TestHTTPAuthorityAuthenticatedStrictTransport(t *testing.T) {
	_, f := setup(t, "oidc")
	calls := 0
	a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/internal/federation/v1/trust" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer service-token" || r.URL.RawQuery != "" {
			t.Error("credential/path binding")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.snapshot)
	})
	s, err := a.Trust(context.Background(), f.snapshot.Trust.ID)
	if err != nil || s.SnapshotID != f.snapshot.SnapshotID || calls != 1 {
		t.Fatal(s, err, calls)
	}
	if _, err = a.Trust(context.Background(), "../target"); err == nil || calls != 1 {
		t.Fatal("invalid ID reached source")
	}
}
func TestHTTPAuthorityFailuresNeverProduceProof(t *testing.T) {
	_, f := setup(t, "oidc")
	valid, _ := json.Marshal(f.snapshot)
	cases := []struct {
		name        string
		code        int
		media, body string
		want        error
	}{
		{"unauthorized", 401, "application/json", "{}", ErrDenied}, {"down", 503, "application/json", "secret-database-detail", ErrUnavailable}, {"unsupported", 501, "application/json", "{}", ErrUnsupported}, {"redirect", 302, "application/json", "{}", ErrUnavailable},
		{"unknown", 200, "application/json", `{"CallerBoolean":true}`, ErrInvalid}, {"duplicate", 200, "application/json", `{"SnapshotID":"a","SnapshotID":"b"}`, ErrInvalid}, {"null", 200, "application/json", `{"SnapshotID":null}`, ErrInvalid}, {"trailing", 200, "application/json", string(valid) + " {}", ErrInvalid}, {"oversize", 200, "application/json", strings.Repeat("a", 65537), ErrInvalid}, {"html", 200, "text/html", "{}", ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "https://credential-leak.example")
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			})
			out, err := a.Trust(context.Background(), f.snapshot.Trust.ID)
			if !errors.Is(err, tc.want) || out.SnapshotID != "" {
				t.Fatal(out, err)
			}
		})
	}
}
func TestHTTPAuthorityRejectsUnsafeConfigurationAndTLS(t *testing.T) {
	token := &testAuthorityToken{value: "x"}
	for _, origin := range []string{"http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?token=x", "https://example.test/#frag"} {
		if _, err := NewHTTPAuthority(origin, token, nil); err == nil {
			t.Fatal(origin)
		}
	}
	if _, err := NewHTTPAuthority("https://example.test", token, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("insecure accepted")
	}
	if _, err := NewHTTPAuthority("https://example.test", nil, nil); err == nil {
		t.Fatal("anonymous authority")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted server reached") }))
	defer server.Close()
	a, err := NewHTTPAuthority(server.URL, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Trust(context.Background(), proposalID)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
