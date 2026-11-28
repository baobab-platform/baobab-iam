package nativebff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestN08OperationalTelemetryCannotLeakSecretsOrCallerLabels(t *testing.T) {
	m := NewN08OperationalMetrics()
	h := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), m)
	for _, path := range []string{"/auth/session?access_token=sensitive", "/auth/session?code=private",
		"/sensitive-private-email@example.test?state=oauth-secret"} {
		req := httptest.NewRequest(http.MethodGet, "https://estate.test"+path, nil)
		req.Header.Set("X-Request-ID", "client-forged-label")
		req.Header.Set("Authorization", "Bearer private-original")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized || len(w.Header().Get("X-Baobab-Request-ID")) != 32 {
			t.Fatal("N08 unexpected result or missing original correlation ID")
		}
		if w.Header().Get("X-Baobab-Request-ID") == "client-forged-label" {
			t.Fatal("caller request ID became trusted")
		}
	}
	reply := m.SnapshotJSON()
	for _, sensitive := range []string{"sensitive", "private-original", "private-email", "state",
		"code=", "oauth-secret", "client-forged-label", "Bearer", "estate.test"} {
		if strings.Contains(reply, sensitive) {
			t.Fatalf("privacy-unsafe observability label: %s", sensitive)
		}
	}
	if !strings.Contains(reply, "\"route\":\"session\"") || !strings.Contains(reply, "\"route\":\"other\"") ||
		!strings.Contains(reply, "\"status_class\":\"4xx\"") {
		t.Fatal("trusted bounded route/status vocabulary missing")
	}
	var observed N08Snapshot
	if json.Unmarshal([]byte(reply), &observed) != nil || observed.Authority ||
		observed.Classification != "IAM_N08_SOURCE_OBSERVABILITY_NOT_ISSUER_ACCEPTANCE" {
		t.Fatal("operational observation misclassified as issuer authority")
	}
}

func TestN08OperationalBucketsHaveFixedCardinality(t *testing.T) {
	m := NewN08OperationalMetrics()
	for _, entry := range []struct {
		duration time.Duration
		want     string
	}{
		{25 * time.Millisecond, "le25ms"},
		{100 * time.Millisecond, "le100ms"},
		{500 * time.Millisecond, "le500ms"},
		{501 * time.Millisecond, "over500ms"},
	} {
		if got := n08Latency(entry.duration); got != entry.want {
			t.Fatalf("duration bucket %s, want %s", got, entry.want)
		}
	}
	h := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}), m)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET",
				"https://estate.test/auth/session?tenant=foreign", nil))
		}()
	}
	wg.Wait()
	out := m.Snapshot()
	var count uint64
	for _, v := range out.Metrics {
		if v.Route != "session" || v.StatusClass != "4xx" {
			t.Fatal("untrusted labels entered native metrics")
		}
		count += v.Count
	}
	if count != 100 {
		t.Fatalf("lost concurrent observations: %d", count)
	}
}

func TestN08OperationalImplicit200AndRedirect(t *testing.T) {
	m := NewN08OperationalMetrics()
	one := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("limited diagnostic only"))
	}), m)
	one.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://estate.test/auth/session", nil))
	two := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
	}), m)
	two.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://estate.test/auth/login", nil))
	out := m.SnapshotJSON()
	if !strings.Contains(out, "\"status_class\":\"2xx\"") ||
		!strings.Contains(out, "\"status_class\":\"3xx\"") {
		t.Fatal("response writer status classifier drift")
	}
}

// Microbenchmark only: measures in-memory observability overhead, not the
// real Kratos/Hydra/Control Plane/estate latency acceptance.
func BenchmarkN08SourceOnlyNativeObservation(b *testing.B) {
	m := NewN08OperationalMetrics()
	h := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), m)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
			"https://estate.test/auth/session", nil))
	}
}
