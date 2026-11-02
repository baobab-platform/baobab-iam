package nativebff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Real HTTPS transport / process handler, not the Keycloak or Hydra product.
// Current native security response stays DENIED under forged tracing.
func TestDEV11N08NativeRealHTTPSChildAndDeniedAuthority(t *testing.T) {
	var mu sync.Mutex
	var outbound []string
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outbound = append(outbound, r.Header.Get("traceparent"))
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer issuer.Close()
	client := issuer.Client()
	client.Transport = N08TraceTransport{Base: client.Transport}

	metrics := NewN08OperationalMetrics()
	handler := ObserveN08Native(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, ok := n08CurrentTrace(r.Context())
		if !ok || upstream.TraceID == "" {
			t.Error("native BFF did not carry its own W3C context")
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, issuer.URL, nil)
		if err != nil {
			t.Error("invalid test request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// This adversarial header must never override the trusted local span.
		request.Header.Set("traceparent", "00-"+strings.Repeat("b", 32)+"-"+strings.Repeat("c", 16)+"-01")
		result, err := client.Do(request)
		if err != nil {
			t.Error("native TLS transport unavailable")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = result.Body.Close()
		w.WriteHeader(result.StatusCode)
	}), metrics)

	for _, tc := range []struct {
		incoming string
		expected string
	}{
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01", ""},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://estate.example.test/auth/start?token=secret", nil)
		request.Header.Set("traceparent", tc.incoming)
		request.Header.Set("Authorization", "Bearer confidential")
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, request)
		if reply.Code != http.StatusForbidden {
			t.Fatal("trace context overrode provider denial")
		}
		got, ok := n08ParseTraceparent(reply.Header().Get("traceparent"))
		if !ok {
			t.Fatal("native BFF did not return valid server-generated W3C context")
		}
		if tc.expected != "" && got.TraceID != tc.expected {
			t.Fatal("valid upstream trace was not preserved")
		}
		if tc.expected == "" && (got.TraceID == strings.Repeat("0", 32) || got.TraceID == strings.Repeat("b", 32)) {
			t.Fatal("malformed or forged trace became trusted")
		}
		if got.SpanID == "00f067aa0ba902b7" {
			t.Fatal("server copied upstream span without a child")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outbound) != 2 {
		t.Fatal("native secured HTTPS outbound operations were not observed")
	}
	first, ok := n08ParseTraceparent(outbound[0])
	if !ok || first.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || first.SpanID == "00f067aa0ba902b7" {
		t.Fatal("native issuer TLS HTTP lost W3C causality")
	}
	second, ok := n08ParseTraceparent(outbound[1])
	if !ok || second.TraceID == strings.Repeat("b", 32) {
		t.Fatal("adversarial caller headers controlled the issuer span")
	}
	if metrics.Snapshot().Authority {
		t.Fatal("observability was mistaken for native issuer approval")
	}
}
