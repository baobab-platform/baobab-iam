package nativebff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestN08ActualServerAndTransportSpansAreExported(t *testing.T) {
	originals := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	previous := os.Getenv("BAOBAB_ENVIRONMENT")
	defer func() {
		_ = os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", originals)
		_ = os.Setenv("BAOBAB_ENVIRONMENT", previous)
	}()
	var spans []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var obj map[string]any
		if json.NewDecoder(r.Body).Decode(&obj) != nil {
			t.Error("invalid OTLP JSON")
			w.WriteHeader(400)
			return
		}
		resource := obj["resourceSpans"].([]any)[0].(map[string]any)
		attrs := resource["resource"].(map[string]any)["attributes"].([]any)
		if attrs[0].(map[string]any)["value"].(map[string]any)["stringValue"] != "baobab-iam" {
			t.Error("unexpected service")
		}
		span := resource["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
		spans = append(spans, span)
	}))
	defer server.Close()
	_ = os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
	_ = os.Setenv("BAOBAB_ENVIRONMENT", "test")
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace, ok := n08CurrentTrace(r.Context())
		if !ok {
			t.Fatal("missing real IAM request trace")
		}
		request := httptest.NewRequest("GET", "https://hydra.example.invalid/introspection", nil)
		request = request.WithContext(r.Context())
		transport := N08TraceTransport{Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("traceparent") == "" {
				t.Error("missing server-generated child")
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
		})}
		_, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		if trace.SpanID == "" {
			t.Fatal("missing native span")
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := ObserveN08Native(downstream, NewN08OperationalMetrics())
	req := httptest.NewRequest("GET", "https://iam.example.invalid/auth/session?token=private", nil)
	req.Header.Set("Authorization", "Bearer private")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if len(spans) != 2 || spans[0]["name"] != "baobab.iam.issuer.client" ||
		spans[1]["name"] != "baobab.iam.http" ||
		spans[0]["parentSpanId"] != spans[1]["spanId"] ||
		spans[0]["traceId"] != spans[1]["traceId"] {
		t.Fatalf("real export must contain client child and server parent; got %d", len(spans))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
