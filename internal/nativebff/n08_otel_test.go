package nativebff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestN08ActualServerAndTransportSpansAreExported(t *testing.T) {
	delivered := make(chan map[string]any, 2)
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
		delivered <- span
	}))
	defer server.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
	t.Setenv("BAOBAB_ENVIRONMENT", "test")
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
			return &http.Response{StatusCode: http.StatusForbidden, Body: http.NoBody, Header: make(http.Header)}, nil
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
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	spans := map[string]map[string]any{}
	deadline := time.After(2 * time.Second)
	for range 2 {
		select {
		case span := <-delivered:
			spans[span["name"].(string)] = span
		case <-deadline:
			t.Fatal("missing asynchronous IAM exports")
		}
	}
	client, root := spans["baobab.iam.issuer.client"], spans["baobab.iam.http"]
	if client == nil || root == nil ||
		client["parentSpanId"] != root["spanId"] ||
		client["traceId"] != root["traceId"] ||
		root["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" ||
		root["parentSpanId"] != "00f067aa0ba902b7" ||
		!n08ValidOtlpID(root["spanId"].(string), 8) ||
		client["status"].(map[string]any)["code"] != float64(2) ||
		root["status"].(map[string]any)["code"] != float64(0) {
		t.Fatal("IAM export must preserve wire IDs, ancestry and HTTP status")
	}
}

func TestN08CollectorRequiresExplicitDisposableEnvironment(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://collector.example.invalid/v1/traces")
	for _, env := range []string{"", "staging", "production", "unknown"} {
		t.Setenv("BAOBAB_ENVIRONMENT", env)
		if n08Collector() != "" {
			t.Fatalf("export enabled for environment %q", env)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
