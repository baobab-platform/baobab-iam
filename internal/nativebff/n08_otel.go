package nativebff

// DEV-11: opt-in OTLP/HTTP JSON export for ACTUAL Kratos/Hydra client
// requests and N08 confidential issuer HTTP handlers. No customer, token,
// path, OAuth code, raw error or Principal identity is ever exported.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func n08Collector() string {
	raw := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/traces" {
		return ""
	}
	env := os.Getenv("BAOBAB_ENVIRONMENT")
	if env == "" {
		env = "development"
	}
	// Do not synchronously export on protected traffic; this is disposable L4 only.
	if env != "development" && env != "test" && env != "integration" {
		return ""
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (env == "development" || env == "test" || env == "integration")) {
		return ""
	}
	return u.String()
}
func n08OtlpId(raw string) string {
	data, err := hex.DecodeString(raw)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
func n08ExportSpan(trace N08Trace, begin time.Time, kind string) {
	endpoint := n08Collector()
	if endpoint == "" || trace.TraceID == "" || trace.SpanID == "" || trace.Flags != "01" {
		return
	}
	if kind != "baobab.iam.http" && kind != "baobab.iam.issuer.client" {
		return
	}
	spanKind := 2
	if kind == "baobab.iam.issuer.client" {
		spanKind = 3
	}
	message := map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": []any{
			map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "baobab-iam"}},
			map[string]any{"key": "service.namespace", "value": map[string]any{"stringValue": "baobab"}},
		}},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]any{"name": "baobab.iam.native", "version": "dev11"},
			"spans": []any{map[string]any{
				"traceId": n08OtlpId(trace.TraceID), "spanId": n08OtlpId(trace.SpanID),
				"parentSpanId": n08OtlpId(trace.ParentSpanID),
				"name":         kind, "kind": spanKind,
				"startTimeUnixNano": strconv.FormatInt(begin.UnixNano(), 10),
				"endTimeUnixNano":   strconv.FormatInt(time.Now().UnixNano(), 10),
				"attributes": []any{map[string]any{"key": "baobab.operation",
					"value": map[string]any{"stringValue": kind}}},
			}},
		}},
	}}}
	body, err := json.Marshal(message)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err == nil {
		_ = response.Body.Close()
	}
}
