package nativebff

// DEV-11: opt-in OTLP/HTTP JSON export for ACTUAL Kratos/Hydra client
// requests and N08 confidential issuer HTTP handlers. No customer, token,
// path, OAuth code, raw error or Principal identity is ever exported.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	// Export is available only in an explicitly selected disposable environment.
	if env != "development" && env != "test" && env != "integration" {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	return u.String()
}
func n08ValidOtlpID(raw string, size int) bool {
	data, err := hex.DecodeString(raw)
	return err == nil && len(data) == size && hex.EncodeToString(data) == raw && strings.Trim(raw, "0") != ""
}

var n08PendingExports = make(chan struct{}, 32)
var n08OTLPClient = &http.Client{
	Timeout:       time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func n08ExportSpan(trace N08Trace, begin time.Time, kind string, httpStatus int) {
	endpoint := n08Collector()
	flags, err := strconv.ParseUint(trace.Flags, 16, 8)
	if endpoint == "" || err != nil || flags&1 == 0 ||
		!n08ValidOtlpID(trace.TraceID, 16) || !n08ValidOtlpID(trace.SpanID, 8) ||
		(trace.ParentSpanID != "" && !n08ValidOtlpID(trace.ParentSpanID, 8)) {
		return
	}
	if kind != "baobab.iam.http" && kind != "baobab.iam.issuer.client" {
		return
	}
	spanKind := 2
	if kind == "baobab.iam.issuer.client" {
		spanKind = 3
	}
	statusClass := "OTHER"
	if httpStatus >= 100 && httpStatus < 600 {
		statusClass = strconv.Itoa(httpStatus/100) + "xx"
	}
	statusCode := 0
	if httpStatus == 0 || httpStatus >= 500 || (spanKind == 3 && httpStatus >= 400) {
		statusCode = 2
	}
	message := map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": []any{
			map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "baobab-iam"}},
			map[string]any{"key": "service.namespace", "value": map[string]any{"stringValue": "baobab"}},
		}},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]any{"name": "baobab.iam.native", "version": "dev11"},
			"spans": []any{map[string]any{
				"traceId": trace.TraceID, "spanId": trace.SpanID,
				"parentSpanId": trace.ParentSpanID,
				"name":         kind, "kind": spanKind,
				"startTimeUnixNano": strconv.FormatInt(begin.UnixNano(), 10),
				"endTimeUnixNano":   strconv.FormatInt(time.Now().UnixNano(), 10),
				"attributes": []any{
					map[string]any{"key": "baobab.operation", "value": map[string]any{"stringValue": kind}},
					map[string]any{"key": "http.response.status_class", "value": map[string]any{"stringValue": statusClass}},
				},
				"status": map[string]any{"code": statusCode},
			}},
		}},
	}}}
	body, err := json.Marshal(message)
	if err != nil {
		return
	}
	select {
	case n08PendingExports <- struct{}{}:
		go func() {
			defer func() { <-n08PendingExports }()
			n08SendSpan(endpoint, body)
		}()
	default:
		// Telemetry overload leaves IAM handling and authority unchanged.
	}
}

func n08SendSpan(endpoint string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n08OTLPClient.Do(request)
	if err == nil {
		_ = response.Body.Close()
	}
}
