package nativebff

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

// N08Trace is diagnostic request context, never a verified actor/tenant/grant.
type N08Trace struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Flags        string
}

type n08TraceKey struct{}

var n08W3C = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

func n08Fresh(bytes int) (string, bool) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	return hex.EncodeToString(b), true
}

func n08ParseTraceparent(raw string) (N08Trace, bool) {
	m := n08W3C.FindStringSubmatch(raw)
	if m == nil || strings.Trim(m[1], "0") == "" || strings.Trim(m[2], "0") == "" {
		return N08Trace{}, false
	}
	return N08Trace{TraceID: m[1], SpanID: m[2], Flags: m[3]}, true
}

func (trace N08Trace) Traceparent() string {
	if trace.TraceID == "" || trace.SpanID == "" {
		return ""
	}
	return "00-" + trace.TraceID + "-" + trace.SpanID + "-" + trace.Flags
}

func n08BeginTrace(ctx context.Context, remote string) context.Context {
	parent, valid := n08ParseTraceparent(remote)
	traceID := parent.TraceID
	flags := "01"
	parentID := ""
	if valid {
		flags = parent.Flags
		parentID = parent.SpanID
	} else {
		var ok bool
		traceID, ok = n08Fresh(16)
		if !ok {
			return ctx // Telemetry cannot veto a business decision.
		}
	}
	spanID, ok := n08Fresh(8)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, n08TraceKey{}, N08Trace{
		TraceID: traceID, SpanID: spanID, ParentSpanID: parentID, Flags: flags,
	})
}

func n08CurrentTrace(ctx context.Context) (N08Trace, bool) {
	value, ok := ctx.Value(n08TraceKey{}).(N08Trace)
	return value, ok && value.TraceID != "" && value.SpanID != ""
}

// N08TraceTransport propagates a distinct child span on the real native
// Kratos/Hydra HTTPS client. It never adds actor, scope or tenant claims.
// Caller-provided headers cannot override server-constructed trace context.
type N08TraceTransport struct {
	Base http.RoundTripper
}

func (t N08TraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	clone := req.Clone(req.Context())
	clone.Header.Del("traceparent")
	if trace, ok := n08CurrentTrace(req.Context()); ok {
		if childID, ready := n08Fresh(8); ready {
			child := N08Trace{TraceID: trace.TraceID, SpanID: childID, ParentSpanID: trace.SpanID, Flags: trace.Flags}
			clone.Header.Set("traceparent", child.Traceparent())
		}
	}
	return base.RoundTrip(clone)
}
