package nativebff

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// N08OperationalMetrics records fixed-cardinality route/status/latency counters.
// It intentionally retains NO user identifiers, IPs, paths containing secrets,
// cookies, OAuth parameters, request/response bodies or provider URLs. This is
// operational telemetry, never authenticated authority or acceptance evidence.
type N08OperationalMetrics struct {
	mu     sync.Mutex
	counts map[string]uint64
}

type N08Metric struct {
	Route         string `json:"route"`
	StatusClass   string `json:"status_class"`
	LatencyBucket string `json:"latency_bucket"`
	Count         uint64 `json:"count"`
}

type N08Snapshot struct {
	Classification string      `json:"classification"`
	Authority      bool        `json:"authority_certified"`
	Metrics        []N08Metric `json:"metrics"`
}

func NewN08OperationalMetrics() *N08OperationalMetrics {
	return &N08OperationalMetrics{counts: make(map[string]uint64)}
}

func n08Route(method, path string) string {
	switch method + " " + path {
	case "POST /auth/start":
		return "start"
	case "GET /auth/login":
		return "login"
	case "GET /auth/consent", "POST /auth/consent":
		return "consent"
	case "GET /auth/callback":
		return "callback"
	case "GET /auth/session":
		return "session"
	case "POST /auth/logout", "POST /auth/logout-all":
		return "logout"
	case "GET /auth/recovery":
		return "recovery"
	default:
		return "other"
	}
}

func n08Status(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}

func n08Latency(d time.Duration) string {
	switch {
	case d <= 25*time.Millisecond:
		return "le25ms"
	case d <= 100*time.Millisecond:
		return "le100ms"
	case d <= 500*time.Millisecond:
		return "le500ms"
	default:
		return "over500ms"
	}
}

func (m *N08OperationalMetrics) observe(route string, status int, elapsed time.Duration) {
	if m == nil {
		return
	}
	key := route + "|" + n08Status(status) + "|" + n08Latency(elapsed)
	m.mu.Lock()
	m.counts[key]++
	m.mu.Unlock()
}

// Snapshot produces only stable bounded labels for private service monitoring.
// No request ID or identity is retained even transiently in the metrics map.
func (m *N08OperationalMetrics) Snapshot() N08Snapshot {
	out := N08Snapshot{Classification: "IAM_N08_SOURCE_OBSERVABILITY_NOT_ISSUER_ACCEPTANCE", Authority: false}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.counts))
	for key := range m.counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var route, status, latency string
		// keys are exclusively concatenated from hard-coded enumerations.
		for i := 0; i < len(key); i++ {
			if key[i] == '|' {
				route = key[:i]
				for j := i + 1; j < len(key); j++ {
					if key[j] == '|' {
						status, latency = key[i+1:j], key[j+1:]
						break
					}
				}
				break
			}
		}
		out.Metrics = append(out.Metrics, N08Metric{Route: route, StatusClass: status, LatencyBucket: latency, Count: m.counts[key]})
	}
	return out
}

func (m *N08OperationalMetrics) SnapshotJSON() string {
	b, _ := json.Marshal(m.Snapshot())
	return string(b)
}

type n08Response struct {
	http.ResponseWriter
	status int
}

func (w *n08Response) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *n08Response) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap preserves Go's ResponseController support for optional transport
// capabilities; operational wrappers must not silently break streaming.
func (w *n08Response) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ObserveN08Native adds a fresh server-generated correlation identifier to
// browser responses and only fixed-cardinality timings to the private monitor.
// Caller-supplied request IDs and URL/query values cannot select any labels.
func ObserveN08Native(next http.Handler, m *N08OperationalMetrics) http.Handler {
	if next == nil || m == nil {
		panic("N08 source requires a real browser handler and private metrics")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		route := n08Route(r.Method, r.URL.Path)
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			m.observe(route, http.StatusServiceUnavailable, time.Since(start))
			http.Error(w, "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Baobab-Request-ID", hex.EncodeToString(id[:]))
		observed := &n08Response{ResponseWriter: w}
		next.ServeHTTP(observed, r)
		if observed.status == 0 {
			observed.status = http.StatusOK
		}
		m.observe(route, observed.status, time.Since(start))
	})
}
