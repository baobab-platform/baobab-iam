package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

func TestSessionRiskReaderRequiresExactFreshOriginalEvidence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		alter         func(*sessionRiskObservation)
		allowed, held bool
	}{
		{name: "current clear", allowed: true},
		{name: "current hold", alter: func(o *sessionRiskObservation) { o.RecoveryState = "hold" }, allowed: true, held: true},
		{name: "wrong subject", alter: func(o *sessionRiskObservation) { o.Subject = "other" }},
		{name: "different session", alter: func(o *sessionRiskObservation) { o.SessionID = "other" }},
		{name: "different operation", alter: func(o *sessionRiskObservation) { o.Operation = assurance.Login }},
		{name: "replay", alter: func(o *sessionRiskObservation) { o.Nonce = "earlier" }},
		{name: "stale recovery read", alter: func(o *sessionRiskObservation) { o.RecoveryCheckedThrough = o.ObservedAt.Add(-time.Minute) }},
		{name: "future recovery read", alter: func(o *sessionRiskObservation) { o.RecoveryCheckedThrough = o.ObservedAt.Add(time.Second) }},
		{name: "no original recovery reference", alter: func(o *sessionRiskObservation) { o.RecoveryReference = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/internal/iam/v1/session-risk/observe" ||
					r.Header.Get("Authorization") != "Bearer service-token" {
					t.Error("request escaped the authenticated risk endpoint")
				}
				var query sessionRiskQuery
				if err := json.NewDecoder(r.Body).Decode(&query); err != nil || len(query.Nonce) != 48 {
					t.Error("invalid bound request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				o := sessionRiskObservation{sessionRiskQuery: query, Level: "low", ObservedAt: now,
					RecoveryState: "clear", RecoveryCheckedThrough: now.Add(-time.Second),
					RiskReference: "ref_risk_original", RecoveryReference: "ref_recovery_original"}
				if tc.alter != nil {
					tc.alter(&o)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(o)
			})
			reader, err := NewSessionRiskReader(a, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			risk, err := reader.CurrentRisk(context.Background(), assurance.CurrentSessionKey{
				Issuer: "https://kratos.invalid", Subject: "subject", SessionID: "session",
			}, assurance.HighValueApproval)
			if (err == nil) != tc.allowed || risk.PrivilegedContextVerified ||
				tc.allowed && (!risk.RecoveryStateChecked || risk.RecoverySuspicious != tc.held || !risk.ObservedAt.Equal(now.Add(-time.Second))) {
				t.Fatalf("unexpected risk result: %+v %v", risk, err)
			}
		})
	}
}
