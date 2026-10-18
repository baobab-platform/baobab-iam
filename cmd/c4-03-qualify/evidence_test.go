package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionRecheckRequiresLiveDisposableIdentity(t *testing.T) {
	for _, tc := range []struct {
		name               string
		active, disposable bool
		id                 string
		expires            time.Time
		status             int
		want               bool
	}{
		{"eligible", true, true, "synthetic", time.Now().Add(time.Hour), 200, true},
		{"expired", true, true, "synthetic", time.Now().Add(-time.Second), 200, false},
		{"inactive", false, true, "synthetic", time.Now().Add(time.Hour), 200, false},
		{"different identity", true, true, "different", time.Now().Add(time.Hour), 200, false},
		{"not disposable", true, false, "synthetic", time.Now().Add(time.Hour), 200, false},
		{"denied", true, true, "synthetic", time.Now().Add(time.Hour), 401, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/sessions/whoami" || r.Header.Get("X-Session-Token") != "synthetic-session" {
					t.Error("incorrect session request")
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"active": tc.active, "expires_at": tc.expires,
					"identity": map[string]any{"id": tc.id, "state": "active", "metadata_public": map[string]bool{"c403_disposable_fixture": tc.disposable}}})
			}))
			defer s.Close()
			_, err := syntheticSessionExpiry(context.Background(), s.Client(), liveConfig{KratosPublic: s.URL, NativeIdentityID: "synthetic"}, "synthetic-session")
			if (err == nil) != tc.want {
				t.Fatal("incorrect session eligibility")
			}
		})
	}
}

type failingWriter struct {
	writeErr, syncErr, closeErr error
	short                       bool
	closed, synced              bool
}

func (f *failingWriter) Write(b []byte) (int, error) {
	if f.short {
		return len(b) - 1, nil
	}
	return len(b), f.writeErr
}
func (f *failingWriter) Sync() error  { f.synced = true; return f.syncErr }
func (f *failingWriter) Close() error { f.closed = true; return f.closeErr }

func TestReceiptWriterPreservesAllIOFailures(t *testing.T) {
	writeErr, syncErr, closeErr := errors.New("write"), errors.New("sync"), errors.New("close")
	for _, f := range []*failingWriter{
		{writeErr: writeErr, closeErr: closeErr}, {syncErr: syncErr, closeErr: closeErr},
		{closeErr: closeErr}, {short: true, closeErr: closeErr}, {},
	} {
		err := writeSynced(f, []byte("receipt"))
		if !f.closed {
			t.Fatal("file not closed")
		}
		for _, expected := range []error{f.writeErr, f.syncErr, f.closeErr} {
			if expected != nil && !errors.Is(err, expected) {
				t.Fatal("lost IO error")
			}
		}
		if f.short && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("short write accepted")
		}
		if (f.writeErr != nil || f.short) && f.synced {
			t.Fatal("synced failed write")
		}
		if f.writeErr == nil && f.syncErr == nil && f.closeErr == nil && !f.short && err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublishersRejectUnknownEvidenceKeys(t *testing.T) {
	r, _ := newEvidence(strings.Repeat("a", 40))
	r.Checks["secret-bearing-unknown-key"] = false
	if publish(t.TempDir(), r) == nil {
		t.Fatal("unknown evidence serialized")
	}
	f := newFullEvidence(strings.Repeat("b", 40))
	delete(f.Checks, fullRequired[0])
	f.Checks["secret-bearing-replacement-key"] = true
	if publishFull(t.TempDir(), f) == nil {
		t.Fatal("replaced evidence serialized")
	}
}

func TestReplayRequiresSpecificProviderDenial(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   bool
	}{
		{400, `{"error":"invalid_grant"}`, true},
		{401, `{"error":"invalid_client"}`, false},
		{400, `{"error":"invalid_client"}`, false},
		{500, `{"error":"invalid_grant"}`, false},
		{400, `unavailable`, false},
	} {
		if codeReplayDenied(tc.status, []byte(tc.body)) != tc.want {
			t.Fatal("incorrect replay proof")
		}
	}
}

func TestWithdrawalMustPrecedeBothExpirationsAfterResponse(t *testing.T) {
	now := time.Now()
	valid := cpDecision{status: 404, code: "CONTEXT_NOT_FOUND"}
	if !withdrawalObserved(valid, now.Unix()+60, now.Add(time.Minute), now) {
		t.Fatal("valid withdrawal rejected")
	}
	if withdrawalObserved(valid, now.Unix(), now.Add(time.Minute), now) ||
		withdrawalObserved(valid, now.Unix()+60, now, now) ||
		withdrawalObserved(cpDecision{status: 503, code: valid.code}, now.Unix()+60, now.Add(time.Minute), now) {
		t.Fatal("expiry or outage counted as withdrawal")
	}
}
