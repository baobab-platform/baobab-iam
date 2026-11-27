package nativebff

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestKratosSessionRevocationRequiresCompleteActiveInventory(t *testing.T) {
	const subject = "11111111-1111-4111-8111-111111111111"
	for _, tc := range []struct {
		name       string
		inventory  string
		link       string
		counts     []string
		deleteCode int
		readCode   int
		wantOK     bool
	}{
		{name: "empty", inventory: "[]\n", counts: []string{"0"}, link: `</next>; rel="next"`, wantOK: true},
		{name: "sessions remain", inventory: `[{"active":true}]`, counts: []string{"0"}},
		{name: "unknown inventory", inventory: "null", counts: []string{"0"}},
		{name: "malformed inventory", inventory: "[]{}", counts: []string{"0"}},
		{name: "partial inventory", inventory: "[]", counts: []string{"1"}},
		{name: "missing count", inventory: "[]"},
		{name: "ambiguous count", inventory: "[]", counts: []string{"0", "1"}},
		{name: "oversized inventory", inventory: strings.Repeat(" ", 64*1024) + "[]", counts: []string{"0"}},
		{name: "readback outage", readCode: http.StatusServiceUnavailable},
		{name: "unconfirmed deletion", deleteCode: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deletes, reads atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/identities/"+subject+"/sessions" ||
					r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept") != "application/json" {
					t.Error("unexpected Kratos request boundary")
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				switch r.Method {
				case http.MethodDelete:
					deletes.Add(1)
					if tc.deleteCode != 0 {
						w.WriteHeader(tc.deleteCode)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				case http.MethodGet:
					reads.Add(1)
					if deletes.Load() != 1 || r.URL.RawQuery != "active=true" {
						t.Error("expected a fresh, subject-bound active inventory after deletion")
					}
					w.Header().Set("Content-Type", "application/json")
					for _, count := range tc.counts {
						w.Header().Add("X-Total-Count", count)
					}
					if tc.link != "" {
						w.Header().Set("Link", tc.link)
					}
					if tc.readCode != 0 {
						w.WriteHeader(tc.readCode)
					}
					_, _ = w.Write([]byte(tc.inventory))
				default:
					http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			revoker, err := NewKratosAdminSessionRevoker(KratosAdminRevokeConfig{Origin: server.URL, TrustedRoots: roots})
			if err != nil {
				t.Fatal(err)
			}
			if err := revoker.RevokeNativeSessions(context.Background(), subject); (err == nil) != tc.wantOK {
				t.Fatalf("unexpected confirmation result: %v", err)
			}
			wantReads := int32(1)
			if tc.deleteCode != 0 {
				wantReads = 0
			}
			if deletes.Load() != 1 || reads.Load() != wantReads {
				t.Fatal("unexpected deletion or readback count")
			}
		})
	}
}
