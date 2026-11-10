package ory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func TestKratosOpaqueSubjectCannotSelectAdminRoute(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL, HydraAdminURL: srv.URL,
		PublicIssuer: "https://identity.example",
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"..", "../clients", "id/other", "id?scope=admin", "id#fragment", "%2F", "id\\next", " leading", "id\nnewline"} {
		t.Run(subject, func(t *testing.T) {
			ref := provider.ExternalSubject{Issuer: "https://identity.example", Subject: subject}
			if _, err := adapter.GetIdentity(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("malformed subject passed GetIdentity: %v", err)
			}
			if err := adapter.DisableIdentity(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("malformed subject passed DisableIdentity: %v", err)
			}
			if err := adapter.RevokeSessions(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("malformed subject passed RevokeSessions: %v", err)
			}
			if _, err := adapter.ReconcileIdentity(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("malformed subject passed ReconcileIdentity: %v", err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("unsafe subjects reached privileged Kratos Admin API %d times", requests)
	}
}

func TestKratosReadbackMustMatchExactIssuerSubject(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/identities/id-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "id-2", "schema_id": "default", "state": "active",
			"traits":          map[string]any{"email": "not-an-identity-key@example.invalid"},
			"metadata_public": map[string]any{},
			"created_at":      now.Format(time.RFC3339Nano),
			"updated_at":      now.Format(time.RFC3339Nano),
		})
	}))
	defer srv.Close()
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL, HydraAdminURL: srv.URL,
		PublicIssuer: "https://identity.example", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := provider.ExternalSubject{Issuer: "https://identity.example", Subject: "id-1"}
	if v, err := adapter.GetIdentity(context.Background(), ref); err == nil || v != nil {
		t.Fatalf("mismatched provider identity must not be mapped: value=%v err=%v", v, err)
	}
	if v, err := adapter.ReconcileIdentity(context.Background(), ref); err == nil || v != nil {
		t.Fatalf("mismatched provider identity must not be reconciled: value=%v err=%v", v, err)
	}
}
