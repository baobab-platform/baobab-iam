package ory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// TestCheckReady_BothAdminPlanesOK verifies ADR-0021 admin-plane readiness
// when both Kratos and Hydra admin bases answer /admin/health/ready.
// Offline: uses httptest only — no Docker required.
func TestCheckReady_BothAdminPlanesOK(t *testing.T) {
	kratos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer kratos.Close()

	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer hydra.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: kratos.URL,
		HydraAdminURL:  hydra.URL,
		PublicIssuer:   "http://127.0.0.1:4444/",
		HTTPClient:     kratos.Client(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	status, err := a.CheckReady(context.Background())
	if err != nil {
		t.Fatalf("CheckReady: %v (detail=%s)", err, status.Detail)
	}
	if !status.OK() {
		t.Fatalf("expected OK status, got %+v", status)
	}
	if !status.KratosAdminOK || !status.HydraAdminOK {
		t.Fatalf("plane flags: %+v", status)
	}
	if !strings.Contains(status.Detail, "kratos ready") || !strings.Contains(status.Detail, "hydra ready") {
		t.Fatalf("detail should name both planes: %s", status.Detail)
	}
}

// TestCheckReady_FallbackRootHealth covers admin listeners that expose
// /health/ready without the /admin prefix (proxy strip layouts).
func TestCheckReady_FallbackRootHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// First candidate /admin/health/ready must 404 so fallback is used.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL,
		HydraAdminURL:  srv.URL,
		PublicIssuer:   "http://issuer.example/",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	status, err := a.CheckReady(context.Background())
	if err != nil {
		t.Fatalf("CheckReady fallback: %v detail=%s", err, status.Detail)
	}
	if !status.OK() {
		t.Fatalf("expected OK via fallback: %+v", status)
	}
}

// TestCheckReady_KratosDownFailsClosed ensures one failed plane fails the
// whole readiness check (ADR-0021: both runtimes required for foundation).
func TestCheckReady_KratosDownFailsClosed(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer hydra.Close()

	// Kratos base that always returns 503 on health paths.
	kratos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer kratos.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: kratos.URL,
		HydraAdminURL:  hydra.URL,
		PublicIssuer:   "http://issuer.example/",
		HTTPClient:     hydra.Client(),
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	status, err := a.CheckReady(context.Background())
	if err == nil {
		t.Fatal("expected error when kratos is down")
	}
	if status.KratosAdminOK {
		t.Fatal("KratosAdminOK should be false")
	}
	if !status.HydraAdminOK {
		t.Fatal("HydraAdminOK should be true")
	}
	if !provider.IsUnavailable(err) {
		t.Fatalf("expected IsUnavailable, got %v", err)
	}
}
