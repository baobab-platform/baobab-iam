package nativebff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

func TestHydraOAuthRevocationRequiresInactiveTokenReadback(t *testing.T) {
	var revoked, inspected []string
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/revoke" {
			t.Errorf("unexpected public Hydra request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if user, pass, ok := r.BasicAuth(); !ok || user != "estate-bff" || pass != strings.Repeat("s", 32) {
			t.Error("revocation missing confidential client authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		revoked = append(revoked, r.Form.Get("token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer public.Close()

	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/oauth2/introspect" {
			t.Errorf("unexpected private Hydra request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := r.Form.Get("token")
		inspected = append(inspected, token)
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false, "sub": "synthetic-subject"})
	}))
	defer admin.Close()

	revoker, err := NewHydraOAuthRevoker(HydraOAuthRevokeConfig{
		Issuer: public.URL, AdminOrigin: admin.URL, ClientID: "estate-bff",
		ClientSecret: strings.Repeat("s", 32), AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens := humanauth.Response{AccessToken: strings.Repeat("a", 40), RefreshToken: strings.Repeat("r", 40)}
	if err := revoker.Revoke(context.Background(), tokens); err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 || len(inspected) != 2 ||
		revoked[0] != tokens.AccessToken || revoked[1] != tokens.RefreshToken ||
		inspected[0] != tokens.AccessToken || inspected[1] != tokens.RefreshToken {
		t.Fatalf("access/refresh revocation and read-back mismatch: revoked=%d inspected=%d", len(revoked), len(inspected))
	}
}

func TestHydraOAuthRevocationFailsWhenReadbackRemainsActiveOrUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		active bool
	}{
		{name: "still active", status: http.StatusOK, active: true},
		{name: "admin unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer public.Close()
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_ = json.NewEncoder(w).Encode(map[string]bool{"active": tc.active})
				}
			}))
			defer admin.Close()
			revoker, err := NewHydraOAuthRevoker(HydraOAuthRevokeConfig{
				Issuer: public.URL, AdminOrigin: admin.URL, ClientID: "estate-bff",
				ClientSecret: strings.Repeat("s", 32), AllowTestLoopback: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := revoker.Revoke(context.Background(), humanauth.Response{
				AccessToken: strings.Repeat("a", 40), RefreshToken: strings.Repeat("r", 40),
			}); err == nil {
				t.Fatal("unconfirmed Hydra token withdrawal accepted")
			}
		})
	}
}

func TestHydraOAuthRevokerRequiresPrivateAdminOrigin(t *testing.T) {
	if _, err := NewHydraOAuthRevoker(HydraOAuthRevokeConfig{
		Issuer: "https://issuer.example", AdminOrigin: "http://hydra-admin.example",
		ClientID: "estate-bff", ClientSecret: strings.Repeat("s", 32),
	}); err == nil {
		t.Fatal("unencrypted Hydra admin origin accepted")
	}
}
