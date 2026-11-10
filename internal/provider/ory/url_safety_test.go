package ory_test

import (
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// ADR-0001/0003: an IAM provider cannot start with a malformed privileged
// endpoint or issuer. These are constructor/negative checks, not proof of
// private networking or connected Kratos/Hydra/CP acceptance.
func TestNewAdapterRejectsAmbiguousProviderEndpoints(t *testing.T) {
	base := ory.Config{
		KratosAdminURL: "http://kratos-admin:4434",
		HydraAdminURL:  "http://hydra-admin:4445",
		PublicIssuer:   "https://identity.example/issuer",
	}
	tests := []struct {
		name, endpoint string
		set           func(*ory.Config, string)
	}{
		{"kratos-userinfo", "http://user:password@kratos-admin:4434", func(c *ory.Config, s string) { c.KratosAdminURL = s }},
		{"kratos-extra-path", "https://kratos-admin:4434/admin/identities", func(c *ory.Config, s string) { c.KratosAdminURL = s }},
		{"kratos-encoded-path", "https://kratos-admin:4434/%2F", func(c *ory.Config, s string) { c.KratosAdminURL = s }},
		{"kratos-query", "http://kratos-admin:4434?api_key=secret", func(c *ory.Config, s string) { c.KratosAdminURL = s }},
		{"hydra-file", "file:///etc/passwd", func(c *ory.Config, s string) { c.HydraAdminURL = s }},
		{"hydra-fragment", "https://hydra-admin:4445/#token", func(c *ory.Config, s string) { c.HydraAdminURL = s }},
		{"hydra-userinfo", "https://user@hydra-admin:4445", func(c *ory.Config, s string) { c.HydraAdminURL = s }},
		{"issuer-relative", "/identity", func(c *ory.Config, s string) { c.PublicIssuer = s }},
		{"issuer-userinfo", "https://attacker@identity.example", func(c *ory.Config, s string) { c.PublicIssuer = s }},
		{"issuer-javascript", "javascript:alert(1)", func(c *ory.Config, s string) { c.PublicIssuer = s }},
		{"issuer-query", "https://identity.example?token=secret", func(c *ory.Config, s string) { c.PublicIssuer = s }},
		{"issuer-fragment", "https://identity.example/#section", func(c *ory.Config, s string) { c.PublicIssuer = s }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.set(&cfg, tc.endpoint)
			if _, err := ory.NewAdapter(cfg); err == nil {
				t.Fatalf("unsafe endpoint %q was accepted", tc.endpoint)
			}
		})
	}
	if _, err := ory.NewAdapter(base); err != nil {
		t.Fatalf("valid internal admin origins and path-qualified issuer refused: %v", err)
	}
}
