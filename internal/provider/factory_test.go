package provider_test

import (
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestParseProviderName(t *testing.T) {
	cases := []struct {
		in   string
		want provider.ProviderName
		ok   bool
	}{
		{"ory", provider.ProviderOry, true},
		{"KRATOS", provider.ProviderOry, true},
		{"hydra", provider.ProviderOry, true},
		{"keycloak", provider.ProviderKeycloak, true},
		{"kc", provider.ProviderKeycloak, true},
		{"", "", false},
		{"auth0", "", false},
	}
	for _, tc := range cases {
		got, err := provider.ParseProviderName(tc.in)
		if tc.ok {
			if err != nil {
				t.Fatalf("%q: unexpected err %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
			}
		} else if err == nil {
			t.Fatalf("%q: expected error", tc.in)
		}
	}
}
