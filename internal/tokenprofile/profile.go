// Package tokenprofile governs workload claims from pinned Shared configuration.
// It consumes authenticated provider evidence, never tenant/domain authority.
package tokenprofile

import (
	"fmt"
	"regexp"
	"strings"
)

const FederatedGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type Workload struct {
	CredentialType string `json:"credential_type"`
	Status string `json:"status"`
	Scopes []string `json:"allowed_scopes"`
	Audiences []string `json:"allowed_audiences"`
}

// Binding is governed runtime configuration, reconciled with provider trust.
// It must not be supplied by the workload requesting a token.
type Binding struct {
	Issuer string `json:"issuer"`
	Subject string `json:"subject"`
}

type Config struct {
	SharedCommit string `json:"shared_commit"`
	Workloads map[string]Workload `json:"workloads"`
	Bindings map[string]Binding `json:"bindings"`
}

type Evidence struct {
	ClientID string
	Subject string
	Grant string
	AssertionIssuer string
	AssertionSubject string
	RequestedScopes []string
	GrantedScopes []string
	GrantedAudiences []string
}

func (c Config) Validate() error {
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(c.SharedCommit) || len(c.Workloads) == 0 {
		return fmt.Errorf("exact Shared commit and workload profiles required")
	}
	for id, p := range c.Workloads {
		if id == "" || strings.TrimSpace(id) != id || len(p.Scopes) == 0 || len(p.Audiences) == 0 {
			return fmt.Errorf("invalid workload profile")
		}
		if p.CredentialType != "client_credentials" && p.CredentialType != "federated_workload_token" {
			return fmt.Errorf("unsupported workload credential profile")
		}
		switch p.Status {
		case "ACTIVE", "PROVISIONED", "SUSPENDED", "REVOKED", "RETIRED":
		default: return fmt.Errorf("unknown Shared lifecycle")
		}
		for _, values := range [][]string{p.Scopes, p.Audiences} {
			seen := map[string]bool{}
			for _, value := range values {
				if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n*") || seen[value] {
					return fmt.Errorf("noncanonical or duplicate scope/audience")
				}
				seen[value] = true
			}
		}
	}
	for id, binding := range c.Bindings {
		p, ok := c.Workloads[id]
		if !ok || p.CredentialType != "federated_workload_token" || binding.Issuer == "" || binding.Subject == "" {
			return fmt.Errorf("invalid federated workload binding")
		}
	}
	return nil
}

// Claims evaluates already-authenticated provider evidence. PROVISIONED permits
// provider mechanics only; it is never returned as canonical activation evidence.
func (c Config) Claims(e Evidence) (map[string]any, error) {
	p, ok := c.Workloads[e.ClientID]
	if !ok || (p.Status != "ACTIVE" && p.Status != "PROVISIONED") { return nil, fmt.Errorf("workload issuance denied") }
	switch p.CredentialType {
	case "client_credentials":
		if e.Grant != "client_credentials" || e.Subject != e.ClientID { return nil, fmt.Errorf("workload credential profile mismatch") }
	case "federated_workload_token":
		binding, ok := c.Bindings[e.ClientID]
		if !ok || e.Grant != FederatedGrant || e.Subject != binding.Subject || e.AssertionSubject != binding.Subject || e.AssertionIssuer != binding.Issuer { return nil, fmt.Errorf("workload assertion binding mismatch") }
	default: return nil, fmt.Errorf("unsupported credential profile")
	}
	if len(e.RequestedScopes) == 0 || !subset(e.RequestedScopes, p.Scopes) || !sameSet(e.GrantedScopes, e.RequestedScopes) {
		return nil, fmt.Errorf("workload scope mismatch")
	}
	if len(e.GrantedAudiences) == 0 || !subset(e.GrantedAudiences, p.Audiences) { return nil, fmt.Errorf("workload audience mismatch") }
	return map[string]any{"actor_type":"workload", "azp":e.ClientID, "scope":strings.Join(e.GrantedScopes," ")}, nil
}

func subset(values, allowed []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		found := false
		for _, candidate := range allowed { if value == candidate { found = true; break } }
		if !found || seen[value] { return false }; seen[value] = true
	}
	return true
}

func sameSet(a,b []string) bool { return len(a) == len(b) && subset(a,b) }
