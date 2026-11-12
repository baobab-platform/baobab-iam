package tokenprofile

import (
	"slices"
	"testing"
)

func TestPeopleReadIssuerIsNonAuthorisingAndScoped(t *testing.T) {
	profile := Workload{Environment: "development", CredentialType: "client_credentials",
		Status: "ACTIVE", Scopes: []string{"context:resolve", "people:provider:read"},
		Audiences: []string{"baobab-control-plane"}}
	evidence := Evidence{ClientID: "people-integration", Subject: "people-integration", Grant: "client_credentials",
		RequestedScopes: slices.Clone(profile.Scopes), GrantedScopes: slices.Clone(profile.Scopes),
		GrantedAudiences: []string{"baobab-control-plane"}}
	if err := validatePeopleProviderReaderProfile("people-integration", profile); err != nil {
		t.Fatal(err)
	}
	if err := validatePeopleProviderReaderToken(profile, evidence); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Workload, *Evidence){
		"other-audience":  func(_ *Workload, e *Evidence) { e.GrantedAudiences = []string{"baobab-erp"} },
		"extra-audience":  func(_ *Workload, e *Evidence) { e.GrantedAudiences = append(e.GrantedAudiences, "baobab-trade") },
		"missing-context": func(_ *Workload, e *Evidence) { e.GrantedScopes = []string{"people:provider:read"} },
		"missing-request": func(_ *Workload, e *Evidence) { e.RequestedScopes = []string{"context:resolve"} },
		"provisioned":     func(p *Workload, _ *Evidence) { p.Status = "PROVISIONED" },
		"protected":       func(p *Workload, _ *Evidence) { p.Environment = "production" },
	} {
		t.Run(name, func(t *testing.T) {
			p, e := profile, evidence
			e.GrantedScopes = slices.Clone(e.GrantedScopes)
			e.RequestedScopes = slices.Clone(e.RequestedScopes)
			e.GrantedAudiences = slices.Clone(e.GrantedAudiences)
			mutate(&p, &e)
			if err := validatePeopleProviderReaderToken(p, e); err == nil {
				t.Fatal("unauthorised People scope admitted")
			}
		})
	}
}
func TestPeopleProfileRejectsUnqualifiedDistribution(t *testing.T) {
	p := Workload{Environment: "development", CredentialType: "client_credentials", Status: "PROVISIONED",
		Scopes: []string{"context:resolve", "people:provider:read"}, Audiences: []string{"baobab-control-plane"}}
	for name, alter := range map[string]func(*Workload){
		"foreign-audience":   func(p *Workload) { p.Audiences = []string{"baobab-erp"} },
		"multiple-audiences": func(p *Workload) { p.Audiences = []string{"baobab-control-plane", "baobab-erp"} },
		"missing-context":    func(p *Workload) { p.Scopes = []string{"people:provider:read"} },
		"protected":          func(p *Workload) { p.Environment = "staging" },
	} {
		t.Run(name, func(t *testing.T) {
			x := p
			x.Scopes = slices.Clone(p.Scopes)
			x.Audiences = slices.Clone(p.Audiences)
			alter(&x)
			if err := validatePeopleProviderReaderProfile("people-integration", x); err == nil {
				t.Fatal("unqualified profile accepted")
			}
		})
	}
}
