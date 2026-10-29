package tokenprofile

import "testing"

const tmsSharedPin = "ab7a473a1f69784f115ad353e36383faf9b95965"

func tmsTestProfile() Config {
	return Config{
		Environment:  "development",
		SharedCommit: tmsSharedPin,
		Workloads: map[string]Workload{
			"synthetic-other": {
				Environment:    "development",
				CredentialType: "client_credentials",
				Status:         "ACTIVE",
				Scopes:         []string{"context:resolve"},
				Audiences:      []string{"baobab-control-plane"},
			},
		},
	}
}

func TestProposedTMSValidatorCannotIssueBeforeSharedAcceptance(t *testing.T) {
	for _, tc := range []struct {
		id        string
		scopes    []string
		audiences []string
	}{
		{"baobab-dev-tms-validator", []string{"context:validate"}, []string{"baobab-control-plane"}},
		{"other-client", []string{"context:validate"}, []string{"baobab-tms-development"}},
		{"baobab-tms", []string{"context:validate"}, []string{"baobab-control-plane"}},
		{"baobab-tms-validator-development", []string{"context:validate"}, []string{"baobab-control-plane"}},
		{"other-client", []string{"tms:native-execution:resolve"}, []string{"baobab-control-plane"}},
		{"other-client", []string{"billing:read"}, []string{"baobab-tms"}},
	} {
		c := tmsTestProfile()
		c.Workloads[tc.id] = Workload{
			Environment:    "development",
			CredentialType: "client_credentials",
			Status:         "ACTIVE",
			Scopes:         tc.scopes,
			Audiences:      tc.audiences,
		}
		if err := c.Validate(); err == nil {
			t.Fatalf("unaccepted TMS scope/validator accepted by Validate: %s", tc.id)
		}
		e := Evidence{
			ClientID:         tc.id,
			Subject:          tc.id,
			Grant:            "client_credentials",
			RequestedScopes:  tc.scopes,
			GrantedScopes:    tc.scopes,
			GrantedAudiences: tc.audiences,
		}
		// Claims is independently guarded even on a hand-built Config
		// which bypassed Validate or normal provisioning.
		if _, err := c.Claims(e); err == nil {
			t.Fatalf("unaccepted TMS scope/validator issued by Claims: %s", tc.id)
		}
		if _, err := c.AdmitRequest(WorkloadTokenRequest{
			WorkloadID: tc.id,
			Audience:   tc.audiences[0],
			Scopes:     tc.scopes,
		}, nil, e); err == nil {
			t.Fatalf("unaccepted TMS profile passed canonical admission: %s", tc.id)
		}
	}
}

func TestUnrelatedActiveWorkloadUnaffectedByTMSHold(t *testing.T) {
	c := tmsTestProfile()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e := Evidence{
		ClientID: "synthetic-other", Subject: "synthetic-other",
		Grant:            "client_credentials",
		RequestedScopes:  []string{"context:resolve"},
		GrantedScopes:    []string{"context:resolve"},
		GrantedAudiences: []string{"baobab-control-plane"},
	}
	if _, err := c.Claims(e); err != nil {
		t.Fatalf("unrelated approved workload regressed: %v", err)
	}
}

func TestTMSNestedHumanProfileCannotBypassDirectHooks(t *testing.T) {
	for _, mutate := range []func(*Workload){
		func(p *Workload) { p.HumanTokenProfile = &HumanTokenProfile{Audiences: []string{"baobab-tms"}} },
		func(p *Workload) { p.HumanTokenProfile = &HumanTokenProfile{Scopes: []string{"tms:booking:submit"}} },
		func(p *Workload) { p.HumanScopeAudiences = map[string][]string{"buyer:handoff": {"baobab-tms"}} },
		func(p *Workload) { p.HumanScopeAudiences = map[string][]string{"tms:booking:submit": {"baobab-trade"}} },
	} {
		c := tmsTestProfile()
		p := c.Workloads["synthetic-other"]
		mutate(&p)
		c.Workloads["synthetic-other"] = p
		if err := c.Validate(); err == nil {
			t.Fatal("nested TMS profile accepted")
		}
		if _, err := c.HumanConsent("synthetic-other", []string{"openid", "buyer:handoff"}); err == nil {
			t.Fatal("direct human consent bypassed hold")
		}
		if _, err := c.HumanClaims(HumanEvidence{ClientID: "synthetic-other"}, make([]byte, MinConsentSealKeyBytes)); err == nil {
			t.Fatal("direct human claims bypassed hold")
		}
	}
}

func TestTMSEvidenceIndependentlyDenied(t *testing.T) {
	for _, e := range []Evidence{
		{ClientID: "baobab-dev-tms-validator"},
		{ClientID: "synthetic-other", RequestedScopes: []string{"tms:booking:submit"}},
		{ClientID: "synthetic-other", GrantedScopes: []string{"tms:booking:submit"}},
		{ClientID: "synthetic-other", GrantedAudiences: []string{"baobab-tms"}},
	} {
		if err := tmsGrantHold(e); err == nil {
			t.Fatal("TMS provider evidence bypassed hold")
		}
		if _, err := tmsTestProfile().Claims(e); err == nil {
			t.Fatal("direct workload claims bypassed hold")
		}
	}
}
