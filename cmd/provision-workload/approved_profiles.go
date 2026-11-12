package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

// This deliberately closed, generated-from-reviewed-Shared snapshot is NOT a
// second workload registry. CI compares each value against the exact commit in
// contracts.lock.yaml. Changes must originate in Shared and be reviewed here.
// This snapshot is for offline planning.
//
//go:embed approved_profiles.json
var approvedProfileData []byte

type approvedProfile struct {
	Environment      string   `json:"environment"`
	Status           string   `json:"status"`
	CredentialType   string   `json:"credential_type"`
	AllowedScopes    []string `json:"allowed_scopes"`
	AllowedAudiences []string `json:"allowed_audiences"`
}

type approvedManifest struct {
	SourceCommit   string                     `json:"source_commit"`
	ScopeAudiences map[string][]string        `json:"scope_audiences"`
	Workloads      map[string]approvedProfile `json:"workloads"`
}

func approvedClient(id string) (approvedManifest, approvedProfile, error) {
	var manifest approvedManifest
	if err := json.Unmarshal(approvedProfileData, &manifest); err != nil {
		return approvedManifest{}, approvedProfile{}, fmt.Errorf("invalid reviewed workload manifest: %w", err)
	}
	p, ok := manifest.Workloads[id]
	if !ok || manifest.SourceCommit != "1517429bcae601a1b0288ca0279e524ce48a3d77" ||
		p.Environment != "production" || p.CredentialType != "client_credentials" || p.Status != "ACTIVE" ||
		!slices.Contains(m4ClientCredentials, id) {
		return approvedManifest{}, approvedProfile{}, fmt.Errorf("workload not admitted by the pinned Shared client-credentials profile")
	}
	return manifest, p, nil
}

// approvedProvision enforces the workload-specific Shared scopes and derives
// the exact Hydra client audience ceiling from the selected scope owners.
// No identity with the unallocated native commitment scope can pass this gate.
func approvedProvision(id string, scopes []string) (workloadPlan, error) {
	manifest, p, err := approvedClient(id)
	if err != nil {
		return workloadPlan{}, err
	}
	if len(scopes) == 0 {
		return workloadPlan{}, fmt.Errorf("at least one explicitly selected Shared scope is required")
	}
	audiences := map[string]bool{}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if scope == "" || seen[scope] || !slices.Contains(p.AllowedScopes, scope) {
			return workloadPlan{}, fmt.Errorf("scope not allocated to selected Shared workload")
		}
		seen[scope] = true
		owners := manifest.ScopeAudiences[scope]
		if len(owners) != 1 || !slices.Contains(p.AllowedAudiences, owners[0]) {
			return workloadPlan{}, fmt.Errorf("scope has no single approved resource audience")
		}
		audiences[owners[0]] = true
	}
	if len(audiences) == 0 {
		return workloadPlan{}, fmt.Errorf("no verified audience for selected scopes")
	}
	out := make([]string, 0, len(audiences))
	for audience := range audiences {
		out = append(out, audience)
	}
	sort.Strings(out)
	return workloadPlan{
		LogicalClientID: id,
		Environment:     p.Environment,
		RegistryCommit:  manifest.SourceCommit,
		Scopes:          scopes,
		Audiences:       out,
	}, nil
}
