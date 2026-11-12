package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPlanReportsExactPinnedWorkloadAndAudience(t *testing.T) {
	env := map[string]string{
		"ORY_ACTION":            "plan",
		"ORY_LOGICAL_CLIENT_ID": "baobab-trade-workload",
		"ORY_ALLOWED_SCOPES":    "context:resolve",
	}
	var out bytes.Buffer
	if err := run(func(name string) string { return env[name] }, &out); err != nil {
		t.Fatal(err)
	}
	var plan workloadPlan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.LogicalClientID != env["ORY_LOGICAL_CLIENT_ID"] || plan.Environment != "production" ||
		plan.RegistryCommit != "1517429bcae601a1b0288ca0279e524ce48a3d77" ||
		len(plan.Scopes) != 1 || plan.Scopes[0] != "context:resolve" ||
		len(plan.Audiences) != 1 || plan.Audiences[0] != "baobab-control-plane" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestLegacyMutationsAndInvalidInputsAreRefused(t *testing.T) {
	for _, action := range []string{"", "provision", "rotate", "disable", "all-primary"} {
		var out bytes.Buffer
		err := run(func(name string) string {
			if name != "ORY_ACTION" {
				t.Fatalf("mutation read input %s", name)
			}
			return action
		}, &out)
		if err == nil || out.Len() != 0 {
			t.Fatalf("unexpected result for %q: %s, %v", action, &out, err)
		}
	}
	for _, scopes := range []string{"", "context:resolve,", " context:resolve", "trade:native-commitment:submit"} {
		env := map[string]string{
			"ORY_ACTION":            "plan",
			"ORY_LOGICAL_CLIENT_ID": "baobab-trade-workload",
			"ORY_ALLOWED_SCOPES":    scopes,
		}
		var out bytes.Buffer
		if err := run(func(name string) string { return env[name] }, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid scopes %q produced a plan", scopes)
		}
	}
}
