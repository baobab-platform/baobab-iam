package main

import (
	"context"
	"reflect"
	"testing"
)

func TestApprovedProvisionUsesPinnedSharedResourceAudiences(t *testing.T) {
	cases := []struct {
		client string
		scopes []string
		want   []string
	}{
		{"baobab-trade-workload", []string{"erp:read"}, []string{"baobab-erp"}},
		{"baobab-trade-workload", []string{"context:resolve", "erp:read"}, []string{"baobab-control-plane", "baobab-erp"}},
		{"baobab-erp-workload", []string{"erp:integrate"}, []string{"baobab-erp"}},
		{"baobab-pulse-workload", []string{"context:validate"}, []string{"baobab-control-plane"}},
		{"thamani-backend", []string{"context:resolve"}, []string{"baobab-control-plane"}},
		{"zuribeans-backend", []string{"context:resolve"}, []string{"baobab-control-plane"}},
	}
	for _, tc := range cases {
		got, err := approvedProvision(tc.client, tc.scopes)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s %v: audiences=%v, error=%v; want=%v", tc.client, tc.scopes, got, err, tc.want)
		}
	}
}

func TestApprovedProvisionRejectsUnallocatedAndCrossEngineGrants(t *testing.T) {
	for _, tc := range []struct {
		client string
		scopes []string
	}{
		{"synthetic-server-checkout", []string{"trade:native-commitment:submit"}},
		{"baobab-trade-workload", []string{"trade:native-commitment:submit"}},
		{"baobab-trade-workload", []string{"erp:integrate"}},
		{"baobab-cms-workload", []string{"erp:read"}},
		{"thamani-backend", []string{"context:validate"}},
		{"baobab-int03-cms-consumer", []string{"context:resolve"}},
		{"baobab-cp-provisioning-workload", []string{"erp:provision"}},
		{"baobab-trade-workload", []string{"context:resolve", "context:resolve"}},
		{"baobab-trade-workload", nil},
		{"baobab-trade-workload", []string{"context:resolve", ""}},
	} {
		if _, err := approvedProvision(tc.client, tc.scopes); err == nil {
			t.Fatalf("%s %v admitted outside pinned Shared ceilings", tc.client, tc.scopes)
		}
		// Prove denial precedes all provider operations (nil adapter panics if called).
		if err := provisionOne(context.Background(), nil, tc.client, tc.scopes, ""); err == nil {
			t.Fatalf("%s %v reached provider provisioning", tc.client, tc.scopes)
		}
	}
}

func TestApprovedLifecyclePreventsArbitraryClientMutation(t *testing.T) {
	for _, id := range []string{"pk_forged", "unknown-operator", "baobab-cp-provisioning-workload", "synthetic-server-checkout"} {
		if _, _, err := approvedClient(id); err == nil {
			t.Fatalf("%s admitted to lifecycle control", id)
		}
	}
	for _, id := range m4ClientCredentials {
		if _, _, err := approvedClient(id); err != nil {
			t.Fatalf("%s lost approved client-credentials lifecycle: %v", id, err)
		}
	}
}
