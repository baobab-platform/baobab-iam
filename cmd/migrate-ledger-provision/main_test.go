package main

import "testing"

func TestSplitCSVTrimsAndDropsEmptyValues(t *testing.T) {
	got := splitCSV("  billing:manage, billing:read , ,payment:read\t")
	want := []string{"billing:manage", "billing:read", "payment:read"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestEnvRequiredRejectsWhitespaceOnlyValues(t *testing.T) {
	if _, err := envRequired("MIGRATION_TEST_MISSING"); err == nil {
		t.Fatal("expected missing env to be rejected")
	}
	t.Setenv("MIGRATION_TEST_BLANK", " \t \n ")
	if _, err := envRequired("MIGRATION_TEST_BLANK"); err == nil {
		t.Fatal("expected whitespace-only env to be rejected")
	}
}
