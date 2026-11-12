package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func approvedPacket(t *testing.T, now time.Time) (Approval, Keyring) {
	t.Helper()
	p := approvedPlan()
	digest, err := planDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	a := Approval{WorkloadID: p.WorkloadID, SharedCommit: p.SharedCommit, PlanDigest: digest,
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339)}
	trust := Keyring{Reviewers: map[string]TrustedReviewer{}}
	for _, candidate := range []struct {
		id   string
		role string
	}{{"maker_a", "MAKER"}, {"checker_b", "CHECKER"}} {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		trust.Reviewers[candidate.id] = TrustedReviewer{Role: candidate.role, PublicKey: base64.StdEncoding.EncodeToString(pub)}
		sig := Signature{KeyID: candidate.id, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(signatureText(a))))}
		if candidate.role == "MAKER" {
			a.Maker = sig
		} else {
			a.Checker = sig
		}
	}
	return a, trust
}

func TestGovernedPeopleIssuerPlanAndDenials(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	a, trust := approvedPacket(t, now)
	p := approvedPlan()
	if err := verifyApproval(p, a, trust, now); err != nil {
		t.Fatalf("valid distinct signatures denied: %v", err)
	}
	cases := map[string]func(*Approval, *Keyring){
		"replayed approval for another client": func(a *Approval, _ *Keyring) { a.WorkloadID = "baobab-erp-workload" },
		"wrong Shared commit":                  func(a *Approval, _ *Keyring) { a.SharedCommit = "unapproved" },
		"self approval":                        func(a *Approval, _ *Keyring) { a.Checker = a.Maker },
		"tampered signed expiry":               func(a *Approval, _ *Keyring) { a.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339) },
		"missing trusted checker":              func(_ *Approval, k *Keyring) { delete(k.Reviewers, "checker_b") },
		"unapproved plan":                      func(a *Approval, _ *Keyring) { a.PlanDigest = "sha256:" + strings.Repeat("f", 64) },
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			cloned := a
			other := Keyring{Reviewers: map[string]TrustedReviewer{}}
			for k, v := range trust.Reviewers {
				other.Reviewers[k] = v
			}
			mutate(&cloned, &other)
			if err := verifyApproval(p, cloned, other, now); err == nil {
				t.Fatal("unsupported authority accepted")
			}
		})
	}
	if err := verifyApproval(p, a, trust, now.Add(35*time.Minute)); err == nil {
		t.Fatal("expired review accepted")
	}
	if err := verifyApproval(p, a, trust, now.Add(-24*time.Hour)); err == nil {
		t.Fatal("long-lived review accepted")
	}
}

func TestIssuerNeverMutatesWithoutDevelopmentAndApprovals(t *testing.T) {
	now := time.Now().UTC()
	for _, env := range []string{"", "staging", "production", "test", "integration", "DEVELOPMENT"} {
		var output bytes.Buffer
		err := run(func(k string) string {
			if k == "BAOBAB_ENVIRONMENT" {
				return env
			}
			return "apply"
		}, &output, now)
		if err == nil {
			t.Fatalf("unsafe environment %q accepted", env)
		}
	}
	var output bytes.Buffer
	vars := map[string]string{"BAOBAB_ENVIRONMENT": "development", "PEOPLE_DEV_ACTION": "plan"}
	lookup := func(k string) string { return vars[k] }
	if err := run(lookup, &output, now); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "client_secret") || !strings.Contains(output.String(), sharedCommit) {
		t.Fatal("plan has wrong provenance or secrets")
	}
	for _, action := range []string{"apply", "revoke", "production", ""} {
		vars["PEOPLE_DEV_ACTION"] = action
		if err := run(lookup, &output, now); err == nil {
			t.Fatal("privileged command without approvals accepted")
		}
	}
}

func TestAdminEndpointAndPrivateFileChecks(t *testing.T) {
	for _, endpoint := range []string{"https://example.com", "http://hydra-admin:4445",
		"http://evil.test", "http://127.0.0.1:4445/path", "http://a:b@localhost:4445",
		"http://127.0.0.1:4445?mode=unsafe", ""} {
		if err := privateAdmin(endpoint); err == nil {
			t.Fatalf("public/noncanonical admin accepted: %q", endpoint)
		}
	}
	if err := privateAdmin("http://127.0.0.1:4445"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "approval.json")
	if err := os.WriteFile(p, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	var a Approval
	if err := loadJSON(p, &a); err == nil {
		t.Fatal("group-readable approval accepted")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadJSON(p, &a); err != nil {
		t.Fatal(err)
	}
}
