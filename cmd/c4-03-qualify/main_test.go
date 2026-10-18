package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceFailsClosedUnlessEveryCPCheckPasses(t *testing.T) {
	r, err := newEvidence(strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range requiredChecks {
		r.Checks[name] = true
	}
	r.close()
	if r.Result != "FAIL" {
		t.Fatal("uncontacted CP accepted")
	}
	r.ActualCP = true
	for _, name := range requiredChecks {
		r.Checks[name] = false
		r.close()
		if r.Result != "FAIL" {
			t.Fatalf("missing %s was accepted", name)
		}
		r.Checks[name] = true
	}
	r.Checks["extra"] = true
	r.close()
	if r.Result != "FAIL" {
		t.Fatal("unrecognized evidence accepted")
	}
	delete(r.Checks, "extra")
	r.close()
	if r.Result != "PASS" || r.HydraIssuance || r.ProtectedResource || r.Revocation || r.ProductionReady {
		t.Fatal("CP-only evidence overclaimed full C4 acceptance")
	}
}

func TestEvidenceRequiresExactProvenance(t *testing.T) {
	for _, sha := range []string{"", "main", strings.Repeat("B", 40), strings.Repeat("f", 39), strings.Repeat("a", 41)} {
		if _, err := newEvidence(sha); err == nil {
			t.Fatal("unsafe SHA accepted")
		}
	}
}

func TestEvidencePublishedAtomicallyWithDigestAndPrivatePermissions(t *testing.T) {
	r, err := newEvidence(strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	r.ActualCP = true
	for _, name := range requiredChecks {
		r.Checks[name] = true
	}
	dir := filepath.Join(t.TempDir(), "receipts")
	if err := publish(dir, r); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "run-") {
		t.Fatal("incomplete evidence directory")
	}
	receiptPath := filepath.Join(dir, entries[0].Name(), "receipt.json")
	digestPath := filepath.Join(dir, entries[0].Name(), "receipt.sha256")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := os.ReadFile(digestPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if string(digest) != hex.EncodeToString(sum[:])+"  receipt.json\n" {
		t.Fatal("invalid digest")
	}
	var recorded Evidence
	if json.Unmarshal(data, &recorded) != nil || recorded.Result != "PASS" ||
		recorded.ProductionReady || recorded.HydraIssuance || recorded.ProtectedResource || recorded.Revocation {
		t.Fatal("incorrect evidence scope")
	}
	for _, p := range []string{receiptPath, digestPath} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("insecure receipt permissions")
		}
	}
	// Every run must create a fresh bundle rather than overwrite prior evidence.
	if err := publish(dir, r); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("prior receipt replaced")
	}
}

func TestPublisherCannotBeForcedToMarkIncompleteEvidencePassed(t *testing.T) {
	r, err := newEvidence(strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	r.Result = "PASS"
	dir := t.TempDir()
	if err := publish(dir, r); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name(), "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recorded Evidence
	if json.Unmarshal(data, &recorded) != nil || recorded.Result != "FAIL" {
		t.Fatal("incomplete evidence became PASS")
	}
}
