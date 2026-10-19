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

func TestC403IndependentReceiptVerifierRejectsIncompleteAndTamperedBundles(t *testing.T) {
	sha := strings.Repeat("a", 40)
	receipt := newFullEvidence(sha)
	receipt.ProviderAndCPActuallyContacted = true
	receipt.CPGrantWithdrawalObserved = true
	for _, key := range fullRequired {
		receipt.Checks[key] = true
	}
	dir := t.TempDir()
	if err := publishFull(dir, receipt); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("exactly one completed bundle required")
	}
	bundle := filepath.Join(dir, entries[0].Name())
	if err := verifyFullReceipt(bundle, sha); err != nil {
		t.Fatal("completed digest-matched source-bound receipt denied", err)
	}
	if verifyFullReceipt(bundle, strings.Repeat("b", 40)) == nil {
		t.Fatal("different source revision accepted")
	}
	if verifyFullReceipt(bundle, "main") == nil {
		t.Fatal("unresolved source branch accepted")
	}

	receiptPath := filepath.Join(bundle, "receipt.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, append(append([]byte{}, data...), byte(' ')), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyFullReceipt(bundle, sha) == nil {
		t.Fatal("modified receipt accepted against old digest")
	}
	if err := os.WriteFile(receiptPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "unknown.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyFullReceipt(bundle, sha) == nil {
		t.Fatal("extra bundle file accepted")
	}
	if err := os.Remove(filepath.Join(bundle, "unknown.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(receiptPath, 0644); err != nil {
		t.Fatal(err)
	}
	if verifyFullReceipt(bundle, sha) == nil {
		t.Fatal("non-private evidence accepted")
	}
}

func TestC403ReceiptSnapshotHashesAndDecodesExactlyTheSameBytes(t *testing.T) {
	sha := strings.Repeat("d", 40)
	receipt := newFullEvidence(sha)
	receipt.ProviderAndCPActuallyContacted = true
	receipt.CPGrantWithdrawalObserved = true
	for _, key := range fullRequired {
		receipt.Checks[key] = true
	}
	receipt.close()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	checksum := func(value []byte) []byte {
		sum := sha256.Sum256(value)
		return []byte(hex.EncodeToString(sum[:]) + "  receipt.json\n")
	}
	if verifyFullReceiptSnapshot(raw, checksum(raw), sha) != nil {
		t.Fatal("complete source-bound snapshot denied")
	}
	// Model independent file versions: neither the old digest with new
	// document nor a freshly digested forbidden document can become valid.
	changed := []byte(strings.Replace(string(raw), `"production_ready":false`, `"production_ready":true`, 1))
	if string(changed) == string(raw) {
		t.Fatal("fixture did not change production flag")
	}
	if verifyFullReceiptSnapshot(changed, checksum(raw), sha) == nil ||
		verifyFullReceiptSnapshot(changed, checksum(changed), sha) == nil {
		t.Fatal("different or forbidden document accepted as checked snapshot")
	}
	for _, invalid := range [][]byte{
		[]byte(strings.Replace(string(raw), `"schema":`, `"unknown":true,"schema":`, 1)),
		[]byte(strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1)),
		append(append([]byte{}, raw...), []byte(" {}")...),
	} {
		if verifyFullReceiptSnapshot(invalid, checksum(invalid), sha) == nil {
			t.Fatal("strict service JSON rules lost in byte-snapshot decoding")
		}
	}
}

func TestC403ReceiptVerifierRejectsRewrittenDigestAndUnknownFields(t *testing.T) {
	sha := strings.Repeat("c", 40)
	receipt := newFullEvidence(sha)
	receipt.ProviderAndCPActuallyContacted = true
	receipt.CPGrantWithdrawalObserved = true
	for _, key := range fullRequired {
		receipt.Checks[key] = true
	}
	dir := t.TempDir()
	if err := publishFull(dir, receipt); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	bundle := filepath.Join(dir, entries[0].Name())
	path := filepath.Join(bundle, "receipt.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Even rewriting the matching checksum cannot launder an unknown
	// property into the closed evidence schema.
	withUnknown := strings.Replace(string(original), "\"schema\":", "\"surprise\":true,\"schema\":", 1)
	if withUnknown == string(original) {
		t.Fatal("fixture did not inject unknown field")
	}
	if err := os.WriteFile(path, []byte(withUnknown), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(withUnknown))
	if err := os.WriteFile(filepath.Join(bundle, "receipt.sha256"),
		[]byte(hex.EncodeToString(digest[:])+"  receipt.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyFullReceipt(bundle, sha) == nil {
		t.Fatal("closed schema bypassed after digest replacement")
	}
}
