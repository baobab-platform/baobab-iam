package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/baobab-platform/baobab-iam/internal/federation"
)

// verifyFullReceipt is an INTEGRITY AND STRUCTURE check over a previously
// published C4-03B–E bundle. It does not contact a provider or CP and does
// not independently authenticate the recorder, approval or runtime origin.
// A rewritten receipt plus rewritten checksum is NOT a trusted attestation.
func verifyFullReceipt(bundle, expectedCommit string) error {
	denied := errors.New("untrusted C4-03 evidence bundle")
	if !shaPattern.MatchString(expectedCommit) || bundle == "" {
		return denied
	}
	dir, err := os.Lstat(bundle)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0022 != 0 {
		return denied
	}
	entries, err := os.ReadDir(bundle)
	if err != nil || len(entries) != 2 || entries[0].Name() != "receipt.json" ||
		entries[1].Name() != "receipt.sha256" {
		return denied
	}
	read := func(name string) ([]byte, error) {
		return federation.ReadProtectedServiceFile(filepath.Join(bundle, name))
	}
	raw, err := read("receipt.json")
	if err != nil {
		return denied
	}
	checksum, err := read("receipt.sha256")
	if err != nil {
		return denied
	}
	return verifyFullReceiptSnapshot(raw, checksum, expectedCommit)
}

// The checksum, strict decode and semantic checks all apply to one immutable
// in-process snapshot. No path is reopened after verifying its digest; later
// filesystem edits cannot change the document this observation describes.
func verifyFullReceiptSnapshot(raw, checksum []byte, expectedCommit string) error {
	denied := errors.New("untrusted C4-03 evidence bundle")
	if !shaPattern.MatchString(expectedCommit) {
		return denied
	}
	sum := sha256.Sum256(raw)
	if string(checksum) != hex.EncodeToString(sum[:])+"  receipt.json\n" {
		return denied
	}
	// Preserve the service loader's duplicate/unknown/trailing JSON rejection.
	// Inode custody was validated by the single-descriptor reads above.
	var evidence fullEvidence
	if federation.DecodeServiceDocument(raw, &evidence) != nil ||
		evidence.Schema != fullSchema || evidence.SourceCommit != expectedCommit ||
		evidence.Result != "PASS" || evidence.ProductionReady || evidence.PhysicalPasskey ||
		!evidence.ProviderAndCPActuallyContacted || !evidence.CPGrantWithdrawalObserved ||
		!closedChecks(evidence.Checks, fullRequired) {
		return denied
	}
	for _, key := range fullRequired {
		if !evidence.Checks[key] {
			return denied
		}
	}
	// No independent cryptographic signature or attestable CI run identity
	// is present here. Never return an "accepted" result to a release gate.
	return nil
}
