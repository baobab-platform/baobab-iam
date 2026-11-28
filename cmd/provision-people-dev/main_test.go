package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func approvedPacket(t *testing.T, now time.Time) (Approval, Keyring) {
	t.Helper()
	p := approvedPlan()
	digest, err := planDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	a := Approval{WorkloadID: p.WorkloadID, SharedCommit: p.SharedCommit, Action: "apply", PlanDigest: digest,
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
	if err := verifyApproval(p, a, trust, "apply", now); err != nil {
		t.Fatalf("valid distinct signatures denied: %v", err)
	}
	if err := verifyApproval(p, a, trust, "revoke", now); err == nil {
		t.Fatal("apply approval replayed as revoke authority")
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
			if err := verifyApproval(p, cloned, other, "apply", now); err == nil {
				t.Fatal("unsupported authority accepted")
			}
		})
	}
	if err := verifyApproval(p, a, trust, "apply", now.Add(35*time.Minute)); err == nil {
		t.Fatal("expired review accepted")
	}
	if err := verifyApproval(p, a, trust, "apply", now.Add(-24*time.Hour)); err == nil {
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

func secureTestDirectory(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("test requires a non-world-writable home directory")
	}
	dir, err := os.MkdirTemp(home, ".iam-private-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestAdminEndpointAndPrivateFileChecks(t *testing.T) {
	for _, endpoint := range []string{"https://example.com", "http://hydra-admin:4445",
		"http://evil.test", "http://127.0.0.1:4445/path", "http://a:b@localhost:4445",
		"http://127.0.0.1:4445?mode=unsafe", "http://127.0.0.1:4445?",
		"http://127.0.0.1:4445#", "http://127.0.0.1:", ""} {
		if err := privateAdmin(endpoint); err == nil {
			t.Fatalf("public/noncanonical admin accepted: %q", endpoint)
		}
	}
	if err := privateAdmin("http://127.0.0.1:4445"); err != nil {
		t.Fatal(err)
	}
}

func TestSecureApprovalRejectsSymlinkAndUnsafeDirectory(t *testing.T) {
	dir := secureTestDirectory(t)
	path := filepath.Join(dir, "approval.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	var approval Approval
	if err := loadApproval(path, &approval); err != nil {
		t.Fatalf("valid owner-private approval rejected: %v", err)
	}
	link := filepath.Join(dir, "approval-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := loadApproval(link, &approval); err == nil {
		t.Fatal("symlink approval accepted")
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if err := loadApproval(path, &approval); err == nil {
		t.Fatal("group-writable approval directory accepted")
	}
}

func TestSecureFileDescriptorChecksTypeOwnerModeAndLinks(t *testing.T) {
	dir := secureTestDirectory(t)
	if _, err := openSecureDirectory(dir, uint32(os.Geteuid())+1, 0700); err == nil {
		t.Fatal("wrong directory owner accepted")
	}
	d, err := openSecureDirectory(dir, uint32(os.Geteuid()), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := os.WriteFile(filepath.Join(dir, "wrong-mode.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateFileAt(d, "wrong-mode.json", uint32(os.Geteuid()), 0600, unix.O_RDONLY); err == nil {
		t.Fatal("group-readable file accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "approval.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateFileAt(d, "approval.json", uint32(os.Geteuid())+1, 0600, unix.O_RDONLY); err == nil {
		t.Fatal("wrong file owner accepted")
	}
	if _, err := openPrivateFileAt(d, "approval.json", uint32(os.Geteuid()), 0600, unix.O_RDONLY); err != nil {
		t.Fatalf("correct descriptor custody rejected: %v", err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "approval.fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateFileAt(d, "approval.fifo", uint32(os.Geteuid()), 0600, unix.O_RDONLY); err == nil {
		t.Fatal("FIFO accepted as approval file")
	}
	if err := os.Link(filepath.Join(dir, "approval.json"), filepath.Join(dir, "approval-hardlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateFileAt(d, "approval.json", uint32(os.Geteuid()), 0600, unix.O_RDONLY); err == nil {
		t.Fatal("multiply-linked approval accepted")
	}
}

func TestDirectoryDescriptorPreventsPathReplacement(t *testing.T) {
	parent := secureTestDirectory(t)
	original := filepath.Join(parent, "custody")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "approval.json"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := openSecureDirectory(original, uint32(os.Geteuid()), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	moved := filepath.Join(parent, "custody-original")
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "approval.json"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openPrivateFileAt(opened, "approval.json", uint32(os.Geteuid()), 0600, unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("opened directory descriptor followed replaced path: %q", got)
	}
}

func TestCredentialCustodyUsesVerifiedDirectoryDescriptor(t *testing.T) {
	dir := secureTestDirectory(t)
	path := filepath.Join(dir, "client-secret")
	credential, err := createSecureCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credential.Write([]byte("private-secret\n")); err != nil {
		t.Fatal(err)
	}
	if err := credential.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := credential.Close(); err != nil {
		t.Fatal(err)
	}
	if err := credential.CloseDirectory(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("credential mode = %o, want 600", st.Mode().Perm())
	}
	if _, err := createSecureCredential(filepath.Join(dir, "missing", "secret")); err == nil {
		t.Fatal("credential in missing custody directory accepted")
	}
	if err := os.Symlink(dir, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := createSecureCredential(filepath.Join(dir, "alias", "other-secret")); err == nil {
		t.Fatal("symlink custody directory accepted")
	}
}

func TestApprovalRequiresDistinctTrustedPublicKeys(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	plan := approvedPlan()
	digest, err := planDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval := Approval{
		WorkloadID: plan.WorkloadID, SharedCommit: plan.SharedCommit, Action: "apply",
		PlanDigest: digest, ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(signatureText(approval))))
	approval.Maker = Signature{KeyID: "maker_a", Signature: signature}
	approval.Checker = Signature{KeyID: "checker_b", Signature: signature}
	trust := Keyring{Reviewers: map[string]TrustedReviewer{
		"maker_a":   {Role: "MAKER", PublicKey: base64.StdEncoding.EncodeToString(public)},
		"checker_b": {Role: "CHECKER", PublicKey: base64.StdEncoding.EncodeToString(public)},
	}}
	if err := verifyApproval(plan, approval, trust, "apply", now); err == nil {
		t.Fatal("same public key accepted for maker and checker")
	}
}

type closeFailCredentialFile struct {
	bytes.Buffer
	closeErr error
	closed   bool
}

func (f *closeFailCredentialFile) Sync() error { return nil }
func (f *closeFailCredentialFile) Close() error {
	f.closed = true
	return f.closeErr
}

type shortWriteCredentialFile struct{ closed bool }

func (f *shortWriteCredentialFile) Write(p []byte) (int, error) { return len(p) - 1, nil }
func (f *shortWriteCredentialFile) Sync() error                 { return nil }
func (f *shortWriteCredentialFile) Close() error                { f.closed = true; return nil }

func TestPersistCredentialDetectsShortWrite(t *testing.T) {
	file := &shortWriteCredentialFile{}
	err := persistCredential(file, "private-secret")
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write was not rejected: %v", err)
	}
	if !file.closed {
		t.Fatal("short-written credential was not closed")
	}
}

func TestPersistCredentialReportsCloseFailure(t *testing.T) {
	want := errors.New("simulated close failure")
	file := &closeFailCredentialFile{closeErr: want}
	err := persistCredential(file, "private-secret")
	if !errors.Is(err, want) {
		t.Fatalf("close error was not returned: %v", err)
	}
	if !file.closed {
		t.Fatal("credential file was not closed")
	}
	if got := file.String(); got != "private-secret\n" {
		t.Fatalf("unexpected persisted bytes %q", got)
	}
}

func TestCredentialCleanupHandlesAlreadyClosedFile(t *testing.T) {
	dir := secureTestDirectory(t)
	path := filepath.Join(dir, "client-secret")
	credential, err := createSecureCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credential.Write([]byte("private-secret\n")); err != nil {
		t.Fatal(err)
	}
	if err := credential.Close(); err != nil {
		t.Fatal(err)
	}
	if err := credential.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup left the credential behind: %v", err)
	}
}

func TestDecodePrivateJSONRejectsOversizedAndTrailingData(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "oversized", data: bytes.Repeat([]byte(" "), 32769)},
		{name: "trailing", data: []byte("{}{}")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := secureTestDirectory(t)
			path := filepath.Join(dir, "input.json")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var target map[string]any
			if err := decodePrivateJSON(file, &target); err == nil {
				t.Fatal("invalid private JSON accepted")
			}
		})
	}
}

func TestIssuerMutationRequiresNonRootRuntime(t *testing.T) {
	if err := requireNonRootRuntime(0); err == nil {
		t.Fatal("root runtime accepted for issuer mutation")
	}
	if err := requireNonRootRuntime(1000); err != nil {
		t.Fatalf("dedicated non-root runtime rejected: %v", err)
	}
}
