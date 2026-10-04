//go:build linux

package federation

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDurableLedgersRejectUnsafeFiles(t *testing.T) {
	for _, ledger := range []string{"approvals", "events"} {
		for _, kind := range []string{"public", "symlink", "hardlink", "fifo", "directory"} {
			t.Run(ledger+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "ledger.db")
				target := filepath.Join(dir, "target")
				original := []byte("must not be changed by a rejected open")
				if err := os.WriteFile(target, original, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "public":
					err = os.WriteFile(path, original, 0644)
				case "symlink":
					err = os.Symlink(target, path)
				case "hardlink":
					err = os.Link(target, path)
				case "fifo":
					err = syscall.Mkfifo(path, 0600)
				case "directory":
					err = os.Mkdir(path, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
				if ledger == "approvals" {
					f := &approvalFixture{}
					l, e := OpenApprovalLedger(path, f, f, time.Now)
					if l != nil {
						l.Close()
						t.Fatal("unsafe approval ledger opened")
					}
					err = e
				} else {
					f := &oidcFixture{}
					l, e := OpenOIDCEvents(path, f, f, time.Now, time.Minute)
					if l != nil {
						l.Close()
						t.Fatal("unsafe event ledger opened")
					}
					err = e
				}
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("expected redacted failure, got %v", err)
				}
				got, err := os.ReadFile(target)
				if err != nil || string(got) != string(original) {
					t.Fatal("rejected open changed the target", err)
				}
			})
		}
	}
}
