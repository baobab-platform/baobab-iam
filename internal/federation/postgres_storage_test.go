package federation

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func postgresFixture(t *testing.T) (*PostgresStorage, *PostgresStorage) {
	t.Helper()
	dsn := os.Getenv("TEST_FEDERATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL integration database absent")
	}
	// Plaintext is confined to this package-private fixture. Runtime opening always requires verified TLS.
	cfg, err := pgxTestPool(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.Close() })
	migration, err := os.ReadFile("migrations/001_shared_storage.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cfg.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	namespace := fmt.Sprintf("ci_%d", time.Now().UnixNano())
	epoch := "epoch1"
	if _, err = cfg.Exec(`INSERT INTO iam_federation_control VALUES($1,$2,1)`, namespace, epoch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cfg.Exec(`DELETE FROM iam_federation_records WHERE namespace=$1`, namespace)
		cfg.Exec(`DELETE FROM iam_federation_control WHERE namespace=$1`, namespace)
	})
	a, err := openPostgresStorage(context.Background(), dsn, namespace, epoch, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openPostgresStorage(context.Background(), dsn, namespace, epoch, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func TestPostgresApprovalIndependentReplicasSingleWinner(t *testing.T) {
	a, b := postgresFixture(t)
	old, f, r, _ := approvalSetup(t)
	old.Close()
	one, err := OpenApprovalLedgerWithStorage(a, f, f, func() time.Time { return f.clock })
	if err != nil {
		t.Fatal(err)
	}
	two, err := OpenApprovalLedgerWithStorage(b, f, f, func() time.Time { return f.clock })
	if err != nil {
		t.Fatal(err)
	}
	p, err := one.Propose(context.Background(), proposalID, r)
	if err != nil {
		t.Fatal(err)
	}
	f.actor = "44444444-4444-4444-8444-444444444444"
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		l := one
		if i%2 != 0 {
			l = two
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := l.Decide(context.Background(), p.ID, p.TargetDigest, true)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("decision winners=%d", wins)
	}
	if _, err = two.Reference(context.Background(), r.Expectation); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresOIDCReplayAcrossIndependentConnections(t *testing.T) {
	a, b := postgresFixture(t)
	old, f, s, key, _ := oidcSetup(t)
	old.Close()
	one, e := OpenOIDCEventsWithStorage(a, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	two, e := OpenOIDCEventsWithStorage(b, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	r, e := one.Begin(ctx, s, secretDigest(browserSecret))
	if e != nil {
		t.Fatal(e)
	}
	if e = two.Complete(ctx, r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(f, s, r)), s); e != nil {
		t.Fatal(e)
	}
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		l := one
		if i%2 != 0 {
			l = two
		}
		wg.Add(1)
		go func() { defer wg.Done(); _, _, e := l.Verify(ctx, r.ID, s); results <- e }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("consumption winners=%d", wins)
	}
}
func TestPostgresRollbackStickyErrorsAndEpochFence(t *testing.T) {
	a, b := postgresFixture(t)
	one, _ := openLedger("", a, "test")
	two, _ := openLedger("", b, "test")
	bucket := []byte("test")
	if e := one.Update(func(tx ledgerTx) error { tx.Bucket(bucket).Put([]byte("a"), []byte("secret")); return ErrDenied }); e != ErrDenied {
		t.Fatal(e)
	}
	if e := two.View(func(tx ledgerTx) error {
		if tx.Bucket(bucket).Get([]byte("a")) != nil {
			t.Fatal("rolled-back write persisted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := one.Update(func(tx ledgerTx) error {
		p := tx.(*postgresTx)
		p.tx.ExecContext(p.ctx, `SELECT 1/0`)
		tx.Bucket(bucket).Get([]byte("missing"))
		return nil
	}); e != ErrUnavailable {
		t.Fatalf("query failure became absence: %v", e)
	}
	if _, e := a.db.Exec(`UPDATE iam_federation_control SET epoch='epoch2' WHERE namespace=$1`, a.namespace); e != nil {
		t.Fatal(e)
	}
	for _, l := range []ledgerDB{one, two} {
		if e := l.Update(func(tx ledgerTx) error { return tx.Bucket(bucket).Put([]byte("a"), []byte("stale")) }); e != ErrDenied {
			t.Fatalf("stale epoch accepted: %v", e)
		}
	}
	if e := a.Check(context.Background()); e != ErrDenied {
		t.Fatal("stale readiness accepted")
	}
}

func TestPostgresDestructiveRecoveryInvalidatesAuthorityAndFencesOldPools(t *testing.T) {
	a, _ := postgresFixture(t)
	for _, name := range []string{"native", "approvals", "oidc"} {
		d, _ := openLedger("", a, name)
		if e := d.Update(func(tx ledgerTx) error { return tx.Bucket([]byte("records")).Put([]byte("old"), []byte("restricted")) }); e != nil {
			t.Fatal(e)
		}
	}
	// A restricted temporary dump proves the real backup tool round trip before recovery.
	dump := filepath.Join(t.TempDir(), "records.dump")
	backup := postgresTool("pg_dump", "--format=custom", "--table=iam_federation_records", "--dbname="+os.Getenv("TEST_FEDERATION_DATABASE_URL"))
	backup.Env = append(os.Environ(), "PGDATABASE="+os.Getenv("TEST_FEDERATION_DATABASE_URL"))
	backupBytes, e := backup.Output()
	if e != nil {
		t.Fatal("backup failed", e)
	}
	if e = os.WriteFile(dump, backupBytes, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dump, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := a.db.Exec(`DELETE FROM iam_federation_records WHERE namespace=$1`, a.namespace); e != nil {
		t.Fatal(e)
	}
	restore := postgresTool("pg_restore", "--data-only", "--no-owner", "--no-privileges", "--dbname="+os.Getenv("TEST_FEDERATION_DATABASE_URL"))
	restore.Stdin = bytes.NewReader(backupBytes)
	if output, e := restore.CombinedOutput(); e != nil {
		t.Fatalf("restore failed (%d bytes of diagnostic): %v", len(output), e)
	}
	var restored int
	if e := a.db.QueryRow(`SELECT count(*) FROM iam_federation_records WHERE namespace=$1`, a.namespace).Scan(&restored); e != nil || restored != 3 {
		t.Fatal("backup round trip did not restore records", e, restored)
	}
	run := func(old, next string) error {
		command := postgresTool("psql", "--dbname="+os.Getenv("TEST_FEDERATION_DATABASE_URL"), "-X", "-v", "ON_ERROR_STOP=1", "-v", "namespace="+a.namespace, "-v", "old_epoch="+old, "-v", "new_epoch="+next, "-f", "-")
		sql, e := os.ReadFile("../../scripts/operations/federation-recovery.sql")
		if e != nil {
			return e
		}
		command.Stdin = bytes.NewReader(sql)
		command.Env = append(os.Environ(), "PGDATABASE="+os.Getenv("TEST_FEDERATION_DATABASE_URL"))
		_, e = command.CombinedOutput()
		return e
	}
	if e := run("wrong", "epoch2"); e == nil {
		t.Fatal("wrong recovery epoch accepted")
	}
	if e := run("epoch1", "epoch2"); e != nil {
		t.Fatal(e)
	}
	if e := a.Check(context.Background()); e != ErrDenied {
		t.Fatal("old pool not fenced")
	}
	next, e := openPostgresStorage(context.Background(), os.Getenv("TEST_FEDERATION_DATABASE_URL"), a.namespace, "epoch2", false)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	for _, name := range []string{"native", "approvals", "oidc"} {
		d, _ := openLedger("", next, name)
		if e := d.View(func(tx ledgerTx) error {
			got := tx.Bucket([]byte("records")).Get([]byte("old"))
			if (got != nil) != (name == "native") {
				t.Fatal("recovered authority was resurrected")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := a.db.QueryRow(`SELECT count(*) FROM iam_federation_recovery_archive WHERE namespace=$1`, a.namespace).Scan(&count); e != nil || count != 3 {
		t.Fatal("recovery archive incomplete", e, count)
	}
	a.db.Exec(`DELETE FROM iam_federation_recovery_archive WHERE namespace=$1`, a.namespace)
}

func postgresTool(tool string, args ...string) *exec.Cmd {
	if container := os.Getenv("POSTGRES_TOOLS_CONTAINER"); container != "" {
		prefix := []string{"exec", "-i", "-e", "PGDATABASE=" + os.Getenv("TEST_FEDERATION_DATABASE_URL"), container, tool}
		return exec.Command("docker", append(prefix, args...)...)
	}
	return exec.Command(tool, args...)
}
