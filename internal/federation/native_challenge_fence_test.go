package federation

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func nativeFenceRace(t *testing.T, one, two *NativeChallengeLedger) {
	t.Helper()
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ledger := one
			if i%2 == 1 {
				ledger = two
			}
			if ledger.ConsumeNativeChallenge(context.Background(), strings.Repeat("a", 64)) == nil {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("native challenge did not have exactly one winner")
	}
}

func TestNativeChallengeLedgerRestartAndInvalidInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.db")
	one, err := OpenNativeChallengeLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	nativeFenceRace(t, one, one)
	if err := one.Close(); err != nil {
		t.Fatal(err)
	}
	two, err := OpenNativeChallengeLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	if two.ConsumeNativeChallenge(context.Background(), strings.Repeat("a", 64)) == nil {
		t.Fatal("restart accepted replay")
	}
	for _, key := range []string{"", "challenge-secret", strings.Repeat("A", 64), strings.Repeat("b", 62)} {
		if two.ConsumeNativeChallenge(context.Background(), key) == nil {
			t.Fatal("invalid digest accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if two.ConsumeNativeChallenge(ctx, strings.Repeat("b", 64)) == nil {
		t.Fatal("cancelled challenge consumed")
	}
}

func TestPostgresNativeChallengeIndependentReplicasAndEpochFence(t *testing.T) {
	a, b := postgresFixture(t)
	one, err := OpenNativeChallengeLedgerWithStorage(a)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := OpenNativeChallengeLedgerWithStorage(b)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	nativeFenceRace(t, one, two)
	if _, err := a.db.ExecContext(context.Background(), `UPDATE iam_federation_control SET epoch='epoch2' WHERE namespace=$1`, a.namespace); err != nil {
		t.Fatal(err)
	}
	for _, ledger := range []*NativeChallengeLedger{one, two} {
		if ledger.ConsumeNativeChallenge(context.Background(), strings.Repeat("b", 64)) == nil {
			t.Fatal("old recovery epoch accepted a native challenge")
		}
	}
}
