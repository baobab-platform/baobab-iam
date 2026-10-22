package main

// INT-03C's native Hydra clients have NO inherent absolute wall-clock
// grant deadline. Merely checking a deadline before create permits issuance
// after a crash. A separate, independently supervised reaper must be ACTIVE
// before create and must destroy both clients no later than the approved run
// deadline. The one-minute bearer lifetime is a separate upper bound.
//
// This watchdog is only a building block: a real disposable deployment MUST
// run it under an independent restart-on-failure supervisor and independently
// verify no client, bearer or accepting service survives the deadline.
import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const deadlineLeaseSchema = "iam.int03c.deadline-supervisor.v1"

type deadlineLease struct {
	Schema    string `json:"schema"`
	RunID     string `json:"run_id"`
	Deadline  string `json:"deadline"`
	Heartbeat string `json:"heartbeat"`
	PID       int    `json:"pid"`
	Qualified bool   `json:"qualified"`
}

func privateLeaseDir(file string) error {
	root := filepath.Dir(file)
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
		return errors.New("private 0700 supervised run directory required")
	}
	return nil
}

func writeLease(file string, lease deadlineLease) error {
	if err := privateLeaseDir(file); err != nil {
		return err
	}
	if st, err := os.Lstat(file); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return errors.New("supervisor lease file unsafe")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("supervisor lease unavailable")
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return errors.New("supervisor lease cannot be encoded")
	}
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("supervisor lease cannot be written exclusively")
	}
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return errors.New("supervisor lease write failure")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("supervisor lease fsync failure")
	}
	if err = f.Close(); err != nil {
		return errors.New("supervisor lease close failure")
	}
	if err = os.Rename(tmp, file); err != nil {
		return errors.New("supervisor lease atomic rename failure")
	}
	d, err := os.Open(filepath.Dir(file))
	if err != nil {
		return errors.New("supervisor lease directory unavailable")
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return errors.New("supervisor lease directory fsync failure")
	}
	return nil
}

func verifyLiveLease(file, runID, deadline string, now time.Time) error {
	if err := privateLeaseDir(file); err != nil {
		return err
	}
	st, err := os.Lstat(file)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() <= 0 || st.Size() > 4096 {
		return errors.New("independent deadline supervisor absent")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return errors.New("independent supervisor state unreadable")
	}
	var lease deadlineLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return errors.New("supervisor state malformed")
	}
	exp, err1 := time.Parse(time.RFC3339Nano, lease.Deadline)
	heartbeat, err2 := time.Parse(time.RFC3339Nano, lease.Heartbeat)
	if lease.Schema != deadlineLeaseSchema || lease.RunID != runID ||
		lease.Deadline != deadline || lease.Qualified || err1 != nil || err2 != nil ||
		time.Until(exp) <= 60*time.Second || exp.Sub(now) > 90*time.Minute ||
		now.Sub(heartbeat) < 0 || now.Sub(heartbeat) > 12*time.Second ||
		lease.PID <= 1 || lease.PID == os.Getpid() {
		return errors.New("independent supervisor lease stale, incorrect or expired")
	}
	if err := syscall.Kill(lease.PID, 0); err != nil {
		return errors.New("supervisor process not running")
	}
	return nil
}

func superviseDeadline(ctx context.Context, n *native, file, deadline string) error {
	if err := privateLeaseDir(file); err != nil {
		return err
	}
	until, err := time.Parse(time.RFC3339Nano, deadline)
	if err != nil || time.Until(until) <= 60*time.Second || time.Until(until) > 90*time.Minute {
		return errors.New("supervised run deadline not bounded")
	}
	// Startup is deliberately exclusive: a second supervisor or different
	// run cannot overwrite an existing lease. Crash recovery requires an
	// authorised operator to reconcile issuer client state first.
	if _, err := os.Lstat(file); err == nil {
		return errors.New("previous run requires independent reconciliation")
	} else if !os.IsNotExist(err) {
		return errors.New("supervisor lease inspection failed")
	}
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	lease := deadlineLease{Schema: deadlineLeaseSchema, RunID: n.runID, Deadline: deadline, PID: os.Getpid()}
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	for {
		lease.Heartbeat = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeLease(file, lease); err != nil {
			// If watchdog can no longer evidence liveness, force cleanup.
			return destroyOwnedProofClients(n)
		}
		if !time.Now().Before(until) {
			return destroyOwnedProofClients(n)
		}
		select {
		case <-sigCtx.Done():
			return destroyOwnedProofClients(n)
		case <-tick.C:
		}
	}
}

func destroyOwnedProofClients(n *native) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// Retry every independently owned client. A failed deletion leaves
	// the lease on disk so future issuance is blocked and recovery is explicit.
	for _, name := range []string{consumer, validator} {
		if err := n.destroy(ctx, name); err != nil {
			return errors.New("independent deadline cleanup requires recovery")
		}
	}
	return nil
}
