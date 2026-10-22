package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeadlineLeaseRequiresIndependentCurrentSupervisor(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "watchdog.json")
	run := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().UTC()
	end := now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	lease := deadlineLease{
		Schema: deadlineLeaseSchema, RunID: run,
		Deadline: end, Heartbeat: now.Add(-time.Second).Format(time.RFC3339Nano),
		PID: os.Getppid(), Qualified: false,
	}
	if err := writeLease(file, lease); err != nil {
		t.Fatal(err)
	}
	if err := verifyLiveLease(file, run, end, now); err != nil {
		t.Fatalf("independent live lease refused: %v", err)
	}
	for _, mutation := range []func(*deadlineLease){
		func(x *deadlineLease) { x.RunID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
		func(x *deadlineLease) { x.Qualified = true },
		func(x *deadlineLease) { x.PID = os.Getpid() },
		func(x *deadlineLease) { x.PID = 999999999 },
		func(x *deadlineLease) { x.Heartbeat = now.Add(-25*time.Second).Format(time.RFC3339Nano) },
		func(x *deadlineLease) { x.Deadline = now.Add(30*time.Second).Format(time.RFC3339Nano) },
		func(x *deadlineLease) { x.Deadline = now.Add(100*time.Minute).Format(time.RFC3339Nano) },
	} {
		next := lease
		mutation(&next)
		if err := writeLease(file, next); err != nil {
			t.Fatal(err)
		}
		if err := verifyLiveLease(file, run, end, now); err == nil {
			t.Fatal("unqualified or stale supervisor was trusted")
		}
	}
}

func TestDeadlineLeaseIsPrivateAndCannotAdoptUnsafePath(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "watchdog.json")
	if err := verifyLiveLease(file, "run", "deadline", time.Now()); err == nil {
		t.Fatal("missing supervisor accepted")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeLease(file, deadlineLease{}); err == nil {
		t.Fatal("public parent accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyLiveLease(file, "run", "deadline", time.Now()); err == nil {
		t.Fatal("unsafe lease accepted")
	}
}

func TestDeadlineLeaseCannotPromoteItsOwnEvidence(t *testing.T) {
	var state deadlineLease
	if err := json.Unmarshal([]byte(`{"schema":"iam.int03c.deadline-supervisor.v1","qualified":true}`), &state); err != nil {
		t.Fatal(err)
	}
	if !state.Qualified {
		t.Fatal("bad test fixture")
	}
}
