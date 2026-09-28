package provider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type stubLifecycle struct {
	disableCalls int
	disableErr   error
}

func (s *stubLifecycle) DisableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	s.disableCalls++
	return s.disableErr
}
func (s *stubLifecycle) EnableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	return nil
}

type stubSessions struct {
	revokeCalls int
	revokeErr   error
}

func (s *stubSessions) RevokeSessions(ctx context.Context, subject provider.ExternalSubject) error {
	s.revokeCalls++
	return s.revokeErr
}

func TestKillSwitchOK(t *testing.T) {
	lc := &stubLifecycle{}
	ss := &stubSessions{}
	ks := provider.KillSwitch{Lifecycle: lc, Sessions: ss}
	err := ks.Execute(context.Background(), provider.ExternalSubject{
		Issuer: "https://id.example", Subject: "u1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if lc.disableCalls != 1 || ss.revokeCalls != 1 {
		t.Fatalf("calls disable=%d revoke=%d", lc.disableCalls, ss.revokeCalls)
	}
}

func TestKillSwitchDisableFails(t *testing.T) {
	lc := &stubLifecycle{disableErr: errors.New("no")}
	ss := &stubSessions{}
	ks := provider.KillSwitch{Lifecycle: lc, Sessions: ss}
	err := ks.Execute(context.Background(), provider.ExternalSubject{
		Issuer: "https://id.example", Subject: "u1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if ss.revokeCalls != 0 {
		t.Fatal("revoke must not run if disable fails")
	}
}

func TestKillSwitchRequiresSubject(t *testing.T) {
	ks := provider.KillSwitch{Lifecycle: &stubLifecycle{}, Sessions: &stubSessions{}}
	err := ks.Execute(context.Background(), provider.ExternalSubject{})
	if !provider.IsInvalidArgument(err) {
		t.Fatalf("got %v", err)
	}
}
