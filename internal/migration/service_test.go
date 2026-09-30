package migration_test

import (
	"context"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func TestServiceRegisterAndTransition(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}

	r := sampleRecord("svc1")
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(ctx, r); err == nil {
		t.Fatal("duplicate register should fail")
	}

	out, err := svc.ApplyTransition(ctx, "svc1", migration.StateValidated)
	if err != nil {
		t.Fatal(err)
	}
	if out.MigrationState != migration.StateValidated {
		t.Fatalf("state=%s", out.MigrationState)
	}

	_, err = svc.ApplyTransition(ctx, "svc1", migration.StateCutover)
	if err == nil {
		t.Fatal("illegal transition should fail")
	}
}

func TestServiceSetTargetBinding(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	_ = svc.Register(ctx, sampleRecord("t1"))
	_, err := svc.ApplyTransition(ctx, "t1", migration.StateValidated)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ApplyTransition(ctx, "t1", migration.StateReady)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ApplyTransition(ctx, "t1", migration.StateProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.SetTargetBinding(ctx, "t1", migration.ProviderBinding{
		Provider: "ory",
		Issuer:   "http://127.0.0.1:4444",
		Subject:  "kratos-uuid",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ApplyTransition(ctx, "t1", migration.StateProvisioned)
	if err != nil {
		t.Fatal(err)
	}
	if out.Target.Subject != "kratos-uuid" {
		t.Fatalf("%+v", out.Target)
	}
}
