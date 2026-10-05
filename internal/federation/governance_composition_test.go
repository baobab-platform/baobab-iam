package federation

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGovernanceCompositionWiresCompositeAuthority(t *testing.T) {
	_, f := setup(t, "oidc")
	registration := &targetRegistrationFixture{}
	actors := &approvalFixture{
		actor: "33333333-3333-4333-8333-333333333333",
		clock: f.clock,
	}
	dir := t.TempDir()
	g, err := OpenGovernanceComposition(GovernanceCompositionConfig{
		NativeTargetLedgerPath: filepath.Join(dir, "native.db"),
		ApprovalLedgerPath:     filepath.Join(dir, "approvals.db"),
		TrustLedgerPath:        filepath.Join(dir, "trusts.db"),
		Registration:           registration,
		ApprovalAuthority:      actors,
		Now:                    func() time.Time { return actors.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if g.NativeTargets == nil || g.Targets == nil || g.Approvals == nil || g.Trusts == nil {
		t.Fatal("governance composition did not wire required authorities")
	}
	sources, err := g.AuthoritySources(&isolatedAccess{}, actors, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sources.Governance != g.Trusts || sources.Targets != g.Targets ||
		sources.Ledger != g.Approvals || sources.TrustLedger != g.Trusts ||
		sources.Approvals != actors {
		t.Fatalf("unexpected authority sources: %#v", sources)
	}
}

func TestGovernanceCompositionRejectsUnsafeConfiguration(t *testing.T) {
	_, f := setup(t, "oidc")
	registration := &targetRegistrationFixture{}
	actors := &approvalFixture{
		actor: "33333333-3333-4333-8333-333333333333",
		clock: f.clock,
	}
	dir := t.TempDir()
	base := GovernanceCompositionConfig{
		NativeTargetLedgerPath: filepath.Join(dir, "native.db"),
		ApprovalLedgerPath:     filepath.Join(dir, "approvals.db"),
		TrustLedgerPath:        filepath.Join(dir, "trusts.db"),
		Registration:           registration,
		ApprovalAuthority:      actors,
		Now:                    func() time.Time { return actors.clock },
	}
	for name, mutate := range map[string]func(*GovernanceCompositionConfig){
		"missing registration": func(c *GovernanceCompositionConfig) { c.Registration = nil },
		"missing approval":     func(c *GovernanceCompositionConfig) { c.ApprovalAuthority = nil },
		"missing clock":        func(c *GovernanceCompositionConfig) { c.Now = nil },
		"shared native approval file": func(c *GovernanceCompositionConfig) {
			c.ApprovalLedgerPath = c.NativeTargetLedgerPath
		},
		"shared native trust file": func(c *GovernanceCompositionConfig) {
			c.TrustLedgerPath = c.NativeTargetLedgerPath
		},
		"shared approval trust file": func(c *GovernanceCompositionConfig) {
			c.TrustLedgerPath = c.ApprovalLedgerPath
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if g, err := OpenGovernanceComposition(cfg); !errors.Is(err, ErrInvalid) || g != nil {
				if g != nil {
					g.Close()
				}
				t.Fatalf("composition=%#v err=%v", g, err)
			}
		})
	}
}

func TestGovernanceCompositionCloseIsExplicit(t *testing.T) {
	_, f := setup(t, "oidc")
	dir := t.TempDir()
	g, err := OpenGovernanceComposition(GovernanceCompositionConfig{
		NativeTargetLedgerPath: filepath.Join(dir, "native.db"),
		ApprovalLedgerPath:     filepath.Join(dir, "approvals.db"),
		TrustLedgerPath:        filepath.Join(dir, "trusts.db"),
		Registration:           &targetRegistrationFixture{},
		ApprovalAuthority: &approvalFixture{
			actor: "33333333-3333-4333-8333-333333333333",
			clock: f.clock,
		},
		Now: func() time.Time { return f.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.NativeTargets.NativeTargetDigest(context.Background(), ReferenceExpectation{}); err == nil {
		t.Fatal("closed native ledger remained usable")
	}
}
