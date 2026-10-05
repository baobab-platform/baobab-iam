package federation

import (
	"path/filepath"
	"time"
)

// GovernanceComposition is the bounded IAM-native MP2-C governance source.
// It composes CP's live non-approval registration authority with IAM's
// immutable native target bytes, four-eyes reference approvals and durable
// trust revisions. It does not mount HTTP or activate a provider by itself.
type GovernanceComposition struct {
	NativeTargets *NativeTargetLedger
	Targets       *CompositeApprovalTargets
	Approvals     *ApprovalLedger
	Trusts        *TrustLedger
}

type GovernanceCompositionConfig struct {
	NativeTargetLedgerPath string
	ApprovalLedgerPath     string
	TrustLedgerPath        string
	Registration           TargetRegistrationAuthority
	ApprovalAuthority      ApprovalAuthority
	Now                    func() time.Time
}

func OpenGovernanceComposition(cfg GovernanceCompositionConfig) (*GovernanceComposition, error) {
	if cfg.NativeTargetLedgerPath == "" || cfg.ApprovalLedgerPath == "" || cfg.TrustLedgerPath == "" ||
		filepath.Clean(cfg.NativeTargetLedgerPath) == filepath.Clean(cfg.ApprovalLedgerPath) ||
		filepath.Clean(cfg.NativeTargetLedgerPath) == filepath.Clean(cfg.TrustLedgerPath) ||
		filepath.Clean(cfg.ApprovalLedgerPath) == filepath.Clean(cfg.TrustLedgerPath) ||
		absent(cfg.Registration) || absent(cfg.ApprovalAuthority) || cfg.Now == nil {
		return nil, ErrInvalid
	}
	native, err := OpenNativeTargetLedger(cfg.NativeTargetLedgerPath)
	if err != nil {
		return nil, err
	}
	targets, err := NewCompositeApprovalTargets(cfg.Registration, native)
	if err != nil {
		native.Close()
		return nil, err
	}
	approvals, err := OpenApprovalLedger(cfg.ApprovalLedgerPath, cfg.ApprovalAuthority, targets, cfg.Now)
	if err != nil {
		native.Close()
		return nil, err
	}
	trusts, err := OpenTrustLedger(cfg.TrustLedgerPath, cfg.ApprovalAuthority, targets, approvals, cfg.Now)
	if err != nil {
		approvals.Close()
		native.Close()
		return nil, err
	}
	return &GovernanceComposition{
		NativeTargets: native,
		Targets:       targets,
		Approvals:     approvals,
		Trusts:        trusts,
	}, nil
}

func (g *GovernanceComposition) Close() error {
	if g == nil {
		return ErrUnavailable
	}
	var first error
	if g.Trusts != nil {
		if err := g.Trusts.Close(); err != nil && first == nil {
			first = err
		}
	}
	if g.Approvals != nil {
		if err := g.Approvals.Close(); err != nil && first == nil {
			first = err
		}
	}
	if g.NativeTargets != nil {
		if err := g.NativeTargets.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// AuthoritySources returns the IAM-owned source set for NewAuthorityHandler.
// CP remains separately authoritative for ApprovalAuthority and target
// registration. The ApprovalAuthority configured when this composition is
// opened is consumed only by the durable ledgers and is deliberately not
// re-exported through IAM's authority handler; IAM must not proxy a CP-owned
// human authority source. Protocol configuration/assurance sources are
// supplied by the caller because this increment does not invent policy material.
func (g *GovernanceComposition) AuthoritySources(
	access AuthorityAccess,
	configuration OIDCConfigurationAuthority,
	assurance AssuranceMapper,
) (AuthoritySources, error) {
	if g == nil || g.Approvals == nil || g.Trusts == nil || g.Targets == nil || absent(access) {
		return AuthoritySources{}, ErrInvalid
	}
	return AuthoritySources{
		Access:        access,
		Governance:    g.Trusts,
		Targets:       g.Targets,
		Configuration: configuration,
		Assurance:     assurance,
		Ledger:        g.Approvals,
		TrustLedger:   g.Trusts,
	}, nil
}
