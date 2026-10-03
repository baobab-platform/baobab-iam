// Target path: baobab-iam/internal/migration/batch.go
//
// Batch registration turns DiscoveryPort output into DISCOVERED ledger rows
// (Gate IAM-M5 / Phase C). No provider provisioning or cutover is performed.
package migration

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// BatchRegisterRequest configures a non-production cohort registration.
type BatchRegisterRequest struct {
	// BatchID is stored on every row as MigrationBatchID.
	BatchID string
	// DefaultStrategy applied when not overridden per class.
	DefaultStrategy CredentialStrategy
	// DefaultClass used when SuggestedClass is empty and mapping exists.
	DefaultClass IdentityClass
	// OrphanClass is used when CanonicalResolver returns ErrNoCanonicalMapping.
	// Defaults to ClassOrphanCandidate.
	OrphanClass IdentityClass
}

// BatchRegisterResult summarizes a RegisterBatch run.
type BatchRegisterResult struct {
	BatchID       string
	Registered    int
	Orphans       int
	SkippedExists int
	// MigrationIDs are newly registered ids (not pre-existing).
	MigrationIDs []string
}

// RegisterBatch lists source bindings via discovery, resolves canonical ids,
// and registers DISCOVERED rows. It does not call IdentityProvisioner,
// WorkloadProvisioner, or advance past DISCOVERED.
//
// Idempotent per migration_id: if a row already exists, it is counted in
// SkippedExists and left unchanged.
//
// Migration identity (ADR-IAM-0022): deterministic key includes issuer so that
// issuer A / subject 123 and issuer B / subject 123 never collapse.
func (s *Service) RegisterBatch(
	ctx context.Context,
	discovery DiscoveryPort,
	resolver CanonicalResolver,
	req BatchRegisterRequest,
) (*BatchRegisterResult, error) {
	if s == nil || s.Store == nil {
		return nil, fmt.Errorf("migration: service or store is nil")
	}
	if discovery == nil {
		return nil, fmt.Errorf("migration: DiscoveryPort is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("migration: CanonicalResolver is required")
	}
	req.BatchID = strings.TrimSpace(req.BatchID)
	if req.BatchID == "" {
		return nil, fmt.Errorf("migration: BatchID is required")
	}
	if req.DefaultStrategy == "" {
		req.DefaultStrategy = StrategyNoCredentialRequired
	} else {
		req.DefaultStrategy = CredentialStrategy(strings.TrimSpace(string(req.DefaultStrategy)))
	}
	if !req.DefaultStrategy.Valid() {
		return nil, fmt.Errorf("migration: invalid DefaultStrategy %q", req.DefaultStrategy)
	}
	if req.DefaultClass == "" {
		req.DefaultClass = ClassTestOrNonProd
	} else {
		req.DefaultClass = IdentityClass(strings.TrimSpace(string(req.DefaultClass)))
	}
	if !req.DefaultClass.Valid() {
		return nil, fmt.Errorf("migration: invalid DefaultClass %q", req.DefaultClass)
	}
	if req.OrphanClass == "" {
		req.OrphanClass = ClassOrphanCandidate
	} else {
		req.OrphanClass = IdentityClass(strings.TrimSpace(string(req.OrphanClass)))
	}

	bindings, err := discovery.ListSourceBindings(ctx, req.BatchID)
	if err != nil {
		return nil, err
	}

	result := &BatchRegisterResult{BatchID: req.BatchID}
	for i, b := range bindings {
		b.Provider = strings.TrimSpace(b.Provider)
		b.Issuer = strings.TrimSpace(b.Issuer)
		b.Subject = strings.TrimSpace(b.Subject)
		if b.Provider == "" || b.Issuer == "" || b.Subject == "" {
			return nil, fmt.Errorf("migration: binding[%d] missing provider/issuer/subject", i)
		}
		source := ProviderBinding{
			Provider: b.Provider,
			Issuer:   b.Issuer,
			Subject:  b.Subject,
		}
		// Deterministic id: batch + provider + issuer + subject (issuer required).
		migrationID := fmt.Sprintf("%s:%s:%s:%s", req.BatchID, b.Provider, b.Issuer, b.Subject)

		_, getErr := s.Store.Get(ctx, migrationID)
		switch {
		case getErr == nil:
			result.SkippedExists++
			continue
		case errors.Is(getErr, ErrNotFound):
			// proceed to register
		default:
			// Fail closed: timeouts, permission errors, etc. are not "missing".
			return nil, fmt.Errorf("migration: store get %s: %w", migrationID, getErr)
		}

		canonicalID, resErr := resolver.ResolveCanonical(ctx, source)
		class := b.SuggestedClass
		if class == "" {
			class = req.DefaultClass
		}
		strategy := req.DefaultStrategy

		if resErr != nil {
			if !isNoCanonical(resErr) {
				return nil, fmt.Errorf("migration: resolve %s: %w", migrationID, resErr)
			}
			// ORPHAN_CANDIDATE: no authoritative CanonicalIdentity yet.
			// Do not fabricate a placeholder id (ADR-IAM-0022).
			canonicalID = ""
			class = req.OrphanClass
			result.Orphans++
		}

		rec := &Record{
			MigrationID:             migrationID,
			MigrationBatchID:        req.BatchID,
			CanonicalIdentityID:     canonicalID,
			Source:                  source,
			IdentityClass:           class,
			CredentialStrategy:      strategy,
			MigrationState:          StateDiscovered,
			SourceSnapshotReference: b.SnapshotReference,
		}
		if err := s.Register(ctx, rec); err != nil {
			return nil, fmt.Errorf("migration: register %s: %w", migrationID, err)
		}
		result.Registered++
		result.MigrationIDs = append(result.MigrationIDs, migrationID)
	}
	return result, nil
}

func isNoCanonical(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrNoCanonicalMapping {
		return true
	}
	return err.Error() == ErrNoCanonicalMapping.Error()
}
