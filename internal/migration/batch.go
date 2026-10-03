// Target path: baobab-iam/internal/migration/batch.go
//
// Batch registration turns DiscoveryPort output into DISCOVERED ledger rows
// (Gate IAM-M5 / Phase C). No provider provisioning or cutover is performed.
package migration

import (
	"context"
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
	// OrphanCanonicalPlaceholder is stored as CanonicalIdentityID for orphans
	// so structural validation still requires a non-empty id without inventing
	// a real Principal. Default: "orphan:pending-review".
	OrphanCanonicalPlaceholder string
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
	req.OrphanCanonicalPlaceholder = strings.TrimSpace(req.OrphanCanonicalPlaceholder)
	if req.OrphanCanonicalPlaceholder == "" {
		req.OrphanCanonicalPlaceholder = "orphan:pending-review"
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
		// Deterministic id for greenfield: batch + provider + subject.
		// Production runners may prefer UUIDs; this keeps tests stable.
		migrationID := fmt.Sprintf("%s:%s:%s", req.BatchID, b.Provider, b.Subject)

		if _, err := s.Store.Get(ctx, migrationID); err == nil {
			result.SkippedExists++
			continue
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
			canonicalID = req.OrphanCanonicalPlaceholder
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
	// string fallback for wrapped errors without requiring errors.Is on sentinel
	return err.Error() == ErrNoCanonicalMapping.Error()
}
