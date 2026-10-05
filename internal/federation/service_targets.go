package federation

import (
	"context"
	"encoding/json"
)

// LoadReviewedTargets loads operator-reviewed NON_SECRET documents. Loading
// persists immutable bytes only; CP registration and two human approvals are
// independently required before those bytes can be consumed.
func (g *GovernanceComposition) LoadReviewedTargets(ctx context.Context, path string) error {
	data, err := privateDocument(path)
	if err != nil {
		return err
	}
	var entries []struct {
		Expectation ReferenceExpectation
		Content     json.RawMessage
		Snapshot    *TrustSnapshot
	}
	if decodeAuthority(data, &entries) != nil || len(entries) == 0 {
		return ErrInvalid
	}
	for _, entry := range entries {
		if entry.Expectation.Kind == "federation_activation" {
			if entry.Snapshot == nil || len(entry.Content) != 0 {
				return ErrInvalid
			}
			if _, err = g.NativeTargets.RegisterTrustSnapshotTarget(ctx, entry.Expectation, *entry.Snapshot); err != nil {
				return err
			}
		} else {
			if entry.Snapshot != nil {
				return ErrInvalid
			}
			if _, err = g.NativeTargets.RegisterNonSecretTarget(ctx, entry.Expectation, entry.Content); err != nil {
				return err
			}
		}
	}
	return nil
}
