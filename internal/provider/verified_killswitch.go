package provider

import (
	"context"
	"errors"
)

// ErrRevocationUnverified marks a fail-closed, possibly partial provider
// operation. Never reinterpret it as evidence that downstream access tokens,
// CP memberships or domain grants have been revoked.
var ErrRevocationUnverified = errors.New("provider identity revocation outcome not independently verified")

// ExecuteVerified is the observed provider-half of the IAM identity kill switch
// (ADR-0016/0017/0018). It refuses a positive result on an unobserved PATCH,
// mismatched issuer+subject, ACTIVE readback, session-revocation failure, or
// reactivation during the sequence. CP membership/domain revocation and a
// durable security-event publisher must be qualified separately.
//
// The legacy Execute intentionally remains available for low-level provider
// mechanics, but callers seeking a VERIFIED recovery/incident result must use
// this version with an independent provider readback.
func (k KillSwitch) ExecuteVerified(ctx context.Context, subject ExternalSubject, reader IdentityReader) error {
	if ctx == nil || ctx.Err() != nil || reader == nil || k.Lifecycle == nil || k.Sessions == nil {
		return ErrRevocationUnverified
	}
	if err := subject.Validate(); err != nil {
		return err
	}
	if err := k.Lifecycle.DisableIdentity(ctx, subject); err != nil {
		return errors.Join(ErrRevocationUnverified, err)
	}
	checkDisabled := func() error {
		if ctx.Err() != nil {
			return ErrRevocationUnverified
		}
		got, err := reader.GetIdentity(ctx, subject)
		if err != nil {
			return errors.Join(ErrRevocationUnverified, err)
		}
		if got == nil || got.Issuer != subject.Issuer || got.Subject != subject.Subject || got.Status != IdentityStatusDisabled {
			return ErrRevocationUnverified
		}
		return nil
	}
	if err := checkDisabled(); err != nil {
		// After an uncertain disable, never assert that sessions were safely
		// revoked or re-enable an identity as a cleanup side effect.
		return err
	}
	if err := k.Sessions.RevokeSessions(ctx, subject); err != nil {
		return errors.Join(ErrRevocationUnverified, err)
	}
	return checkDisabled()
}
