package provider

import (
	"context"
	"fmt"
)

// KillSwitch combines provider-side identity disable and session revocation.
// This is the technical half of the Baobab kill-switch (ADR-0016 / ADR-0020).
// Control Plane membership revocation remains a separate concern and is not
// performed here.
type KillSwitch struct {
	Lifecycle IdentityLifecycleManager
	Sessions  SessionRevoker
}

// Execute disables the identity then revokes sessions.
// If disable succeeds and revoke fails, the disable is left in place and the
// revoke error is returned (caller may retry revoke).
func (k KillSwitch) Execute(ctx context.Context, subject ExternalSubject) error {
	if err := subject.Validate(); err != nil {
		return err
	}
	if k.Lifecycle == nil || k.Sessions == nil {
		return fmt.Errorf("provider: KillSwitch requires Lifecycle and Sessions")
	}
	if err := k.Lifecycle.DisableIdentity(ctx, subject); err != nil {
		return err
	}
	if err := k.Sessions.RevokeSessions(ctx, subject); err != nil {
		return err
	}
	return nil
}
