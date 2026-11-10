package provider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type observedIdentity struct {
	id         *provider.ProviderIdentity
	err        error
	reads      int
	reanimated bool
}

func (o *observedIdentity) GetIdentity(context.Context, provider.ExternalSubject) (*provider.ProviderIdentity, error) {
	o.reads++
	if o.err != nil {
		return nil, o.err
	}
	v := *o.id
	if o.reanimated && o.reads == 2 {
		v.Status = provider.IdentityStatusActive
	}
	return &v, nil
}

func TestVerifiedKillSwitchRequiresTwoExactDisabledObservations(t *testing.T) {
	subject := provider.ExternalSubject{Issuer: "https://identity.example", Subject: "human-1"}
	lc, ss := &stubLifecycle{}, &stubSessions{}
	reader := &observedIdentity{id: &provider.ProviderIdentity{
		Issuer: subject.Issuer, Subject: subject.Subject, Status: provider.IdentityStatusDisabled,
	}}
	ks := provider.KillSwitch{Lifecycle: lc, Sessions: ss}
	if err := ks.ExecuteVerified(context.Background(), subject, reader); err != nil {
		t.Fatal(err)
	}
	if lc.disableCalls != 1 || ss.revokeCalls != 1 || reader.reads != 2 {
		t.Fatalf("disable=%d revoke=%d observed=%d", lc.disableCalls, ss.revokeCalls, reader.reads)
	}
}

func TestVerifiedKillSwitchRejectsWrongStateAndPartialRevocation(t *testing.T) {
	subject := provider.ExternalSubject{Issuer: "https://identity.example", Subject: "human-1"}
	cases := []struct {
		name          string
		readback      provider.ProviderIdentity
		observedErr   error
		reanimate     bool
		revocationErr error
		disableErr    error
		wantRevoke    int
	}{
		{
			name: "unobserved ACTIVE after PATCH",
			readback: provider.ProviderIdentity{
				Issuer: subject.Issuer, Subject: subject.Subject, Status: provider.IdentityStatusActive,
			},
		},
		{
			name: "wrong subject after PATCH",
			readback: provider.ProviderIdentity{
				Issuer: subject.Issuer, Subject: "attacker", Status: provider.IdentityStatusDisabled,
			},
		},
		{
			name: "wrong issuer after PATCH",
			readback: provider.ProviderIdentity{
				Issuer: "https://other.example", Subject: subject.Subject, Status: provider.IdentityStatusDisabled,
			},
		},
		{name: "provider readback unavailable", observedErr: errors.New("outage")},
		{
			name: "reanimated after revoke",
			readback: provider.ProviderIdentity{
				Issuer: subject.Issuer, Subject: subject.Subject, Status: provider.IdentityStatusDisabled,
			},
			reanimate: true, wantRevoke: 1,
		},
		{
			name: "revoke failed",
			readback: provider.ProviderIdentity{
				Issuer: subject.Issuer, Subject: subject.Subject, Status: provider.IdentityStatusDisabled,
			},
			revocationErr: errors.New("outage"), wantRevoke: 1,
		},
		{name: "disable failed", disableErr: errors.New("PATCH uncertain")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc, ss := &stubLifecycle{disableErr: tc.disableErr}, &stubSessions{revokeErr: tc.revocationErr}
			reader := &observedIdentity{id: &tc.readback, err: tc.observedErr, reanimated: tc.reanimate}
			err := (provider.KillSwitch{Lifecycle: lc, Sessions: ss}).ExecuteVerified(context.Background(), subject, reader)
			if !errors.Is(err, provider.ErrRevocationUnverified) || ss.revokeCalls != tc.wantRevoke {
				t.Fatalf("partial revocation incorrectly accepted: %v, revoke=%d", err, ss.revokeCalls)
			}
		})
	}
}
