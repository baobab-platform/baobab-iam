package federation

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// NativeRuntimeDispatch is a deliberately narrow composition, not a new grant:
// the IAM caller needs both existing human and workload-issuer capabilities.
// OAuth evidence must identify that same Hydra instance, revision and artifact.
// User scopes, audiences, client approval and persistent replay fencing remain
// independent handoff requirements.
type NativeRuntimeDispatch struct {
	human, issuer *RuntimeDispatch
	oauth         *HTTPRuntimeAuthority
}

// StartNativeRuntimeComposition supplies an executable host factory without
// exposing a new public login endpoint. Both components share IAM's CP-owned
// context and current caller; no estate context or provider-selected URL enters.
func StartNativeRuntimeComposition(ctx context.Context, human, issuer RuntimeComposition, tlsConfig *tls.Config) (*NativeRuntimeDispatch, *SupervisedContexts, error) {
	if issuer.RuntimeTokenFile == "" || issuer.ResolutionTokenFile == "" || human.CPOrigin != issuer.CPOrigin || human.ResolutionTokenFile != issuer.ResolutionTokenFile || human.ContextTarget != issuer.ContextTarget || human.EstateID != issuer.EstateID || human.SecurityDomainReference != issuer.SecurityDomainReference || human.EngineInstanceID == issuer.EngineInstanceID {
		return nil, nil, ErrInvalid
	}
	// Construct the companion before starting a worker, so a static error cannot
	// leave renewal running after a failed factory call.
	oauth, err := NewHTTPRuntimeAuthority(issuer.CPOrigin, FileAuthorityTokens{issuer.RuntimeTokenFile}, tlsConfig, RuntimeAuthorityTarget{ProviderID: issuer.ProviderID, EngineInstanceID: issuer.EngineInstanceID, Scope: Scope{OrganisationID: issuer.ContextTarget.OrganisationID, EstateID: issuer.EstateID}, RuntimeCapability: "OAUTH_AUTHORIZATION_SERVER", ConfigurationReference: issuer.ConfigurationReference, SecurityDomainReference: issuer.SecurityDomainReference}, time.Now)
	if err != nil {
		return nil, nil, err
	}
	// A validation-only construction checks issuer routing before acquisition.
	resolver, err := NewHTTPAuthority(issuer.CPOrigin, FileAuthorityTokens{issuer.ResolutionTokenFile}, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	platform, err := NewHTTPRuntimeAuthority(issuer.CPOrigin, FileAuthorityTokens{issuer.RuntimeTokenFile}, tlsConfig, RuntimeAuthorityTarget{ProviderID: issuer.ProviderID, EngineInstanceID: issuer.EngineInstanceID, Scope: oauth.target.Scope, RuntimeCapability: "WORKLOAD_TOKEN_ISSUANCE", ConfigurationReference: issuer.ConfigurationReference, SecurityDomainReference: issuer.SecurityDomainReference}, time.Now)
	if err != nil {
		return nil, nil, err
	}
	hydra, err := NewRuntimeDispatch(RuntimeDispatchConfig{Resolver: resolver, Contexts: FileResolutionContexts{}, Platform: platform, Scope: oauth.target.Scope, CapabilityKey: provider.CapabilityWorkloadTokenIssue, ProviderID: issuer.ProviderID, EngineInstanceID: issuer.EngineInstanceID, ServiceReference: issuer.ServiceReference, Now: time.Now})
	if err != nil {
		return nil, nil, err
	}
	kratos, contexts, err := StartRuntimeComposition(ctx, human, provider.CapabilityHumanAuthentication, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	hydra.config.Contexts = contexts
	return &NativeRuntimeDispatch{kratos, hydra, oauth}, contexts, nil
}

func (d *NativeRuntimeDispatch) CheckCapability(ctx context.Context, key string) error {
	if d == nil || ctx == nil || key != provider.CapabilityHumanAuthentication {
		return ErrDenied
	}
	started := time.Now().UTC()
	handle, err := d.human.config.Contexts.Context(ctx)
	if err != nil {
		return err
	}
	if err := d.human.Check(ctx); err != nil {
		return err
	}
	humanProfile, err := d.human.profile(ctx)
	if err != nil {
		return err
	}
	if err := d.issuer.Check(ctx); err != nil {
		return err
	}
	p, err := d.issuer.profile(ctx)
	if err != nil {
		return err
	}
	t := d.oauth.target
	read := func() (PlatformSnapshot, error) {
		return d.oauth.RuntimeBinding(ctx, t.ProviderID, t.EngineInstanceID, t.Scope, t.RuntimeCapability)
	}
	first, err := read()
	if err != nil {
		return err
	}
	if first.ArtifactDigest != p.ArtifactDigest || first.ProfileRevision != p.ProfileRevision {
		return ErrDenied
	}
	if err := d.human.Check(ctx); err != nil {
		return err
	}
	if err := d.issuer.Check(ctx); err != nil {
		return err
	}
	latest, err := d.issuer.profile(ctx)
	if err != nil {
		return err
	}
	current, err := read()
	if err != nil {
		return err
	}
	latestHuman, err := d.human.profile(ctx)
	if err != nil {
		return err
	}
	currentHandle, err := d.human.config.Contexts.Context(ctx)
	if err != nil {
		return err
	}
	finished := time.Now().UTC()
	if finished.Before(started) || currentHandle != handle || latestHuman != humanProfile || !finished.Before(handle.ExpiresAt) || !finished.Before(humanProfile.EvidenceExpiresAt) || !finished.Before(p.EvidenceExpiresAt) || latest != p || current != first || ctx.Err() != nil || !finished.Before(first.EvidenceExpiresAt) {
		return ErrDenied
	}
	return nil
}
