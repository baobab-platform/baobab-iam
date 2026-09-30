// Target path: baobab-iam/internal/provider/ory/capabilities.go
//
// Declares the capabilities of the Ory (Kratos + Hydra) adapter.
// Missing required capabilities MUST fail deployment validation
// (ADR-IAM-0020 §11).
package ory

import "github.com/baobab-platform/baobab-iam/internal/provider"

// capabilities returns the static capability set for this adapter build.
// Runtime probes (e.g. version-specific WebAuthn import support) can refine
// these later; the base set is conservative and matches ADR-IAM-0019/0021.
func (a *Adapter) capabilities() provider.ProviderCapabilities {
	return provider.ProviderCapabilities{
		Provider: "ory",

		HumanIdentity:     true, // Kratos
		SessionRevocation: true, // Kratos admin sessions API
		WorkloadIdentity:  true, // Hydra OAuth2 clients

		// Credential import support depends on the pinned Kratos version.
		// Password hash import is well-supported; TOTP/passkey import landed
		// in recent releases — confirm against the version lock file.
		PasswordImport: true,
		TOTPImport:     true,
		PasskeyImport:  true, // set false if pinned Kratos lacks admin WebAuthn import

		// Enterprise SSO (OIDC/SAML IdP connections) is deployment-dependent
		// on Kratos configuration and available social/OIDC providers.
		EnterpriseSSO: "deployment-dependent",

		// SCIM is not a native Kratos/Hydra feature in the open-source stack
		// used by Baobab; treat as unsupported unless a later ADR adds it.
		SCIM: "unsupported",
	}
}
