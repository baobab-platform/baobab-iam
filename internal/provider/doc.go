// Package provider defines the Baobab provider-neutral identity provider
// contract (ADR-IAM-0020, Gate IAM-M1).
//
// Callers depend on capability interfaces (IdentityReader, WorkloadProvisioner,
// …) rather than concrete Ory or Keycloak types. Concrete adapters live in
// subpackages ory and keycloak.
//
// Standards (OIDC, OAuth, JWKS, PKCE, client credentials) remain direct.
// Business semantics (Tenant, LegalEntity, Market, Capability, domain
// authorization) never appear on these types.
//
// Canonical resolution stays issuer + subject → ExternalIdentity → Principal
// in baobab-cp.
package provider
