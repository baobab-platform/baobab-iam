// Package migration defines the domain model for the Keycloak → Ory
// migration ledger (Gate IAM-M5, ADR-IAM-0022 §7–12).
//
// This package is intentionally storage-agnostic: it holds types, validation,
// and the migration state machine only. Persistence, workers, and production
// runners are out of scope until a later implementation PR.
//
// Normative constraints applied here:
//
//   - Map source issuer+subject → existing CanonicalIdentity → target issuer+subject.
//   - Do not resolve canonical identity by email alone (ADR-0022 §7).
//   - Do not store password hashes, TOTP secrets, passkeys, or client secrets
//     on ledger records (ADR-0022 §9).
//   - Business authority (Tenant, Capability, …) is never recorded as Ory state.
//
// Phase C adds DiscoveryPort, CanonicalResolver, PolicyGate (default deny
// CUTOVER), FixtureDiscovery, MapCanonicalResolver, RegisterBatch,
// ProvisionBridge (DISCOVERED→PROVISIONED via Identity/Workload provisioners),
// and CredentialStage (PROVISIONED→CREDENTIAL_* without secrets on the ledger).
//
// Workload rows default to Shared federated_workload_token (M4-F / RFC 7523);
// client_secret is M4-C only via explicit ClientSecretAllowList (ADR-IAM-0021).
//
// See docs/governance/gate-iam-m5-migration-ledger-scope.md and
// docs/governance/gate-iam-m5-phase-c-design.md.
package migration
