// Package migration defines the domain model for the Keycloak → Ory
// migration ledger (Gate IAM-M5, ADR-IAM-0022 §7–12).
//
// The package keeps its provider-neutral types and state machine. IAM-N05
// introduces a PostgreSQL 17 RecordStore with optimistic compare-and-swap,
// append-only migration history, immutable external-identity mappings and
// explicit durable deny fences. The schema is separately deployed; opening
// a store never upgrades a database or authorizes a production cutover.
// The existing MemoryStore remains only a non-durable Phase C pilot.
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
