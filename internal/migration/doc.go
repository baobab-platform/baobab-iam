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
// See docs/governance/gate-iam-m5-migration-ledger-scope.md.
package migration
