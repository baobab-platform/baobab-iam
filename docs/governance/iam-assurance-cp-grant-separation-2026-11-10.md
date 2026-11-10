# ADR-IAM-0024 canonical assurance authority boundary — 2026-11-10

The enterprise provider audit and capability registry reconciliation identified two separately canonical Shared IAM capability keys: `identity.authentication.perform` (native interactive login) and `identity.authentication.assurance` (current server-owned assurance evaluation). They are **not interchangeable CP permissions**.

## Corrected IAM implementation

The guarded native Kratos assurance reader introduced in IAM #174 originally checked the existing human-login CP dispatch. This would have allowed a caller possessing only a native login capability grant to invoke a separately catalogued assurance-evaluation operation. The reader now requires **`identity.authentication.assurance` major 1 CP authority** on each before/after Kratos state read. Denial, revocation, absence of a specific provider support/binding or an unavailable CP returns a denied assurance outcome; no local fallback and no reversion to the human-login key.

Regression tests use a CP fake that only authorizes the distinct assurance key and explicitly refuse a human-login-only grant without issuing a Kratos request.

This **does not** publish production support or activate a CP grant. The separate IAM provider declaration PR #169 still classifies the Kratos assurance capability as PARTIAL and has a separate read-only canonical Shared contract pin; the workload issuer runtime pin remains unchanged.

**Important integration effect:** Until CP assigns and verifies a separate assurance provider/engine-instance capability support and grant, live assurance calls fail closed. Preserve existing browser native LOGIN mechanics, which independently depend on `identity.authentication.perform`; do not move human authentication to the assurance key.

**Remaining:** accepted operation-specific server policy, original risk/recovery hold source, independent RP-bound UV passkey attestation, privileged witness and hardware proof, CP and consumer originally sourced grant+binding tests, exact-head Go formatting/CI, and protected release approvals.
