# IAM-N06 PostgreSQL-backed one-use WebAuthn challenges

`internal/nativebff/n06_webauthn_pg.go` provides the real PostgreSQL 17
durable `WebAuthnChallengeStore` consumed by `WebAuthnA3Verifier`.
No database schema is installed implicitly by constructing the store.
Apply `migrations/001_n06_webauthn.sql` through a reviewed IAM migration.
The runtime key must be a distinct externally supplied 256-bit IAM secret.

The challenge's issuer, subject, session, RP, origin and 32-byte random nonce
are serialized into AES-256-GCM ciphertext, with a fresh random IV and opaque
challenge ID as authenticated associated data. No raw subject/session,
credential secret or browser data is stored in queryable PostgreSQL columns.
`Consume` uses `DELETE ... RETURNING` inside a serializable transaction:
only one concurrent caller may obtain the original challenge. No replay,
empty/expired read, decryption failure, invalid source database state or
uncertain transaction commit produces an A3 proof.

**Not yet qualified as full A3:** this is one real durable phase; credential
public-key readback from native Kratos COSE records, credential sign-count
CAS, actual browser CTAP2 assertion and original independent witness are
separate current completion tasks. Never treat encryption+Postgres unit tests
as native passkey ceremony proof or A4 hardware evidence.
