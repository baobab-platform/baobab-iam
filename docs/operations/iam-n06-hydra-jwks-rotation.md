# IAM-N06 native Hydra signing-key rotation

**Implementation candidate, not live issuer-signing qualification.**

`internal/provider/ory/signing_rotation.go` implements an actual provider
mutation path through the pinned Hydra v26.2 Admin JWK API. It permits only
reviewed `hydra.openid.id-token` and `hydra.jwt.access-token` signing sets,
plus a quarantined `baobab-development-*` custom set in an explicitly
disposable, loopback-only Ory Foundation.

- The old KID must exist, the new KID must not. A separate securityops
  authority checks the exact reviewed change, actor and independent approval.
- Add invokes Hydra `POST /admin/keys/{set}` with RS256/signature use and
  independently rereads the **same** admin key set. Actual issuer signing
  sets ALSO require old+new KIDs from the original public issuer JWKS.
- Retirement invokes `DELETE /admin/keys/{set}/{oldKid}` **only after**
  a distinct external authority approves an *old-token-expired and
  consumer-verified* retirement. Independently rereads admin and (for
  signing sets) issuer JWKS; the old key must be absent while the new
  key remains.
- No private JWK, client secret or token is written to logs or returned by
  the provider observation. Redirects, unfamiliar origins and unreviewed
  sets fail closed; an uncertain write is an UNKNOWN, not a success.

**Still required:** a real pinned Hydra OIDC issuer token signed with each
KID, old/new JWT verification during overlap, stale-key verification refusal
after retirement, original no-skip CI receipts and an independently
implemented reviewer wired to the securityops rotation ledger. A disposable
custom-set test proves native provider mechanics, **not** an actual live
issuer-signing-rotation qualification. No staging/production deployment or
CP activation is required for this development proof.

## Required exact real issuer-signing test

`TestLiveN06HydraIssuerSigningKeyOverlap` provisions a random disposable
Hydra workload client, obtains and independently verifies a real signed
60-second access token, finds its **actual** Admin signing set by current
KID, creates a second signed key under reviewed provider machinery, and
requires both keys to remain in the issuer's public JWKS. It then verifies
the old unexpired JWT and a new JWT, demanding the new KID is genuinely
used for issuance. Premature retirement is denied. After the original
JWT's explicit expiry, it requires new-token signature verification,
removes the old key through the native API and verifies the new token
remains valid and the public old KID disappeared.

The test has no external securityops/CP approver, nor can it prove
fleet-wide stale JWKS caches. Its reviewer is a **disposable test fixture**;
real development qualification still requires separate original evidence
of the approved rotation ledger and representative consumer verification.
The Ory Foundation runner now makes a missing/skip/fail live test a hard
failure. No protected runtime or tenant is touched.
