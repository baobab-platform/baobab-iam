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
