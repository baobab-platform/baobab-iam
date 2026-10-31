# IAM-N02 — Connected native browser and protected-evidence qualification

**Status: ENGINEERING SOURCE / REAL HYDRA COMPONENT TEST CANDIDATE, CONNECTED EVIDENCE HELD.**
**Stack:** IAM #147 → IAM #146 (N02) → IAM #145 (N01). No PR merged.
**Governing authorities:** accepted IAM ADR-IAM-0023, 0024, 0025, 0033; accepted Shared ADR-SHARED-042/043; EA v2.3 and EA-DEV DEV-03/04/05/07/11/13/14; EA-XB v1.1. N01 exact Shared pin remains unchanged. Provider support remains PARTIAL.

## Existing real-component reference and what N02 adds

The Infrastructure DEV-04 [native INT-03C plan](https://github.com/baobab-platform/infrastructure/blob/main/tests/platform-integration/development/INT03C.md) already specifies real Kratos/Hydra, CP-owned maker/checker-created Principals, seven genuine issuer/CP positive and negative cases, and independently verified development teardown. That **does not** include an estate browser BFF or Playwright proof. The preexisting source lock pins an older IAM SHA; no prior receipt can be re-labeled as N02 acceptance. Recreate the isolated bounded development topology with reviewed immutable Shared/CP/IAM/Infrastructure pins and record a new common run ID and original immutable artifacts. Never modify or splice a historical receipt.

N02 extends the owner components without inventing CP authority:

| Workstream | Executable path | Qualification and refusal boundary |
| --- | --- | --- |
| Actual synthetic estate-client registration | `internal/nativebff/development_client.go` and `TestLiveDevelopmentHydraEstateClientRegistration` | Direct real Hydra Admin POST/GET/DELETE and final 404 under disposable local loopback with fresh client secret, exact ZuriBeans dev callback, bounded run ID and one-hour lease. No CP Principal, BFF/client binding, delegated audience registration or production support is activated. |
| Browser-facing native login and consent | `internal/nativebff/handler.go` + TLS host `cmd/native-browser-bff/` | Real Kratos public browser flow, current CP-gated governed handoff and Hydra code/S256. Browser must have the **actual** Kratos cookie, exact first-party origin, server-held state/verifier/nonce and explicit CSRF-protected consent. |
| Recovery | `GET /auth/recovery` | Redirects only to the approved Kratos `/self-service/recovery/browser`. Actual verified courier/recovery code and post-recovery **fresh login** must be observed. No recovery result creates, enables or remaps a CP Principal. |
| Assurance and step-up | `ory.GovernedNativeHumanHandoff.AuthenticatorAAL`, `RequireAAL2` | Fresh Kratos whoami session and current CP dispatch; reviewed AAL2 requires real enrolled second factor and explicit Kratos refresh/step-up. No BFF field can assert AAL. AAL2 is **not** BAOBAB-A3, privileged permission, recovery approval or purchasing authorization. |
| Logout and session withdrawal | `POST /auth/logout`, `POST /auth/logout-all`, `internal/nativebff/kratos_session_revoker.go`, PostgreSQL migration 002 | Current-client Hydra token revocation, all-Kratos-session admin revocation and private Hydra all-client subject login/consent-session revocation for the same signed UUID. BFF session-wide invalidation uses the IAM-only HMAC issuer+subject index across replicas. Remote failure is 503/UNKNOWN. Stateless Hydra JWTs may remain usable until expiry unless the resource requires current issuer-status validation; no Keycloak/federated SLO or protected resource-level token-withdrawal proof is claimed. |
| Browser automation | `tests/browser/n02_live.py` | Real Playwright Chromium follows real Hydra/Kratos/estate UI, tests origin/CSRF, sign-in, AAL2, one-code replay, current CP session, recovery and all-session revocation. Requires real installed UI and owner-private synthetic credentials; this test is **never** run by the source-only PR CI as a fake success. |
| Evidence custody and protected review | `scripts/n02_evidence_gate.py`, `tests/unit/test_n02_evidence_gate.py` | Checks actual original browser and Infrastructure DEV-04 receipts, matching run and IAM source SHA, seven positive/negative cases, digests and source freshness. Optional protected packet requires all evidence references and an externally trust-anchored independent reviewer signature; still returns review pending, not approval. |

## Connected development execution (real services, synthetic data)

1. Review Shared/CP/IAM/Infrastructure exact source heads and update Infrastructure's disposable `development/lock.json` only through its own reviewed PR and tests. Never patch the lock to the mutable `main` branch or fabricate an image digest.
2. Run the original Infrastructure development lifecycle with `BAOBAB_ENVIRONMENT=development`. It must provision real two-person **synthetic** CP maker/checker Principals and distinct genuine Kratos sessions, issue genuine Hydra credentials and verify the same seven native INT-03C cases and host cleanup. Retain its **unaltered** completed receipt and SHA-256 sidecar.
3. On an isolated run-labelled first-party estate host, configure real browser-cookie routing to Kratos public, Hydra OAuth login and consent URLs pointing to the BFF's `/auth/login` and `/auth/consent`, and real scoped confidential development client registration. Provision the CP **caller workload** separately through CP-owned guarded development APIs, with `identity:principal:resolve`, `subject_principal_audiences=[baobab-trade]` and an approved buyer BFF profile. None of these are auto-granted by the Hydra client registration code.
4. Apply PostgreSQL migrations 001 then 002 in the IAM-only browser vault. Migration 002 drains unindexed older sessions, rather than leave them outside session-wide logout. Configure the managed vault encryption key (exactly 32 bytes), TTL purge, TLS roots, separate private Kratos Admin, signed token-profile hook, CP trust and a short-lived reviewed lease.
5. Run the real browser with the *private* profile below. The synthetic identity must be supplied by the actual Kratos/CP lease. AAL2 needs a **real enrolled second factor**, real Kratos recovery courier and an approved estate frontend form. A missing factor or courier is BLOCKED, not a passing negative. Run the full suite before applying DEV-04's destructive Principal-deactivation/revocation steps and before teardown.
6. Complete the original DEV-04 owner-led negative/withdrawal checks and independently witnessed cleanup; check both results from their original producers. If the browser and DEV-04 do not share the same exact synthetic run ID, reviewed IAM SHA, providers and CP evidence chain, do not claim connected N02 acceptance. Use a separate protected execution only after its own approval and records.

**31 October N02 qualification correction:** The browser producer now checks the running immutable clean IAM checkout rather than trusting a profile SHA, requires real Kratos `aal2` session readback, verifies that recovery does not create a CP session and that a separate post-recovery OAuth login resolves the **same** CP Principal. The approved synthetic recovery journey must provide a private `post_recovery_password_file` (0600), representing the actual post-recovery credential. Original observation and SHA-256 sidecar are both atomically written as owner-private 0600 files and fsynced; an original browser report is never emitted on a partial case. These changes are source-level corrections, not connected acceptance evidence. Retain all seven immutable case IDs and mandatory same-run Infrastructure receipt.\n\nThe current Infrastructure DEV-04 driver and IAM-N02 Playwright runner are **separate executable tools**. A single supervised orchestration workflow binding their *actual* source+runtime+run identity is not yet demonstrated, so the connected acceptance gate remains **BLOCKED**. This limitation cannot be resolved by renaming an artifact or weakening the evidence validator.

### Private runtime commands

```sh
# Python 3.14; install browser only in the designated disposable dev runner.
python3 -m pip install -r tests/browser/requirements.txt
python3 -m playwright install chromium

# Actual trusted runtime and private synthetic fixtures MUST already exist.
export BAOBAB_ENVIRONMENT=development
export BAOBAB_N02_PRIVATE_PROFILE=/run/secrets/iam-n02-browser-profile.json
export BAOBAB_N02_EVIDENCE_DIR=/run/private-evidence/iam-n02
python3 -B tests/browser/n02_live.py

# Evidence must be original, owner-private, unchanged; same immutable
# IAM source and run_id in both receipts and independent DEV-04 custody.
python3 -B scripts/n02_evidence_gate.py \
  --browser /run/private-evidence/iam-n02/browser-observation.json \
  --browser-digest /run/private-evidence/iam-n02/browser-observation.sha256 \
  --int03c /run/private-evidence/iam-dev04/completed/receipt.json \
  --int03c-digest /run/private-evidence/iam-dev04/completed/receipt.sha256.json \
  --iam-sha EXACT_REVIEWED_40_HEX_COMMIT
```

The browser profile schema is `baobab.iam.n02.browser-qualification.v1`. Its owner-only file is mode 0600 with owner-private 0700 parents. It names three distinct reviewed browser origins, exact source SHA and 32-character run nonce, synthetic identifier, owner-private password, *post-recovery password*, recovery-code and enrolled TOTP seed file paths, and selectors for the *real* estate UI. Browser traces, downloads, storage state, screenshots, identity attributes, tokens, OTP, passwords and HTTP payloads are never uploaded. Use [the structural example](../../tests/browser/n02-profile.example.json) only as a worksheet; it contains no credentials.

### Observations and evidence classification

| Class | Permitted assertion | Not permitted |
| --- | --- | --- |
| `SOURCE` | Compiles, static checks, unit negative gates pass | Hydra, CP, estate, browser or provider accepted |
| `REAL_COMPONENT_SYNTHETIC_DATA` | Actual disposable native Hydra/CP service cases and original teardown receipts, if run | Protected approval, production legal identity, full estate/browser |
| `REAL_BROWSER_SYNTHETIC_DATA` | Real Chromium tested the specified runtime, if run | Independently certified CP/issuer binding, all native INT-03C withdrawal |
| `N02_DEVELOPMENT_BROWSER_AND_CP_OBSERVED_UNATTESTED` | Both original unmodified receipts have same exact source/run and required cases | Independent protected custody, infrastructure topology approval, production |
| `N02_PROTECTED_PACKET_SIGNATURE_OBSERVED_REVIEW_PENDING` | Cryptographic reviewer packet signature over exact bytes verified against pre-approved external key | Actual review/approval decision, legal source, or deployment permission |

The signed protected packet must be independently authored **after** the actual protected run, with independent maker/checker/witness principals, the original browser+INT-03C digest anchors and evidence digests for the approved runtime/image, issuer, CP, authenticator, client, cross-tenant negative, revocation, backup/restore, teardown and separate external retention custody read-back. A signature on fictional digests is neither evidence nor certification.

Protected staging execution additionally needs the exact Infrastructure #49 approval packet, real private service credentials, independently authorized CP maker/checker, secret/network boundary, explicit protected topology, retained provider and privacy compliance, image hashes, reviewer identity/trust anchor and external custody witness. **None of those authorities or protected observations is supplied by this PR.** After a real authorized execution a reviewer must download originals independently, verify chain+signature+expiry, and decide acceptance; no source CLI auto-promotes C4-03B–E or C4-04B/C.

## Open engineering gates

- Cross-repository consumer adoption: actual approved estate-owned Kratos UI/ingress, CP delegated buyer caller and registered BFF binding, genuine Hydra hook, provider-specific login/consent URLs and user-friendly recovery/step-up. Nabhold executive and Thamani B2B require their *own* approved audience profiles; they must not reuse Trade buyer grants.
- One coherent disposable development browser/CP/Trade runtime orchestrator with shared immutable run ID, exact source SHA, mandatory browser step before destructive DEV-04 checks, bounded resource lease and independent teardown (Infrastructure owning PR).
- Connected browser Playwright run and real CP readback/withdrawal; browser code alone cannot prove execution. Include no skipped cases in acceptance.
- `/auth/logout-all` requests Kratos session-wide revocation, Hydra subject login/consent revocation across clients, current-client OAuth token revocation and local IAM BFF session-wide invalidation. **Immediate withdrawal of a previously minted stateless JWT at CP/Trade requires independently observed live issuer-status and resource-denial evidence before natural expiry.** Keycloak enterprise federation, other external IdPs and OIDC front/back-channel single logout remain separate qualification and application duties.
- Actual protected stage and independent evidence custody; passkey/recovery/administrative A3 proof separate from the AAL2 TOTP development path.
- N01 Shared re-pin review and canonical registration; C4-03B–E, C4-04B/C and provider support `PARTIAL` remain unchanged.

**Release rule:** Until actual protected evidence and independent owner approval, every staging/production N02 result is **HELD**. Do not merge IAM #145/#146/#147 or alter existing provider support/approval gates based on this source increment.
