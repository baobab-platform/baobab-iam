# IAM-N06 — executable assurance verification (development source only)

**Parent source:** baobab-iam #151 at `4cf17485028c6781f947214ea2838c6260c14d61`.
**Purpose:** run mandatory Go, Ory Foundation, security, Foundation and real
PostgreSQL 17 tests against the corrected N06 native BFF implementation
without rewriting the unqualified #147 parent or bypassing PR conflicts.

## Immutable boundary

This disposable review branch changes *documentation only* relative to
the original #151 head. Every code, migration and CI file is identical
to the corrected source parent at the time of branch creation.

The executable now sets `N06Required=true` and binds an explicit current
Kratos TLS session reader, server-owned scope-to-operation policy and
fail-closed unavailable-risk witness. The exact allowed browser
`openid trade:buy` scope is authentication-only `buyer.read`.
Neither signed identity nor an N06 A1/A2 authentication result grants
CP Principal membership, Trade purchase authorization or TMS booking.

CI must execute the command-level `TestN06*` regressions as well as
existing real Ory component, PostgreSQL security and negative tests.
A temporary PR's green CI is **source/component qualification only**;
this packet cannot be used as independent provider/browser/resource
acceptance or as current-head acceptance of the unmerged #151 branch.

## Explicit connected holds

- N02: real first-party browser with exact Kratos/Hydra confidential
  registration, CP active Principal/market/grant and seven unchanged
  N02/INT-03C cases, including revocation, session switch and teardown.
- N03/N04: current issuer -> CP -> owner-native resource enforcement,
  exact executable provider capability and separate native PEP veto.
- N06: genuine AAL2 step-up and recovery, RP-verified WebAuthn A3,
  independent current risk/CP authority for higher-risk A4,
  and tamper/replay/withdrawal negatives.
- N07/N08: private, source-pinned same-run originals for Nabhold,
  ZuriBeans, Thamani, Pulse and Payments, plus native booking
  restrictions, provider-state readback, and independent cleanup.
- Staging and production protected admission remains not authorized.

Do not merge this verification PR into protected branches, confuse its
Actions run with independent provider certification, or override
the blocked source heads of IAM #147/#151.
