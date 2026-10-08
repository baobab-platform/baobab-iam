# Native human canonical handoff

`internal/provider/ory.NativeHumanHandoff` verifies a current Kratos session
before accepting Hydra login or consent. The estate/BFF retains the canonical
Shared request inside its browser-bound, CSRF-protected transaction. Pass that
retained value, never a replacement request reconstructed from callback input.
The adapter compares the Hydra challenge to client, redirect URI, state, nonce,
scope and S256 challenge exactly. It rechecks the Kratos session immediately
before acceptance and does not trust Hydra's remembered-login hint.

Public authorization and token exchange remain direct standards operations.
The bridge calls only Kratos's public session verification and Hydra's private
login/consent admin plane. Its constructor requires explicit HTTPS origins and
an explicit clock and atomic challenge fence; only isolated loopback fixtures may allow HTTP. Redirects
are disabled on server calls and returned continuations must stay on the exact
Hydra issuer origin and authorization path. Session credentials never travel
to Hydra. Provider JSON is bounded and duplicate/trailing JSON fails closed.

Use `federation.OpenNativeChallengeLedgerWithStorage` with the existing shared,
verified-TLS Postgres storage and exact namespace/recovery epoch in production.
The bridge burns a digest of issuer, stage and exact opaque challenge before
Hydra acceptance. Concurrent/repeated acceptance fails closed; a timeout or
invalid continuation does not release the fence. Recovery starts a new browser
transaction, never retries an uncertain acceptance. Local ledger files are
disposable development/CI storage. Recovery-epoch rotation must also invalidate
all retained estate browser transactions; old storage pools are fenced. Retain
consumption records through the provider challenge lifetime and recovery window;
this increment exposes no deletion/reset operation.

Consent is explicit, for the exact retained OIDC scopes (openid/profile/email).
Business scopes, resource audiences, unsupported ACR requests, inferred grants
and remembered consent fail closed. Kratos's observed assurance level remains
provider evidence; it is not a fabricated Baobab assurance decision. No tenant,
canonical identity, membership or binding is created by this bridge.

After callback state verification and direct code/S256 exchange, project the
provider response with `humanauth.ProjectOAuthResponse`. Independently verify
the returned ID token's signature, exact issuer, client audience, subject,
nonce and validity before consumption. The live CI fixture exercises that
sequence against pinned Kratos/Hydra and requires PASS, not SKIP, on both Hydra
variants. It also checks authorization-code and challenge replay denial.

This package is provider mechanics. It is not an internet-facing login server
or proof of current CP authority. Estate integration must supply CSRF/browser
binding, current CP resolution, approved clients, canonical identity mapping,
consent UI, operational session/recovery controls and resource acceptance.
All provider declarations remain PARTIAL until those full proofs exist.

The Hydra integration follows Ory's documented
[login and consent flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow).
