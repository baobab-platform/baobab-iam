# DEV-07 native buyer clients

Shared #405 registers two isolated development identities. CP's companion
owns the canonical validator Principal, leased Tenant assignment and estate
binding. IAM's `scripts/dev07_buyer_fixture.py` builds their native Hydra client
registrations from the exact Shared ceilings, a fresh <= one-hour run and distinct
private credentials. It does not provision a client, sign a bearer or confer a
buyer membership. Production clients and Keycloak/federation configuration are
unchanged.

The confidential BFF has separate authorization-code and client-credentials
grants. Its human profile contains only `trade:buy` at `baobab-trade`; its own
workload ceiling contains only `trade:buyer-handoff`. The CP validator has only
current-context, Principal-resolution and estate-binding-resolution scopes.
Buyer JIT registration is absent. The builder does not permit password grants,
refresh grants or a CP-audience buyer token.

The disposable orchestrator must create and GET/read back the exact Hydra native
configuration, drive real Kratos login/WhoAmI plus Hydra code/S256 PKCE, and call
`normalised_claims` only with the actual native grant/session subject and native
assurance value. A dual-grant client ID alone never determines actor type.
Claims normalize identity/assurance only; no roles, Tenant, Organisation, Market,
legal actor or purchase rights are inserted. Existing independent issuer reader
credentials observe the actual tokens before and after revocation.

A wrong-audience human token comes from the existing separate CP human test
client, not by extending the buyer client's approved profile. Infrastructure
owns private packet custody, native client/token deletion and complete host
teardown. Source tests prove refusal boundaries, not actual issuance or INT-05.
