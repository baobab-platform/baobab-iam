# INT-03 CMS fixture preparation (source only)

21 October 2026. Shared #354 is treated as Accepted. Registry activation remains
on hold; Shared #356 was closed unmerged to preserve that hold. This change does not advance
`contracts.lock.yaml`, add either identity to committed clients, provision an
issuer client, issue a token, establish a tenant grant, or qualify a provider.

`scripts/int03_cms_fixture.py` prepares private Keycloak client documents only
when IAM's exact clean Shared pin contains BOTH complete approved development
rows. The current pin does not, so preparation refuses. A locally modified
registry or the proposed branch cannot supply authority. The helper is not
called by ordinary bootstrap. The integration inventory recognises a future
exact pair only after proving absence from both committed and ordinary live
clients; a partial or widened pair fails.

The consumer's optional scopes are `context:resolve` and
`content:entry:resolve`. The separate validator has only `context:validate` and
validates only the CMS audience. Default scopes carry no business operation.
Each preparation generates two independent random secrets; documents use an
exclusive 0700 directory and 0600 files. No secret is printed. The new
`content:entry:resolve` scope definition maps only the CMS audience and is
assigned to no ordinary client.

`verify_readback` compares actual issuer API client configuration AND its
separate secret endpoint response against the generated document. It rejects
extra scopes, flows, attributes, protocol mappers, or swapped secrets. Its
boolean result is not an issuer receipt; the disposable orchestrator must
capture actual API provenance, verify service-account role mappings, and prove
real token acquisition, introspection and audience isolation separately.

Preparation requires a timezone-aware absolute deadline more than 60 seconds
and at most 90 minutes away. Configured token lifetime is 60 seconds. This
helper does not enforce runtime shutdown or refuse issuance near the deadline:
the future orchestrator MUST cap every token at that fixed deadline and enforce
early closure by revocation or destruction of all issuer trust and accepting
runtimes, with unconditional teardown. Do not use these documents independently
as a live fixture until that lifecycle is implemented and reviewed.

Nine unit tests exercise exact rows, absent/half pairs, immutable deadlines,
independent secrets/scopes, strict read-back, duplicate JSON fields, private
exclusive files, refusal before writes, and cleanup after a partial write.
Existing pinned Shared verification is reused, the IAM working lock must equal
its immutable committed blob, and the registry is read from the pinned Shared
commit rather than the working tree. Shell syntax and focused tests
are checked locally; issuer integration runs in mandatory CI. No connected
CMS/PostgreSQL run is claimed by these tests.

Actual CMS provider qualification, independent maker/checker certification,
current CP context/release/health/binding, full INT-03 and retained normative L4
matrix, protected Kratos/Hydra IAM↔CP proof, executive authority, staging,
production and R0–R3 remain open. Keep PARTIAL support and Nabhold non-trading.

CI prerequisite: the image scanner reported CVE-2026-111943 in the existing
Go 1.27.2 standard library. Module minimum and federation builder now use
1.27.3. The Docker multi-platform index digest was downloaded from the official
registry and independently SHA-256 checked against its response header. No
vulnerability exclusion was added. This does not rehash the earlier identity
run artifact, whose digest remains GitHub-reported only.

## Service-account read-back dependency

`verify_runtime_readback` adds the mandatory service-account boundary to client
and separately retrieved secret checks. The disposable orchestrator must obtain
all eight actual issuer responses independently: client, secret, full realm,
global default client scopes, service-account user, direct role-mappings,
unfiltered group count and dedicated federated identities. The account must be enabled, come from the exact client-specific service-account
endpoint, and have a distinct valid issuer UUID. Realm roles,
client roles, group memberships and federated identity links all deny. Unknown
mapping categories and malformed/absent endpoint responses deny. This excludes
offline_access, administrative roles and group/composite-role inheritance; none
is needed for the narrow CMS proof scopes.

This is source validation, not network provenance. A producer cannot turn copied
JSON into qualification evidence by calling the function. The future runtime
must use this combined checker, capture real endpoint provenance, independently
verify tokens, enforce the fixed deadline/early-close lifecycle and tear down all
issuer trust and accepting services. Ten fixture tests plus two INT-02 tests pass
locally. The canonical registry/pin remain unchanged; no client is provisioned.

The function constructs and reads `clients/<issuer UUID>/service-account-user`; it does not depend on `serviceAccountClientId`, which the pinned Keycloak endpoint does not populate. Federated identities require the dedicated `users/<UUID>/federated-identity` response; absent embedded fields prove no absence. The orchestrator supplies authenticated, bounded relative-path I/O. Embedded role/group fields and external federation links must also be empty.

## Reader visibility (fine-grained admin)

Keycloak 26.7.5 filters the combined `role-mappings` response through the
reader's role visibility, and the group list through group visibility. A
fine-grained admin credential therefore receives `{}`/`[]` for authority it
cannot see, without a 403. Empty reads are accepted only after the reader
proves an unfiltered view. Filtering hides entries but never invents them, so
two positive answers are sufficient:

- the full realm representation (relative path `''`) with
  `adminPermissionsEnabled` exactly `false`. Only a view-realm/manage-realm
  reader receives the full representation. False disables realm FGAP v2
  policies; it does not choose the server's v1/v2 evaluator;
- `default-default-client-scopes` proves global client visibility. The v1
  evaluator requires global view-clients/manage-clients. The v2 evaluator
  permits those same roles or a policy, but policy evaluation denies when
  the proved realm flag is false. Either evaluator therefore proves the
  global client visibility required to see every client's role mappings.

Group membership uses the unfiltered `users/<UUID>/groups/count`, which must be
exactly `{"count": 0}`. The federated-identity listing has no permission filter.
The orchestrator should read with the disposable realm's full administrator; a
narrower credential, or a realm with admin permissions v2 enabled, denies.


Pinned-source review references (Keycloak 26.7.5):
[realm representation](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java),
[global and per-client visibility](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/fgap/ClientPermissions.java),
[v2 visibility](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/fgap/ClientPermissionsV2.java),
[v2 policy refusal](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/fgap/FineGrainedAdminPermissionEvaluator.java),
[realm flag and feature conjunction](https://github.com/keycloak/keycloak/blob/26.7.5/server-spi-private/src/main/java/org/keycloak/authorization/fgap/AdminPermissionsSchema.java),
and [unfiltered group count](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/UserResource.java).

## Native Hydra short token lifetime port

The maintained `provider.WorkloadProvisioningSpec` now accepts an optional
`AccessTokenTTLSeconds` of 1–300 seconds. Zero preserves the provider default or
existing client configuration; it does not invent a short lifetime. Hydra uses
its supported `client_credentials_grant_access_token_lifespan` field. An explicit
request requires an independent GET after POST/PUT, with matching client and
equivalent retained duration. A create response echo is insufficient. Missing,
malformed, ignored or widened read-back denies. Rotation, disable and updates
without an override preserve an existing client lifetime instead of dropping it
from a full replacement document.

The existing isolated native client-credentials regression requests 60 seconds
and checks actual response/JWT lifetime and preservation across rotation. Its
ordinary fixture remains a provider-mechanics test, never the named CMS caller
or connected NAB-03 qualification. No extra runtime identity is introduced by
these tests. Fourteen protocol cases separately exercise the administrative
read-back and invalid-input boundaries without an issuer.

The ordinary `provision-workload` command refuses both exact INT-03 CMS names
before any provider access, including create/rotate/disable. They belong only
to the separately reviewed, registry-gated disposable lifecycle; a future ACTIVE
row does not make them ordinary product clients. The maintained Hydra provisioner
selects `client_secret_post`; the separately named Nabhold caller and CMS validator
must use that same method, not broaden audiences for compatibility.

A short token lifetime is not the immutable 90-minute client/run deadline or
revocation. The future orchestrator still must compute the deadline at creation,
refuse out-of-window issuance responses, and destroy issuer trust and every
accepting runtime on early closure. A failed read-back may follow an accepted
POST, so the disposable owner must recover/destroy that run, never infer absence
or blindly retry it as a new fixture. No client is created by this source change;
canonical activation, full lifecycle orchestration, current independent CP
certification/health/binding, connected NAB-03 and protected production gates
remain outstanding.

## Native fixture inputs and fresh-only provisioning — 22 October 2026

`native-plan --shared-checkout PATH --output NEW_PRIVATE_DIRECTORY` prepares a
secret-free native plan only after the same committed IAM lock and immutable
Shared blob verify both complete exact development rows. The current pin
refuses before writing anything. The plan reuses the maintained workload-token
profile builder, preserving separate audience/scope ceilings and owners. It
requests 60-second token lifetimes and `RequireNew` on the existing provider
interface. It does not provision, activate, mint a credential/token, or install
the hook configuration. Provider `PROVISIONED` is not canonical activation.

Hydra's fresh-only mode refuses an existing client before mutation. A new
client uses the maintained OS-random secret generator and requires an independent
GET checking the exact client, lifetime, client-credentials grant, token endpoint
method, scopes, audiences and owner metadata. Redirects, response types, logout
redirects, CORS origins and key material must be empty. The pinned Hydra source
stores the explicit empty response-type list; its `GetResponseTypes()` fallback
does not grant `authorization_code`, which remains absent from `grant_types`.
The existing native provider-mechanics regression exercises this mode without
adding a named CMS identity or widening a profile. Cleanup is registered before
creation because failed read-back does not imply that POST failed.

A native plan is an input, not an independently verified issuance receipt or a
supervised lifecycle. The remaining runtime owner must enforce the immutable
90-minute maximum from creation, validate every actual token and current CP
context, refuse out-of-window responses, and close all issuer trust and accepting
runtimes even on interruption. Neither this CLI nor `RequireNew` enforces that
absolute deadline or revokes existing JWTs. Do not use the plan independently
until that lifecycle is implemented and reviewed. Ordinary provisioning still
refuses both named CMS identities; canonical activation remains held.


## Supervised native CMS bridge — development only

`cmd/int03-cms-native` is a separately opt-in, disposable admin entrypoint.
Ordinary `provision-workload` continues to refuse both exact proof identities.
The bridge's **create** action invokes IAM's original
`int03_cms_fixture.py native-plan` against the immutable committed Shared
pin, rejects partial/widened registry rows and creates only one exact named
client through the maintained Ory WorkloadProvisioner with `RequireNew=true`.
It independently reads the real Hydra admin client, verifies exact grants,
scopes, audiences, method, token lifetime, absence of redirect/JWKS/CORS
authority, provider ownership and a random 128-bit run ownership marker.
Only after read-back does it exclusively persist a per-client secret in an
existing private directory. No credential is printed.

**Revoke** uses IAM's `RevokeWorkload` port and separately confirms that
Hydra reports zero client grant types. This stops *future issuance only*.
**Destroy** performs that revocation, independently rechecks that the client
still carries the exact run nonce, deletes the specific Hydra admin client,
and independently proves a subsequent GET returns 404. Missing clients are
idempotent success. A different run's client is never mutated or deleted.
The external Infrastructure owner *must* stop and verify all accepting
resource servers before destroy: neither disabled grants nor deleting Hydra
makes an existing signed JWT cryptographically invalid. Runtime expiry,
cross-tenant denial and all 14 NAB-03 scenarios remain separate.

Infrastructure writes a durable private recovery journal before first POST,
then calls this bridge using exact pinned source and a per-call bounded
deadline. An interrupted or timed-out POST may have succeeded; the journal
survives and a separate `recover` process attempts both deletes in reverse
creation order, retaining recovery state if either client cannot be safely
verified. Recovery is permitted if the canonical registry later goes HELD;
**new creation is not**. No password, token, private URL, exception text or
secret is put into the public receipt.

The bridge only accepts an explicitly disposable invocation, the exact two
client names, HTTPS administrative origin `hydra.int03.test` secured by the
disposable CA and development-only native specifications. The run executor
must enforce private-network isolation, independent cleanup of CP topology,
outage recovery, and current capability certification. At this source stage
neither client has been provisioned; the registry hold, protected C4,
connected NAB-03, staging and production all remain unqualified.
