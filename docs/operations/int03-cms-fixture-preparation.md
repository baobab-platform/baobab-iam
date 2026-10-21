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
all six actual issuer responses independently: client, secret, service-account
user, direct role-mappings, first-page groups and dedicated federated identities. The account must be enabled, come from the exact client-specific service-account
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
  reader receives the full representation, and `false` selects FGAP v1, where
  admin roles are checked first and per-resource permissions only add
  visibility;
- `default-default-client-scopes`, which under v1 answers only a reader with
  global view-clients/manage-clients.

Group membership uses the unfiltered `users/<UUID>/groups/count`, which must be
exactly `{"count": 0}`. The federated-identity listing has no permission filter.
The orchestrator should read with the disposable realm's full administrator; a
narrower credential, or a realm with admin permissions v2 enabled, denies.
