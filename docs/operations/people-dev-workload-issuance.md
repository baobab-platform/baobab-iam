# Governed People development workload issuance — IAM

**Engineering candidate.** The canonical Shared workload `baobab-erp-people-reader-dev` was accepted in Shared #457 (commit c0d3dd935e4b635fd38f113b280a220e552bc908). Its admission profile is development only: exact audience baobab-control-plane and scopes context:resolve and people:provider:read. It is **not** an employer grant, provider selection, salary-calculation permission, or staging/production workload.

## Two independent approval signatures

Use `BAOBAB_ENVIRONMENT=development PEOPLE_DEV_ACTION=plan go run ./cmd/provision-people-dev` to emit the immutable plan and its sha256 digest; this never accesses Hydra. Two independently controlled reviewers, designated MAKER and CHECKER, sign the following exact UTF-8 payload using Ed25519. The action is `apply` or `revoke` and must be independently signed for each operation.

```text
BAOBAB-PEOPLE-DEV-v1
baobab-erp-people-reader-dev
c0d3dd935e4b635fd38f113b280a220e552bc908
apply
sha256:<exact-digest-from-plan>
<RFC3339-expiry-within-24-hours>
```

The actual bytes contain a trailing newline after every line. Each public key is registered in a trusted keyring with its exact reviewer role, and both signatures are Base64. The approval JSON has workload_id, shared_commit, action, plan_digest, expires_at, maker {key_id,signature}, checker {key_id,signature}. The keyring JSON is {"reviewers":{"maker-identifier":{"role":"MAKER","public_key":"base64-ed25519"},"checker-identifier":{"role":"CHECKER","public_key":"base64-ed25519"}}}.

**Trust-root custody is separate from approval submission.** The command does not accept a caller-selected keyring path. Infrastructure/security operators provision /run/baobab-iam-trust/people-dev as a separately administered read-only mount, with a root-owned 0755 directory and root-owned 0400 trusted-reviewers.json. The command verifies the mounted filesystem is read-only and fails closed if it is writable. The issuer command must run as a dedicated non-root runtime identity; it refuses privileged mutation when effective UID is root. That identity cannot write or replace the trust file or its read-only mount. Reviewer enrollment, role assignment, rotation and revocation are controlled through that separate administrative path and audited independently. The approval submitter supplies only an approval file, owned by the runtime identity with exact 0600 mode in an exact 0700 directory. Maker/checker keys must be controlled by different people; distinct key bytes alone do not prove organizational separation. Keep private signing keys outside the runtime host and repository.

## Development runtime

Set BAOBAB_ENVIRONMENT=development, PEOPLE_DEV_ACTION=apply, PEOPLE_DEV_APPROVAL_FILE, ORY_HYDRA_ADMIN_URL, ORY_PUBLIC_ISSUER, and PEOPLE_DEV_CREDENTIAL_FILE. The Hydra administrator must be available only through a loopback private port-forward, and the public issuer must be HTTPS. Provision /var/lib/baobab/iam/people-dev/credentials as the dedicated external custody directory, owned by the runtime identity with exact 0700 mode; PEOPLE_DEV_CREDENTIAL_FILE must name a direct child of that fixed directory; the command opens every path component without following symlinks, reserves the filename relative to the validated directory descriptor, verifies the created descriptor is a regular owner-owned 0600 file with one link, and refuses overwrites. It provisions only the exact single approved client through IAM's native Ory adapter, with provider lifecycle PROVISIONED and 120-second access tokens. It does not print the secret. It requires a new client to avoid silently adopting old credentials. If the issuer creates a client but writing, syncing or closing its private credential fails, the command attempts immediate provider-side disabling. If disabling also fails, issuer state is **UNKNOWN** and an operator must independently inspect/revoke the client before any retry; a successful remote creation without durable credential custody is never reported as accepted.

To disable future issuer credentials, prepare a **new** review with action=revoke, independently signed by maker/checker, and run PEOPLE_DEV_ACTION=revoke. This is provider-side disabling only: already-issued bearer lifetime and CP resource-server registration/revocation must be independently checked. Revocation evidence must include current CP denials and a registered workload state update; a CLI success alone is not sufficient.

## Protected and statutory gates

No production, staging, sandbox or integration access is enabled by this command. CP provider-choice maker/checker (companion CP #479), independent EA-09 certified external provider release, tenant/employer grant, and external vendor source are separate mandatory authorities. ZA/UG statutory review, external vendor licensing, employee data and provider confidentiality remain HOLD. Neither a certificate label nor a simulated/synthetic source can lift those gates.


## Filesystem trust boundary and evidence status

The privileged issuer path is unavailable to UID 0, preserving separation between root-managed trust installation and the runtime identity. Approval loading uses an opened directory descriptor and relative openat with O_NOFOLLOW; every path component is checked as a directory, root- or runtime-owner controlled, and not group/other writable. The opened approval descriptor is then checked with fstat for regular-file type, runtime ownership, exact 0600 mode, single link and a 32 KiB maximum before decoding. The trust keyring uses the fixed path on the separately administered read-only mount above, root ownership and exact 0400 mode; Fstatfs confirms the parent mount is read-only before opening the keyring and confirms the opened keyring descriptor is also on a read-only mount. Credential creation uses the same descriptor-anchored path walk and validates the newly created descriptor before calling Hydra. Failed custody removes the unaccepted file through the held directory descriptor; successful persistence syncs both file and directory.

The regression suite covers symlink rejection, group-writable parent rejection, file owner/mode mismatch, FIFO and hard-link rejection, path replacement after opening the directory, and secure credential creation. The directory-descriptor design removes the pathname check/open window rather than trying to detect a race after the fact.

**Acceptance remains SOURCE/CAPABILITY ONLY.** No owner-supervised issuance/revocation run, real issuer readback, CP/native allow/deny, same-unexpired-token withdrawal denial or teardown originals are attached. A successful DisableWorkload response is not proof of bearer invalidation or native resource-server denial. Do not mark CTS2-039/041/044 or EA-DEV DEV-14/15 as runtime-qualified from these source tests.


## Development completion versus operational qualification

The PR's mergeable development deliverable and the later live qualification are
separate states. **Development implementation complete** means the scoped
command, filesystem controls, documentation and regression tests are present;
the full required CI suite passes on the final PR head; and independent reviewers
have cleared their implementation findings. This state does not claim that a
real provider has issued or revoked a credential.

**Operationally qualified** is a later, owner-supervised state. Until every
item below has original evidence attached and reviewed, the People workload
remains SOURCE/CAPABILITY ONLY and no production, staging, statutory or CP
business authority follows from it.

### Deferred runtime evidence register
The deferred exercise is tracked in [baobab-iam issue #209](https://github.com/baobab-platform/baobab-iam/issues/209); keep it open until all original evidence is attached and independently accepted.


| Capability / question | Required original evidence and acceptance criteria | Accountable owner | Environment and prerequisites | Gate held |
|---|---|---|---|---|
| Development workload issuance | Signed apply approval and trust-keyring identity; exact Shared pin; command receipt; protected credential-custody confirmation; Hydra client readback proving exact client ID, enabled state, grant type, audience/scope ceiling and 120-second TTL. The readback must match the approved plan exactly. | IAM service owner, with independent Security approver | Isolated governed development Hydra tenant; separately administered root trust keyring; non-root issuer runtime; private loopback admin port-forward; protected secret store/custody directory | No claim of live issuance acceptance; no downstream activation |
| CP/native positive and negative authorization | Exact IAM/CP/engine source pins; token metadata readback; CP resource resolution allowed only for the approved context; explicit denial for wrong audience, wrong scope, wrong context and unregistered principal; native resource-server decision evidence. HTTP errors outside the defined deny classes do not count as policy denials. | CP service owner and consuming engine owner | Same governed development tenant plus isolated CP and consuming engine; exact current Shared People contract | CP provider binding and domain authorization remain ungranted |
| Withdrawal of an unexpired credential | Capture a token before withdrawal and prove it remains within its exp claim; perform separately signed revoke; read back Hydra disabled state; replay the exact same still-unexpired token and prove issuer/CP/native resource denial. A successful DisableWorkload call alone is insufficient. | IAM service owner and CP/engine owners; independently witnessed by Security | Same development deployment with token introspection/readback and CP/native request capture | Revocation acceptance and any production reliance remain blocked |
| Teardown and custody | Issuer readback showing disabled/deleted according to the approved teardown procedure; credential custody destruction/retention record; CP/native binding and grant readback; disposable infrastructure cleanup receipt; no residual client or secret. | IAM operations owner and Security evidence reviewer | After the issuance/withdrawal exercise; access to provider, CP and engine audit/readback surfaces | No qualification closure until cleanup is independently verified |

Do not manufacture these records from unit tests, source inspection, synthetic
INT-02 output, CLI success strings or a provider API's mutation response.
Retain exact timestamps, source tuple, environment identity, actor identities,
redacted request/response evidence and artifact digests. Private signing keys,
client secrets, bearer tokens, cookies and MFA material must never enter Git,
CI logs or public artifacts.

### Implementation controls completed in source

The implementation also treats receipt delivery and local custody as part of
the mutation outcome: a short credential write is an error; a failed credential
write/sync/close or failed success-receipt write triggers compensating provider
disable; the reserved credential file is removed through its held directory
descriptor; and cleanup errors are returned rather than silently discarded.
The empty exclusive reservation is directory-synced before the provider call.
A revoke command reports only that the provider-side disable request was
accepted; it does not claim disabled-state readback or bearer invalidation.

### Failed mutation and compensation handling

A pre-existing Hydra client is refused without changing it. After a successful
new-client creation, if the independent issuer configuration readback fails,
the Ory adapter attempts a provider-side disable using a separate bounded
15-second context and verifies the disabled grant set by readback. A verified
disable is reported as a failed provisioning attempt with the cleanup result
made explicit. If disable/readback cannot be verified, the issuer state is
UNKNOWN: stop retries, preserve the error record, and have the IAM operator
read the exact logical client ID back from Hydra and disable it under the
normal change-control procedure. Never infer absence or disabled state from a
failed command.

If credential custody fails after a successful create, the command similarly
attempts disable with an independent bounded context. The reserved credential
path is removed through its held directory descriptor. A failed compensation
is an incident requiring independent issuer readback; it is not a successful
rollback and must not be marked qualified.

### Current evidence boundary

The repository CI's INT-02 real Keycloak-to-CP browser flow is a separate
synthetic integration check, not the deferred People workload exercise. Its
28 November 2026 run failed during the synthetic human MFA browser step
(login_normal_mfa, HTTP 500, FORM_U1P1T0O0); the harness then destroyed its
disposable IAM, CP, database and network resources. This failure is not waived
as deferred People evidence. It must be diagnosed in the owning integration
harness or IAM integration before the required CI suite can be called green.
