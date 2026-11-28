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

**Trust-root custody is separate from approval submission.** The command does not accept a caller-selected keyring path. Infrastructure/security operators provision /etc/baobab/iam/people-dev/trusted-reviewers.json as a root-owned 0400 file in a root-owned 0755 directory. The runtime identity must not be able to write or replace that file or any parent directory. Reviewer enrollment, role assignment, rotation and revocation are controlled through that separate administrative path and audited independently. The approval submitter supplies only an approval file, owned by the runtime identity with exact 0600 mode in an exact 0700 directory. Maker/checker keys must be controlled by different people; distinct key bytes alone do not prove that organizational separation. Keep private signing keys outside the runtime host and repository.

## Development runtime

Set BAOBAB_ENVIRONMENT=development, PEOPLE_DEV_ACTION=apply, PEOPLE_DEV_APPROVAL_FILE, ORY_HYDRA_ADMIN_URL, ORY_PUBLIC_ISSUER, and PEOPLE_DEV_CREDENTIAL_FILE. The Hydra administrator must be available only through a loopback private port-forward, and the public issuer must be HTTPS. Create a separate private directory owned by the runtime identity with exact 0700 mode for the credential output; the command opens every path component without following symlinks, reserves the filename relative to the validated directory descriptor, verifies the created descriptor is a regular owner-owned 0600 file with one link, and refuses overwrites. It provisions only the exact single approved client through IAM's native Ory adapter, with provider lifecycle PROVISIONED and 120-second access tokens. It does not print the secret. It requires a new client to avoid silently adopting old credentials. If the issuer creates a client but writing, syncing or closing its private credential fails, the command attempts immediate provider-side disabling. If disabling also fails, issuer state is **UNKNOWN** and an operator must independently inspect/revoke the client before any retry; a successful remote creation without durable credential custody is never reported as accepted.

To disable future issuer credentials, prepare a **new** review with action=revoke, independently signed by maker/checker, and run PEOPLE_DEV_ACTION=revoke. This is provider-side disabling only: already-issued bearer lifetime and CP resource-server registration/revocation must be independently checked. Revocation evidence must include current CP denials and a registered workload state update; a CLI success alone is not sufficient.

## Protected and statutory gates

No production, staging, sandbox or integration access is enabled by this command. CP provider-choice maker/checker (companion CP #479), independent EA-09 certified external provider release, tenant/employer grant, and external vendor source are separate mandatory authorities. ZA/UG statutory review, external vendor licensing, employee data and provider confidentiality remain HOLD. Neither a certificate label nor a simulated/synthetic source can lift those gates.


## Filesystem trust boundary and evidence status

Approval loading uses an opened directory descriptor and relative openat with O_NOFOLLOW; every path component is checked as a directory, root- or runtime-owner controlled, and not group/other writable. The opened approval descriptor is then checked with fstat for regular-file type, runtime ownership, exact 0600 mode, single link and a 32 KiB maximum before decoding. The trust keyring uses the fixed root-controlled path above, root ownership and exact 0400 mode. Credential creation uses the same descriptor-anchored path walk and validates the newly created descriptor before calling Hydra. Failed custody removes the unaccepted file through the held directory descriptor; successful persistence syncs both file and directory.

The regression suite covers symlink rejection, group-writable parent rejection, file owner/mode mismatch, FIFO and hard-link rejection, path replacement after opening the directory, and secure credential creation. The directory-descriptor design removes the pathname check/open window rather than trying to detect a race after the fact.

**Acceptance remains SOURCE/CAPABILITY ONLY.** No owner-supervised issuance/revocation run, real issuer readback, CP/native allow/deny, same-unexpired-token withdrawal denial or teardown originals are attached. A successful DisableWorkload response is not proof of bearer invalidation or native resource-server denial. Do not mark CTS2-039/041/044 or EA-DEV DEV-14/15 as runtime-qualified from these source tests.
