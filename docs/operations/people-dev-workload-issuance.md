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

The actual bytes contain a trailing newline after every line. Each public key is registered in a separate trusted keyring with its exact reviewer role, and both signatures are Base64. The approval JSON has workload_id, shared_commit, action, plan_digest, expires_at, maker {key_id,signature}, checker {key_id,signature}. The keyring JSON is `{"reviewers":{"maker-identifier":{"role":"MAKER","public_key":"base64-ed25519"},"checker-identifier":{"role":"CHECKER","public_key":"base64-ed25519"}}}`. Keep approval/keyring files 0600 outside the Git tree and keep private signing keys in independent custody.

## Development runtime

Set BAOBAB_ENVIRONMENT=development, PEOPLE_DEV_ACTION=apply, PEOPLE_DEV_APPROVAL_FILE, PEOPLE_DEV_TRUSTED_KEYS_FILE, ORY_HYDRA_ADMIN_URL, ORY_PUBLIC_ISSUER, and PEOPLE_DEV_CREDENTIAL_FILE. The Hydra administrator must be available only through a loopback private port-forward, and the public issuer must be HTTPS. Create a separate private 0700 directory for the credential output; the command uses exclusive 0600 creation and refuses overwrites. It provisions only the exact single approved client through IAM's native Ory adapter, with provider lifecycle PROVISIONED and 120-second access tokens. It does not print the secret. It requires a new client to avoid silently adopting old credentials. If the issuer creates a client but writing or syncing its private credential fails, the command attempts immediate provider-side disabling. If disabling also fails, issuer state is **UNKNOWN** and an operator must independently inspect/revoke the client before any retry; a successful remote creation without durable credential custody is never reported as accepted.

To disable future issuer credentials, prepare a **new** review with action=revoke, independently signed by maker/checker, and run PEOPLE_DEV_ACTION=revoke. This is provider-side disabling only: already-issued bearer lifetime and CP resource-server registration/revocation must be independently checked. Revocation evidence must include current CP denials and a registered workload state update; a CLI success alone is not sufficient.

## Protected and statutory gates

No production, staging, sandbox or integration access is enabled by this command. CP provider-choice maker/checker (companion CP #479), independent EA-09 certified external provider release, tenant/employer grant, and external vendor source are separate mandatory authorities. ZA/UG statutory review, external vendor licensing, employee data and provider confidentiality remain HOLD. Neither a certificate label nor a simulated/synthetic source can lift those gates.
