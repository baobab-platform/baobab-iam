# P0-04A — Local provider bootstrap without staging or AWS

**Authority:** Accepted ADR-IAM-0031 and ADR-IAM-0033; CP ADR-BCP-020.  
**Implementation:** local credential preparation and bootstrap hardening.  
**Acceptance:** isolated tests and CI evidence only; no real founding human Principal, protected staging or production acceptance.

## Administrator scope

Accepted ADR-IAM-0031 explicitly rejects a single ordinary `SUPER_ADMIN` across
identity, tenants, organisations, business permissions, cryptography and engines.
ADR-IAM-0033 keeps provider administration separate. A strong password alone is
not a canonical Principal, a Control Plane grant or a capability activation.

| Administrative plane | Responsibility | This increment |
|---|---|---|
| Keycloak master realm | Provider bootstrap/federation administration | Fresh local-only password preparation; existing provider startup creates the bootstrap account only for an initial master realm |
| Kratos | Native human credentials and sessions | No identity created or credential ceremony bypassed |
| Hydra | OAuth/workload client administration | No client-secret downgrade or client provisioned |
| Control Plane | Canonical human Principal and bounded administrative authority | No grant created; existing `cmd/admin-bootstrap` requires registered active, distinct operator/recipient Principals and time-bound grants |
| Nabhold/Thamani/domain engines | Business and tenant-specific permissions | No permission inferred from registration, ownership or provider administrator access |

Thus a Keycloak bootstrap credential is not a Nabhold executive login, a Kratos
native account, an authorised verification reviewer or a universal superadmin.

## Fresh local stack

From a fresh IAM checkout with an owner-controlled directory:

```bash
make local-credentials
make dev-up
make bootstrap
```

`make local-credentials` runs `scripts/local_bootstrap_env.py`. It:

- uses OS-backed `secrets.token_urlsafe(32)` separately for administrator and database passwords;
- publishes a complete `.env` with mode 0600 and no overwrite, including symlink refusal;
- rejects foreign/group/world-writable or symlinked final parent directories;
- accepts only local/CI environment and a closed username grammar;
- produces no deterministic/shared workload-client seed;
- prints only a success summary, never credential values;
- creates no identity, account, grant, verification or provider-support claim.

The file is excluded from Git and Docker build context, as are private temporary
files. Do not upload `.env` as CI evidence or attach it to a PR. The Compose
stack requires explicit administrator/database credentials and binds its
published ports to `127.0.0.1`. Copying `.env.example` alone no longer supplies a
working password: that file is a configuration reference with empty secrets.

For a deliberately chosen local provider username:

```bash
python3 scripts/local_bootstrap_env.py --username local-provider-bootstrap
```

Optional `--output` supports `.env` or `.env.local` in a trusted directory.
Compose reads `.env` automatically; if using `.env.local`, pass it explicitly
with `docker compose --env-file .env.local ...`. Store and retrieve the generated
credential locally through an appropriate private channel; this tool does not
print it into terminal history or claim to provision an account.

### Existing databases and realms

The generator refuses existing output. It is not a password-rotation tool and
must not replace an existing deployment's credentials. Startup environment
variables do not reset a password in an already-created Keycloak master realm,
and a new dotenv password does not rotate an existing Postgres user's password.
For existing stacks, use the provider's authenticated rotation/recovery procedure
and update the private configuration only after that change succeeds. Preserve
existing data volumes; do not erase them merely to force new credentials.

Keycloak's bootstrap administrator is temporary provider access. After the
required setup, establish governed provider administration, remove the temporary
account when the operational model permits, and apply the existing break-glass
runbook for recovery. Routine CP administration still needs independent authority.

## Bootstrap and CI enforcement

`scripts/bootstrap.sh` now refuses missing administrator credentials before any
login, disables shell tracing before credential assignments, creates private
session/temporary files, and removes privileged kcadm session material on exit.
The deterministic workload seed is accepted only for explicit local/CI/test
fixtures; production or an unknown environment is rejected before login.

GitHub CI generates fresh isolated credentials per integration run. It masks
values before putting them in the runner's environment; the existing Keycloak
integration test then uses those same explicit values. Secrets are neither
committed nor included in evidence uploads. Source tests exercise file modes,
uniqueness, overwrite/symlink refusal, unsafe directory refusal, input injection,
non-disclosure and early credential/environment rejection. Existing live
Keycloak CI remains the provider login/bootstrap proof.

## Next non-AWS work and real operator prerequisites

P0-04B must establish separate real human identities through the native Kratos/
Hydra path (or approved federation), bind them to canonical CP Principals, and
apply the reviewer/requester/authoriser/decider/operator scopes and grants with
separation of duties. No AWS account is required to implement or test these
interfaces locally, but a password generator cannot perform that acceptance.

CP already has `cmd/admin-bootstrap`: it grants time-bound, scoped bootstrap
permissions to an existing ACTIVE Principal, audited by another registered
ACTIVE operator. It does not create standing, CRITICAL or EMERGENCY authority
and refuses self-bootstrap. Reuse that boundary rather than minting a broad
provider role and treating it as business authority. Protected staging and
source certification remain separate acceptance steps.

Consulted source baselines: IAM `119f6024ac484003de87c365419fe16762cdcc9f`,
CP `989a61fa858c9173b0756cf99a6d92ae86c85f7c`, Nabhold v2.0 G04/P0-04.
Primary implementation references:

- [Keycloak bootstrap and recovery](https://www.keycloak.org/server/bootstrap-admin-recovery)
- [Python cryptographic secret generation](https://docs.python.org/3/library/secrets.html)
- [Compose required-variable interpolation](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)

This is provider-local bootstrap source work. P0-04's authenticated founding
SoD path, P0-03's accepted real cases and production permission remain unproven.
