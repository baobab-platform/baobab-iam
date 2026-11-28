# N08 retained enterprise Keycloak runtime recovery

The N08 workflow now includes a separate *real* Keycloak PostgreSQL 17
destructive restore. The authenticated Keycloak runtime starts from the
pinned enterprise source, with a randomly generated disposable TLS chain.
The script checks the Compose project label and original PostgreSQL 17
server, witnesses a real Keycloak master realm in the original provider DB,
stops the actual Keycloak server, dumps its source of record in a private
SHA-256 checked temporary directory, **destroys and recreates** its
disposable database, restores it through pg_restore, restarts the original
provider and checks both runtime health and persistence of its real realm.

No browser credential, JWT or dump is uploaded; the entire Compose project,
volumes and disposable TLS keys are destroyed even on failure.

**Important distinction:** this adds a *fourth actual provider/database
recovery component* beside the previously successful Kratos/Hydra/IAM
security three-database test. It does NOT demonstrate upstream SAML/OIDC
trust rotation, retained broker sessions, CP provider/support records,
BFF/Redis session cache, or a **same-transaction distributed snapshot**.
True whole-service disaster recovery and protected deployments remain HELD.

## Original native session revocation across restore

The disposable Keycloak restore job now uses a separate TLS-authenticated Admin
client to provision an isolated realm, an ephemeral direct-grant client and a
random native user. It witnesses a **real Keycloak password-grant login and
active user-scoped broker session**, disables that exact identity and revokes
its broker sessions, and checks the original current Admin state. Only the
synthetic subject binding (never the password, bearer or session ID) enters
private test custody. After the actual Keycloak PostgreSQL 17 destroy/restore
and server restart, the job independently rereads the **same** account as
disabled and its sessions as empty. Any lost original, ambiguous identity,
failed logout or session resurrection fails the qualification job.

This is a *provider-local* recovery component. It does not yet prove actual
federated upstream trust termination, a single consistent four-database
snapshot, BFF/Redis custody, CP grants or consumer-denial readbacks. The
cross-service N08 gate remains HELD until those separately owned effects
are tested in one immutable witnessed recovery transaction.
