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
