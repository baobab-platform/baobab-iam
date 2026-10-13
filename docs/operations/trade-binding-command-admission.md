# P0-04B-02 Trade binding command admission

The four `trade-binding:propose`, `trade-binding:approve`, `trade-binding:activate`
and `trade-binding:revoke` Keycloak scope definitions carry the CP audience only.
No client scope assignment or workload admission is included. Never add these to
a workload client or default/optional human client list as a deployment shortcut.
A separately approved human client configuration and current canonical human
identity are prerequisites to operator acceptance.

CP cryptographically verifies the actual human token, canonical ACTIVE identity,
current exact Organisation grant and assurance. Trade forwards that actual token
to the fixed CP endpoint and never sends it to an invented IAM verifier or
workload token endpoint. No key material, credential or real authority record is
created by the test fixtures. Scope possession is transport admission only.
