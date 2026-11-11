# IAM People provider reader — enforceable issuer scope (ADR-SHARED-045)

The canonical `people:provider:read` scope (Shared #436) allows **only**
an explicitly ACTIVE registered IAM workload with exact
`baobab-control-plane` audience. `context:resolve` must accompany it.
Its token grant requires an exact per-audience request and a current
registered workload; `PROVISIONED` is never positive admission, and no
protected-environment profile is admitted by this development slice.

This constraint is enforced in `internal/tokenprofile.Config.Validate` and
`Config.Claims` through dedicated People admission guards, not merely a
documentation convention. The generic canonical token hook already invokes
those validations. No grant is inserted into the Shared workload registry,
Hydra, Keycloak or a tenant by this PR. No credentials are issued.

**This is IAM's entire authority:** the actor is the registered workload,
for its permitted audience and scopes. The legal employer, jurisdiction,
selected HRIS/payroll provider, binding revision, data access purpose and
maker/checker controls remain live CP and ERP responsibilities. A token
cannot be translated into employment or pay-run authority.

Qualification to unlock staging/production requires a **later accepted
policy change**, a provisioned dedicated workload, actual Hydra/Ory token
issuance, CP current registry and Context redemption, negative cross-tenant
tests and independent evidence. Source-only Go tests never count as that
qualification.
