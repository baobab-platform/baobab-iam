# Nabhold R0 — canonical workload scope convergence

**Source authority:** Shared #305, immutable pin
`892d09c64ca6490c46c2f54c37bd366fcc36c3e5`.  
**Identity authority:** Accepted ADR-IAM-0031/0033; Shared canonical identity
contracts and the existing scope/workload registries.  
**Status:** issuer source/contract correction, not workload qualification.

The existing Nabhold workload ceiling permits `content:entry:resolve` for
`baobab-cms`, but the old Shared and IAM request grammars admitted only a single
colon. The public contract could therefore not represent that registered R0
operation. Existing Intelligence hierarchical scopes had the same lexical gap.

Shared #305 fixes the canonical schema and absolute end-of-string checks. IAM
now consumes that exact pin and admits hierarchical syntax in its Go request
parser. The shared Python/Go corpus includes CMS and Intelligence examples,
malformed segments, final newlines, wildcard scopes and closed-shape negatives.
Go's dollar anchor is end-of-text; Shared adds a portable absolute-end guard
because JSON Schema/ECMAScript dollar anchors alone permit a final line break.

The parser change does not grant a scope. `Config.AdmitRequest` still requires:

- an ACTIVE workload in the exact issuer environment;
- registered audience and scope ceilings;
- independently authenticated credential type and issuer/subject binding;
- exact agreement with requested/granted scope and audience evidence;
- explicit least-privilege defaults when scopes are omitted.

New admission tests prove the existing authorised CMS read scope succeeds only
with synthetic approved authority, while PROVISIONED status, unallocated preview
scope, wrong audience, wrong credential, wrong issuer and wrong environment fail.
The lexical corpus's valid preview example tests grammar only; it does not add
preview to Nabhold's allocation.

The pin also includes the already merged ERP posting-authority vocabulary and
its PROVISIONED workload ceiling. This increment creates no Keycloak client,
optional scope assignment, administrative grant, workload ACTIVE state or runtime
admission for that vocabulary. Federation fixtures and CP consumer provenance
retain their existing reviewed authority; the cross-language contract checks
verify they remain compatible with the new source pin.

Nabhold remains PROVISIONED in Shared. Real workload credential issuance, CMS/CP
context validation, binding activation, cross-tenant negative proof and protected
acceptance are still separate P0-06/P0-07 exits. No staging/AWS credential is
required to implement or exercise this source correction locally.
