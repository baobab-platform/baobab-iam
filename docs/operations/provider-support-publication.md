# Governed provider support publication

Authority: ADR-IAM-0033 MP3/MP4, ADR-SHARED-017. This procedure prepares
canonical registration documents; it neither registers nor activates a provider.

## Construction preflight

Use a clean Shared checkout at the exact `contracts.lock.yaml` commit:

```sh
python3 scripts/provider_publication.py --shared-checkout .shared-contracts
python3 scripts/provider_publication.py --shared-checkout .shared-contracts --require-registrable
```

The first command validates construction and reports exclusions. The second is
the publication gate: exit 2 means one or more providers have no IMPLEMENTED
canonical support. Exit 1 is invalid input or contract validation failure.
Only Shared's canonical generator emits EngineRegistration, always DRAFT.
PARTIAL and planned support never enter the generated documents. An empty
registration list is not readiness. A source revision marked dirty is local
construction evidence and must not be used as a release receipt.

Optional `--registration-export reviewed-registrations.json` compares a JSON
array of previously reviewed canonical DRAFT EngineRegistration documents.
Missing, additional, substituted or changed declarations cause exit 2. Invalid,
duplicate or foreign documents cause exit 1. These are registration documents,
not live CapabilityProvider resources; ACTIVE resources are not valid exports.
The tool does not contact CP and makes no claim about export freshness, live
drift, binding eligibility, health, certification or runtime readiness.

## Current publication dependency

At IAM main `cef8d0210f128352b2d3a264f349e5c12e646d4d`, Kratos, Hydra and
Keycloak each declare PARTIAL support. Their canonical contracts require full
interactive Authorization Code/PKCE/token handoff or registered workload token
issuance respectively. Existing credential/session and broker mechanics are
not the complete human authentication capability. Do not change PARTIAL simply
to obtain a registration document. Complete the contract, add composed tests,
and review the declaration evidence before rerunning the gate.

## Owner-approved registry convergence

After construction eligibility, CP owners must supply real provider and
engine-instance IDs, approved configuration/security-domain references, exact
artifact digest and revision, scoped runtime profiles, and governed binding
inputs. Use CP's existing registration and changeset mechanisms. Registering
DRAFT support does not authorise activation, grants, binding or certification.
Read the current authoritative CP projection and resolution before dispatch;
never substitute this offline report for CP authority or cache it as readiness.

Live acceptance additionally requires the protected CP origin/CA and provisioned
workload admission, independent maker/checker approval, real registered estate
clients and workload consumers. Supply secrets through protected deployment
configuration. Retain Keycloak permanently for enterprise federation and SSO.

## Verification of this increment

29 Python tests passed, including eight publication tests. Go `test ./...`,
federation/executable-authority race tests, vet and build passed on the current
baseline. Pinned Shared declaration, matrix and federation/resolution wire
checks passed. The strict publication gate returned exit 2 with three blocked
providers and zero registrations, as required. No live publication was run.
Docker/container scanning, live OIDC/SAML providers and PostgreSQL tests were
not run here because their executable environments are unavailable. Staging
and production acceptance remain open.
