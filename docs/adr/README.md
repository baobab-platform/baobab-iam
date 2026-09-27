# Architecture Decision Records (ADRs)

This directory contains the ADRs for Baobab IAM.

## Programme ADRs (0001–0018)

- [ADR-0001: Baobab Identity and Access Management Architecture](./ADR-0001%20—%20Baobab%20Identity%20and%20Access%20Management%20Architecture.md)
- [ADR-0002: Keycloak as the Baobab Identity Provider](./ADR-0002%20—%20Keycloak%20as%20the%20Baobab%20Identity%20Provider.md) — *superseded as IdP choice by ADR-IAM-0019; architectural constraints still apply where noted*
- [ADR-0003: Identity Authority and Trust Boundaries](./ADR-0003%20—%20Identity%20Authority%20and%20Trust%20Boundaries.md)
- [ADR-0004: Canonical Identity and External Identity Mapping](./ADR-0004%20—%20Canonical%20Identity%20and%20External%20Identity%20Mapping.md)
- [ADR-0005: Realm, Organization, Tenant and Legal-Entity Model](./ADR-0005%20—%20Realm,%20Organization,%20Tenant%20and%20Legal-Entity%20Model.md)
- [ADR-0006: OIDC, OAuth and Token Profile](./ADR-0006%20—%20OIDC,%20OAuth%20and%20Token%20Profile.md)
- [ADR-0007: Workload Identity and Service-to-Service Authentication](./ADR-0007%20—%20Workload%20Identity%20and%20Service-to-Service%20Authentication.md)
- [ADR-0008: Platform Authorization Architecture](./ADR-0008%20—%20Platform%20Authorization%20Architecture.md)
- [ADR-0009: Workforce SSO and Privileged Access](./ADR-0009%20—%20Workforce%20SSO%20and%20Privileged%20Access.md)
- [ADR-0010: Zuribeans B2B Identity and Organization Access](./ADR-0010%20—%20Zuribeans%20B2B%20Identity%20and%20Organization%20Access.md)
- [ADR-0011: Thamani B2C Customer Identity](./ADR-0011%20—%20Thamani%20B2C%20Customer%20Identity.md)
- [ADR-0012: Supplier Identity and Representative Access](./ADR-0012%20—%20Supplier%20Identity%20and%20Representative%20Access.md)
- [ADR-0013: MedusaJS Authentication Integration](./ADR-0013%20—%20MedusaJS%20Authentication%20Integration.md)
- [ADR-0014: iDempiere SSO and ERP Identity Mapping](./ADR-0014%20—%20iDempiere%20SSO%20and%20ERP%20Identity%20Mapping.md)
- [ADR-0015: Credential Security, MFA, Passkeys and Account Recovery](./ADR-0015%20—%20Credential%20Security,%20MFA,%20Passkeys%20and%20Account%20Recovery.md)
- [ADR-0016: Identity Lifecycle, Revocation and Deprovisioning](./ADR-0016%20—%20Identity%20Lifecycle,%20Revocation%20and%20Deprovisioning.md)
- [ADR-0017: IAM Audit, Security Events and Observability](./ADR-0017%20—%20IAM%20Audit,%20Security%20Events%20and%20Observability.md)
- [ADR-0018: IAM Availability, Backup, Recovery and Disaster Resilience](./ADR-0018%20—%20IAM%20Availability,%20Backup,%20Recovery%20and%20Disaster%20Resilience.md)

## Migration and successor ADRs (0019–0032)

- [ADR-IAM-0019: Migration from Keycloak to Ory and Provider-Neutral Baobab Identity Architecture](./ADR-IAM-0019%20—%20Migration%20from%20Keycloak%20to%20Ory%20and%20Provider-Neutral%20Baobab%20Identity%20Architecture.md) — **decision + M0–M19 gate plan**
- [ADR-IAM-0020: Provider-Neutral Identity Provider Contract and Adapter Architecture](./ADR-IAM-0020%20—%20Provider-Neutral%20Identity%20Provider%20Contract%20and%20Adapter%20Architecture.md) — **Gate IAM-M1**
- [ADR-IAM-0021: Ory Kratos and Hydra Deployment, Persistence and Runtime Architecture](./ADR-IAM-0021%20—%20Ory%20Kratos%20and%20Hydra%20Deployment,%20Persistence%20and%20Runtime%20Architecture.md) — **Gates IAM-M2/M3**
- [ADR-IAM-0022: Keycloak-to-Ory Identity Migration, Dual-Issuer Trust and Cutover Architecture](./ADR-IAM-0022%20—%20Keycloak-to-Ory%20Identity%20Migration,%20Dual-Issuer%20Trust%20and%20Cutover%20Architecture.md) — **Gates IAM-M5, M18, M19**
- [ADR-IAM-0023: Digital Estate Authentication UX, Browser Session and BFF Security Boundary](./ADR-IAM-0023%20—%20Digital%20Estate%20Authentication%20UX,%20Browser%20Session%20and%20BFF%20Security%20Boundary.md)
- [ADR-IAM-0024: Authentication Assurance, MFA, Passkeys, Step-Up and Risk-Based Authentication Policy](./ADR-IAM-0024%20—%20Authentication%20Assurance,%20MFA,%20Passkeys,%20Step-Up%20and%20Risk-Based%20Authentication%20Policy.md)
- [ADR-IAM-0025: Identity Proofing, Verification, Account Recovery and High-Risk Identity Rebinding](./ADR-IAM-0025%20—%20Identity%20Proofing,%20Verification,%20Account%20Recovery%20and%20High-Risk%20Identity%20Rebinding.md)
- [ADR-IAM-0026: Enterprise Federation, B2B SSO, Organization Trust and Identity Lifecycle Federation](./ADR-IAM-0026%20—%20Enterprise%20Federation,%20B2B%20SSO,%20Organization%20Trust%20and%20Identity%20Lifecycle%20Federation.md)
- [ADR-IAM-0027: IAM Multi-Region, Data Residency, Sovereignty, High Availability and Disaster-Recovery Topology](./ADR-IAM-0027%20—%20IAM%20Multi-Region,%20Data%20Residency,%20Sovereignty,%20High%20Availability%20and%20Disaster-Recovery%20Topology.md)
- [ADR-IAM-0028: IAM Cryptographic Key Management, Signing-Key Rotation, Secrets, Certificates and Trust Distribution Architecture](./ADR-IAM-0028%20—%20IAM%20Cryptographic%20Key%20Management,%20Signing-Key%20Rotation,%20Secrets,%20Certificates%20and%20Trust%20Distribution%20Architecture.md)
- [ADR-IAM-0029: IAM Security Operations, Threat Detection, Incident Response and Identity Compromise Containment Architecture](./ADR-IAM-0029%20—%20IAM%20Security%20Operations,%20Threat%20Detection,%20Incident%20Response%20and%20Identity%20Compromise%20Containment%20Architecture.md)
- [ADR-IAM-0030: Identity Privacy, Personal Information Governance, Retention, Erasure and Regulatory Compliance Architecture](./ADR-IAM-0030%20—%20Identity%20Privacy,%20Personal%20Information%20Governance,%20Retention,%20Erasure%20and%20Regulatory%20Compliance%20Architecture.md)
- [ADR-IAM-0031: IAM Administration, Delegated Administration, Privileged Access and Break-Glass Governance](./ADR-IAM-0031%20—%20IAM%20Administration,%20Delegated%20Administration,%20Privileged%20Access%20and%20Break-Glass%20Governance.md)
- [ADR-IAM-0032: IAM Production Governance, SLOs, Capacity, Compatibility, Upgrade and Operational Acceptance Architecture](./ADR-IAM-0032%20—%20IAM%20Production%20Governance,%20SLOs,%20Capacity,%20Compatibility,%20Upgrade%20and%20Operational%20Acceptance%20Architecture.md)

## Related documents

- [Consolidated Technical Specification](./Consolidated-Technical-Specification.md) — merges ADR-0001 through ADR-0018
- [Gate IAM-0 discovery](../governance/gate-iam-0-discovery.md) — Keycloak-era verified state
- [Gate IAM-M0 migration baseline](../governance/gate-iam-m0-migration-baseline.md) — inventory, classification, freeze list
- [Gate IAM-M0 ADR matrix](../governance/gate-iam-m0-adr-matrix.md) — ADR → M-gate mapping
- [Gate IAM-M1 provider-neutral contracts scope](../governance/gate-iam-m1-provider-neutral-contracts-scope.md)
- [Gate IAM-M1 evidence checklist](../governance/gate-iam-m1-evidence-checklist.md)
- [Gate IAM-M2/M3 Ory foundation scope](../governance/gate-iam-m2-m3-ory-foundation-scope.md)
- [Gate IAM-M4 workload Hydra scope](../governance/gate-iam-m4-workload-hydra-scope.md)
- [Gate IAM-M4 client inventory](../governance/gate-iam-m4-client-inventory.md)
- [Gate IAM-M5 migration ledger scope](../governance/gate-iam-m5-migration-ledger-scope.md)
- [Ory foundation smoke](../operations/ory-foundation-smoke.md)
- [Migration rollback baseline](../operations/migration-rollback-baseline.md)
