# ADR-IAM-0028 — IAM Cryptographic Key Management, Signing-Key Rotation, Secrets, Certificates and Trust Distribution Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture / Infrastructure  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold and all future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0027  
**Extends:** ADR-IAM-0006, 0007, 0015, 0017, 0018, 0019–0027  
**Decision Type:** Cryptographic Trust / Key Management / Secrets / Certificates / Rotation / Recovery  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Trust Boundary:** Baobab IAM + Infrastructure

---

# 1. Decision

Baobab SHALL operate IAM cryptographic material under a formally governed **Cryptographic Trust Architecture**.

Cryptographic material SHALL be classified by purpose and SHALL NOT be treated as a single generic category called "secrets."

At minimum Baobab SHALL distinguish:

```text
1. TOKEN SIGNING KEYS
   OAuth/OIDC signing trust

2. APPLICATION ENCRYPTION / INTEGRITY SECRETS
   Provider/session/cookie/encryption secrets

3. WORKLOAD CREDENTIALS
   OAuth client secrets, private keys, mTLS identities

4. TRANSPORT CERTIFICATES
   TLS and mTLS certificates

5. FEDERATION TRUST MATERIAL
   SAML signing/encryption certificates,
   external OIDC trust configuration

6. DATABASE CREDENTIALS
   PostgreSQL authentication material

7. RECOVERY / BACKUP CRYPTOGRAPHIC MATERIAL
   keys required to recover encrypted Tier-0 state

8. BOOTSTRAP CREDENTIALS
   temporary credentials used to establish the platform
```

Each class SHALL have explicit:

```text
owner
purpose
storage
distribution
access policy
rotation mechanism
revocation mechanism
recovery policy
residency policy
audit policy
compromise procedure
```

The fundamental rule is:

> **A cryptographic secret SHALL have one defined purpose, one controlled authority, the smallest practical distribution scope, and a tested path to rotation and revocation.**

---

# 2. Core Security Principle

Baobab SHALL separate:

```text
IDENTITY
   ≠
KEY

KEY
   ≠
SECRET

SECRET
   ≠
CERTIFICATE

CERTIFICATE
   ≠
TRUST POLICY

POSSESSION
   ≠
AUTHORIZATION
```

A key proves only what its associated protocol and trust policy allow it to prove.

---

# 3. Cryptography Does Not Define Business Authority

Possession of a valid:

```text
JWT
certificate
OAuth client secret
private key
SAML assertion
session cookie
```

does not itself establish:

```text
Tenant
LegalEntity
Market
BuyerOrganization
SupplierOrganization
purchase authority
shipment authority
ERP authority
platform administration
```

Those remain governed by CP and domain authorization.

---

# 4. Trust Architecture

```text
                  ┌─────────────────────┐
                  │ TRUST GOVERNANCE    │
                  │                     │
                  │ policy              │
                  │ algorithms          │
                  │ rotation            │
                  │ compromise response │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ SECRET / KEY        │
                  │ MANAGEMENT SYSTEM   │
                  │                     │
                  │ KMS / HSM /         │
                  │ Secret Manager      │
                  └──────────┬──────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Signing Keys     App Secrets    Certificates
              │              │              │
              ▼              ▼              ▼
           Hydra           Kratos        TLS / mTLS
              │
              ▼
             JWKS
              │
              ▼
       Resource Servers
              │
              ▼
       CP + Domain AuthZ
```

---

# 5. Secrets SHALL NOT Be Stored in Git

Private cryptographic material SHALL NOT be committed to:

```text
Git repositories
Dockerfiles
container images
Helm values
Terraform state in plaintext
GitHub Actions YAML
DevContainer configuration
documentation
test fixtures
```

---

# 6. Public Material May Be Version Controlled

Public material MAY be committed where appropriate, including:

```text
public certificates
public JWKs
CA certificates
certificate fingerprints
non-secret trust metadata
```

provided its purpose is clear.

---

# 7. Secret Manager

Production cryptographic secrets SHALL be stored in an approved secrets-management or key-management system.

The underlying implementation MAY be:

```text
cloud KMS
managed secret manager
Vault-compatible service
HSM-backed KMS
other approved equivalent
```

The architecture SHALL NOT depend unnecessarily on one vendor's secret representation.

---

# 8. KMS vs Secret Manager

Baobab SHALL distinguish:

```text
Secret Manager
    │
    ▼
stores/distributes secret material

KMS/HSM
    │
    ▼
performs/protects cryptographic key operations
```

Where practical, high-value private keys SHOULD be non-exportable and protected by KMS/HSM-backed operations.

---

# 9. Key Hierarchy

Baobab SHOULD avoid a single root secret from which every IAM credential is derived.

Conceptually:

```text
Trust Governance
│
├── OIDC Signing Keys
├── Kratos Secrets
├── Hydra Secrets
├── Federation Keys
├── TLS PKI
├── Workload Credentials
├── Database Credentials
└── Recovery Keys
```

Compromise of one branch SHOULD NOT automatically compromise the others.

---

# 10. Environment Isolation

Cryptographic material SHALL be isolated by environment:

```text
development
integration
staging
production
```

A production private key SHALL never be used in non-production.

---

# 11. Regional Isolation

Where ADR-IAM-0027 defines distinct IdentitySecurityDomains, keys SHALL also respect those boundaries.

```text
IAM Domain A
   │
   └── Key Set A

IAM Domain B
   │
   └── Key Set B
```

unless a deliberate trust architecture requires otherwise.

---

# 12. Key Identity

Every managed key SHALL have a stable internal identifier independent of human-readable labels.

Conceptually:

```text
CryptographicKey
├── key_id
├── purpose
├── algorithm
├── environment
├── security_domain
├── status
├── created_at
├── activated_at
├── rotate_after
├── expires_at
├── compromised_at
└── retired_at
```

---

# 13. Key Lifecycle

```text
GENERATED
    │
    ▼
STAGED
    │
    ▼
ACTIVE
    │
    ▼
ROTATING
    │
    ▼
VERIFY_ONLY
    │
    ▼
RETIRED
    │
    ▼
DESTROYED
```

Exceptional state:

```text
COMPROMISED
```

---

# 14. Secret Lifecycle

Secrets SHALL similarly support:

```text
GENERATED
ACTIVE
ROTATING
REVOKED
RETIRED
DESTROYED
```

---

# 15. Rotation Is a First-Class Operation

Baobab SHALL assume that every long-lived cryptographic credential will eventually require rotation because of:

```text
routine hygiene
staff change
policy
certificate expiry
provider migration
suspected compromise
algorithm migration
regional migration
customer offboarding
incident response
```

Rotation SHALL therefore be designed before production.

---

# 16. Rotation Is Not Redeployment

A key SHALL be rotatable without requiring architectural reconstruction.

Applications SHOULD obtain secrets through runtime-supported secret delivery rather than hard-coded build-time values.

---

# 17. OIDC/OAuth Signing Keys

Hydra's token-signing trust SHALL be treated as Tier-0 cryptographic infrastructure.

Private signing keys SHALL be available only to the components that actually require signing authority.

---

# 18. Public Verification

Resource servers SHALL verify tokens using public trust material.

They SHALL NOT require possession of signing private keys.

```text
Hydra
 │
 │ private signing key
 ▼
JWT
 │
 ▼
Resource Server
 │
 │ public JWK
 ▼
Verify
```

---

# 19. Private Signing Key Distribution

The private signing key SHALL NOT be distributed to:

```text
baobab-cp
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
ZuriBeans
Thamani
Nabhold
browser applications
```

They need verification capability, not signing authority.

---

# 20. JWKS

Public verification keys SHALL be distributed through standards-compatible JWKS/discovery mechanisms.

RFC 7517 defines a JWK Set as a collection of public JSON Web Keys and defines `kid` specifically to distinguish keys, including during rollover.

---

# 21. Distinct Key IDs

Concurrent keys in a JWKS SHOULD have distinct:

```text
kid
```

values.

Consumers SHALL use `kid` only within the configured trusted issuer/key-set relationship.

---

# 22. Never Trust Arbitrary Key URLs

A resource server SHALL NOT blindly trust a token-supplied:

```text
jku
x5u
```

or arbitrary key location.

RFC 8725 specifically warns that blindly following token-supplied key URLs can introduce SSRF and trust-substitution vulnerabilities.

---

# 23. Trusted Issuer Registry

The existing provider-neutral trusted issuer architecture SHALL determine:

```text
issuer
discovery URL
JWKS URL
accepted algorithms
audiences
status
environment
security domain
migration expiry
```

---

# 24. Algorithm Pinning

Token validators SHALL explicitly configure acceptable algorithms.

They SHALL NOT accept whatever algorithm appears in the JWT header.

RFC 8725 requires callers to specify supported algorithms and verify that the algorithm used is acceptable.

---

# 25. Algorithm Confusion Prevention

Validators SHALL reject:

```text
unexpected algorithms
algorithm/key-type mismatch
unsigned tokens
unapproved symmetric algorithms
invalid issuer/key relationships
```

---

# 26. Signing-Key Rotation

Normal signing-key rotation SHALL follow:

```text
Generate K2
     │
     ▼
Publish K2 public key
     │
     ▼
verification systems observe K2
     │
     ▼
begin signing with K2
     │
     ├─────────────┐
     │             │
     ▼             ▼
K2 tokens      K1 tokens
valid          still valid
     │             │
     └──────┬──────┘
            ▼
     overlap period
            │
            ▼
maximum K1 token lifetime expires
            │
            ▼
retire K1 verification key
```

---

# 27. Rotation Overlap

Old verification keys SHALL remain available long enough to validate legitimate unexpired tokens issued before rotation.

---

# 28. Signing Rotation Invariant

```text
new signing key active
```

SHALL occur only after:

```text
new verification key safely distributed
```

---

# 29. Old-Key Retirement

An old signing key SHALL not disappear from JWKS merely because a new signing key exists.

Retirement SHALL account for:

```text
maximum access-token lifetime
ID-token use
cache lifetime
clock skew
deployment propagation
```

---

# 30. Key Rotation Test

Every production signing-key rotation SHALL test:

```text
old token + old key → valid until expiry

new token + new key → valid

tampered token → invalid

new token + unknown key → safe failure

old token after legitimate expiry → invalid
```

---

# 31. Emergency Signing-Key Rotation

Compromise is different from routine rotation.

If K1 is suspected compromised:

```text
K1 → COMPROMISED
```

Baobab MAY need to invalidate K1 immediately even if some legitimate tokens remain unexpired.

---

# 32. Security Over Session Continuity

During signing-key compromise:

```text
security
>
preserving existing token sessions
```

---

# 33. Emergency Rotation Flow

```text
suspected key compromise
        │
        ▼
incident declared
        │
        ▼
K1 marked compromised
        │
        ▼
K2 activated
        │
        ▼
trust/JWKS updated
        │
        ▼
K1 verification removed where required
        │
        ▼
sessions/tokens reassessed
        │
        ▼
clients reauthenticate
        │
        ▼
forensics + reconciliation
```

---

# 34. Signing-Key Compromise Blast Radius

The incident process SHALL identify:

```text
issuers affected
audiences affected
token types affected
regions affected
time window
downstream consumers
```

before declaring recovery complete.

---

# 35. Signing Keys and DR

ADR-IAM-0027 requires a DR region to recover valid issuer semantics.

Therefore required signing trust SHALL be recoverable securely in the promoted region.

---

# 36. DR Key Availability

A DR region SHALL NOT be declared IAM-ready unless it can:

```text
sign valid new tokens
publish correct JWKS
validate existing trust relationships
rotate compromised keys
```

---

# 37. Key Replication

Private signing-key replication across regions SHALL occur only through an approved secure key-management/recovery mechanism.

Do not replicate private keys through:

```text
Git
ordinary object storage
database rows
container images
manual SCP
```

---

# 38. Non-Exportable Keys

Where supported and operationally appropriate, production signing keys SHOULD be non-exportable.

If provider/runtime constraints require exportable material, additional access and recovery controls SHALL apply.

---

# 39. Key Backup

A private key backup is itself Tier-0 secret material.

Backup protection SHALL be at least equivalent to active-key protection.

---

# 40. Recovery Escrow

If recovery requires escrowed key material:

```text
RecoveryKeyRecord
├── key reference
├── encrypted material/reference
├── security domain
├── recovery authorization
├── integrity metadata
└── recovery test status
```

SHALL be governed separately from routine runtime access.

---

# 41. Kratos Application Secrets

Kratos secrets used for:

```text
cookies
session integrity
encryption
provider internals
```

SHALL be treated as application cryptographic secrets rather than OAuth signing keys.

They SHALL have separate lifecycle and rotation procedures.

---

# 42. Hydra Application Secrets

Hydra internal/system secrets SHALL likewise be separate from OAuth client credentials and signing keys.

---

# 43. No Secret Reuse Between Kratos and Hydra

Prohibited:

```text
KRATOS_SECRET == HYDRA_SECRET
```

---

# 44. No Cross-Environment Secret Reuse

Prohibited:

```text
STAGING_SECRET == PRODUCTION_SECRET
```

---

# 45. No Cross-Region Reuse by Accident

Where a secret must be shared across DR regions to preserve a logical security domain, that SHALL be deliberate and documented.

Otherwise secrets remain region/security-domain scoped.

---

# 46. Secret Rotation Compatibility

Before rotating an application encryption/integrity secret, Baobab SHALL determine whether the underlying runtime supports:

```text
multiple simultaneous secrets
graceful decryption with old key
session invalidation
re-encryption
```

Rotation procedures SHALL follow actual provider semantics.

---

# 47. Never Guess Secret Rotation Semantics

If the current pinned Ory version does not support safe online rotation for a particular secret:

```text
controlled session invalidation
or maintenance procedure
```

is preferable to inventing unsupported behavior.

---

# 48. OAuth Client Secrets

OAuth confidential-client secrets SHALL be unique per logical client.

Prohibited:

```text
one client secret
shared by Trade + ERP + CMS
```

---

# 49. Workload Isolation

Each independently revocable workload SHALL have its own credential.

```text
Trade API
   │
   └── Credential A

ERP Integration
   │
   └── Credential B

Pulse
   │
   └── Credential C
```

---

# 50. Shared Secret Prohibition

Two unrelated workloads SHALL NOT share a credential merely because they belong to the same repository, tenant or Kubernetes namespace.

---

# 51. Prefer Asymmetric Workload Credentials

Where Hydra/client capabilities permit and operational maturity supports it, Baobab SHOULD prefer:

```text
private_key_jwt
mTLS-bound client authentication
```

over widely distributed static client secrets for higher-value workloads.

---

# 52. Client Secret Rotation

Where secrets remain necessary:

```text
create S2
    │
    ▼
deploy S2
    │
    ▼
verify S2
    │
    ▼
revoke S1
```

SHALL be preferred over destructive replacement that creates avoidable downtime.

---

# 53. Workload Credential Lifetime

Long-lived credentials SHOULD have:

```text
rotation schedule
owner
last-rotated timestamp
next-rotation deadline
```

---

# 54. Workload Revocation

Revoking a workload in Baobab SHALL ultimately disable the provider credential as established by ADR-IAM-0007 and ADR-IAM-0020.

---

# 55. CI Credentials Are Not Runtime Credentials

```text
GitHub Actions identity
       ≠
production workload identity
```

A deployment workflow SHALL not hand its own long-lived credentials to the deployed service.

---

# 56. GitHub Actions

CI/CD SHOULD use short-lived workload federation/OIDC to cloud infrastructure where supported rather than persistent cloud access keys.

---

# 57. GitHub Repository Secrets

Repository/organization secrets MAY bootstrap CI integrations where unavoidable.

They SHALL NOT become the general production secrets store.

---

# 58. Build-Time Secrets

Production runtime secrets SHALL not be baked into:

```text
Docker layers
compiled frontend bundles
Next.js public environment
SBOM artifacts
package archives
```

---

# 59. Browser Boundary

No confidential client secret or private platform key SHALL be delivered to a browser.

---

# 60. BFF Boundary

ADR-IAM-0023's BFF SHALL keep confidential OAuth credentials and server-side session material outside browser-accessible JavaScript.

---

# 61. TLS Certificates

TLS certificates establish transport/server identity.

They SHALL NOT be treated as business identity.

---

# 62. Public TLS

Internet-facing identity endpoints SHALL use valid certificates from an approved trust chain.

---

# 63. Internal TLS

Tier-0 internal connections SHOULD use authenticated encrypted transport appropriate to the infrastructure.

---

# 64. mTLS

mTLS MAY establish workload identity evidence for:

```text
service-to-service
database client authentication
privileged administration
internal control-plane operations
```

where appropriate.

---

# 65. mTLS Is Not Business Authorization

```text
valid service certificate
        ≠
permission to access any tenant
```

CP/domain authorization still applies.

---

# 66. Certificate Lifecycle

Certificates SHALL have:

```text
issuer
subject/SAN
purpose
owner
not_before
not_after
renewal policy
revocation policy
```

---

# 67. Certificate Renewal

Renewal SHALL begin sufficiently before expiry to permit:

```text
issuance failure
deployment propagation
validation
rollback
```

---

# 68. Certificate Expiry Monitoring

Production SHALL alert on approaching expiry.

No Tier-0 certificate should first become operationally visible because it expired.

---

# 69. Automatic Renewal

Where mature automation exists, short-lived automatically renewed certificates SHOULD be preferred over manually managed long-lived certificates.

---

# 70. Certificate Revocation

Compromised certificates SHALL be revoked/replaced according to the governing PKI.

---

# 71. Trust Store Governance

Trusted CA bundles SHALL be governed configuration.

Applications SHALL not trust arbitrary CAs merely because the operating system happens to contain them when a narrower trust model is required.

---

# 72. PostgreSQL TLS

Connections carrying IAM persistence SHALL use encrypted transport.

PostgreSQL 17 supports TLS for client/server communications and allows clients to verify the server certificate.

---

# 73. PostgreSQL Server Verification

Production PostgreSQL clients SHOULD use:

```text
sslmode=verify-full
```

or an equivalent mechanism providing server certificate and hostname verification.

PostgreSQL explicitly recommends `verify-ca` or `verify-full` when server identity needs to be authenticated and notes that merely enabling SSL does not itself ensure server verification.

---

# 74. PostgreSQL Client Certificates

Where architecture chooses certificate-based PostgreSQL client authentication, PostgreSQL 17 can require a trusted client certificate and can map certificate identity to database users.

---

# 75. Database Credentials

Kratos and Hydra SHALL retain distinct PostgreSQL identities.

```text
Kratos
   │
   └── kratos_db_role

Hydra
   │
   └── hydra_db_role
```

---

# 76. Database Least Privilege

Runtime database roles SHALL not automatically possess:

```text
superuser
database creation
role creation
unrelated database access
```

---

# 77. Migration Credentials

Database schema migrations MAY use a distinct elevated migration identity.

Runtime services SHOULD not retain migration privileges where unnecessary.

---

# 78. PostgreSQL Passwords

If PostgreSQL password authentication is used, SCRAM-SHA-256 SHALL be preferred.

PostgreSQL 17 uses `scram-sha-256` as the default password-encryption setting and describes SCRAM as preferable to the older PostgreSQL-specific MD5 mechanism.

---

# 79. Federation Certificates

SAML federation introduces distinct signing/encryption certificates.

These SHALL remain scoped to the federation trust they serve.

---

# 80. Federation Certificate != Platform Signing Key

Prohibited conceptual reuse:

```text
Hydra JWT Signing Key
        =
ACME SAML Signing Key
```

---

# 81. Customer Federation Trust

For inbound enterprise federation:

```text
Customer IdP
     │
     │ signs assertion
     ▼
Baobab validates
```

Baobab stores the required public trust material, not the customer's private signing key.

---

# 82. Federation Certificate Rotation

Enterprise federation SHALL support controlled overlapping certificates where protocol/provider capabilities permit.

```text
Old certificate
      +
New certificate
```

may coexist during rotation.

---

# 83. Metadata Is Not Automatically Trusted

New SAML metadata SHALL not automatically replace trusted certificates without controlled validation.

---

# 84. Federation Compromise

If an enterprise federation signing key is compromised:

```text
FederationTrust → SUSPENDED
```

MAY be required until replacement trust is established.

---

# 85. Federation Blast Radius

Compromise of ACME's federation key SHALL NOT compromise:

```text
ZuriBeans signing keys
Thamani identities
another customer's federation
Baobab workforce
Hydra signing authority
```

---

# 86. OIDC Federation

External OIDC federation SHALL validate:

```text
issuer
signature
audience
subject
approved algorithms
trusted discovery/JWKS location
```

---

# 87. External JWKS Caching

External federation keys MAY be cached.

Caching policy SHALL balance:

```text
availability
rotation responsiveness
compromise responsiveness
```

---

# 88. Unknown External Key

If an external IdP begins signing with an unknown key:

```text
refresh trusted JWKS
```

MAY be attempted according to safe policy.

If trust cannot be established:

```text
reject
```

---

# 89. Trust Distribution

Baobab SHALL distribute trust, not private signing authority.

```text
PRIVATE KEY
    │
    ▼
Signer only

PUBLIC KEY
    │
    ├── CP
    ├── Trade
    ├── ERP integration
    ├── CMS
    ├── Pulse
    └── other resource servers
```

---

# 90. Trust Distribution Registry

Conceptually:

```text
TrustAnchor
├── id
├── type
├── issuer
├── key_id
├── algorithm
├── environment
├── security_domain
├── status
├── valid_from
├── valid_until
└── source
```

---

# 91. Trust Anchor State

```text
STAGED
ACTIVE
VERIFY_ONLY
REVOKED
EXPIRED
COMPROMISED
```

---

# 92. Trust Is Not Forever

Every trust relationship SHALL have an owner and lifecycle.

---

# 93. No Global Trust Bucket

Baobab SHALL NOT maintain one undifferentiated directory of "trusted certificates" used for every purpose.

---

# 94. Purpose Binding

Trust SHALL be bound to purpose.

Example:

```text
Key K1
purpose = OIDC_TOKEN_SIGNING
issuer = identity.baobab...
environment = production
```

K1 SHALL not automatically be accepted for another purpose.

---

# 95. Environment Binding

A staging signing key SHALL never validate a production token.

---

# 96. Issuer Binding

A key trusted for Issuer A SHALL not automatically validate tokens claiming Issuer B.

RFC 8725 explicitly requires validation that the cryptographic keys used for JWT validation belong to the issuer.

---

# 97. Audience Binding

Correct signature does not remove audience validation.

```text
signature valid
+
wrong audience
=
reject
```

---

# 98. Token-Type Confusion

Where relevant, Baobab SHOULD use explicit token typing and mutually exclusive validation rules to reduce token substitution/confusion risks.

RFC 8725 recommends explicit typing and distinct validation rules where different JWT kinds could otherwise be confused.

---

# 99. Secrets Delivery

Production workloads SHOULD receive secrets through mechanisms such as:

```text
secret-manager API
CSI/secret-store integration
workload identity
memory/file injection with strict permissions
```

depending on platform capabilities.

---

# 100. Environment Variables

Environment variables MAY be used as an application delivery mechanism when operationally justified.

They SHALL NOT be assumed inherently secure merely because they are environment variables.

---

# 101. Secret Files

Mounted secret files SHALL have:

```text
minimal filesystem permissions
appropriate ownership
ephemeral lifecycle where possible
```

---

# 102. Secret Reload

Where supported, applications SHOULD reload rotated secrets without unnecessary downtime.

---

# 103. Secret Caching

Applications SHALL not indefinitely cache credentials beyond their intended rotation lifecycle.

---

# 104. Secret Logging

Secrets SHALL never appear in:

```text
application logs
trace attributes
metrics labels
panic dumps
HTTP error responses
audit event payloads
CI logs
```

---

# 105. Token Logging

Bearer tokens SHALL not be logged.

Where correlation is needed, use safe identifiers rather than raw credentials.

---

# 106. Private-Key Logging

Private key material SHALL never be logged.

---

# 107. Secret Redaction

Structured logging SHALL include secret-redaction controls.

Security tests SHALL verify them.

---

# 108. Metrics Cardinality

Key IDs MAY appear in controlled security metrics where useful.

Sensitive subject IDs or raw secrets SHALL not become high-cardinality metric labels.

---

# 109. Access to Secret Management

Access SHALL be workload/person specific.

Avoid:

```text
all platform services
can read all IAM secrets
```

---

# 110. Least Privilege Example

```text
Hydra workload
   │
   └── Hydra secrets/signing access

Kratos workload
   │
   └── Kratos secrets

Trade
   │
   └── Trade OAuth credential

ERP integration
   │
   └── ERP OAuth credential
```

---

# 111. Human Secret Access

Routine developers SHOULD NOT need direct access to production secret values.

---

# 112. Break-Glass Secret Access

Exceptional human access SHALL require:

```text
strong authentication
authorization
reason
time-bound access
audit
post-event review
```

---

# 113. Four-Eyes Control

Highly sensitive operations SHOULD support dual control where operationally feasible, including:

```text
root signing-key recovery
destructive key revocation
DR cryptographic recovery
CA/root trust modification
```

---

# 114. Key Generation

Production keys SHALL be generated using cryptographically secure approved mechanisms.

Human-chosen secrets SHALL not be used for cryptographic signing keys.

---

# 115. Secret Generation

Machine secrets SHALL have sufficient entropy and SHALL not use:

```text
company names
repository names
predictable templates
dates
reused passwords
```

---

# 116. Key Algorithms

Algorithms SHALL be selected according to:

```text
protocol requirements
current security guidance
runtime support
interoperability
operational capability
```

rather than personal preference.

---

# 117. Algorithm Agility

Baobab SHALL design trust metadata so algorithms can evolve without redesigning CanonicalIdentity or domain authorization.

---

# 118. No Algorithm in Domain Model

Trade SHALL not care whether IAM signs using:

```text
RSA
ECDSA
EdDSA
```

except through its standard token-validation configuration.

---

# 119. Cryptographic Inventory

Baobab SHALL maintain an inventory of production cryptographic material.

At minimum:

```text
identifier
purpose
owner
location/reference
environment
security domain
algorithm/type
status
creation
rotation deadline
expiry
dependents
```

---

# 120. No Secret Values in Inventory

Inventory records references and metadata.

It SHALL not become another plaintext secret store.

---

# 121. Dependency Graph

Baobab SHOULD be able to answer:

```text
If key K17 is revoked,
what breaks?
```

before revoking it.

---

# 122. Cryptographic Dependency Example

```text
Hydra Signing Key K17
       │
       ├── JWKS
       ├── CP validation
       ├── Trade validation
       ├── ERP integration
       └── CMS validation
```

---

# 123. Rotation Calendar

Routine rotation SHALL be automated or scheduled according to risk.

Not every credential requires the same lifetime.

---

# 124. Short-Lived Credentials

Where practical, prefer short-lived dynamically issued credentials over manually rotated long-lived secrets.

---

# 125. Dynamic Workload Identity

The strategic direction SHOULD be:

```text
workload identity
      │
      ▼
short-lived credential
```

rather than:

```text
service
      │
      ▼
five-year static secret
```

---

# 126. Development Secrets

Development MAY use local generated secrets.

They SHALL be:

```text
non-production
replaceable
clearly documented
safe to destroy
```

---

# 127. DevContainer

DevContainer configurations SHALL bootstrap local secret placeholders/generated development credentials without embedding production values.

---

# 128. Codespaces

Codespaces secrets SHALL be environment-scoped and SHALL not expose production secrets to arbitrary development environments.

---

# 129. CI Secret Scanning

CI SHALL detect accidental secret commits.

At minimum production repositories SHOULD include:

```text
secret scanning
dependency scanning
SBOM
container scanning
```

consistent with existing Baobab CI architecture.

---

# 130. Historical Secret Exposure

Removing a secret from the latest Git commit is not sufficient if it previously entered Git history.

Any exposed credential SHALL be treated as compromised and rotated.

---

# 131. Secret Compromise State Machine

```text
SUSPECTED
    │
    ▼
CONTAINING
    │
    ▼
ROTATING
    │
    ▼
REVOKED
    │
    ▼
RECONCILING
    │
    ▼
RECOVERED
```

---

# 132. Compromise Response

For each compromised credential determine:

```text
what could it authenticate?
what could it decrypt?
what could it sign?
where was it accepted?
when was it exposed?
what logs/events require review?
what dependent credentials must rotate?
```

---

# 133. Do Not Rotate Blindly

A secret incident SHALL not trigger indiscriminate platform-wide key replacement unless blast-radius analysis requires it.

Unnecessary simultaneous rotation can itself create an outage.

---

# 134. Signing-Key Incident

If signing authority is compromised, assume an attacker MAY have forged tokens within the compromise window.

Therefore investigate downstream authorization/audit events, not merely rotate the key.

---

# 135. Client Secret Incident

Compromised workload client secret:

```text
disable/revoke client credential
        │
        ▼
rotate
        │
        ▼
review token issuance
        │
        ▼
review workload activity
```

---

# 136. TLS Private-Key Incident

Compromised TLS private key requires:

```text
certificate replacement
revocation where applicable
traffic/security investigation
trust update
```

---

# 137. Federation-Key Incident

Compromise of an external customer's federation key SHOULD normally be contained to that federation trust.

---

# 138. Database Credential Incident

Compromised DB credentials require:

```text
rotate DB credential
review database access
verify data integrity
review lateral access
```

---

# 139. Recovery Material Incident

Compromise of backup/recovery cryptographic material is a Tier-0 security incident.

---

# 140. DR and Secret Recovery

ADR-IAM-0027 DR exercises SHALL include cryptographic recovery.

A DR environment that has database state but cannot securely restore signing/encryption trust is not operational.

---

# 141. Recovery Order

Conceptually:

```text
Infrastructure
      │
      ▼
Secret/KMS trust
      │
      ▼
Database
      │
      ▼
Kratos/Hydra cryptographic state
      │
      ▼
issuer/JWKS
      │
      ▼
baobab-iam
      │
      ▼
CP reconciliation
      │
      ▼
domain verification
```

---

# 142. Key Recovery Validation

After DR:

```text
old legitimate token → expected result
new token → validates
revoked key → rejected
wrong issuer → rejected
wrong audience → rejected
```

---

# 143. Region Failover

Failover SHALL NOT silently substitute a different untrusted signing key under the same issuer without controlled trust transition.

---

# 144. Regional Key Rotation

When a logical issuer spans primary/DR runtime:

```text
key lifecycle
```

belongs to the IdentitySecurityDomain, not to an individual Kubernetes pod.

---

# 145. No Pod-Local Trust Authority

A pod restart SHALL not generate an unrelated production signing identity unless explicitly part of the provider's supported coordinated key mechanism.

---

# 146. Backup Encryption

Backups containing IAM data SHALL be encrypted.

Backup encryption keys SHALL be separated from the backup objects sufficiently to prevent one compromised storage credential from trivially exposing both.

---

# 147. Recovery Independence

Baobab SHALL avoid a circular disaster dependency such as:

```text
Need IAM to unlock KMS
but
Need KMS to start IAM
```

A controlled bootstrap/recovery path SHALL exist.

---

# 148. Bootstrap Secrets

Bootstrap credentials SHALL be:

```text
minimal
time-bound where possible
rotated after bootstrap
not used for routine runtime
audited
```

---

# 149. Bootstrap Completion

Production readiness SHALL verify that temporary installation/bootstrap credentials have been disabled or rotated.

---

# 150. Root Trust

Root trust material requires the strongest governance.

Changes SHALL be rare, deliberate and auditable.

---

# 151. Root CA vs Application Keys

Baobab SHALL not use a platform root CA private key as an application signing key.

---

# 152. PKI Separation

Where practical, separate:

```text
public edge TLS PKI
internal workload PKI
database client PKI
federation certificates
OAuth signing keys
```

---

# 153. Certificate Identity

Certificate SAN/subject naming SHALL use controlled naming conventions.

---

# 154. DNS Dependency

TLS certificate trust depends partly on stable DNS identity.

DNS administration for IAM endpoints SHALL therefore be treated as security-sensitive.

---

# 155. DNS Compromise

A compromised DNS control plane can undermine authentication routing even when keys remain secure.

DNS change authority SHALL therefore be restricted and audited.

---

# 156. JWKS Cache

Consumers SHALL cache JWKS safely to tolerate short IAM/network interruptions.

---

# 157. JWKS Cache Expiry

Caching SHALL not be effectively permanent.

Consumers must eventually discover:

```text
new keys
retired keys
compromised-key removal
```

---

# 158. Refresh on Unknown kid

A validator MAY perform a controlled JWKS refresh when encountering an unknown `kid`.

It SHALL NOT repeatedly hammer the issuer for attacker-generated random `kid` values.

---

# 159. JWKS Refresh Protection

Implement:

```text
rate limiting
cache
backoff
trusted URL pinning
```

for refresh behavior.

---

# 160. Key-Rollover Availability

During normal rollover:

```text
old key + new key
```

SHALL coexist in verification trust long enough for safe transition.

---

# 161. Emergency Rollover Availability

During compromise, overlap MAY intentionally be shortened or eliminated.

---

# 162. Token Lifetimes Matter

Short access-token lifetimes reduce the operational burden of normal signing-key retirement and compromise containment.

This reinforces ADR-IAM-0006.

---

# 163. Refresh Tokens

Refresh-token security SHALL be governed by provider-supported mechanisms and ADR-IAM-0023 session architecture.

They SHALL not be treated as ordinary bearer API keys.

---

# 164. Session Cookies

Session cookies SHALL use:

```text
Secure
HttpOnly
appropriate SameSite
appropriate Domain/Path
```

as established by ADR-IAM-0023.

Their cryptographic secrets belong to this ADR's application-secret lifecycle.

---

# 165. Passkeys

Passkey private keys belong to users/authenticators.

Baobab SHALL never attempt to centralize users' private passkey keys.

---

# 166. Passkey Server State

Server-side WebAuthn credential public keys and metadata SHALL remain protected identity data but are not secret private keys.

---

# 167. TOTP

TOTP seed material is secret credential material.

It SHALL receive protections appropriate to credential secrets.

---

# 168. Passwords

Baobab SHALL never store plaintext passwords.

Password credential mechanics remain the responsibility of the selected identity runtime.

---

# 169. Recovery Codes

Recovery codes SHALL be treated as authentication credentials, not ordinary profile attributes.

---

# 170. Audit Signing

If Baobab later cryptographically signs security audit records, audit-signing keys SHALL be separate from OAuth token-signing keys.

---

# 171. Event Signing

Likewise, event-signing keys—if adopted—SHALL have distinct purpose and lifecycle.

---

# 172. Encryption Keys

Keys used to encrypt:

```text
proofing evidence
sensitive stored secrets
backup archives
```

SHALL be distinct from token-signing keys.

---

# 173. Envelope Encryption

Where supported, sensitive stored material SHOULD use envelope encryption:

```text
Data
 │
 ▼
Data Encryption Key
 │
 ▼
encrypted by
Key Encryption Key
 │
 ▼
KMS/HSM
```

---

# 174. Data-Key Rotation

Encryption-key rotation SHALL distinguish:

```text
new writes use new key
```

from:

```text
historical data re-encryption
```

These need not always occur simultaneously.

---

# 175. Crypto-Shredding

Where legally and operationally appropriate, destruction of encryption keys MAY form part of secure data-destruction architecture.

It SHALL not be used without considering backups, legal retention and audit obligations.

---

# 176. Residency

Cryptographic material SHALL follow ADR-IAM-0027 residency policy where applicable.

A key that decrypts residency-controlled data may itself be residency-sensitive.

---

# 177. Cross-Border Key Access

Cross-border administrative access to cryptographic material SHALL be explicitly considered in sovereignty analysis.

---

# 178. Customer-Managed Keys

Future enterprise customers MAY require customer-managed encryption keys.

This is not part of the initial baseline.

Any such capability requires explicit architecture because customer-controlled key revocation affects service availability and data recovery.

---

# 179. Bring Your Own Key

BYOK/HYOK SHALL not be advertised until operational consequences are implemented and tested.

---

# 180. Cryptographic Policy Registry

Baobab SHOULD maintain a versioned policy defining:

```text
approved algorithms
minimum key sizes
certificate lifetimes
rotation requirements
secret entropy
TLS minimums
deprecated algorithms
exceptions
```

---

# 181. Policy Is Configuration

Cryptographic policy SHOULD be machine-testable where possible.

---

# 182. CI Policy Enforcement

CI SHOULD detect:

```text
weak TLS settings
unapproved algorithms
hard-coded secrets
private keys
expired certificates
wildcard trust
production secrets in fixtures
```

---

# 183. Runtime Policy Enforcement

Startup validation SHOULD fail when critical configuration violates mandatory cryptographic policy.

---

# 184. Exception Process

Any exception SHALL specify:

```text
reason
risk
owner
compensating controls
expiry
remediation
```

---

# 185. Observability

Security observability SHOULD include:

```text
key age
key status
certificate expiry
secret rotation age
failed JWKS refresh
unknown kid rate
signature-validation failures
issuer mismatch
algorithm mismatch
secret-access anomalies
KMS failures
certificate renewal failures
```

---

# 186. Alerting

Urgent alerts SHALL exist for:

```text
signing key compromise
unexpected signing key change
certificate expiry threshold
secret-manager outage
KMS access anomaly
private-key access anomaly
JWKS mismatch
federation certificate failure
```

---

# 187. Avoid Secret-Based Metrics

Never expose:

```text
secret value
private key
raw token
credential
```

through telemetry.

---

# 188. Audit

Privileged cryptographic operations SHALL generate security audit events.

Examples:

```text
crypto.key.generated
crypto.key.activated
crypto.key.rotated
crypto.key.revoked
crypto.key.compromised
crypto.key.destroyed

secret.rotated
secret.revoked

certificate.issued
certificate.rotated
certificate.revoked

trust_anchor.added
trust_anchor.removed
```

---

# 189. Audit Actor

Audit SHALL capture:

```text
actor
action
target key reference
reason
timestamp
environment
security domain
correlation ID
outcome
```

but never private material.

---

# 190. Reconciliation

Periodic reconciliation SHALL detect:

```text
expired active key
unregistered production key
secret beyond rotation policy
unknown certificate
trust anchor absent from registry
retired key still signing
revoked client still active
environment-crossed credential
```

---

# 191. Orphaned Secrets

Secrets with no identifiable consuming workload SHALL be investigated and retired.

---

# 192. Orphaned Trust

Trust anchors without a known issuer/integration SHALL be removed after controlled review.

---

# 193. Provider Migration

ADR-IAM-0022 Keycloak-to-Ory migration SHALL include cryptographic migration explicitly.

Do not assume identity migration automatically migrates:

```text
issuer keys
client secrets
federation certificates
session secrets
TLS certificates
```

---

# 194. No Key Reuse from Keycloak by Default

Ory SHOULD receive newly generated cryptographic material unless preserving a specific key is required for a controlled migration reason.

---

# 195. Dual-Issuer Migration

During Keycloak/Ory coexistence:

```text
Keycloak issuer
    │
    └── Keycloak JWKS

Ory issuer
    │
    └── Ory JWKS
```

SHALL remain separately trusted.

---

# 196. No Cross-Signing Shortcut

Baobab SHALL NOT make Ory sign with Keycloak's key merely to disguise provider migration unless a separately approved migration design demonstrates a compelling security need.

---

# 197. Legacy-Key Retirement

After Keycloak retirement:

```text
Keycloak issuer → RETIRED
Keycloak trust anchors → RETIRED
Keycloak client secrets → REVOKED
Keycloak admin credentials → REVOKED
```

according to ADR-IAM-0022.

---

# 198. Provider-Neutrality Test

Replacing Ory in the future SHOULD primarily require changes to:

```text
provider adapter
issuer configuration
trust material
OAuth clients
deployment
migration tooling
```

It SHALL NOT require changing:

```text
CanonicalIdentity
Tenant
LegalEntity
BuyerOrganization
SupplierOrganization
Trade authority
ERP authority
```

---

# 199. Ownership Matrix

| Material | Primary Owner | Consumer |
|---|---|---|
| OAuth signing private key | IAM/Infrastructure | Hydra |
| OAuth public JWKS | IAM | APIs |
| Kratos app secrets | IAM/Infrastructure | Kratos |
| Hydra app secrets | IAM/Infrastructure | Hydra |
| OAuth client secret | Owning workload/IAM | One client |
| Workload private key | Owning workload | That workload |
| Public TLS private key | Infrastructure | Edge endpoint |
| Internal mTLS key | Infrastructure/workload identity | One workload |
| PostgreSQL credential | Infrastructure/IAM | One DB workload |
| SAML customer public cert | IAM federation | Federation validator |
| Baobab SAML private key | IAM federation | Federation runtime |
| Backup encryption key | Infrastructure/Security | Backup system |
| Proofing encryption key | IAM/Security | Proofing service |

---

# 200. Separation-of-Duties Matrix

| Operation | Required Authority |
|---|---|
| Routine secret rotation | IAM/Infrastructure automation |
| Signing-key rotation | IAM Security |
| Emergency key revocation | Security incident authority |
| Root trust change | Security + Infrastructure |
| Recovery key access | Restricted recovery authority |
| Federation cert update | IAM federation admin |
| Workload credential rotation | workload owner + IAM policy |
| DB credential rotation | Infrastructure/DB operations |

---

# 201. Prohibited Practices

The following are prohibited:

```text
private keys in Git

production secrets in Docker images

same secret across environments

same workload credential across unrelated services

same key for signing and encryption without explicit protocol requirement

same signing key for unrelated issuers by convenience

trusting arbitrary jku/x5u

accepting token-selected algorithms

using public TLS cert as business authorization

browser-held confidential client secret

CI credential reused as runtime credential

permanent bootstrap credentials

manual untracked production secrets

unverified PostgreSQL TLS

private signing keys distributed to resource servers

indefinite JWKS cache

rotation without rollback

DR without key recovery

backup encryption key stored beside backup with equivalent access

email/domain identity used as cryptographic trust
```

---

# 202. Security Invariants

```text
Signing Key ≠ Encryption Key

Signing Key ≠ Federation Key

TLS Certificate ≠ Business Identity

mTLS Identity ≠ Business Authorization

Client Secret ≠ Human Identity

CI Identity ≠ Runtime Identity

Public Key ≠ Secret

Possession ≠ Authorization

Issuer Trust ≠ Global Trust

Valid Signature ≠ Valid Audience

Valid Signature ≠ Valid Context

Valid JWT ≠ Current Business Authority

Key Rotation ≠ Identity Migration

Key Backup ≠ Key Distribution

Encryption ≠ Authentication

Certificate Expiry ≠ Rotation Strategy

Secret Manager ≠ Authorization Engine

KMS ≠ Canonical Identity Authority

DR Key Recovery ≠ Security-State Recovery
```

---

# 203. Implementation Gates

## IAM-CR0 — Cryptographic Inventory

Inventory all existing:

```text
Keycloak keys
Ory keys/secrets
OAuth client secrets
database credentials
TLS certificates
mTLS certificates
federation certificates
CI credentials
backup encryption
bootstrap secrets
```

Classify owner, purpose, environment and rotation status.

---

## IAM-CR1 — Cryptographic Policy

Define machine-readable policy for:

```text
algorithms
key sizes
TLS versions
certificate lifetime
secret entropy
rotation intervals
exceptions
```

---

## IAM-CR2 — Secret Manager / KMS Foundation

Establish approved production:

```text
secret manager
KMS/HSM boundary
access policies
audit integration
regional recovery
```

---

## IAM-CR3 — Ory Secret Hardening

Move all Kratos/Hydra secrets into governed runtime secret delivery.

Verify exact rotation semantics against pinned Ory versions.

---

## IAM-CR4 — Signing-Key Architecture

Implement:

```text
signing key lifecycle
JWKS
kid
algorithm pinning
issuer binding
audience validation
normal rollover
emergency rollover
```

---

## IAM-CR5 — Workload Credentials

Eliminate shared credentials.

Introduce per-workload:

```text
client credentials
private_key_jwt
mTLS
```

according to risk.

---

## IAM-CR6 — TLS and Internal PKI

Harden:

```text
edge TLS
internal TLS
mTLS
PostgreSQL TLS
certificate automation
expiry monitoring
```

---

## IAM-CR7 — Federation Trust Material

Implement lifecycle for:

```text
SAML certificates
external OIDC JWKS
customer federation rotation
compromise suspension
```

---

## IAM-CR8 — Database Credential Hardening

Implement:

```text
distinct DB roles
least privilege
TLS verification
credential rotation
migration/runtime separation
```

---

## IAM-CR9 — DR Cryptographic Recovery

Prove:

```text
key recovery
issuer continuity
JWKS continuity
secret recovery
backup decryption
regional promotion
```

without insecure manual key copying.

---

## IAM-CR10 — CI/CD Secret Hardening

Implement:

```text
secret scanning
short-lived CI identity where supported
no secrets in images
no production secrets in DevContainers
artifact scanning
```

---

## IAM-CR11 — Rotation Exercises

Exercise:

```text
normal signing-key rotation
emergency signing-key rotation
OAuth client rotation
TLS renewal
DB credential rotation
federation cert rotation
Kratos/Hydra secret rotation
```

---

## IAM-CR12 — Compromise Exercise

Simulate:

```text
signing key compromise
client secret compromise
TLS key compromise
DB credential compromise
federation certificate compromise
```

and verify blast-radius containment.

---

## IAM-CR13 — Production Certification

Require:

```text
no unmanaged production secrets
successful rotation
successful DR recovery
successful compromise drill
trust registry reconciliation
security approval
```

---

# 204. Required Test Matrix

| Scenario | Expected Result |
|---|---|
| Valid token, trusted key | Accept subject to remaining validation |
| Valid signature, wrong issuer | Reject |
| Valid signature, wrong audience | Reject |
| Unsupported algorithm | Reject |
| Unknown `kid` | Controlled refresh then reject if unresolved |
| Arbitrary `jku` | Never blindly follow |
| Old key during normal overlap | Accept legitimate unexpired token |
| Old key after retirement | Reject |
| Compromised key | Reject according to incident policy |
| Staging key in production | Reject |
| Trade secret used by ERP workload | Reject |
| Revoked client secret | Reject |
| Expired TLS certificate | Fail |
| Untrusted DB certificate | Reject |
| Federation old/new cert overlap | Controlled success |
| Unknown federation cert | Reject |
| Secret appears in log | Test fails |
| Secret committed to Git | CI fails |
| DR region lacks signing authority | Promotion fails readiness |
| Restored DB with wrong keys | Recovery fails safely |
| Key rotation during valid sessions | Defined behavior verified |
| Key compromise with forged token possibility | Incident/reconciliation triggered |

---

# 205. Production Readiness Checklist

### Governance

- [ ] cryptographic inventory complete
- [ ] every secret has owner
- [ ] every key has purpose
- [ ] approved algorithm policy
- [ ] rotation policy
- [ ] exception process
- [ ] compromise runbooks

### Signing

- [ ] signing private keys protected
- [ ] JWKS published
- [ ] unique `kid`
- [ ] algorithms pinned
- [ ] issuer validated
- [ ] audience validated
- [ ] normal rollover tested
- [ ] emergency rollover tested

### Secrets

- [ ] no production secrets in Git
- [ ] no production secrets in images
- [ ] no cross-environment reuse
- [ ] secret manager configured
- [ ] least-privilege secret access
- [ ] rotation tested
- [ ] logging redaction tested

### Workloads

- [ ] unique credentials
- [ ] no shared service account
- [ ] short-lived credentials preferred
- [ ] client rotation tested
- [ ] revoked workloads denied
- [ ] CI identity separate

### Certificates

- [ ] edge TLS
- [ ] internal TLS policy
- [ ] mTLS where required
- [ ] expiry monitoring
- [ ] automatic renewal where appropriate
- [ ] certificate revocation process

### PostgreSQL

- [ ] encrypted connections
- [ ] server verification
- [ ] distinct Kratos/Hydra roles
- [ ] least privilege
- [ ] migration/runtime privilege separation
- [ ] credential rotation tested

### Federation

- [ ] SAML trust scoped
- [ ] OIDC federation trust scoped
- [ ] certificate rotation tested
- [ ] unknown key fails closed
- [ ] compromised federation can be suspended

### DR

- [ ] signing keys recoverable
- [ ] encryption secrets recoverable
- [ ] backup keys recoverable
- [ ] recovery authorization controlled
- [ ] issuer continuity verified
- [ ] JWKS continuity verified
- [ ] cryptographic DR exercise passed

### CI/CD

- [ ] secret scanning
- [ ] private-key scanning
- [ ] short-lived deployment identity where supported
- [ ] SBOM
- [ ] image scanning
- [ ] no secret leakage in build logs

---

# 206. Final Cryptographic Architecture

```text
                        BAOBAB TRUST GOVERNANCE
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
                  KMS/HSM    Secret Manager    PKI
                    │             │             │
        ┌───────────┼───────┐     │       ┌─────┼─────┐
        │           │       │     │       │     │     │
        ▼           ▼       ▼     ▼       ▼     ▼     ▼
      OAuth      Backup   Proof   Ory    TLS   mTLS Federation
     Signing      Keys    Keys   Secrets Certs Certs   Certs
        │                         │
        ▼                         ▼
      Hydra                     Kratos
        │
        ▼
       JWKS
        │
        │ PUBLIC TRUST ONLY
        ▼
 ┌──────────────────────────────────────────┐
 │               RESOURCE APIs              │
 │                                          │
 │ CP   Trade   ERP   CMS   Pulse   Domains │
 └────────────────────┬─────────────────────┘
                      │
                      ▼
              Context + Authorization
```

Workload credentials form a separate trust path:

```text
Workload
    │
    │ unique private credential
    ▼
Hydra
    │
    ▼
short-lived token
    │
    ▼
API
    │
    ▼
WorkloadIdentity
    │
    ▼
Capability Authorization
```

Federation forms another:

```text
Enterprise IdP
      │
      │ enterprise signing key
      ▼
Federation Boundary
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity
```

None of these cryptographic paths redefine the Baobab business model.

---

# 207. Consequences

## Positive

This architecture provides:

- controlled signing authority;
- safe JWKS rollover;
- provider-neutral trust;
- compartmentalized secrets;
- reduced credential blast radius;
- stronger workload identity;
- explicit federation trust;
- secure regional recovery;
- production-grade TLS and database trust;
- algorithm agility;
- measurable rotation readiness;
- better incident containment;
- reduced dependency on manually managed static secrets.

## Costs

Baobab must operate:

```text
KMS/secret-management infrastructure
cryptographic inventory
certificate automation
rotation automation
trust registries
compromise runbooks
recovery procedures
cryptographic monitoring
```

This is appropriate for Tier-0 identity infrastructure.

---

# 208. Explicitly Deferred

This ADR does not mandate:

```text
a specific cloud KMS vendor
a specific HSM vendor
customer-managed keys
BYOK/HYOK
a proprietary Baobab PKI product
one particular asymmetric signing algorithm
global multi-region private-key sharing
```

These decisions SHALL be made from deployment constraints and current cryptographic guidance without altering the architecture above.

---

# 209. Final Decision Principle

Baobab SHALL treat cryptographic material as **purpose-bound security authority**, not configuration trivia.

The trust chain is:

```text
Cryptographic Key
       │
       ▼
Protocol Proof
       │
       ▼
Authenticated Principal
       │
       ▼
Canonical Identity
       │
       ▼
Control Plane Context
       │
       ▼
Domain Authorization
```

Each layer answers a different question.

A signing key answers:

> "Was this token produced by the trusted issuer?"

It does not answer:

> "May this user approve this purchase?"

A TLS certificate answers:

> "Is this the endpoint/workload represented by this certificate?"

It does not answer:

> "Which tenant may it access?"

A client secret answers:

> "Can this client authenticate?"

It does not answer:

> "What business capability should the client receive?"

Therefore:

> **Cryptography establishes trust evidence. Baobab architecture determines what that evidence means.**

And the operational rule is:

> **Every production key must be identifiable, purpose-bound, minimally distributed, rotatable, revocable, recoverable where required, observable without disclosure, and disposable when its trust has ended.**

No production credential is permanent.

No private key is casually shared.

No valid signature bypasses authorization.

No disaster-recovery plan is complete until the cryptographic trust chain itself has been recovered and proven.