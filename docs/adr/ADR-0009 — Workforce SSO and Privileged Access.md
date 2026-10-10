# ADR-0009: Workforce SSO and Privileged Access

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, domain engines  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Workforce identity, single sign-on, privileged access, administrator segregation, MFA, step-up authentication, executive access, break-glass access, joiner/mover/leaver lifecycle and engine-specific workforce authorization  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  
- ADR-0005 — Realm, Organization, Tenant and Legal-Entity Model  
- ADR-0006 — OIDC, OAuth and Token Profile  
- ADR-0007 — Workload Identity and Service-to-Service Authentication  
- ADR-0008 — Platform Authorization Architecture  

---

# 1. Context

Baobab will be operated by a workforce requiring access to multiple applications and engines.

Examples include:

- Nabhold executives;
- Control Plane administrators;
- IAM administrators;
- Trade administrators;
- iDempiere finance users;
- ERP administrators;
- CMS editors;
- CMS publishers;
- operations engineers;
- security administrators;
- developers;
- support personnel;
- auditors.

Without a central workforce-access model, each system could create separate credentials and administrator accounts.

That would lead to:

- credential proliferation;
- inconsistent MFA;
- difficult employee offboarding;
- duplicate accounts;
- weak privilege visibility;
- poor auditability;
- local superuser proliferation;
- inconsistent access reviews.

Baobab SHALL instead use one canonical workforce identity across the platform while maintaining strict separation of privileges.

---

# 2. Decision

Baobab SHALL provide centralized workforce authentication through Baobab IAM.

A workforce user SHALL authenticate using one Canonical Identity and may then receive explicitly authorized access to multiple Baobab systems.

The target model is:

```text id="n9nrp5"
                    WORKFORCE USER
                          │
                          ▼
                    BAOBAB IAM
                        SSO
                          │
                          ▼
                  CanonicalIdentity
                          │
                    BAOBAB CP
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    Control Plane       iDempiere        Medusa
      privileges         roles            admin
         │
         ├────────► CMS roles
         │
         └────────► other approved access
```

Authentication is centralized.

Authorization remains separated by authority.

---

# 3. Core Principle

The governing rule SHALL be:

> **One workforce identity does not mean one universal workforce privilege.**

A person may authenticate once but receive different permissions in different systems.

---

# 4. Workforce Identity

A workforce identity represents a human performing duties for:

- Nabhold;
- a Nabhold legal entity;
- an operating company;
- an approved contractor or partner role.

Workforce status SHALL be a relationship to the Canonical Identity.

It SHALL NOT require a separate global identity if the person already possesses one.

---

# 5. Workforce Is a Relationship, Not a New Person

Example:

```text id="rfhe6n"
CanonicalIdentity
      │
      ├── workforce membership
      ├── supplier relationship
      └── consumer relationship
```

where legitimate.

Baobab SHALL not duplicate the human solely because the actor has multiple personas.

---

# 6. Single Sign-On

Approved workforce applications SHALL use Baobab IAM for SSO where supported.

Initial targets SHOULD include:

```text id="jss0wi"
baobab-cp administration
Medusa administration
iDempiere
Payload CMS
future operational consoles
```

Each relying application SHALL remain a separate OIDC client.

---

# 7. SSO Does Not Mean Shared Authorization

The following is prohibited:

```text id="ciuj4q"
User logged into Baobab IAM
          │
          ▼
automatically admin everywhere
```

Instead:

```text id="l0te6w"
User authenticated
      │
      ▼
application-specific authorization
```

shall remain mandatory.

---

# 8. Workforce Authentication Flow

```text id="2hpd22"
Employee
   │
   ▼
Baobab IAM
   │
   ├── authenticate
   ├── MFA where required
   └── issue OIDC token
   │
   ▼
Application
   │
   ▼
CP/context authorization
   │
   ▼
application/domain authorization
```

---

# 9. Workforce Client Separation

Each administrative system SHALL have a distinct client registration.

Examples:

```text id="86v0lf"
baobab-control-plane-admin
baobab-trade-admin
baobab-erp
baobab-cms-admin
```

A universal:

```text id="hswegl"
baobab-admin
```

client SHOULD be avoided.

---

# 10. Why Client Separation Matters

Separate clients allow:

- independent audiences;
- independent redirect URIs;
- independent scopes;
- independent session policy;
- independent revocation;
- clearer audit;
- reduced blast radius.

---

# 11. Privileged Access Definition

Privileged access includes any permission that can materially affect:

- IAM;
- tenancy;
- platform configuration;
- customer or supplier data;
- commercial operations;
- ERP records;
- accounting;
- security configuration;
- infrastructure;
- content publication;
- secrets;
- production operations.

Privileged identities SHALL receive stronger controls than ordinary end-user accounts.

---

# 12. Privileged Access Is Additive, Not Identity-Defining

A privileged administrator remains:

```text id="28t1os"
CanonicalIdentity
```

with one or more privileged relationships.

The person SHALL not require a separate Canonical Identity merely because they possess administrative privileges.

However, separate administrative accounts MAY be adopted later for particularly sensitive responsibilities if operational risk justifies it.

---

# 13. Least Privilege

Every workforce user SHALL receive only the privileges required for assigned duties.

This is prohibited:

```text id="3wh577"
employee
   │
   ▼
platform-admin
```

as a default onboarding pattern.

---

# 14. Privilege Segregation

Baobab SHALL distinguish at least these privilege domains:

```text id="tgndjz"
IAM administration
Control Plane administration
Trade administration
ERP administration
CMS administration
Infrastructure administration
Security administration
```

Privileges SHALL not automatically propagate between domains.

---

# 15. IAM Administrator

IAM administrators MAY manage:

- IAM clients;
- identity providers;
- authentication flows;
- MFA policies;
- account recovery policy;
- Keycloak configuration;
- selected identity lifecycle operations.

They SHALL NOT automatically receive:

- ERP financial posting;
- Trade order administration;
- CMS publishing;
- tenant commercial administration.

---

# 16. Control Plane Administrator

A CP administrator MAY manage:

- tenants;
- legal-entity relationships;
- Digital Estates;
- markets;
- capabilities;
- engine instances;
- canonical mappings;
- platform memberships;
- platform context policy.

This SHALL not make the user an IAM super-admin or ERP superuser.

---

# 17. Trade Administrator

Trade administrators MAY manage commerce functions according to Trade policy.

Examples:

- orders;
- products;
- buyer organisations;
- supplier commerce relationships;
- pricing;
- inventory;
- commercial configuration.

Such authority SHALL remain `baobab-trade` domain state.

---

# 18. ERP User

ERP users SHALL authenticate through IAM where supported but retain iDempiere-native authorization.

Example:

```text id="65u4h1"
IAM:
Peter authenticated

CP:
Peter allowed Nabhold ERP context

iDempiere:
AD_User = Peter
AD_Role = Finance_Manager
```

---

# 19. ERP Administrator

ERP administrative roles SHALL remain especially restricted because they may affect:

- accounting;
- financial controls;
- organisational structures;
- workflows;
- master data;
- system configuration.

ERP admin SHALL not be granted merely because a person has general platform-admin access.

---

# 20. CMS Editor

A CMS editor may be permitted to:

- create content;
- edit content;
- submit content for review.

They SHALL not automatically receive publication rights.

---

# 21. CMS Publisher

CMS publish authority SHOULD be separable from edit authority where governance requires it.

Example:

```text id="0hsfvp"
Editor
   │
   ▼
draft

Publisher
   │
   ▼
production content
```

---

# 22. Operations Engineer

Operations engineers may require:

- deployment visibility;
- logs;
- service health;
- runtime operations.

They SHALL not automatically receive customer-data or ERP-business permissions.

---

# 23. Security Administrator

Security administration SHOULD be distinct where practical from ordinary platform operations.

Responsibilities may include:

- IAM security configuration;
- security-event review;
- privileged access review;
- incident response;
- key/certificate security procedures.

---

# 24. Executive Access

Nabhold executives may require visibility across several Digital Estates and operating companies.

Example:

```text id="f0fs51"
Executive
   │
   ├── Nabhold
   ├── Zuribeans
   ├── Thamani
   └── Equator & Estate
```

Such access SHALL be explicitly authorized through Control Plane context.

---

# 25. Executive Visibility Is Not Universal Authority

The following SHALL NOT be assumed:

```text id="tb1ohx"
executive
   │
   ▼
superuser
```

An executive may have:

```text id="oox68k"
read-only dashboards
operational reporting
cross-tenant visibility
```

without:

```text id="juyeqa"
journal posting
IAM configuration
customer refund authority
supplier approval
content publication
```

---

# 26. Cross-Tenant Executive Access

Cross-tenant executive access SHALL still use explicit resolved target context.

Example:

```text id="3uc05e"
Executive
   │
   ▼
select Thamani
   │
   ▼
CP authorizes Thamani context
   │
   ▼
read approved operational data
```

No normal application path SHOULD use unscoped "all tenant data" access simply because the user is an executive.

---

# 27. Workforce Membership

The Control Plane SHOULD maintain platform-level workforce relationships where needed.

Conceptually:

```text id="oxipg8"
CanonicalIdentity
      │
      ▼
WorkforceMembership
      │
      ├── LegalEntity
      ├── Tenant
      └── status
```

Exact persistence SHALL align with existing CP membership models.

---

# 28. Employment Status Is Not IAM Credential Status

This distinction SHALL remain explicit:

```text id="73jrqy"
IAM account ACTIVE
```

does not necessarily mean:

```text id="0j7a4w"
employee ACTIVE
```

and vice versa.

Workforce lifecycle must coordinate both.

---

# 29. Joiner Process

The target joiner process SHALL be:

```text id="f3v2xr"
employment/contract approved
        │
        ▼
CanonicalIdentity identified/created
        │
        ▼
workforce membership created
        │
        ▼
IAM identity/invite provisioned
        │
        ▼
baseline application access
        │
        ▼
specific privileges granted
        │
        ▼
MFA enrollment
```

Privileged access SHALL not be assigned merely because identity provisioning succeeded.

---

# 30. Existing Identity Joiner

If the new workforce user already has a Canonical Identity as:

- customer;
- supplier representative;
- buyer representative;

the existing identity SHOULD be reused where appropriate.

Example:

```text id="qd8qry"
existing CanonicalIdentity
        │
        ▼
add workforce membership
```

rather than automatically creating a duplicate.

---

# 31. Mover Process

When an employee changes role:

```text id="vk0bmy"
old role
   │
   ▼
revoke obsolete privileges
   │
   ▼
grant new privileges
```

Access SHALL not simply accumulate indefinitely.

---

# 32. Privilege Accumulation

Baobab SHALL explicitly guard against privilege accumulation.

A user's move from:

```text id="edkb4p"
Trade Operations
```

to:

```text id="roea71"
Finance
```

shall not automatically leave all previous Trade administrative rights active.

---

# 33. Leaver Process

On workforce termination:

```text id="b3o5hi"
employment ends
     │
     ▼
workforce membership disabled
     │
     ▼
sessions revoked
     │
     ▼
IAM access disabled as policy requires
     │
     ▼
platform access revoked
     │
     ▼
domain roles revoked
     │
     ▼
active privileged credentials reviewed
```

This SHALL be treated as a coordinated security process.

---

# 34. Identity Retention After Employment

Ending workforce membership SHALL not necessarily delete the Canonical Identity.

The person may still legitimately exist as:

- customer;
- supplier contact;
- buyer representative;
- historical actor.

Therefore:

```text id="kd6tax"
workforce membership revoked
```

does not necessarily equal:

```text id="udvtki"
CanonicalIdentity deleted
```

---

# 35. Domain Deprovisioning

Offboarding SHALL include explicit domain deprovisioning.

Examples:

```text id="zrasvh"
remove iDempiere roles
disable CMS publisher access
remove Trade admin role
remove CP admin scope
```

Disabling only the Keycloak account is not sufficient for long-term consistency.

---

# 36. Immediate Termination

For high-risk or immediate termination:

```text id="xa650b"
revoke active IAM sessions
disable authentication
revoke platform membership
disable privileged engine accounts
```

SHOULD occur with minimal delay.

---

# 37. Privileged MFA

MFA SHALL be mandatory for privileged workforce accounts.

At minimum this includes users with:

```text id="8bx1tv"
IAM administration
Control Plane administration
ERP finance/admin access
Trade administration
CMS publishing/admin access
production infrastructure access
```

where technically supported.

---

# 38. MFA Is Centralized

Where possible, MFA SHALL be implemented centrally through Baobab IAM.

Engines SHOULD avoid maintaining separate parallel MFA enrolments unless native product limitations require them.

---

# 39. Strong Authentication Preference

Privileged users SHOULD preferentially use phishing-resistant authentication methods as supported by the IAM platform and deployment policy.

Passkeys/WebAuthn SHOULD be preferred over weaker second-factor methods where practical.

Exact assurance policy will be refined in ADR-0015.

---

# 40. MFA for Ordinary Workforce

Ordinary workforce access SHOULD also require MFA unless a documented exception exists.

The stronger mandatory requirement for privileged users does not imply that ordinary employees should remain password-only.

---

# 41. Step-Up Authentication

Certain sensitive actions SHALL be able to demand stronger or more recent authentication.

Examples include:

```text id="s9toxn"
grant platform-admin
change IAM policy
reset another administrator's MFA
post high-risk financial transaction
change supplier bank details
approve exceptional B2B purchase
rotate security credentials
```

---

# 42. Step-Up Flow

```text id="gyctgg"
User authenticated
      │
      ▼
requests sensitive action
      │
      ▼
application detects required assurance
      │
      ▼
Baobab IAM step-up
      │
      ▼
higher assurance established
      │
      ▼
domain/platform authorization
      │
      ▼
action
```

---

# 43. Authentication Assurance

Applications MAY rely on defined OIDC assurance information such as:

```text id="c2kl5x"
acr
amr
auth_time
```

where centrally standardized.

Applications SHALL not invent incompatible MFA claims.

---

# 44. Recent Authentication

Security-sensitive operations MAY require:

```text id="e76fch"
authentication within N minutes
```

rather than merely checking that some session exists.

Exact thresholds SHALL be risk-based and centrally documented.

---

# 45. Password Re-Prompt

Individual applications SHOULD NOT implement arbitrary local password prompts for reauthentication where IAM-based step-up is available.

Credential verification belongs to IAM.

---

# 46. Privileged Sessions

Privileged sessions SHOULD have stricter policy than ordinary B2C sessions.

Potential differences include:

- shorter idle timeout;
- shorter maximum lifetime;
- stronger MFA;
- step-up;
- reduced refresh persistence.

---

# 47. Separate Risk Classes

Baobab SHOULD classify application clients by risk.

For example:

| Class | Examples |
|---|---|
| Tier 0 | IAM administration |
| Tier 1 | CP admin, ERP finance/admin, infrastructure |
| Tier 2 | Trade admin, CMS publishing |
| Tier 3 | ordinary workforce read/use |

Exact names MAY change, but differentiated control is required.

---

# 48. IAM Administrative Isolation

Keycloak's highest-level administration SHALL be highly restricted.

The IAM administrative population SHOULD be significantly smaller than the general workforce population.

---

# 49. Master Realm

Keycloak's master realm SHALL not be used for ordinary workforce authentication.

Administrative access to the master realm, if needed operationally, SHALL be restricted and separated from routine Baobab application access.

---

# 50. Bootstrap Administrator

Bootstrap or emergency IAM administrator credentials SHALL not become normal daily-use credentials.

Once platform initialization is complete, routine administration SHALL use named, auditable identities.

---

# 51. Shared Administrator Accounts

This is prohibited for ordinary operations:

```text id="5epuh7"
admin@example.com
shared by five people
```

Privileged activity SHALL map to an identifiable human.

---

# 52. Named Privileged Accounts

Privileged actions SHALL be attributable to a Canonical Identity.

Audit SHALL be able to answer:

```text id="a4b11w"
Who performed this action?
```

---

# 53. Break-Glass Access

Baobab SHALL maintain a controlled break-glass mechanism for scenarios such as:

- IAM configuration failure;
- federation outage;
- administrative lockout;
- severe incident;
- disaster recovery.

Break-glass is an emergency control, not routine access.

---

# 54. Break-Glass Requirements

Break-glass credentials or access SHALL be:

- strongly protected;
- rarely used;
- separately stored;
- monitored;
- tested;
- time-limited where practical;
- audited;
- rotated after use where appropriate.

---

# 55. Break-Glass Flow

```text id="eyr7pw"
Normal privileged login unavailable
        │
        ▼
authorized incident declared
        │
        ▼
break-glass access retrieved
        │
        ▼
emergency action
        │
        ▼
security alert + audit
        │
        ▼
credential rotation/reseal
        │
        ▼
incident review
```

---

# 56. Break-Glass SHALL Not Bypass Domain Governance Indefinitely

Emergency access may restore platform administration.

It SHALL not create an invisible permanent bypass around:

- ERP audit;
- tenant policy;
- business authorization.

---

# 57. Privileged Access Approval

High-risk roles SHOULD require explicit approval.

Examples:

```text id="gc4kjx"
IAM admin
ERP finance administrator
CP platform admin
production infrastructure admin
```

The request and approval SHOULD be auditable.

---

# 58. Self-Grant Prohibition

Administrators SHALL not ordinarily be able to grant themselves higher privilege without appropriate governance.

Where the underlying system technically allows it, procedural and monitoring controls SHALL compensate.

---

# 59. Separation of Duties

Baobab SHOULD support separation of duties where risk warrants it.

Examples:

```text id="r2bhcl"
request access
      ≠
approve access
```

and:

```text id="m0p9kp"
create supplier
      ≠
approve supplier payment change
```

Domain-specific separation remains owned by the relevant engine.

---

# 60. Finance Separation

ERP financial authorization may require specific segregation such as:

- journal creation versus posting;
- payment proposal versus payment approval;
- master-data change versus transaction approval.

These rules SHALL remain in iDempiere rather than being moved to IAM.

---

# 61. IAM Separation

IAM security administration SHOULD separate where practical:

```text id="h5s0mp"
identity helpdesk
```

from:

```text id="ipxwxy"
realm security administration
```

A helpdesk agent able to reset MFA SHALL not automatically become an IAM configuration administrator.

---

# 62. Helpdesk

Helpdesk functions MAY include:

- user lookup;
- approved recovery assistance;
- resend invitation;
- MFA recovery according to policy.

Helpdesk SHALL not automatically receive broad application administration.

---

# 63. Access Reviews

Privileged workforce access SHALL be periodically reviewed.

Review SHOULD answer:

```text id="gc1r97"
Does this person still need this role?
Is employment/membership still active?
Is privilege appropriate?
Are dormant privileged accounts present?
```

---

# 64. Review Frequency

Higher-risk privileges SHOULD receive more frequent review than low-risk access.

Exact review cadence SHALL be governance-driven and may be defined operationally rather than hard-coded.

---

# 65. Dormant Privileged Accounts

Privileged accounts unused for a defined period SHOULD be reviewed, suspended, or otherwise investigated according to policy.

Dormancy does not necessarily mean malicious activity, but unused privilege increases risk.

---

# 66. Temporary Privilege

Baobab SHOULD support temporary privileged grants.

Example:

```text id="5w4lpp"
incident support access
valid until:
2026-09-10T18:00
```

where platform/domain capabilities support expiration.

---

# 67. Just-in-Time Privilege

Just-in-time privileged elevation MAY be introduced later for high-risk roles.

It is not mandatory in the initial IAM rollout.

The architecture SHALL avoid design choices that make future JIT access impossible.

---

# 68. Contractor Access

Contractors SHALL use named workforce identities with explicit expiry or relationship lifecycle.

They SHALL not use:

```text id="ualzg4"
shared vendor login
```

for normal administrative operations.

---

# 69. External Support Personnel

External vendor support access SHALL be:

- explicitly approved;
- scoped;
- time-bounded;
- audited;
- revoked after need ends.

Vendor support SHALL not receive permanent unmonitored platform administration.

---

# 70. Developer Access

Developer access to production SHALL be restricted.

Repository write access, CI/CD deployment rights and runtime production administration are separate privileges.

They SHALL not be assumed equivalent.

---

# 71. Production Database Access

Direct production database access SHOULD be exceptional.

Application administration SHALL preferably occur through governed application/control-plane interfaces.

If direct access is required, it SHALL be separately controlled and audited.

---

# 72. Database Access ≠ Application Role

A user with:

```text id="9t9wvd"
ERP application role
```

does not automatically receive PostgreSQL credentials.

Likewise, database administrators SHALL not automatically receive application business permissions.

---

# 73. GitHub Access

GitHub organization/repository access SHALL remain distinct from Baobab runtime IAM.

A developer's GitHub identity may be federated or linked operationally in the future, but repository privileges SHALL not automatically create runtime production privileges.

---

# 74. CI/CD Administration

The ability to modify production deployment pipelines is privileged.

CI/CD administrators SHALL be treated as privileged workforce even if they do not use application admin consoles.

---

# 75. Infrastructure Access

Infrastructure access SHALL be separately authorized from:

```text id="4oerbe"
CP administration
Trade administration
ERP administration
IAM administration
```

Infrastructure operators should not receive business-domain access unnecessarily.

---

# 76. Executive Dashboard Access

Where Nabhold executives require consolidated operational visibility, the preferred model is:

```text id="qzwy1f"
Executive
   │
   ▼
CP cross-context authorization
   │
   ▼
read-oriented reporting/intelligence layer
```

rather than granting full administrator roles in every engine.

---

# 77. Audit Access

Auditors may require read-only access to:

- IAM events;
- CP authorization decisions;
- ERP audit;
- Trade audit;
- CMS history.

Audit roles SHOULD be read-oriented and isolated from operational mutation privileges.

---

# 78. Impersonation

User impersonation SHALL be disabled or heavily restricted for ordinary administrators.

If retained for support or incident use, it SHALL:

- require privileged authorization;
- be clearly indicated;
- be audited;
- retain the real administrator identity;
- never erase actor provenance.

---

# 79. Impersonation Model

Audit SHOULD preserve:

```text id="fk0g10"
subject = customer
actor = support administrator
```

not:

```text id="k9mgb6"
subject = customer
actor = customer
```

when impersonation occurs.

---

# 80. Privileged Credential Recovery

Recovery of privileged workforce accounts SHALL require stronger verification than routine low-risk consumer recovery.

Recovery SHALL not silently remove mandatory MFA requirements.

---

# 81. Recovery Does Not Restore Roles Automatically

If privilege was revoked independently, recovering authentication access SHALL not recreate:

```text id="c89j41"
CP admin
ERP role
Trade admin
```

merely because the user regained their account.

---

# 82. Lost MFA Device

Lost MFA-device recovery SHALL follow centrally governed IAM policy.

Privileged users may require:

- recovery codes;
- secondary strong authenticator;
- administrator-assisted recovery;
- identity verification.

The exact mechanics will be refined in ADR-0015.

---

# 83. Compromised Workforce Identity

On suspected account compromise:

```text id="40rhfu"
suspend/restrict authentication
        │
        ▼
revoke active sessions
        │
        ▼
review recent privileged actions
        │
        ▼
rotate/recover credentials
        │
        ▼
review domain/platform memberships
```

---

# 84. Privileged Session Revocation

Security administrators SHALL be able to revoke privileged sessions rapidly.

A user SHALL not need to remain globally disabled after the incident if only specific privileged relationships need revocation.

---

# 85. Federation

Baobab MAY later federate workforce authentication with an enterprise identity provider.

If federation is introduced:

```text id="czilfs"
external enterprise IdP
       │
       ▼
Keycloak
       │
       ▼
Baobab ExternalIdentity
       │
       ▼
CanonicalIdentity
```

The federation SHALL not replace CP/domain authorization.

---

# 86. Federation Is Not Employment Proof

A valid corporate upstream identity SHALL not by itself create:

```text id="vdcl8s"
active workforce membership
```

unless an explicit provisioning policy allows it.

---

# 87. Just-In-Time Workforce Provisioning

JIT creation of workforce identities SHALL be disabled by default unless a trusted enterprise federation and governance model explicitly supports it.

Workforce access SHOULD normally be invitation/provisioning driven.

---

# 88. Privileged JIT Provisioning

Automatic JIT creation of highly privileged administrators SHALL be prohibited.

Privileged role assignment requires explicit governance.

---

# 89. Device Trust

Device posture or managed-device requirements MAY be introduced later for privileged access.

This ADR does not require a specific device-management product.

The IAM architecture SHALL remain compatible with future conditional-access controls.

---

# 90. Network Location

Internal office/VPN/network location MAY contribute to risk policy.

It SHALL not replace identity, MFA, or authorization.

---

# 91. Privileged APIs

Administrative APIs SHOULD be distinguishable from public/customer APIs.

They MAY receive stronger controls such as:

- stricter audiences;
- stronger MFA;
- narrower CORS;
- tighter rate limits;
- stronger audit;
- network restrictions.

---

# 92. Administrative Frontends

Admin UIs SHALL not rely on client-side role hiding.

Every corresponding administrative API SHALL independently authorize requests.

---

# 93. Access Denial

If a workforce user is authenticated but lacks application authorization:

```text id="9xopmz"
IAM login succeeds
```

but:

```text id="iylbt7"
application access denied
```

This is expected behavior and SHALL not be treated as an IAM error.

---

# 94. Multi-Application Logout

Logging out from one application MAY terminate only that application's local session or MAY invoke IAM session logout according to client policy.

Security-sensitive global revocation SHALL remain available independently.

---

# 95. Workforce Session Inventory

Baobab IAM SHOULD provide operational visibility into active workforce sessions where supported.

This capability is particularly useful during:

- offboarding;
- incident response;
- administrator compromise.

---

# 96. Audit Requirements

Privileged operations SHALL be auditable.

Audit SHOULD answer:

```text id="hnsej7"
which canonical identity?
which application?
which tenant/context?
which role?
which action?
which time?
which authentication assurance?
which result?
```

where relevant.

---

# 97. Authentication Events

Security-relevant events SHOULD include:

```text id="ntn9zt"
login success
login failure
MFA challenge
MFA enrollment
MFA reset
session revocation
recovery event
privileged login
```

subject to event/PII policy.

---

# 98. Privilege Events

Privilege lifecycle events SHOULD include:

```text id="d7k4ap"
role granted
role revoked
membership granted
membership revoked
privileged access approved
break-glass used
```

where systems support them.

---

# 99. Audit Correlation

Where a privileged operation crosses systems, audit SHOULD correlate:

```text id="mcw0rw"
IAM authentication
      │
      ▼
CP authorization decision
      │
      ▼
domain action
```

through shared request/decision/correlation identifiers where practical.

---

# 100. Monitoring

Security monitoring SHOULD detect patterns such as:

- repeated privileged-login failures;
- unexpected MFA resets;
- use of dormant admin identity;
- break-glass use;
- large privilege changes;
- unusual cross-tenant access;
- administrator login from unexpected environment;
- privilege escalation.

---

# 101. Alerts

Break-glass use and critical IAM administrator changes SHOULD generate security alerts.

High-value ERP or CP privilege changes SHOULD also be observable.

---

# 102. Workforce Role Naming

Role names SHALL be specific enough to express their authority.

Prefer:

```text id="800the"
cp-tenant-admin
iam-helpdesk
iam-security-admin
cms-publisher
```

over:

```text id="xkh87m"
admin
superuser
manager
```

where ambiguity would cause risk.

---

# 103. Role Namespace

Roles SHOULD be namespaced by authority/domain when represented outside the engine.

Examples:

```text id="seovg1"
iam:security-admin
cp:platform-admin
trade:operator
cms:publisher
```

Exact syntax SHALL follow Shared conventions.

---

# 104. Role Explosion Avoidance

Baobab SHALL avoid replicating every engine permission into IAM.

For example, individual iDempiere window/process permissions SHALL remain in ERP.

IAM may only need coarse authorization sufficient to enter the ERP application.

---

# 105. Access Mapping

Workforce SSO mapping MAY conceptually be:

```text id="j3u02t"
CanonicalIdentity
      │
      ├── CP membership/role
      ├── Trade admin mapping
      ├── ERP AD_User mapping
      └── CMS user mapping
```

Each mapping SHALL remain independently revocable.

---

# 106. No Universal Administrator

Baobab SHOULD avoid creating a daily-use role equivalent to:

```text id="kc6o8t"
admin of everything
```

If a Tier-0 emergency capability exists, it SHALL be break-glass or similarly restricted.

---

# 107. Access Matrix

A conceptual workforce matrix may look like:

| Persona | CP | Trade | ERP | CMS | IAM |
|---|---|---|---|---|---|
| Executive | read/cross-context | read | reporting | read | none |
| CP operator | admin | none | none | none | none |
| Finance manager | contextual | limited | finance role | none | none |
| Commerce operator | contextual | admin/operator | limited integration | none | none |
| CMS editor | contextual | none | none | editor | none |
| IAM security admin | minimal CP | none | none | none | security admin |

The exact matrix SHALL be configured from actual operational requirements.

---

# 108. Required Tests

At minimum test:

### SSO
- one workforce identity accesses multiple approved clients;
- unapproved application denied;
- logout behavior;
- session expiry.

### MFA
- privileged client requires MFA;
- missing assurance denied;
- successful step-up accepted;
- stale authentication rejected where recency required.

### Separation
- CP admin cannot post ERP journal solely because of CP role;
- ERP admin cannot manage IAM;
- CMS publisher cannot administer Trade;
- Trade admin cannot administer CP unless separately authorized.

### Lifecycle
- joiner provisioned correctly;
- mover loses obsolete roles;
- leaver loses access;
- domain roles revoked;
- active customer relationship survives workforce offboarding where appropriate.

### Cross-tenant
- executive receives only approved tenants;
- ordinary employee cannot select unauthorized tenant;
- executive read role does not become domain mutation authority.

---

# 109. Break-Glass Tests

Staging SHALL periodically prove:

```text id="fwhugk"
normal IAM admin path unavailable
        │
        ▼
authorized break-glass procedure succeeds
        │
        ▼
use is logged/alerted
        │
        ▼
credential is resealed/rotated
```

without using production credentials in testing.

---

# 110. Offboarding Tests

A production-readiness exercise SHOULD demonstrate:

```text id="d6k72m"
terminate workforce membership
      │
      ├── IAM session revoked
      ├── CP access revoked
      ├── Trade admin revoked
      ├── ERP access revoked
      └── CMS access revoked
```

within the platform's documented revocation expectations.

---

# 111. Access Review Tests

Administrative tooling SHOULD be able to produce a report such as:

```text id="8hvkg5"
Canonical Identity
Employment relationship
IAM privileges
CP privileges
Trade privileges
ERP roles
CMS roles
Last privileged use
```

to support periodic review.

---

# 112. Rejected Alternative — Separate Credentials Per Engine

### Advantages

Simple local implementation.

### Disadvantages

- credential proliferation;
- weak offboarding;
- duplicate MFA;
- fragmented audit;
- inconsistent recovery.

### Decision

Rejected.

---

# 113. Rejected Alternative — SSO Plus Universal Admin Role

### Advantages

Very simple administration.

### Disadvantages

- extreme blast radius;
- no separation of duties;
- poor audit semantics;
- unnecessary privilege.

### Decision

Rejected.

---

# 114. Rejected Alternative — Executive Equals Superuser

### Advantages

Easy access for leadership.

### Disadvantages

- unnecessary operational authority;
- financial risk;
- weak segregation;
- increased account-takeover impact.

### Decision

Rejected.

---

# 115. Rejected Alternative — Engine Role Mirroring in Keycloak

### Advantages

Central role catalogue.

### Disadvantages

- role explosion;
- synchronization complexity;
- stale authorization;
- domain coupling.

### Decision

Rejected.

---

# 116. Rejected Alternative — Shared Administrator Account

### Advantages

Operational convenience.

### Disadvantages

- no accountability;
- impossible personal revocation;
- weak audit;
- credential sharing.

### Decision

Rejected.

---

# 117. Rejected Alternative — Permanent Break-Glass Superuser

### Advantages

Always available.

### Disadvantages

- hidden standing privilege;
- high compromise impact;
- likely normal-use drift.

### Decision

Rejected.

Emergency access SHALL remain tightly controlled.

---

# 118. Consequences

## Positive

This decision provides:

- one workforce identity;
- consistent SSO;
- centralized MFA;
- clean offboarding;
- reduced credential duplication;
- application-level privilege separation;
- safer executive access;
- stronger administrator governance;
- improved auditability.

## Negative

It requires:

- application SSO integration;
- role-mapping discipline;
- coordinated joiner/mover/leaver processes;
- access reviews;
- MFA/step-up configuration;
- break-glass operations.

These costs are accepted.

---

# 119. Implementation Ownership

| Concern | Owner |
|---|---|
| Workforce authentication | `baobab-iam` |
| SSO sessions | `baobab-iam` |
| MFA/step-up | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| Workforce platform membership | `baobab-cp` |
| Cross-tenant entitlement | `baobab-cp` |
| CP privileges | `baobab-cp` |
| Trade admin privileges | `baobab-trade` |
| ERP roles | `baobab-erp` |
| CMS roles | `baobab-cms` |
| infrastructure privileges | `infrastructure` |
| cross-system contracts | `shared` |

---

# 120. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend contracts for:

```text id="cw5fxs"
workforce membership
actor type
authentication assurance
privileged access events
membership lifecycle
delegated actor metadata
```

without attempting to centralize engine-native permission catalogues.

---

# 121. Production-Readiness Checklist

Workforce IAM SHALL not be considered production-ready until:

- named workforce identities are used;
- shared admin accounts are removed or formally controlled;
- CP administration uses SSO;
- Medusa administration uses SSO where supported;
- iDempiere SSO is integrated;
- CMS administration uses SSO where supported;
- MFA is mandatory for privileged users;
- privileged-client policies are differentiated;
- joiner/mover/leaver workflow exists;
- offboarding revokes domain roles;
- executive access is explicitly scoped;
- break-glass procedure exists;
- break-glass use is audited;
- access-review capability exists;
- privilege grants/revocations are auditable;
- no universal daily-use superuser is required.

---

# 122. Architectural Invariants

The following become binding:

```text id="vnvrc7"
One Workforce Identity ≠ Universal Privilege

SSO ≠ Shared Authorization

Executive ≠ Superuser

IAM Admin ≠ CP Admin

CP Admin ≠ ERP Admin

ERP Admin ≠ Trade Admin

Trade Admin ≠ CMS Admin

Authentication Recovery ≠ Privilege Recovery

Workforce Membership ≠ Canonical Identity

Employment End ≠ Canonical Identity Deletion

MFA Reset ≠ Authorization Grant

Break-Glass ≠ Routine Administration

Shared Admin Account ≠ Acceptable Default
```

---

# 123. Target Workforce Architecture

```text id="2yfkxz"
                         BAOBAB IAM
                     Workforce SSO + MFA
                             │
                             ▼
                    CanonicalIdentity
                             │
                       BAOBAB CP
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
          CP Admin        Trade Admin      ERP
          Context         Domain roles    AD_User
              │              │            AD_Role
              │              │
              ▼              ▼
         Tenant scope      Medusa
              │
              └──────────────┬──────────────┐
                             ▼              ▼
                            CMS       Executive views
```

The identity is shared.

The privileges are not.

---

# 124. Decision Flow

```text id="3rphn1"
WORKFORCE USER
      │
      ▼
Authenticate with Baobab IAM
      │
      ▼
Required MFA satisfied?
      │
      ├── NO ─────────────► DENY
      │
      ▼ YES
Is workforce membership active?
      │
      ├── NO ─────────────► DENY
      │
      ▼ YES
Is requested application/context allowed?
      │
      ├── NO ─────────────► DENY
      │
      ▼ YES
Does application/domain role permit action?
      │
      ├── NO ─────────────► DENY
      │
      ▼ YES
If sensitive, is step-up sufficient/recent?
      │
      ├── NO ─────────────► STEP-UP / DENY
      │
      ▼ YES
ALLOW
```

---

# 125. Decision Summary

Baobab SHALL provide centralized SSO for workforce identities without centralizing every privilege.

The authorization pattern is:

```text id="fy8vmn"
WHO?
  │
  ▼
Baobab IAM

WHERE MAY THEY OPERATE?
  │
  ▼
Baobab Control Plane

WHAT MAY THEY DO?
  │
  ▼
Application / Domain Engine
```

Privileged workforce accounts SHALL receive stronger controls, including mandatory MFA, explicit role assignment, auditable access, coordinated lifecycle management and controlled emergency access.

Nabhold executives may receive broad visibility without automatically receiving broad operational power.

The governing principle is:

> **Baobab shall centralize workforce authentication, decentralize business privilege to the proper authority, and ensure that every privileged action remains attributable to a named human identity.**