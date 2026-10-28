# HYB-04 — IAM-side TMS workload issuance hold

**Status:** Engineering denial, not a workload registration or active IAM token. Shared #409 remains PROPOSED and is not an accepted contract. CP companion #448 is also non-authorising. IAM owner decision: #141.

## Accepted boundaries

The current Shared workload registry has no baobab-tms or baobab-dev-tms-validator client. It also has no TMS-native scope allocation. The existing context:validate scope is an audience-specific resource-server check, NOT native carrier booking authority. Actual tenant/legal actor/market/capability authority remains with CP and the relevant domain service.

## Changes

The new internal/tokenprofile/tms_authority_hold.go guard is integrated into both Config.Validate and the separately callable Config.Claims path. This prevents a forged or unreviewed projected workload from minting a native TMS audience/scope or provisional TMS workload identity, including on a direct provider hook path that bypasses canonical AdmitRequest. It checks client IDs, native scope prefixes, resource-server and human audiences. Existing unrelated CP validators and context:validate allocations remain valid.

These denials may only be amended when Shared has formally accepted and published TMS-specific workload registration/scope contracts and the owning IAM and CP implementations are independently reviewed. There is NO environment switch, test bypass, provisional token minting or automatic acceptance of proposed Shared #409.

## Acceptance and non-claims

Tests exercise a hypothetical ACTIVE TMS profile, dev validator client, foreign client claiming a TMS resource-server audience, forged native command scope, direct Config.Claims, canonical AdmitRequest, and unaffected existing workloads. They are synthetic tests and DO NOT issue real OAuth tokens or prove CP integration.

Next owner gates: accepted Shared registration, supported IAM workload credentials, independent CP validator relationship, actual native legal/market/operation grant, revoked/wrong-audience negative evidence, disposable IAM-to-CP A/B runtime and teardown. TMS #26 remains permanently UNVERIFIED until this is established.

**Merge hold:** user expressly forbids merging any PR without a further instruction.
