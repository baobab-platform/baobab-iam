# MP2-C governance target composition

This increment implements the IAM-owned portion of the MP2-C governance source
required by ADR-IAM-0033 while preserving the authority split established by
Shared and the Control Plane.

It does **not** make an ExternalReference, a Control Plane fingerprint, or a
successful HTTP fetch equivalent to approval.

## Authority composition

The final IAM `ApprovalTargets` decision for IAM-owned federation governance
targets is:

```text
ReferenceExpectation
        |
        +----------------------------+
        |                            |
        v                            v
Control Plane                   Baobab IAM
target-registration             NativeTargetLedger
attestation                     immutable native bytes
        |                            |
        | ref/provider/instance      | exact ref/kind/trust revision/
        | org/estate/environment     | snapshot/provider/instance/scope
        | ACTIVE topology            | NON_SECRET classification
        | current fingerprint        | recomputed SHA-256 digest
        |                            |
        +-------------+--------------+
                      |
                      v
             CompositeApprovalTargets
                      |
          digests must match exactly
                      |
                      v
              ApprovalLedger / TrustLedger
```

The Control Plane is read before and after the IAM native target lookup.
Registration or topology drift therefore fails closed rather than composing
evidence from two different target states.

## Control Plane dependency

The companion Control Plane increment exposes:

`POST /internal/federation/v1/target-registration`

under the existing `federation-authority:read` workload boundary.

The endpoint returns only the current SHA-256 fingerprint after validating the
calling IAM workload and the exact governed ExternalReference/provider/
EngineInstance/organisation/Digital Estate/environment tuple. It is
non-approval evidence.

The IAM HTTP client consumes that endpoint through
`TargetRegistrationAuthority`.

## IAM native targets

`NativeTargetLedger` persists immutable non-secret JSON bytes in a protected
single-writer bbolt file. It calculates the digest from the stored bytes and
binds the bytes to the complete `ReferenceExpectation`.

A reference cannot be overwritten with different bytes or a different native
kind. No update or delete operation exists.

The bounded IAM-owned native target set follows the Shared ownership policy:

| Target kind | Native-byte owner in this increment |
| --- | --- |
| `federation_configuration` | IAM |
| `federation_trust_material` | IAM, public/non-secret material only |
| `assurance_policy` | IAM |
| `attribute_mapping` | IAM |
| `provisioning_policy` | IAM |
| `federation_activation` | IAM |
| `assurance_mapping_decision` | IAM |
| `identity_security_domain` | IAM |
| `canonical_identity_mapping` | Control Plane; unsupported by the IAM native-byte ledger |
| `identity_runtime_profile` | Control Plane; unsupported by the IAM native-byte ledger |
| `identity_runtime_support` | Control Plane; unsupported by the IAM native-byte ledger |

The final IAM composite resolver returns `ErrUnsupported` for CP-owned native
target kinds. It does not copy those bytes into IAM and does not reinterpret a
CP registration fingerprint as their native authority. A separately reviewed
owner-native resolver is required before those kinds can participate in this
approval target pipeline.

Secret material is outside this ledger. The `NON_SECRET` classification is an
input contract for the trusted IAM composition root, not a content-inspection
or DLP claim. Secrets and private keys remain in the platform secret boundary.

## Trust snapshot binding

`RegisterTrustSnapshotTarget` is the only supported
`federation_activation` writer in this increment.

It stores the canonical JSON representation of the exact
`TrustSnapshot` and verifies:

```text
native target digest == TrustSnapshotDigest(candidate)
```

The expectation must match the snapshot's:

- trust ID;
- approved revision;
- snapshot ID;
- provider ID;
- EngineInstance ID;
- organisation;
- Digital Estate.

This preserves the pre-existing `TrustLedger.Propose` and
`TrustLedger.Decide` invariant that a trust lifecycle approval cannot authorize
unrelated activation bytes.

## Proposal, decision and use

The same `CompositeApprovalTargets` instance is injected into:

- `ApprovalLedger.Propose`;
- `ApprovalLedger.Decide`;
- `ApprovalLedger.Reference` (consumption/use);
- `TrustLedger.Propose`;
- `TrustLedger.Decide`.

Consequently a target that drifts in CP, changes native bytes, loses its exact
trust-revision/snapshot binding, or becomes unavailable cannot be approved or
consumed using a stale receipt.

`GovernanceComposition` opens and wires:

```text
NativeTargetLedger
       |
       +--> CompositeApprovalTargets <--- CP TargetRegistrationAuthority
                         |
             +-----------+-----------+
             |                       |
             v                       v
       ApprovalLedger            TrustLedger
             |                       |
             +------ receipts -------+
```

The three durable files must be distinct.

## Private authority service

`NewAuthorityHandler` already exposes
`/internal/federation/v1/target` when its `AuthoritySources.Targets` is
configured. With this increment, IAM can mount that route with
`CompositeApprovalTargets`; the route then represents the **final IAM composite
resolver**, not a direct proxy to CP.

The existing `HTTPAuthority.ResolveApprovedTarget` remains the remote client
for that IAM-owned final route. It must not be configured to treat the Control
Plane as the final `/target` authority.

## Verification

Tests cover:

- immutable native bytes and restart;
- digest recomputation;
- rejection of IAM storage for CP-owned native targets;
- Shared ownership split;
- exact TrustSnapshot digest binding;
- CP/native digest mismatch;
- CP registration drift between the two reads;
- proposal, four-eyes decision and receipt use through the composite resolver;
- failure of receipt use after CP drift;
- authenticated private target-registration transport;
- composition-root configuration and distinct durable ledger files.

## Remaining production gates

This is repository/runtime composition, not production activation.

Still required before production consumption:

1. deploy the IAM federation-authority executable/service and mount the
   `GovernanceComposition` with real CP Hydra-authenticated private authority
   clients;
2. populate reviewed IAM native target bytes and register matching CP
   ExternalReference fingerprints through an approved provisioning/
   reconciliation workflow;
3. provide owner-native resolution for CP-owned governed target kinds where the
   approval workflow requires them;
4. wire live OIDC configuration, assurance policy and Keycloak broker evidence;
5. retain encrypted durable state, backup/restore fencing and single-writer
   guarantees or replace the local bbolt ledgers with a reviewed HA store;
6. complete SAML verification, provider resolver/registry and operational
   acceptance gates.

No provider is activated by this increment. Keycloak remains the bounded
enterprise federation provider; canonical identity, tenancy, platform binding
and business authorization remain outside Keycloak and outside these ledgers.
