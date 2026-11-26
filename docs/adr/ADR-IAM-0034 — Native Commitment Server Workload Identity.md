# ADR-IAM-0034 — Native Commitment Server Workload Identity

**Status:** Proposed. This is IAM's implementation record for ADR-SHARED-042 §14 Decision 9, covering the server workload identity.
**Date:** 2026-10-23
**Governing decision:** Shared ADR-SHARED-042 §14 Decision 9, the Platform Owner ruling of 23 October 2026. Where this record and ADR-SHARED-042 differ, ADR-SHARED-042 governs.
**Original Decision 9 source:** `baobab-platform/shared` at `1517429bcae601a1b0288ca0279e524ce48a3d77` (23 October 2026). The current development consumer inventory is pinned separately at Shared `7f547ccdd759208355ef9224d2177929f4bf224e`, merged through Shared PR #430 on 4 November 2026. That later source reconciles N02/N04/N07 development-only workload and scope declarations; it does not amend Decision 9 or allocate the native-commitment scope.

**Decision 9 canonical contracts at original ruling:**
- `authorization/v1/scope-registry.yaml` `trade:native-commitment:submit` (audience `baobab-trade`, workload actors only, `grants_authority: false`, allocated to no workload);
- `control-plane/v1/estate-resource-assignment.schema.json` (`workloadClientId`).

**Related:** ADR-0007 (workload identity), ADR-IAM-0023 (estate BFF boundary), CP ADR-BCP-031 (governed estate resource assignment).

**Implementation state:** Source rule only. No workload holds the scope and no server application is registered. There is no connected acceptance.

---

## Context

Decision 9 requires every native commitment to carry CP-verified estate provenance:
- commitments from a governed BFF use the estate-client binding;
- commitments from an authenticated server application use a WORKLOAD governed resource assignment, which CP attests after verifying the application's IAM token.

That token must belong to the application itself. A Medusa publishable key, a sales channel and a self-asserted estate are configuration, not identity.

## Decision

IAM issues `trade:native-commitment:submit` only to a narrow server workload (`internal/tokenprofile/native_commitment.go`):

1. **Confidential workload.** The holder uses the `client_credentials` or `federated_workload_token` profile of its pinned Shared workload-registry entry. Humans and keys never qualify.
2. **Canonical client id.** The workload id must match the Shared `workloadClientId` grammar (`^[a-z][a-z0-9-]{2,62}$`), which is what a WORKLOAD assignment names. A publishable key such as `pk_…` can never be one.
3. **Never an estate BFF, never human.** A workload that holds `trade:buyer-handoff` or a `human_token_profile` cannot also hold this scope, and no `human_token_profile` may issue it in human tokens. If one identity held both, the provenance of its commitments (binding or assignment) would be ambiguous.
4. **Trade only.** The registry entry must allow the `baobab-trade` audience, and any token granting the scope must have `baobab-trade` as its only audience. The token cannot be replayed against CP or any other resource. CP checks the same audience and then introspects the token.

IAM grants no authority with this scope. Estate, Tenant, Market and operation come only from CP's governed assignment. Buyer and seller authority stay with Trade.

## Consequences

- Allocating the scope to a real server application needs three separate approved steps: a Shared workload-registry change, an IAM client registration and a CP assignment. Activation needs connected evidence and the Platform Owner's approval. Nothing here allocates or activates.
- `contracts.lock.yaml` and `internal/federation/consume.go` consume the reviewed Shared development inventory at `7f547ccdd759208355ef9224d2177929f4bf224e` (Shared PR #430). This is a source/contract pin only. The N04 gate validates the exact lock, current provider mechanics and development-only scope ceiling; it does not issue credentials, allocate `trade:native-commitment:submit`, register a server application, create a CP assignment or qualify a protected consumer.
- The original Decision 9 contract definitions and the `workloadClientId` grammar remain governed by the 23 October Shared ruling at `1517429bcae601a1b0288ca0279e524ce48a3d77`. The later PR #430 inventory must not be misrepresented as changing that ruling.

## Evidence

`internal/tokenprofile/native_commitment_test.go` covers:
- issuance to a narrow synthetic submitter;
- refusal of a submitter without the Trade audience, of one that is an estate BFF, of a human token profile issuing the scope, and of non-canonical client ids (including `pk_…`);
- refusal of a token for a second audience or another resource;
- the workload's other scopes continuing to work.
