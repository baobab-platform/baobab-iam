# TMS validator/native-workload issuance hold

**State: accepted development design, runtime issuance HELD.** Shared #409 was accepted as design and merged at `84c392105046406f190ee0fe87006ce3510760ef`; it remains outside the active contracts and workload/scope registries. Architecture acceptance does not register an audience, approve credentials or implement CP native authority. IAM ADR-0007, ADR-IAM-0033 and Shared #413's scoped design remain controlling. CP #447 / IAM #141 track actual adoption and connected proof.

This consolidates IAM #142/#143. Config.Validate and direct Config.Claims reject reserved TMS clients (including baobab-dev-tms-*), resource audiences (including suffixes), native tms: scopes, nested human profiles and human scope/audience mappings. Authenticated grant evidence is independently checked. HumanConsent and HumanClaims enforce the same guard even for hand-built Configs. Existing registered unrelated workload and buyer profiles remain supported.

No workload, scope, credential, native operation or provider is activated. Remove the hold only in a separate contract-bound adoption change with an exact active Shared pin, independently registered subject audience and validator relationship, current issuer/Principal/CP source verification, revocation, five-second maximum native claim and positive/negative two-tenant runtime receipts plus teardown. context:validate alone never grants booking purchase authority. No environment bypass exists.

The Platform Owner authorised correction and merge after satisfactory final-head review and passing CI on 29 October 2026. This authorises source corrections only; protected/provider/legal activation remains independently gated.
