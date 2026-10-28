# TMS validator/native-workload proposal — issuance hold

**State: engineering pre-acceptance, no token or client provisioned.** IAM ADR-0007 and ADR-IAM-0033 apply. Shared PR #409 is proposed and not accepted, and CP #447 and IAM #141 are authority requests, not approvals.

The canonical IAM token profile rejects candidate TMS client IDs (baobab-tms and baobab-tms-*), TMS resource audience (baobab-tms), and unaccepted tms: scopes at both Config.Validate and Config.Claims. Config.Claims is independently checked even when a caller constructs an unsafe configuration without calling Validate. AdmitRequest invokes both. This does not deny unrelated registered workloads using their existing scopes and audiences.

This source does not allocate a Shared workload or scope, add a validator, issue credentials or promote an identity lifecycle. The hold must remain until Shared accepts the precise IAM and CP contract, including development-isolated TMS validator with CP audience, context:validate and validates_audiences, distinct TMS subject audience and an independently approved CP-native execution authority. Context validation alone cannot authorize carrier booking.

After acceptance, change the hold in a separate reviewed PR with exact Shared pin adoption, trusted issuer profile, independently verified subject and scope, revocation and runtime CP A/B positive and wrong-tenant/market/issuer/lease negatives. There is no opt-in environment bypass.

CI tests active-looking candidate misconfigurations through both Validate and Claims while proving an unrelated workload still passes. No PR may be merged until the user explicitly authorises it.
