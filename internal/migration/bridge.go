// Target path: baobab-iam/internal/migration/bridge.go
//
// ProvisionBridge advances ledger rows from DISCOVERED through PROVISIONED
// by calling provider-neutral IdentityProvisioner / WorkloadProvisioner /
// FederatedWorkloadProvisioner (ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022).
//
// Workload policy (post EA-04 / Shared federated_workload_token):
//   - Default WORKLOAD / SERVICE_INTEGRATION path is federated JWT-bearer
//     (RFC 7523). No static OAuth client secret is generated or stored.
//   - Client-secret Hydra clients are M4-C only and require an explicit
//     allow-list entry on the bridge (Shared-authorized secret clients).
//   - AllowedScopes / audiences for federated trust MUST be supplied by the
//     operator from the Shared workload registry — the bridge does not invent
//     platform scopes.
//
// Explicitly does not:
//   - advance past PROVISIONED into credential/verification/cutover
//   - store client secrets, private JWKs, password hashes, or TOTP on the ledger
//   - authorize production CUTOVER (PolicyGate still applies on transitions)
//   - mark Shared workload lifecycle ACTIVE (provider evidence only)
package migration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// SEE_LOCAL_RESTORE
