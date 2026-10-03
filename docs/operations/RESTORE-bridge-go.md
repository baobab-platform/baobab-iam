# EMERGENCY: restore `internal/migration/bridge.go`

During Gate 2 work on `feat/ory-migrations-contd`, an incomplete Contents API
write truncated `internal/migration/bridge.go` (header + package only).

## Restore (pick one)

### A. From last good commit on this branch

```bash
git fetch origin
git checkout feat/ory-migrations-contd
git checkout c1f96cf -- internal/migration/bridge.go
# optional: re-apply LifecycleStatus=PROVISIONED on M4-C and M4-F specs
git commit -m "fix(migration): restore ProvisionBridge from c1f96cf"
git push
```

### B. From project artifacts

Copy `artifacts/ory-migration-restore/bridge.go` over
`internal/migration/bridge.go`, then commit and push.

## Verify

```bash
go test ./internal/migration/ -count=1
```

Do **not** open a PR until this file is restored.
