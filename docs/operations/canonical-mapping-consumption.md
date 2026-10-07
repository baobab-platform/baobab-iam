# Owner-aware canonical mapping consumption

Authority: ADR-IAM-0033 MP2/MP11 and Shared federation-authority-policy.yaml.

Deploy the coordinated CP target-registration correction before this IAM build.
Keep CP and IAM engine-instance identifiers distinct: the mapping reference
belongs to a live CP instance; its approved federation provider binding belongs
to a live IAM instance in the same environment and organisation/estate scope.
Never re-register a CP mapping under IAM to satisfy an instance check.

The executable supplies the protected CP authority as both registration and
canonical evidence source. For each proposed, checked and consumed approval,
IAM reads current registration, resolves exact issuer/subject through CP,
checks the exact ref/principal/external identity and active human relationship,
recomputes the canonical evidence digest, and reads registration again. The
maker/checker decision pins the full expectation and digest. Changed evidence,
expired receipts, revoked references, missing authority and transport failure
deny. No email linking, cached approval shortcut or provider fallback exists.

Registration is source evidence. IAM's approval receipt grants permission to
consume the evidence for its exact trust revision/snapshot/provider/scope. It
does not change CP mapping ownership or create platform grants.

Construction checks:

```sh
go test ./...
go test -race ./internal/federation ./cmd/federation-authority
go vet ./...
python3 -m unittest discover -s tests/unit
```

CP's existing PostgreSQL 17 CI runs the mapping target regression, including
owner/provider instance separation, wrong issuer/subject/principal/reference/
scope/instance, stale fingerprint, revoked identity/reference, freshness and
retired owner instance. These database tests skip without TEST_DATABASE_URL;
record a skip as not run, never passed database evidence.

Staging acceptance still requires approved account configuration, IAM/CP
registered workload identities, protected authority endpoints, provider support
and runtime bindings, human administrative grants, reviewed trust material,
approved mapping references, browser/BFF correlation and a registered estate.
Use the existing vX.Y.Z-staging process only after those inputs are approved.
Do not activate a trust or provider to manufacture acceptance evidence.

Multi-replica recovery and operational revocation latency must be measured in
the deployed composition. Bracketed reads reject observed drift; distributed
reads do not claim linearizable cross-service revocation or production HA.
