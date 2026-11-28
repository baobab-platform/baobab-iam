-- A reserved attempt is intentionally retained after uncertain provider outcomes.
CREATE TABLE IF NOT EXISTS iam_admin.breakglass_workload_execution (
    lease_id uuid PRIMARY KEY REFERENCES iam_admin.breakglass_lease (lease_id),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    verified_at timestamptz,
    denial_reference text,
    CHECK ((verified_at IS NULL) = (denial_reference IS NULL)),
    CHECK (verified_at >= started_at)
);
