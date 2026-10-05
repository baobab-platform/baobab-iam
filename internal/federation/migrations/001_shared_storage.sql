-- Applied by a migration administrator, never implicitly by the runtime.
CREATE TABLE IF NOT EXISTS iam_federation_control (
 namespace text PRIMARY KEY,
 epoch text NOT NULL CHECK (epoch ~ '^[a-zA-Z0-9_-]{1,64}$'),
 version integer NOT NULL CHECK (version = 1)
);
CREATE TABLE IF NOT EXISTS iam_federation_records (
 namespace text NOT NULL REFERENCES iam_federation_control(namespace),
 ledger text NOT NULL,
 bucket text NOT NULL,
 key bytea NOT NULL,
 value bytea NOT NULL,
 PRIMARY KEY(namespace,ledger,bucket,key)
);
-- Provision a namespace and externally pinned epoch explicitly after migration.
-- INSERT INTO iam_federation_control VALUES ('<namespace>','<epoch>',1);
-- Recovery archive is accessible only to backup/recovery administrators.
CREATE TABLE IF NOT EXISTS iam_federation_recovery_archive (
 recovered_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 namespace text NOT NULL,
 previous_epoch text NOT NULL,
 ledger text NOT NULL,
 bucket text NOT NULL,
 key bytea NOT NULL,
 value bytea NOT NULL
);
