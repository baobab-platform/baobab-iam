-- Execute with psql -X -v ON_ERROR_STOP=1 using a protected libpq service file.
-- Required non-secret variables: namespace, old_epoch, new_epoch.
-- Recovery deliberately requires fresh human governance approvals and login.
\set ON_ERROR_STOP on
BEGIN;
SELECT namespace AS fenced_namespace
FROM iam_federation_control
WHERE namespace = :'namespace' AND epoch = :'old_epoch'
  AND :'new_epoch' <> :'old_epoch'
FOR UPDATE
\gset
-- \gset requires exactly one row; an absent/mismatched epoch aborts recovery.
INSERT INTO iam_federation_recovery_archive(namespace,previous_epoch,ledger,bucket,key,value)
SELECT namespace, :'old_epoch', ledger, bucket, key, value
FROM iam_federation_records WHERE namespace = :'namespace';
-- Preserve immutable native target material, not resurrected approval authority.
DELETE FROM iam_federation_records WHERE namespace = :'namespace' AND ledger <> 'native';
UPDATE iam_federation_control SET epoch = :'new_epoch' WHERE namespace = :'namespace';
COMMIT;
