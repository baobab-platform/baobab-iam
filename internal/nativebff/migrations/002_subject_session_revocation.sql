-- IAM-N02 native BFF global logout index (PostgreSQL 17).
-- One-time migration after 001. Old session rows cannot be indexed without
-- decrypting their source envelope, so drain them rather than silently retain
-- unrevocable sessions. Reapplying is safe: only unindexed rows are removed.
-- Run under an IAM migration role, NOT the runtime service role.
BEGIN;
ALTER TABLE native_bff_sessions ADD COLUMN IF NOT EXISTS subject_hash BYTEA;
DELETE FROM native_bff_sessions WHERE subject_hash IS NULL;
ALTER TABLE native_bff_sessions ALTER COLUMN subject_hash SET NOT NULL;
ALTER TABLE native_bff_sessions DROP CONSTRAINT IF EXISTS native_bff_sessions_subject_hash_size;
ALTER TABLE native_bff_sessions
    ADD CONSTRAINT native_bff_sessions_subject_hash_size
    CHECK (octet_length(subject_hash)=32);
CREATE INDEX IF NOT EXISTS native_bff_sessions_subject_hash ON native_bff_sessions(subject_hash);
COMMIT;
