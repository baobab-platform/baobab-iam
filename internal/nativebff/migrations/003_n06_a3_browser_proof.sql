-- Expired rows are cleaned with their BFF session. Revoking the BFF session
-- removes evidence custody even if a proof write races the revocation.
CREATE TABLE IF NOT EXISTS native_bff_a3_proofs (
    id_hash bytea REFERENCES native_bff_sessions(id_hash) ON DELETE CASCADE,
    operation text NOT NULL,
    sealed bytea NOT NULL CHECK (octet_length(sealed) BETWEEN 29 AND 65564),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (id_hash, operation)
);
