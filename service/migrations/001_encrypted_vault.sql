-- The host sees vault identifiers and ciphertext lengths, but no application state.
CREATE TABLE IF NOT EXISTS encrypted_vault_state (
    vault_id BYTEA PRIMARY KEY CHECK (octet_length(vault_id) = 32),
    ciphertext BYTEA NOT NULL
);
