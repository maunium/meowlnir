-- v3 (compatible with v1+): Store policy server signatures
CREATE TABLE policy_server_signature (
    event_id   TEXT NOT NULL,
    signature  TEXT NOT NULL,
    created_at BIGINT NOT NULL,

    PRIMARY KEY (event_id)
);
