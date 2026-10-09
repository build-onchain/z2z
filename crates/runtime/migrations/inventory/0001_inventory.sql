-- Native inventory accounting is separate from the market credit ledger.
-- IDs are caller-selected scope labels, not authentication or money authority.
CREATE TABLE inventory_scopes (
    actor BYTEA NOT NULL CHECK (pg_catalog.octet_length(actor) = 32),
    asset BYTEA NOT NULL CHECK (pg_catalog.octet_length(asset) = 32),
    deployment BYTEA NOT NULL CHECK (pg_catalog.octet_length(deployment) = 32),
    PRIMARY KEY (actor, asset, deployment)
);

CREATE TABLE reservations (
    actor BYTEA NOT NULL CHECK (pg_catalog.octet_length(actor) = 32),
    asset BYTEA NOT NULL CHECK (pg_catalog.octet_length(asset) = 32),
    deployment BYTEA NOT NULL CHECK (pg_catalog.octet_length(deployment) = 32),
    order_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(order_id) = 32),
    context_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(context_digest) = 32),
    -- Unsigned U256, exactly 32 big-endian bytes; never a SQL signed integer.
    amount BYTEA NOT NULL CHECK (pg_catalog.octet_length(amount) = 32),
    CONSTRAINT reservation_amount_nonzero
        CHECK (amount <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')),
    state SMALLINT NOT NULL CHECK (state BETWEEN 0 AND 4),
    operation_id BYTEA CHECK (operation_id IS NULL OR pg_catalog.octet_length(operation_id) = 32),
    unsigned_payload_digest BYTEA CHECK (unsigned_payload_digest IS NULL OR pg_catalog.octet_length(unsigned_payload_digest) = 32),
    transaction_hash BYTEA CHECK (transaction_hash IS NULL OR pg_catalog.octet_length(transaction_hash) = 32),
    PRIMARY KEY (actor, asset, deployment, order_id),
    FOREIGN KEY (actor, asset, deployment) REFERENCES inventory_scopes (actor, asset, deployment),
    UNIQUE (actor, asset, deployment, operation_id),
    CONSTRAINT reservation_funding_shape CHECK (
        (state IN (0, 4) AND operation_id IS NULL AND unsigned_payload_digest IS NULL AND transaction_hash IS NULL)
        OR (state = 1 AND operation_id IS NOT NULL AND unsigned_payload_digest IS NOT NULL AND transaction_hash IS NULL)
        OR (state = 2 AND operation_id IS NOT NULL AND unsigned_payload_digest IS NOT NULL AND transaction_hash IS NOT NULL)
        OR (state = 3 AND operation_id IS NOT NULL AND unsigned_payload_digest IS NOT NULL)
    )
);
