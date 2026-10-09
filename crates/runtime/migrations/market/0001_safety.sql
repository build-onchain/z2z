-- Full-u64 values remain exact decimal NUMERIC. Source facts are authenticated
-- policy testimony, never a database-derived chain/history proof.
CREATE DOMAIN kerb_u64 AS NUMERIC(20,0)
    CHECK (VALUE >= 0 AND VALUE <= 18446744073709551615);
CREATE DOMAIN kerb_id AS BYTEA CHECK (octet_length(VALUE) = 32);
CREATE DOMAIN kerb_receiver AS BYTEA CHECK (octet_length(VALUE) = 43);

CREATE TABLE ledger_pairs (
    pair kerb_id PRIMARY KEY, policy BYTEA NOT NULL,
    writer_generation kerb_u64 NOT NULL DEFAULT 0,
    head kerb_id NOT NULL, target_head kerb_id NOT NULL,
    sequence kerb_u64 NOT NULL DEFAULT 0,
    impaired BOOLEAN NOT NULL DEFAULT FALSE,
    halt SMALLINT NOT NULL DEFAULT 0 CHECK (halt IN (0,1))
);
CREATE TABLE ledger_versions (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), entity kerb_id NOT NULL,
    portion kerb_id NOT NULL, version kerb_u64 NOT NULL DEFAULT 0,
    reservation kerb_id, PRIMARY KEY (pair,entity,portion)
);
CREATE TABLE ledger_journal (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), operation kerb_id NOT NULL,
    sequence kerb_u64 NOT NULL, predecessor kerb_id NOT NULL, next_head kerb_id NOT NULL,
    writer_generation kerb_u64 NOT NULL, body BYTEA NOT NULL,
    PRIMARY KEY (pair,operation), UNIQUE (pair,sequence), UNIQUE (pair,next_head)
);
CREATE TABLE ledger_commits (
    pair kerb_id NOT NULL, operation kerb_id NOT NULL, certificate BYTEA NOT NULL,
    PRIMARY KEY (pair,operation), FOREIGN KEY (pair,operation) REFERENCES ledger_journal(pair,operation)
);
CREATE TABLE ledger_credits (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), credit kerb_id NOT NULL,
    claimant kerb_id NOT NULL, amount kerb_u64 NOT NULL CHECK (amount > 0),
    available kerb_u64 NOT NULL CHECK (available <= amount), note kerb_id NOT NULL,
    source_network SMALLINT NOT NULL, source_pool SMALLINT NOT NULL,
    source_genesis kerb_id NOT NULL, txid kerb_id NOT NULL,
    action_index BIGINT NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
    claim BYTEA NOT NULL, PRIMARY KEY (pair,credit), UNIQUE (pair,note),
    UNIQUE (source_network,source_pool,source_genesis,txid,action_index)
);
CREATE TABLE ledger_holds (
    pair kerb_id NOT NULL, hold kerb_id NOT NULL, credit kerb_id NOT NULL,
    amount kerb_u64 NOT NULL CHECK (amount > 0), refund_receiver kerb_receiver NOT NULL,
    disposition SMALLINT NOT NULL CHECK (disposition IN (2,3,5,6,7,14)),
    PRIMARY KEY (pair,hold), FOREIGN KEY (pair,credit) REFERENCES ledger_credits(pair,credit)
);
CREATE TABLE ledger_allocations (
    pair kerb_id NOT NULL, hold kerb_id NOT NULL, allocation kerb_id NOT NULL,
    body BYTEA NOT NULL, active BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (pair,hold), UNIQUE (pair,allocation),
    FOREIGN KEY (pair,hold) REFERENCES ledger_holds(pair,hold)
);
CREATE TABLE ledger_allocation_chunks (
    pair kerb_id NOT NULL, hold kerb_id NOT NULL, chunk_index BIGINT NOT NULL,
    digest kerb_id NOT NULL, authenticated BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (pair,hold,chunk_index),
    FOREIGN KEY (pair,hold) REFERENCES ledger_allocations(pair,hold)
);
CREATE TABLE ledger_portions (
    pair kerb_id NOT NULL, hold kerb_id NOT NULL, portion kerb_id NOT NULL,
    allocation kerb_id NOT NULL, offset_amount kerb_u64 NOT NULL,
    amount kerb_u64 NOT NULL CHECK (amount > 0), kind SMALLINT NOT NULL CHECK (kind IN (1,2)),
    native_recipient kerb_receiver NOT NULL, spl_recipient kerb_id NOT NULL,
    base_atoms kerb_u64 NOT NULL, disposition SMALLINT NOT NULL CHECK (disposition BETWEEN 1 AND 15),
    active BOOLEAN NOT NULL DEFAULT FALSE, live_intent kerb_id,
    PRIMARY KEY (pair,hold,portion), UNIQUE (pair,portion),
    FOREIGN KEY (pair,hold) REFERENCES ledger_allocations(pair,hold)
);
CREATE TABLE ledger_inventory (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), note kerb_id NOT NULL,
    scope kerb_id NOT NULL, receiver kerb_receiver NOT NULL,
    amount kerb_u64 NOT NULL CHECK (amount > 0), origin SMALLINT NOT NULL CHECK (origin IN (1,2,3)),
    parent_intent kerb_id, status SMALLINT NOT NULL CHECK (status IN (1,2,3,4,5)),
    live_intent kerb_id, facts BYTEA NOT NULL,
    PRIMARY KEY (pair,note)
);
CREATE TABLE ledger_intent_records (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), intent kerb_id NOT NULL,
    hold kerb_id NOT NULL, portion kerb_id NOT NULL, kind SMALLINT NOT NULL CHECK (kind IN (1,2,3)),
    transaction kerb_id NOT NULL, nonce kerb_id NOT NULL, plan BYTEA NOT NULL,
    PRIMARY KEY (pair,intent), UNIQUE (pair,transaction), UNIQUE (pair,nonce)
);
CREATE TABLE ledger_intent_states (
    pair kerb_id NOT NULL, intent kerb_id NOT NULL,
    status SMALLINT NOT NULL CHECK (status BETWEEN 1 AND 5),
    PRIMARY KEY (pair,intent), FOREIGN KEY (pair,intent) REFERENCES ledger_intent_records(pair,intent)
);
CREATE TABLE ledger_nonce_tombstones (
    pair kerb_id NOT NULL, nonce kerb_id NOT NULL, intent kerb_id NOT NULL,
    PRIMARY KEY (pair,nonce), FOREIGN KEY (pair,intent) REFERENCES ledger_intent_records(pair,intent)
);
CREATE TABLE ledger_consumptions (
    pair kerb_id NOT NULL, note kerb_id NOT NULL, intent kerb_id NOT NULL, transaction kerb_id NOT NULL,
    PRIMARY KEY (pair,note), FOREIGN KEY (pair,note) REFERENCES ledger_inventory(pair,note),
    FOREIGN KEY (pair,intent) REFERENCES ledger_intent_records(pair,intent)
);
CREATE TABLE ledger_native_observations (
    pair kerb_id NOT NULL, operation kerb_id NOT NULL, intent kerb_id NOT NULL, facts BYTEA NOT NULL,
    PRIMARY KEY (pair,operation), FOREIGN KEY (pair,intent) REFERENCES ledger_intent_records(pair,intent)
);

-- Replica databases are independently provisioned and retain their own enrollment,
-- exact bytes and signed head. No coordinator reset operation exists.
CREATE TABLE replica_pairs (
    pair kerb_id PRIMARY KEY, policy BYTEA NOT NULL, head kerb_id NOT NULL,
    target_head kerb_id NOT NULL, sequence kerb_u64 NOT NULL DEFAULT 0,
    writer_generation kerb_u64 NOT NULL DEFAULT 0
);
CREATE TABLE replica_journal (
    pair kerb_id NOT NULL REFERENCES replica_pairs(pair), operation kerb_id NOT NULL,
    sequence kerb_u64 NOT NULL, predecessor kerb_id NOT NULL, next_head kerb_id NOT NULL,
    body BYTEA NOT NULL, PRIMARY KEY (pair,operation), UNIQUE (pair,sequence), UNIQUE (pair,next_head)
);
CREATE TABLE replica_intents (
    pair kerb_id NOT NULL REFERENCES replica_pairs(pair), intent kerb_id NOT NULL,
    nonce kerb_id NOT NULL, transaction kerb_id NOT NULL, body BYTEA NOT NULL,
    PRIMARY KEY (pair,intent), UNIQUE (pair,nonce), UNIQUE (pair,transaction)
);
CREATE FUNCTION kerb_append_only() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Kerb retained history is append-only' USING ERRCODE = '23514'; END;
$$;
CREATE TRIGGER ledger_journal_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_journal FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_commits_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_commits FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_intents_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_intent_records FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_nonces_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_nonce_tombstones FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_consumptions_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_consumptions FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_native_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_native_observations FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER replica_journal_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON replica_journal FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER replica_intents_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON replica_intents FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
