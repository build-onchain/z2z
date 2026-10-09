-- Unreleased cutover: legacy stores have no authenticated physical identity.
-- Never synthesize identities or rewrite retained signed history.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ledger_pairs)
       OR EXISTS (SELECT 1 FROM replica_pairs) THEN
        RAISE EXCEPTION 'legacy Kerb enrollment/history lacks authenticated physical inventory identity'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE TABLE ledger_physical_claims (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), note kerb_id NOT NULL,
    source_network SMALLINT NOT NULL CHECK (source_network BETWEEN 1 AND 255),
    source_pool SMALLINT NOT NULL CHECK (source_pool BETWEEN 1 AND 255),
    source_genesis kerb_id NOT NULL, txid kerb_id NOT NULL CHECK (txid <> decode(repeat('00',32),'hex')),
    action_index BIGINT NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
    note_commitment kerb_id NOT NULL CHECK (note_commitment <> decode(repeat('00',32),'hex')),
    nullifier kerb_id NOT NULL CHECK (nullifier <> decode(repeat('00',32),'hex')),
    operation kerb_id NOT NULL, change_intent kerb_id,
    PRIMARY KEY (pair,note),
    UNIQUE (source_network,source_pool,source_genesis,txid,action_index),
    UNIQUE (source_network,source_pool,source_genesis,note_commitment),
    UNIQUE (source_network,source_pool,source_genesis,nullifier),
    UNIQUE (pair,note,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier),
    FOREIGN KEY (pair,change_intent) REFERENCES ledger_intent_records(pair,intent)
);
CREATE TRIGGER ledger_physical_claims_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_physical_claims FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();

ALTER TABLE ledger_inventory
    ADD COLUMN source_network SMALLINT NOT NULL,
    ADD COLUMN source_pool SMALLINT NOT NULL,
    ADD COLUMN source_genesis kerb_id NOT NULL,
    ADD COLUMN txid kerb_id NOT NULL,
    ADD COLUMN action_index BIGINT NOT NULL,
    ADD COLUMN note_commitment kerb_id NOT NULL,
    ADD COLUMN nullifier kerb_id NOT NULL,
    ADD FOREIGN KEY (pair,note,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier)
        REFERENCES ledger_physical_claims(pair,note,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier);
