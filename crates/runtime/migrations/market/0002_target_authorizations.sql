ALTER TABLE ledger_holds ADD COLUMN target_binding BYTEA;
ALTER TABLE ledger_portions RENAME COLUMN base_atoms TO target_base_amount;
ALTER TABLE ledger_portions ADD COLUMN target_base_offset kerb_u64 NOT NULL DEFAULT 0;
ALTER TABLE ledger_portions ADD COLUMN fill_fence kerb_id;
ALTER TABLE ledger_pairs ADD COLUMN target_inflight kerb_id;
ALTER TABLE ledger_pairs ADD COLUMN authorized_target_head kerb_id;
ALTER TABLE replica_pairs ADD COLUMN authorized_target_head kerb_id;
CREATE TABLE ledger_target_authorizations (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), target_operation kerb_id NOT NULL,
    private_operation kerb_id NOT NULL, hold kerb_id NOT NULL, portion kerb_id NOT NULL,
    decision BYTEA NOT NULL, payload BYTEA NOT NULL, accounts BYTEA NOT NULL,
    PRIMARY KEY (pair,target_operation), UNIQUE (pair,private_operation)
);
CREATE TABLE ledger_target_observations (
    pair kerb_id NOT NULL, target_operation kerb_id NOT NULL,
    private_operation kerb_id NOT NULL, facts BYTEA NOT NULL,
    PRIMARY KEY (pair,target_operation), UNIQUE (pair,private_operation),
    FOREIGN KEY (pair,target_operation) REFERENCES ledger_target_authorizations(pair,target_operation)
);
CREATE TRIGGER ledger_target_authorizations_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_target_authorizations FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
CREATE TRIGGER ledger_target_observations_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_target_observations FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
