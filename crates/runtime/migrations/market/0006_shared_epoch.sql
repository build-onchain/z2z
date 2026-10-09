CREATE TABLE ledger_epoch_terminal (
    pair kerb_id PRIMARY KEY REFERENCES ledger_pairs(pair),
    decision BYTEA NOT NULL,
    private_operation kerb_id NOT NULL,
    outcome SMALLINT NOT NULL CHECK (outcome IN (1,2))
);
CREATE TRIGGER ledger_epoch_terminal_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_epoch_terminal FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
