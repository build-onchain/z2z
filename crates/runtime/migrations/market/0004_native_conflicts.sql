CREATE TABLE ledger_change_reservations (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), note kerb_id NOT NULL,
    intent kerb_id NOT NULL, PRIMARY KEY (pair,note)
);
CREATE TRIGGER ledger_change_reservations_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON ledger_change_reservations FOR EACH STATEMENT EXECUTE FUNCTION kerb_append_only();
