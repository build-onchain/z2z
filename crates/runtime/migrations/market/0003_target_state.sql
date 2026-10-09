ALTER TABLE ledger_pairs ADD COLUMN target_generation kerb_u64;
ALTER TABLE ledger_pairs ADD COLUMN target_result kerb_id;
ALTER TABLE ledger_pairs ADD COLUMN target_activation_journal kerb_id;
CREATE TABLE ledger_target_versions (
    pair kerb_id NOT NULL REFERENCES ledger_pairs(pair), entity kerb_id NOT NULL,
    version kerb_u64 NOT NULL, PRIMARY KEY (pair,entity)
);
