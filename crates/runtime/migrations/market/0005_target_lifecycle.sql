ALTER TABLE ledger_holds ADD COLUMN target_return_intent kerb_id;
ALTER TABLE ledger_holds ADD COLUMN target_returned BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ledger_portions ADD COLUMN first_leg_intent kerb_id;
ALTER TABLE ledger_portions ADD COLUMN custody_fence kerb_id;
ALTER TABLE ledger_portions ADD COLUMN target_return_intent kerb_id;
ALTER TABLE ledger_portions ADD COLUMN target_returned BOOLEAN NOT NULL DEFAULT FALSE;
