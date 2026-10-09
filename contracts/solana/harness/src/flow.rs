use crate::wire::*;
use crate::{old, system_program, token_program, Fixture, PROGRAM};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;

pub const EPOCH_NUMBER: u64 = 1;

impl Fixture {
    pub fn epoch_key(&self) -> Address {
        epoch(self.pair, EPOCH_NUMBER)
    }
    pub fn hold_key(&self) -> Address {
        hold(self.epoch_key(), HOLD_ID)
    }
    pub fn escrow_key(&self) -> Address {
        escrow(self.hold_key())
    }
    pub fn filled_key(&self) -> Address {
        portion(self.hold_key(), FILLED_ID)
    }
    pub fn unused_key(&self) -> Address {
        portion(self.hold_key(), UNUSED_ID)
    }
    pub fn version(&self, key: Address, offset: usize) -> u64 {
        le_u64(&self.svm.get_account(&key).unwrap().data[offset..offset + 8])
    }
    pub fn initialized(&mut self) {
        self.send(&[self.initialize_instruction()], false)
            .expect("InitializePair");
    }
    pub fn open_instruction(&self) -> Vec<Instruction> {
        self.decision(
            2,
            EPOCH_NUMBER,
            (self.epoch_key(), None),
            (0, [2; 32]),
            EPOCH_NUMBER.to_le_bytes().to_vec(),
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                w(self.pair),
                w(self.epoch_key()),
                r(system_program()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn open(&mut self) {
        self.send(&self.open_instruction(), false)
            .expect("unanimous OpenEpoch");
    }
    pub fn lock_instruction(&self) -> Instruction {
        let mut data = vec![3];
        data.extend_from_slice(&HOLD_ID);
        data.extend_from_slice(&self.amounts.maximum.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        Instruction {
            program_id: PROGRAM,
            data,
            accounts: vec![
                AccountMeta::new(self.seller.pubkey(), true),
                r(self.pair),
                w(self.epoch_key()),
                w(self.hold_key()),
                w(self.escrow_key()),
                w(self.seller_token),
                r(self.mint),
                r(token_program()),
                r(system_program()),
            ],
        }
    }
    pub fn lock(&mut self) {
        self.send(&[self.lock_instruction()], true)
            .expect("actual seller transfer_checked into PDA escrow");
    }
    pub fn prepare_instruction(&self) -> Vec<Instruction> {
        self.decision(
            4,
            EPOCH_NUMBER,
            (self.hold_key(), None),
            (self.version(self.hold_key(), 181), [4; 32]),
            vec![],
            vec![
                w(self.pair),
                w(self.epoch_key()),
                w(self.hold_key()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn prepare(&mut self) {
        self.send(&self.prepare_instruction(), false)
            .expect("unanimous PrepareSeller");
    }
    pub fn commit_instruction(&self) -> Vec<Instruction> {
        self.decision(
            6,
            EPOCH_NUMBER,
            (self.epoch_key(), None),
            (self.version(self.epoch_key(), 49), [6; 32]),
            RESULT.to_vec(),
            vec![w(self.pair), w(self.epoch_key()), r(INSTRUCTIONS_SYSVAR)],
        )
        .0
    }
    pub fn commit(&mut self) {
        self.send(&self.commit_instruction(), false)
            .expect("immutable CommitEpoch");
    }
    pub fn abort_instruction(&self) -> Vec<Instruction> {
        self.decision(
            7,
            EPOCH_NUMBER,
            (self.epoch_key(), None),
            (self.version(self.epoch_key(), 49), [7; 32]),
            vec![],
            vec![w(self.pair), w(self.epoch_key()), r(INSTRUCTIONS_SYSVAR)],
        )
        .0
    }
    pub fn allocation_instruction(&self, filled: bool) -> Vec<Instruction> {
        let id = if filled { FILLED_ID } else { UNUSED_ID };
        let key = if filled {
            self.filled_key()
        } else {
            self.unused_key()
        };
        let mut payload = id.to_vec();
        payload.extend_from_slice(&(if filled { 0u64 } else { self.amounts.filled }).to_le_bytes());
        payload.extend_from_slice(
            &(if filled {
                self.amounts.filled
            } else {
                self.amounts.unused
            })
            .to_le_bytes(),
        );
        payload.push(if filled { 1 } else { 2 });
        payload.extend_from_slice(&RESULT);
        self.decision(
            8,
            EPOCH_NUMBER,
            (self.hold_key(), Some(key)),
            (self.version(self.hold_key(), 181), id),
            payload,
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                w(self.pair),
                w(self.epoch_key()),
                w(self.hold_key()),
                w(key),
                r(if filled {
                    self.buyer_token
                } else {
                    self.seller_token
                }),
                r(self.mint),
                r(token_program()),
                r(system_program()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn record(&mut self, filled: bool) {
        self.send(&self.allocation_instruction(filled), false)
            .expect("authenticated authority allocation chunk");
    }
    pub fn activate_instruction(&self) -> Vec<Instruction> {
        let mut payload = RESULT.to_vec();
        payload.extend_from_slice(&JOURNAL);
        self.decision(
            9,
            EPOCH_NUMBER,
            (self.epoch_key(), None),
            (self.version(self.epoch_key(), 49), [9; 32]),
            payload,
            vec![w(self.pair), w(self.epoch_key()), r(INSTRUCTIONS_SYSVAR)],
        )
        .0
    }
    pub fn activate(&mut self) {
        self.send(&self.activate_instruction(), false)
            .expect("complete allocation activation");
    }
    pub fn prepare_fill_instruction(&self) -> Vec<Instruction> {
        let mut payload = self.amounts.filled.to_le_bytes().to_vec();
        payload.extend_from_slice(&JOURNAL);
        payload.extend_from_slice(&FENCE);
        self.decision(
            10,
            EPOCH_NUMBER,
            (self.filled_key(), Some(self.filled_key())),
            (self.version(self.filled_key(), 153), FIRST_LEG_INTENT),
            payload,
            vec![
                w(self.pair),
                r(self.epoch_key()),
                r(self.hold_key()),
                w(self.filled_key()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn prepare_fill(&mut self) {
        self.send(&self.prepare_fill_instruction(), false)
            .expect("exact first-leg preparation");
    }
    pub fn release_instruction(&self) -> Vec<Instruction> {
        let mut payload = self.amounts.filled.to_le_bytes().to_vec();
        payload.extend_from_slice(&RESULT);
        payload.extend_from_slice(&FENCE);
        self.decision(
            11,
            EPOCH_NUMBER,
            (self.filled_key(), Some(self.filled_key())),
            (self.version(self.filled_key(), 153), FIRST_LEG_INTENT),
            payload,
            vec![
                w(self.pair),
                r(self.epoch_key()),
                w(self.hold_key()),
                w(self.filled_key()),
                w(self.escrow_key()),
                r(self.mint),
                w(self.buyer_token),
                r(token_program()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn cancel_instruction(&self) -> Vec<Instruction> {
        self.decision(
            12,
            EPOCH_NUMBER,
            (self.filled_key(), Some(self.filled_key())),
            (self.version(self.filled_key(), 153), FIRST_LEG_INTENT),
            CUSTODY.to_vec(),
            vec![
                w(self.pair),
                r(self.epoch_key()),
                r(self.hold_key()),
                w(self.filled_key()),
                r(INSTRUCTIONS_SYSVAR),
            ],
        )
        .0
    }
    pub fn return_instruction(&self, mode: u8) -> Vec<Instruction> {
        let selected = if mode == 0 {
            self.hold_key()
        } else if mode == 1 {
            self.unused_key()
        } else {
            self.filled_key()
        };
        let mut payload = vec![mode];
        payload.extend_from_slice(&(if mode == 2 { CUSTODY } else { [0; 32] }));
        let mut accounts = vec![
            w(self.pair),
            r(self.epoch_key()),
            w(self.hold_key()),
            w(self.escrow_key()),
            r(self.mint),
            w(self.seller_token),
            r(token_program()),
            r(INSTRUCTIONS_SYSVAR),
        ];
        if mode != 0 {
            accounts.push(w(selected));
        }
        self.decision(
            13,
            EPOCH_NUMBER,
            (selected, (mode != 0).then_some(selected)),
            (
                self.version(selected, if mode == 0 { 181 } else { 153 }),
                [13; 32],
            ),
            payload,
            accounts,
        )
        .0
    }
    pub fn frozen(&mut self, frozen: bool) {
        let instruction = if frozen {
            spl_token_interface::instruction::freeze_account(
                &spl_token_interface::ID,
                &old(&self.buyer_token),
                &old(&self.mint),
                &old(&self.admin.pubkey()),
                &[],
            )
        } else {
            spl_token_interface::instruction::thaw_account(
                &spl_token_interface::ID,
                &old(&self.buyer_token),
                &old(&self.mint),
                &old(&self.admin.pubkey()),
                &[],
            )
        }
        .unwrap();
        self.send(&[instruction], false)
            .expect("real legacy SPL issuer freeze/thaw");
    }
    pub fn active_fill(&mut self) {
        self.initialized();
        self.open();
        self.lock();
        self.prepare();
        self.commit();
        self.record(true);
        self.record(false);
        self.activate();
        self.prepare_fill();
    }
}
