use crate::{domain_bytes, Fixture, PROGRAM};
use ziquid_solana_interface::Envelope;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

pub const INSTRUCTIONS_SYSVAR: Address =
    Address::new_from_array(ziquid_solana_interface::INSTRUCTIONS_SYSVAR_ID);
pub const RESULT: [u8; 32] = [0x61; 32];
pub const JOURNAL: [u8; 32] = [0x62; 32];
pub const FENCE: [u8; 32] = [0x63; 32];
pub const CUSTODY: [u8; 32] = [0x64; 32];
pub const HOLD_ID: [u8; 32] = [0x68; 32];
pub const FILLED_ID: [u8; 32] = [0x66; 32];
pub const UNUSED_ID: [u8; 32] = [0x75; 32];
pub const FIRST_LEG_INTENT: [u8; 32] = [0x71; 32];

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

pub fn epoch(pair: Address, number: u64) -> Address {
    Address::new_from_array(
        ziquid_solana_interface::epoch_pda_at(&PROGRAM.to_bytes(), &pair.to_bytes(), number).0,
    )
}
pub fn hold(epoch: Address, id: [u8; 32]) -> Address {
    Address::new_from_array(
        ziquid_solana_interface::hold_pda_at(&PROGRAM.to_bytes(), &epoch.to_bytes(), &id).0,
    )
}
pub fn escrow(hold: Address) -> Address {
    Address::new_from_array(
        ziquid_solana_interface::escrow_pda_at(&PROGRAM.to_bytes(), &hold.to_bytes()).0,
    )
}
pub fn portion(hold: Address, id: [u8; 32]) -> Address {
    Address::new_from_array(
        ziquid_solana_interface::portion_pda_at(&PROGRAM.to_bytes(), &hold.to_bytes(), &id).0,
    )
}
pub fn w(key: Address) -> AccountMeta {
    AccountMeta::new(key, false)
}
pub fn r(key: Address) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}

/// Reconstruct independently the full shared Operation478/Decision550 and role64,
/// not a client digest that the program can trust without checking its exact state/effects.
pub fn canonical_decision(
    domain: &[u8],
    subject: (Address, Option<Address>),
    envelope: Envelope,
    tag: u8,
    payload: &[u8],
    accounts: &[AccountMeta],
) -> ([u8; 64], [u8; 32]) {
    let (subject, portion_id) = subject;
    let Envelope {
        intent,
        generation,
        prior: prior_version,
        predecessor,
    } = envelope;
    let mut effects = b"KERBSFX1".to_vec();
    effects.push(tag);
    effects.extend_from_slice(payload);
    for account in accounts.iter().skip(usize::from(tag == 2 || tag == 8)) {
        effects.extend_from_slice(account.pubkey.as_ref());
    }
    let mut operation = b"KERBOP01".to_vec();
    operation.extend_from_slice(domain);
    operation.extend_from_slice(subject.as_ref());
    operation.extend_from_slice(&portion_id.map(|p| p.to_bytes()).unwrap_or([0; 32]));
    operation.extend_from_slice(&intent);
    operation.extend_from_slice(&generation.to_le_bytes());
    operation.extend_from_slice(&prior_version.to_le_bytes());
    operation.push(tag);
    operation.extend_from_slice(&digest(&effects));
    assert_eq!(operation.len(), 478);
    let mut head_bytes = b"KERBHD01".to_vec();
    head_bytes.extend_from_slice(&predecessor);
    head_bytes.extend_from_slice(&digest(&operation));
    let next_head = digest(&head_bytes);
    let mut decision = b"KERBDC01".to_vec();
    decision.extend_from_slice(&operation);
    decision.extend_from_slice(&predecessor);
    decision.extend_from_slice(&next_head);
    assert_eq!(decision.len(), 550);
    let mut message = [0; 64];
    message[..32].copy_from_slice(b"KERB_ED25519_DECISION_V1\0\0\0\0\0\0\0\0");
    message[32..].copy_from_slice(&digest(&decision));
    (message, next_head)
}

pub fn precompile(key: &Keypair, message: &[u8]) -> Instruction {
    new_ed25519_instruction_with_signature(
        message,
        &key.sign_message(message).into(),
        key.pubkey().as_array(),
    )
}

impl Fixture {
    pub fn decision(
        &self,
        tag: u8,
        number: u64,
        subject: (Address, Option<Address>),
        versioned_intent: (u64, [u8; 32]),
        payload: Vec<u8>,
        accounts: Vec<AccountMeta>,
    ) -> (Vec<Instruction>, [u8; 32]) {
        let (prior_version, intent) = versioned_intent;
        let pair = self.svm.get_account(&self.pair).expect("initialized pair");
        let generation = le_u64(&pair.data[463..471]) + 1;
        let predecessor = pair.data[471..503].try_into().unwrap();
        let (message, next_head) = canonical_decision(
            &domain_bytes(self.mint, number),
            subject,
            Envelope {
                intent,
                generation,
                prior: prior_version,
                predecessor,
            },
            tag,
            &payload,
            &accounts,
        );
        let mut data = vec![tag];
        data.extend_from_slice(&intent);
        data.extend_from_slice(&predecessor);
        data.extend_from_slice(&payload);
        let mut instructions: Vec<_> = if self.policy_signing_enabled {
            self.authorizers
                .iter()
                .map(|key| precompile(key, &message))
                .collect()
        } else {
            Vec::new()
        };
        instructions.push(Instruction {
            program_id: PROGRAM,
            accounts,
            data,
        });
        (instructions, next_head)
    }

    pub fn pair_generation(&self) -> u64 {
        le_u64(&self.svm.get_account(&self.pair).unwrap().data[463..471])
    }
    pub fn pair_head(&self) -> [u8; 32] {
        self.svm.get_account(&self.pair).unwrap().data[471..503]
            .try_into()
            .unwrap()
    }
}
