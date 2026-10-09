#![no_main]

// Shared native fixed-key statement/hash and actual Groth16 verification.
#[path = "../../../src/sprout.rs"]
mod sprout;
#[path = "../../../src/sprout_groth16.rs"]
mod sprout_groth16;
use sha2::{Digest, Sha256};
use sprout::LegacyJoinSplit;
const JOURNAL_DOMAIN: &[u8] = b"ziquid/sprout-groth16/subrelation/v1";
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: &[u8; 496] = bytes.as_slice().try_into().expect("invalid Sprout Groth16 qualification length");
    let statement = LegacyJoinSplit {
        anchor: input[0..32].try_into().unwrap(),
        nullifiers: [input[32..64].try_into().unwrap(), input[64..96].try_into().unwrap()],
        macs: [input[96..128].try_into().unwrap(), input[128..160].try_into().unwrap()],
        commitments: [input[160..192].try_into().unwrap(), input[192..224].try_into().unwrap()],
        vpub_old: u64::from_le_bytes(input[224..232].try_into().unwrap()),
        vpub_new: u64::from_le_bytes(input[232..240].try_into().unwrap()),
        random_seed: input[240..272].try_into().unwrap(),
        joinsplit_pubkey: input[272..304].try_into().unwrap(),
    };
    sprout_groth16::verify_sprout_groth16(&statement, &input[304..])
        .expect("Sprout Groth16 cryptographic subrelation failed");
    // Not transaction authorization, accepted history, finality or settlement.
    let mut journal = [0u8; JOURNAL_DOMAIN.len() + 32];
    journal[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    journal[JOURNAL_DOMAIN.len()..].copy_from_slice(&Sha256::digest(input));
    sp1_zkvm::io::commit_slice(&journal);
}
