#![no_main]

// Native reference and guest compile the same authenticated fixed-key verifier.
#[path = "../../../src/sprout.rs"]
mod sprout;

use sha2::{Digest, Sha256};
use sprout::{LegacyJoinSplit, verify_sprout_legacy};

const JOURNAL_DOMAIN: &[u8] = b"ziquid/sprout-legacy/subrelation/v1";

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: &[u8; 600] = bytes
        .as_slice()
        .try_into()
        .expect("invalid legacy Sprout qualification encoding length");
    let statement = LegacyJoinSplit {
        anchor: input[0..32].try_into().unwrap(),
        nullifiers: [
            input[32..64].try_into().unwrap(),
            input[64..96].try_into().unwrap(),
        ],
        macs: [
            input[96..128].try_into().unwrap(),
            input[128..160].try_into().unwrap(),
        ],
        commitments: [
            input[160..192].try_into().unwrap(),
            input[192..224].try_into().unwrap(),
        ],
        vpub_old: u64::from_le_bytes(input[224..232].try_into().unwrap()),
        vpub_new: u64::from_le_bytes(input[232..240].try_into().unwrap()),
        random_seed: input[240..272].try_into().unwrap(),
        joinsplit_pubkey: input[272..304].try_into().unwrap(),
    };
    verify_sprout_legacy(&statement, &input[304..600])
        .expect("legacy Sprout five-equation subrelation failed");

    // This journal qualifies only the legacy subrelation, not source history or settlement.
    let mut journal = [0u8; JOURNAL_DOMAIN.len() + 32];
    journal[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    journal[JOURNAL_DOMAIN.len()..].copy_from_slice(&Sha256::digest(input));
    // No public bytes are committed until every relation check succeeds.
    sp1_zkvm::io::commit_slice(&journal);
}
