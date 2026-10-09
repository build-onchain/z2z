#![no_main]

// Native reference and guest compile the same transaction prechecks, original
// Ed25519 authorization, signature serializer, and fixed-key PHGR verifier.
#[path = "../../../src/legacy_joinsplit.rs"]
mod legacy_joinsplit;
#[path = "../../../src/legacy_sighash.rs"]
mod legacy_sighash;
#[path = "../../../src/overwinter.rs"]
mod overwinter;
#[path = "../../../src/sprout.rs"]
mod sprout;
#[path = "../../../src/sapling_sighash.rs"]
mod sapling_sighash;
#[path = "../../../src/sprout_groth16.rs"]
mod sprout_groth16;

use corez::io::{self, Write};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

const MAX_TRANSACTION_BYTES: usize = 100_000;
const JOURNAL_DOMAIN: &[u8] = b"ziquid/legacy-joinsplit/subrelation/v1";

// Same borrowed canonical round-trip boundary as history::CanonicalBytes;
// including the full history module would pull in unrelated source machinery.
struct CanonicalBytes<'a> {
    remaining: &'a [u8],
}

impl Write for CanonicalBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.remaining.starts_with(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noncanonical transaction",
            ));
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // One SP1 input vector contains the complete public consensus transaction,
    // not a caller-supplied statement, digest, checkpoint, or validity flag.
    let input = sp1_zkvm::io::read_vec();
    assert!(input.len() <= MAX_TRANSACTION_BYTES, "pre-Sapling transaction size");
    let mut remaining = input.as_slice();
    let transaction = Transaction::read(&mut remaining, BranchId::Sprout)
        .expect("invalid legacy transaction encoding");
    assert!(remaining.is_empty(), "trailing legacy transaction bytes");
    let mut canonical = CanonicalBytes { remaining: &input };
    transaction.write(&mut canonical).expect("noncanonical legacy transaction encoding");
    assert!(canonical.remaining.is_empty(), "incomplete canonical transaction encoding");

    legacy_joinsplit::verify_legacy_joinsplit_crypto(&transaction)
        .expect("legacy JoinSplit cryptographic subrelation failed");

    // This qualifies only the transaction-local cryptographic subrelation,
    // never source history, transparent authorization, finality, or settlement.
    let mut journal = [0u8; JOURNAL_DOMAIN.len() + 32];
    journal[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    journal[JOURNAL_DOMAIN.len()..].copy_from_slice(&Sha256::digest(&input));
    // No public bytes are committed until every relation check succeeds.
    sp1_zkvm::io::commit_slice(&journal);
}
