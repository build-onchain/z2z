#![no_main]
#[path = "../../../src/overwinter.rs"]
mod overwinter;
#[path = "../../../src/sapling_sighash.rs"]
mod sapling_sighash;
#[path = "../../../src/sapling_crypto.rs"]
mod sapling_crypto;
use corez::io::{self, Write};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
const JOURNAL_DOMAIN: &[u8] = b"ziquid/sapling-v4-crypto/subrelation/v1";
struct CanonicalBytes<'a>(&'a [u8]);
impl Write for CanonicalBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.0.starts_with(bytes) { return Err(io::Error::other("noncanonical V4 transaction")); }
        self.0 = &self.0[bytes.len()..];
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert!(input.len() <= 2_000_000, "transaction too large");
    let mut remaining = input.as_slice();
    let transaction = Transaction::read(&mut remaining, BranchId::Sapling).expect("invalid V4 encoding");
    assert!(remaining.is_empty(), "trailing transaction bytes");
    let mut canonical = CanonicalBytes(&input);
    transaction.write(&mut canonical).expect("noncanonical V4 encoding");
    assert!(canonical.0.is_empty(), "incomplete V4 canonical encoding");
    let hashes = sapling_sighash::SaplingSignatureHash::new(&transaction).expect("invalid V4 shape");
    sapling_crypto::verify_sapling_v4_crypto(&hashes).expect("Sapling V4 cryptographic subrelation failed");
    // One declared Sapling-branch crypto relation; not all transaction pools/history.
    let mut journal = [0u8; JOURNAL_DOMAIN.len()+32];
    journal[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    journal[JOURNAL_DOMAIN.len()..].copy_from_slice(&Sha256::digest(&input));
    sp1_zkvm::io::commit_slice(&journal);
}
