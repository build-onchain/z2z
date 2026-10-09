#![no_main]
// Private synthetic consumer only: actual shared F/J/C/R checks and real Halo2
// authorization, not origin history, canonicality, financial proof or target ABI.
#[path = "../../../src/canonical_bytes.rs"]
mod canonical_bytes;
#[path = "../../../src/native_relation/effects.rs"]
mod native_effects;
#[path = "../../../src/native_relation.rs"]
mod native_relation;
#[path = "../../../src/orchard_original.rs"]
mod orchard_original;
#[path = "../../../src/zip244.rs"]
mod zip244;
#[path = "../../../src/sapling_crypto.rs"]
mod sapling_crypto;
#[path = "../../../src/sapling_sighash.rs"]
mod sapling_sighash;
#[path = "../../../src/overwinter.rs"]
mod overwinter;
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = zeroize::Zeroizing::new(sp1_zkvm::io::read_vec());
    native_relation::smoke::verify(&input).expect("private native relation rejected");
    // Fixed nonfinancial test success marker; no private values are committed.
    sp1_zkvm::io::commit_slice(native_relation::smoke::SUCCESS);
}
