#![no_main]

// Native reference and guest compile one exact constraint/codec implementation.
#[path = "../../../src/native_relation/effects.rs"]
mod native_effects;
#[path = "../../../src/preparation.rs"]
mod preparation;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = zeroize::Zeroizing::new(sp1_zkvm::io::read_vec());
    let witness = preparation::PreparationWitness::decode_private(&input)
        .expect("invalid private preparation encoding");
    let journal = preparation::verify_preparation(&witness)
        .expect("preparation subrelation failed");
    // No public bytes are committed until every relation check succeeds.
    sp1_zkvm::io::commit_slice(&journal.encode());
}
