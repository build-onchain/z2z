#![no_main]

mod relation;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let witness = relation::SenderWitness::decode_private(&input)
        .expect("invalid private sender encoding");
    let journal = relation::verify_sender(&witness)
        .expect("sender ciphertext relation failed");
    sp1_zkvm::io::commit_slice(&journal);
}
