#![no_main]
#[path = "../../../src/orchard_original.rs"]
mod orchard_original;
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"ziquid/orchard-fixed-nu62-halo2/subrelation/v1";
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert_eq!(input.len(), 162 + 4992, "invalid fixed one-action proof frame");
    assert!(input[160] <= 1 && input[161] <= 1, "noncanonical enable flags");
    let field = |offset| input[offset..offset + 32].try_into().unwrap();
    let instance = orchard_original::OriginalActionInstance {
        anchor: field(0), cv_net: field(32), nullifier: field(64), rk: field(96),
        cmx: field(128), flags: input[160] | (input[161] << 1),
    };
    orchard_original::FixedOrchardVerifier::new().verify(&[instance], &input[162..])
        .expect("fixed Orchard proof subrelation failed");
    let mut journal = [0; DOMAIN.len() + 32];
    journal[..DOMAIN.len()].copy_from_slice(DOMAIN);
    journal[DOMAIN.len()..].copy_from_slice(&Sha256::digest(&input));
    sp1_zkvm::io::commit_slice(&journal);
}
