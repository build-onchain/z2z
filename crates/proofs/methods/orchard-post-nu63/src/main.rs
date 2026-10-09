#![no_main]
#[path = "../../../src/orchard_original.rs"]
mod orchard_original;
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"ziquid/orchard-post-nu63-halo2/subrelation/v1";
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert_eq!(input.len(), 163 + 4992, "invalid post-NU6.3 one-Action proof frame");
    assert!(input[160..163].iter().all(|flag| *flag <= 1), "noncanonical Action flags");
    let field = |offset| input[offset..offset + 32].try_into().unwrap();
    let instance = orchard_original::PostNu63ActionInstance {
        anchor: field(0), cv_net: field(32), nullifier: field(64), rk: field(96), cmx: field(128),
        flags: input[160] | (input[161] << 1), disable_cross_address: input[162] != 0,
    };
    orchard_original::PostNu63OrchardVerifier::new().verify(&[instance], &input[163..])
        .expect("post-NU6.3 proof subrelation failed");
    let mut journal = [0; DOMAIN.len() + 32];
    journal[..DOMAIN.len()].copy_from_slice(DOMAIN);
    journal[DOMAIN.len()..].copy_from_slice(&Sha256::digest(&input));
    sp1_zkvm::io::commit_slice(&journal);
}
