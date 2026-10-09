#![no_main]
#[path="../../../src/orchard_original.rs"]mod orchard_original;
use sha2::{Digest,Sha256};
const DOMAIN:&[u8]=b"ziquid/orchard-original-halo2/subrelation/v1";
sp1_zkvm::entrypoint!(main);
pub fn main(){
 let input=sp1_zkvm::io::read_vec();assert!((162..=2*1024*1024).contains(&input.len()),"invalid original proof fixture frame");
 let field=|offset|input[offset..offset+32].try_into().unwrap();
 assert!(input[160]<=1&&input[161]<=1,"noncanonical enable flags");
 let instance=orchard_original::OriginalActionInstance{anchor:field(0),cv_net:field(32),nullifier:field(64),rk:field(96),cmx:field(128),flags:input[160]|(input[161]<<1)};
 orchard_original::OriginalOrchardVerifier::new().verify(&[instance],&input[162..]).expect("original Orchard Halo2 subrelation failed");
 let mut journal=[0u8;DOMAIN.len()+32];journal[..DOMAIN.len()].copy_from_slice(DOMAIN);journal[DOMAIN.len()..].copy_from_slice(&Sha256::digest(&input));sp1_zkvm::io::commit_slice(&journal);
}
