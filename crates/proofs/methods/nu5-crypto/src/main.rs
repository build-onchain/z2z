#![no_main]
#[path="../../../src/orchard_original.rs"]mod orchard_original;
#[path="../../../src/raw_v5.rs"]mod raw_v5;
#[path="../../../src/zip244.rs"]mod zip244;
#[path="../../../src/sapling_crypto.rs"]mod sapling_crypto;
#[path="../../../src/sapling_sighash.rs"]mod sapling_sighash;
#[path="../../../src/overwinter.rs"]mod overwinter;
use sha2::{Digest,Sha256};
use zcash_primitives::transaction::{Transaction,TxVersion};
use zcash_protocol::consensus::BranchId;
sp1_zkvm::entrypoint!(main);
const DOMAIN:&[u8]=b"ziquid/nu5-through-nu63-crypto/subrelation/v5";
pub fn main(){
 let input=zeroize::Zeroizing::new(sp1_zkvm::io::read_vec());
 assert!((8..=4_000_008).contains(&input.len()),"invalid crypto frame length");
 let raw_len=u32::from_be_bytes(input[..4].try_into().unwrap())as usize;
 assert!(raw_len<=2_000_000,"transaction too large");
 let end=4usize.checked_add(raw_len).unwrap();
 let raw=input.get(4..end).expect("truncated transaction");
 let mut remaining=input.get(end..).expect("truncated prevouts");
 assert!(remaining.len()>=4,"missing prevout count");
 let count=u32::from_be_bytes(remaining[..4].try_into().unwrap())as usize;
 remaining=&remaining[4..];
 assert!(count<=remaining.len()/9,"truncated prevout list");
 let mut previous=Vec::with_capacity(count);
 for _ in 0..count{previous.push(zcash_transparent::bundle::TxOut::read(&mut remaining).expect("invalid previous output"));}
 assert!(remaining.is_empty(),"trailing prevout bytes");
 let version=TxVersion::read(raw).expect("invalid transaction version");
 let hashes=match version {
  TxVersion::V5=>{
   let tx=raw_v5::RawV5::parse_exact(raw).expect("invalid original V5 transaction");
   let branch=tx.consensus_branch_id();
   let orchard=tx.orchard().copied();
   let hashes=tx.into_signature_context(previous).expect("invalid actual prevout context");
   zip244::verify_sapling_post_nu5_crypto(&hashes).expect("Sapling authorization failed");
   if let Some(orchard)=orchard{match branch{
    BranchId::Nu6_3=>orchard.verify_orchard_post_nu63(&orchard_original::PostNu63OrchardVerifier::new(),&hashes.shielded()).expect("post-NU6.3 Orchard authorization failed"),
    BranchId::Nu6_2=>orchard.verify_orchard_fixed(&orchard_original::FixedOrchardVerifier::new(),&hashes.shielded()).expect("fixed Orchard authorization failed"),
    BranchId::Nu5|BranchId::Nu6|BranchId::Nu6_1=>orchard.verify_orchard(&orchard_original::OriginalOrchardVerifier::new(),&hashes.shielded()).expect("original Orchard authorization failed"),
    _=>panic!("unsupported Orchard authorization branch"),
   }}
   hashes
  }
  TxVersion::V6=>{
   let mut reader=raw;
   let tx=Transaction::read(&mut reader,BranchId::Nu6_3).expect("invalid actual V6 transaction");
   assert!(reader.is_empty(),"trailing transaction bytes");
   let mut canonical=Vec::new();
   tx.write(&mut canonical).expect("canonical V6 serialization failed");
   assert_eq!(canonical.as_slice(),raw,"noncanonical V6 transaction");
   let hashes=zip244::PostNu5SignatureHash::new(tx,previous).expect("invalid actual prevout context");
   zip244::verify_sapling_post_nu5_crypto(&hashes).expect("Sapling authorization failed");
   zip244::verify_post_nu63_crypto(&hashes).expect("post-NU6.3 mixed-pool authorization failed");
   hashes
  }
  _=>panic!("unsupported crypto transaction version"),
 };
 let mut journal=[0u8;128];
 journal[..32].copy_from_slice(&Sha256::digest(&input));
 journal[32..64].copy_from_slice(&hashes.effect_id());
 journal[64..96].copy_from_slice(&hashes.auth_digest());
 journal[96..].copy_from_slice(&hashes.shielded());
 sp1_zkvm::io::commit_slice(DOMAIN);
 sp1_zkvm::io::commit_slice(&journal);
}
