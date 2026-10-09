#![no_main]
#[path="../../../src/raw_v5.rs"]mod raw_v5;
#[path="../../../src/orchard_original.rs"]mod orchard_original;
#[path="../../../src/zip244.rs"]mod zip244;
#[path="../../../src/sapling_crypto.rs"]mod sapling_crypto;
#[path="../../../src/sapling_sighash.rs"]mod sapling_sighash;
#[path="../../../src/sapling_coinbase.rs"]mod sapling_coinbase;
#[path="../../../src/overwinter.rs"]mod overwinter;
use sha2::{Digest,Sha256};
sp1_zkvm::entrypoint!(main);
const DOMAIN:&[u8]=b"ziquid/nu5-through-nu63-coinbase-recovery/subrelation/v5";
pub fn main(){
 let input=zeroize::Zeroizing::new(sp1_zkvm::io::read_vec());assert!(input.len()<=2_000_005,"recovery frame too large");let(mode,frame)=input.split_first().expect("missing recovery mode");
 let values=match mode{
  0=>{assert!(frame.len()>=4,"missing action count");let count=u32::from_be_bytes(frame[..4].try_into().unwrap())as usize;assert!(count>0&&count<=65535,"invalid action count");let bytes=count.checked_mul(820).unwrap();assert_eq!(frame.len(),4+bytes,"invalid action frame");let mut values=Vec::with_capacity(count);for action in frame[4..].as_chunks::<820>().0{values.push(raw_v5::recover_orchard_coinbase_action(action).expect("original Orchard zero OVK recovery failed"));}values},
  1=>{
   assert!(frame.len()>=4,"missing candidate height");
   let height=u32::from_be_bytes(frame[..4].try_into().unwrap());
   assert!((1_842_420..4_465_026).contains(&height),"not supported NU5 through NU6.3 height");
   let branch=zcash_protocol::consensus::BranchId::for_height(&zcash_protocol::consensus::TEST_NETWORK,height.into());
   assert!(matches!(branch,zcash_protocol::consensus::BranchId::Nu5|zcash_protocol::consensus::BranchId::Nu6|zcash_protocol::consensus::BranchId::Nu6_1|zcash_protocol::consensus::BranchId::Nu6_2|zcash_protocol::consensus::BranchId::Nu6_3),"unsupported recovery branch");
   let mut raw=&frame[4..];
   let tx=zcash_primitives::transaction::Transaction::read(&mut raw,branch).expect("invalid Sapling source transaction");
   assert!(raw.is_empty(),"trailing transaction bytes");
   assert_eq!(tx.consensus_branch_id(),branch,"incorrect encoded branch");
   assert!(tx.version().valid_in_branch(branch),"incorrect transaction version");
   let bundle=tx.sapling_bundle().expect("missing Sapling outputs");
   assert!(!bundle.shielded_outputs().is_empty(),"empty Sapling output set");
   let mut values=Vec::with_capacity(bundle.shielded_outputs().len());
   for output in bundle.shielded_outputs(){values.push(sapling_coinbase::recover_sapling_coinbase_output(output,height).expect("original Sapling zero OVK recovery failed"));}
   values
  },
  2=>{
   assert!(frame.len()>=4,"missing candidate height");
   let height=u32::from_be_bytes(frame[..4].try_into().unwrap());
   assert!((4_134_000..4_465_026).contains(&height),"not supported NU6.3 height");
   let mut raw=&frame[4..];
   let tx=zcash_primitives::transaction::Transaction::read(&mut raw,zcash_protocol::consensus::BranchId::Nu6_3).expect("invalid Ironwood source transaction");
   assert!(raw.is_empty(),"trailing transaction bytes");
   assert_eq!(tx.version(),zcash_primitives::transaction::TxVersion::V6,"incorrect Ironwood transaction version");
   assert_eq!(tx.consensus_branch_id(),zcash_protocol::consensus::BranchId::Nu6_3,"incorrect encoded branch");
   let bundle=tx.ironwood_bundle().expect("missing Ironwood outputs");
   let mut values=Vec::with_capacity(bundle.actions().len());
   for action in bundle.actions().iter(){values.push(sapling_coinbase::recover_ironwood_coinbase_output(action,height).expect("Ironwood zero OVK recovery failed"));}
   values
  },
  _=>panic!("unsupported recovery mode"),
 };
 sp1_zkvm::io::commit_slice(DOMAIN);sp1_zkvm::io::commit_slice(&Sha256::digest(&input));sp1_zkvm::io::commit_slice(&(values.len()as u32).to_be_bytes());for value in values{sp1_zkvm::io::commit_slice(&value.to_le_bytes());}
}
