#![no_main]
#[path="../../../src/samechain.rs"]mod samechain;
sp1_zkvm::entrypoint!(main);
pub fn main(){
 let input=zeroize::Zeroizing::new(sp1_zkvm::io::read_vec());assert!(input.len()<=1+samechain::MAX_PRIVATE_INPUT_BYTES,"owner frame too large");
 let (mode,frame)=input.split_first().expect("missing owner mode");
 let journal=match mode{
  0=>{let witness=samechain::OwnerWitness::decode(frame).expect("invalid owner witness");samechain::verify_owner_relation(&witness.packet,&witness).expect("owner bilateral relation failed").encode().expect("invalid owner journal")},
  1=>{let witness=samechain::CancelExitWitness::decode(frame).expect("invalid single owner witness");samechain::verify_cancel_exit_relation(&witness).expect("owner cancel exit relation failed").encode().expect("invalid owner journal")},
  2=>{let witness=samechain::withdrawal::NoteWithdrawalWitness::decode(frame).expect("invalid ordinary withdrawal witness");samechain::withdrawal::verify_note_withdrawal_relation(&witness).expect("ordinary withdrawal relation failed").encode().expect("invalid ordinary withdrawal journal")},
  3=>{let witness=samechain::creation::NoteCreationWitness::decode(frame).expect("invalid note creation witness");samechain::creation::verify_note_creation_relation(&witness).expect("note creation relation failed").encode().expect("invalid note creation journal")},
  _=>panic!("unsupported owner mode"),
 };
 sp1_zkvm::io::commit_slice(&journal);
}
