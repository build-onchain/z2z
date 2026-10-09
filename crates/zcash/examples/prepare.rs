//! Local generated fixture only: no chain-admissible note, node, send or settlement claim.
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use ziquid_zcash::{IronwoodTransaction, OutputPlan, OwnedInput, SourceParameters, prepare};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::from_seed([71; 32]);
    let sk = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    let rho = Rho::from_bytes(&[8; 32]).unwrap();
    let note = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(seed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho))
            && let Some(note) = Option::<Note>::from(Note::from_parts(
                fvk.address_at(0u32, Scope::External),
                NoteValue::from_raw(100_000),
                rho,
                seed,
                NoteVersion::V3,
            ))
        {
            break note;
        }
    };
    let path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8))),
    );
    let input = OwnedInput::new(
        note,
        fvk.clone(),
        path.clone(),
        path.root(note.commitment().into()),
    )?;
    let params = SourceParameters {
        network: Network::TestNetwork,
        target_height: BlockHeight::from(4_134_000),
        expiry_height: BlockHeight::from(4_134_040),
        consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    let recipient = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap())
        .address_at(0u32, Scope::External);
    let output = |address, value| {
        OutputPlan::new(
            address,
            Zatoshis::from_u64(value).unwrap(),
            MemoBytes::empty(),
        )
    };
    let pair = prepare(
        &params,
        &input,
        &[
            output(recipient, 60_000),
            output(fvk.address_at(1u32, Scope::Internal), 30_000),
        ],
        &[output(fvk.address_at(2u32, Scope::Internal), 90_000)],
        &mut rng,
    )?;
    let sender = pair
        .payout_witness()
        .recover_pczt_output(pair.unsigned_payment().pczt_bytes(), 0)?;
    assert_eq!(sender.recipient(), recipient);
    assert_eq!(sender.value(), 60_000);
    let p = pczt::Pczt::parse(pair.unsigned_payment().pczt_bytes()).expect("generated P parses");
    assert!(
        p.ironwood()
            .actions()
            .iter()
            .all(|a| a.spend().spend_auth_sig().is_none())
    );
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let q = pair.finish_recovery(&SpendAuthorizingKey::from(&sk), &pk, &vk)?;
    let parsed = IronwoodTransaction::parse(q.transaction_bytes(), BranchId::Nu6_3)?;
    parsed.verify_authorization(&vk, &mut rng)?;
    let bundle = parsed
        .transaction()
        .ironwood_bundle()
        .expect("Ironwood-only Q");
    let self_return = bundle
        .decrypt_outputs_with_keys(&[fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)])
        .iter()
        .map(|(_, _, note, _, _)| note.value().inner())
        .sum::<u64>();
    assert_eq!(self_return, 90_000);
    assert_eq!(i64::from(*bundle.value_balance()), 10_000);
    println!("Generated fixture only; no chain-valid note/anchor or node action.");
    println!(
        "P actions={}, SpendAuth absent; sender recovery={} zat without S IVK.",
        p.ironwood().actions().len(),
        sender.value()
    );
    println!(
        "Q actions={}, all signatures/binding/proof valid; self-return={} zat; fee={} zat.",
        bundle.actions().len(),
        self_return,
        u64::from(pair.recovery_fee())
    );
    println!("Q export is final consensus bytes only; no U FVK or spend key.");
    Ok(())
}
