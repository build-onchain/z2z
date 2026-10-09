//! Deterministic public synthetic keys and actual AEAD; no input/root/backing state.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_protocol::samechain::{Asset, FeePolicy, FeeRule, OrderPolicy, Role};
use ziquid_protocol::samechain::creation::{InitialOrder, NoteCreationPacket};
use ziquid_proofs::samechain::{NoteOpening, OrderState, prepare_output};
use ziquid_proofs::samechain::creation::{NoteCreationWitness, note_creation_consent_message};
use crate::fill_support as source;

/// Sign the current exact packet without repairing any hostile private opening.
pub fn resign(witness: &mut NoteCreationWitness) {
    witness.consent = SigningKey::from_bytes(&witness.owner_seed)
        .sign(&note_creation_consent_message(&witness.packet).unwrap()).to_bytes();
}

pub fn rebind(witness: &mut NoteCreationWitness) {
    witness.packet.terms_commitment = witness.packet.terms_commitment_for(&witness.blind).unwrap();
    resign(witness);
}

/// Reprepare the actual note and recovery bytes, then bind and freshly consent.
pub fn replace_output(witness: &mut NoteCreationWitness) {
    witness.packet.output = prepare_output(&witness.note, witness.packet.role,
        &witness.recovery_key, [153; 24]).unwrap();
    rebind(witness);
}

fn from_note(note: NoteOpening, role: Role) -> NoteCreationWitness {
    let recovery_key = [152; 32];
    let output = prepare_output(&note, role, &recovery_key, [153; 24]).unwrap();
    let packet = NoteCreationPacket { deployment: source::deployment(), token: [7; 20],
        payer: [8; 20], creation_nonce: [154; 32], owner_key: note.owner_key, role,
        asset: note.asset, amount: note.value,
        order: note.order.as_ref().map(|order| InitialOrder { id: order.id }),
        output, expiry: 700, terms_commitment: [0; 32] };
    let owner_seed = match role { Role::A => [21; 32], Role::B => [22; 32] };
    let mut witness = NoteCreationWitness { packet, blind: [155; 32], owner_seed,
        note, recovery_key, consent: [0; 64] };
    rebind(&mut witness);
    witness
}

pub fn ordinary_native() -> NoteCreationWitness {
    from_note(source::note(Role::A, 151, Asset::Native, U256::from(100), None), Role::A)
}
pub fn ordinary_token() -> NoteCreationWitness {
    from_note(source::note(Role::B, 161, Asset::Token([7; 20]), U256::from(100), None), Role::B)
}

fn initial_order(role: Role) -> NoteCreationWitness {
    // Same synthetic policy as the existing owner fixture, with generation one.
    // Creation requires no input note, membership path or simulated backing.
    let (asset, buy_asset, value, id): (Asset, Asset, u64, [u8; 32]) = match role {
        Role::A => (Asset::Native, Asset::Token([7; 20]), 105, [11; 32]),
        Role::B => (Asset::Token([7; 20]), Asset::Native, 100, [12; 32]),
    };
    let policy = OrderPolicy { sell_asset: asset, buy_asset,
        min_buy_num: U256::one(), min_sell_den: U256::one(),
        fee_policy: FeePolicy { entries: vec![FeeRule { payer: role, asset: buy_asset,
            beneficiary: [8; 20], max_atoms: U256::one() }] } };
    let order = OrderState { id, generation: 1, remaining_sell: U256::from(100), policy };
    let note = source::note(role, 171 + role as u8, asset, U256::from(value), Some(order));
    from_note(note, role)
}
pub fn initial_order_a() -> NoteCreationWitness { initial_order(Role::A) }
pub fn initial_order_b() -> NoteCreationWitness { initial_order(Role::B) }
