//! Deterministic synthetic keys only; this fixture performs real signing/AEAD.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, FeeRule, InputDescriptor, OrderPolicy,
    OutputDescriptor, PublicPacket, Role, SingleOwnerPacket, single_terms_commitment,
};
use ziquid_protocol::samechain::fill::{FillExecution, aggregate_commitment, owner_leaf};
use ziquid_proofs::samechain::{
    CancelExitWitness, MerkleMembership, NoteOpening, OrderState, OwnerWitness,
    PreparedOutputOpening, fill_consent_message, prepare_output, single_consent_message,
};

pub struct KnownFill {
    pub packet: PublicPacket,
    pub a: OwnerWitness,
    pub b: OwnerWitness,
}

pub fn deployment() -> Deployment {
    Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

fn policy(role: Role) -> OrderPolicy {
    let (sell_asset, buy_asset) = match role {
        Role::A => (Asset::Native, Asset::Token([7; 20])),
        Role::B => (Asset::Token([7; 20]), Asset::Native),
    };
    OrderPolicy { sell_asset, buy_asset, min_buy_num: U256::one(),
        min_sell_den: U256::one(), fee_policy: FeePolicy { entries: vec![FeeRule {
            payer: role, asset: buy_asset, beneficiary: [8; 20], max_atoms: U256::one(),
        }] } }
}

pub fn note(role: Role, tag: u8, asset: Asset, value: U256, order: Option<OrderState>) -> NoteOpening {
    let seed = match role { Role::A => [21; 32], Role::B => [22; 32] };
    NoteOpening { deployment_digest: deployment().digest().unwrap(),
        owner_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        nf_key: [tag; 32], nonce: [tag.wrapping_add(1); 32], salt: [tag.wrapping_add(2); 32],
        asset, value, order }
}

fn input(role: Role) -> NoteOpening {
    let p = policy(role);
    let (tag, value, remaining, id): (u8, u64, u64, [u8; 32]) = match role {
        Role::A => (31, 105, 100, [11; 32]), Role::B => (41, 100, 100, [12; 32]),
    };
    note(role, tag, p.sell_asset, U256::from(value), Some(OrderState {
        id, generation: 7, remaining_sell: U256::from(remaining), policy: p,
    }))
}

pub fn descriptor(input: &NoteOpening, membership: &MerkleMembership) -> InputDescriptor {
    let order = input.order.as_ref().unwrap();
    let commitment = input.commitment().unwrap();
    InputDescriptor { commitment, root: membership.root(&input.deployment_digest, &commitment),
        tree_id: membership.tree_id, index: membership.index, order_id: order.id,
        generation: order.generation, nullifier: input.nullifier().unwrap(), owner_key: input.owner_key }
}

fn path(role: Role) -> MerkleMembership {
    MerkleMembership { tree_id: 9, index: role.index() as u32,
        siblings: std::array::from_fn(|level| [80 + level as u8; 32]) }
}

fn add_note(outputs: &mut Vec<OutputDescriptor>, owned: &mut Vec<PreparedOutputOpening>,
    role: Role, note: NoteOpening, tag: u8)
{
    let recovery_key = [tag; 32];
    let descriptor = prepare_output(&note, role, &recovery_key, [tag.wrapping_add(1); 24]).unwrap();
    owned.push(PreparedOutputOpening { manifest_index: outputs.len() as u32, note, recovery_key });
    outputs.push(descriptor);
}

pub fn known_fill() -> KnownFill {
    let a_input = input(Role::A);
    let b_input = input(Role::B);
    let a_path = path(Role::A);
    let b_path = path(Role::B);
    let a_order = a_input.order.as_ref().unwrap();
    let b_order = b_input.order.as_ref().unwrap();
    let mut outputs = vec![];
    let mut a_owned = vec![];
    let mut b_owned = vec![];
    // A sells 40 native, receives 50 token, and pays one token: net 49.
    add_note(&mut outputs, &mut a_owned, Role::A, note(Role::A, 51, Asset::Native,
        U256::from(65), Some(OrderState { id: a_order.id, generation: 8,
            remaining_sell: U256::from(60), policy: a_order.policy.clone() })), 91);
    add_note(&mut outputs, &mut a_owned, Role::A, note(Role::A, 55, Asset::Token([7; 20]),
        U256::from(49), None), 93);
    outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [8; 20], amount: U256::one() });
    // B sells 50 token and receives 40 native: the committed limit is 3/4.
    let mut b_policy = b_order.policy.clone();
    b_policy.min_buy_num = U256::from(3);
    b_policy.min_sell_den = U256::from(4);
    let mut b_input = b_input;
    b_input.order.as_mut().unwrap().policy = b_policy.clone();
    add_note(&mut outputs, &mut b_owned, Role::B, note(Role::B, 61, Asset::Token([7; 20]),
        U256::from(50), Some(OrderState { id: [12; 32], generation: 8,
            remaining_sell: U256::from(50), policy: b_policy.clone() })), 95);
    add_note(&mut outputs, &mut b_owned, Role::B, note(Role::B, 65, Asset::Native,
        U256::from(40), None), 97);
    let packet = PublicPacket { deployment: deployment(), inputs: [descriptor(&a_input, &a_path),
        descriptor(&b_input, &b_path)], outputs, expiry: 500, terms_commitment: [0; 32] };
    let execution = FillExecution { asset_a: Asset::Native, asset_b: Asset::Token([7; 20]),
        sell_a: U256::from(40), sell_b: U256::from(50) };
    let a = OwnerWitness { packet: packet.clone(), execution, leaves: [[0; 32]; 2],
        own_salt: [231; 32], role: Role::A, owner_seed: [21; 32],
        input: a_input, membership: a_path, consent: [0; 64], owned_outputs: a_owned };
    let b = OwnerWitness { packet: packet.clone(), execution, leaves: [[0; 32]; 2],
        own_salt: [232; 32], role: Role::B, owner_seed: [22; 32],
        input: b_input, membership: b_path, consent: [0; 64], owned_outputs: b_owned };
    let mut fill = KnownFill { packet, a, b };
    bind_pair(&mut fill);
    fill
}

/// Valid paired baseline: `fill.packet` and both equal executions are shared
/// public state; each leaf is independently reopened from its actual input policy.
/// Does not repair intentionally invalid descriptors, paths or output semantics.
pub fn bind_pair(fill: &mut KnownFill) {
    assert_eq!(fill.a.role, Role::A);
    assert_eq!(fill.b.role, Role::B);
    assert_eq!(fill.a.execution, fill.b.execution);
    let execution = &fill.a.execution;
    let leaves = [&fill.a, &fill.b].map(|owner| owner_leaf(&fill.packet, execution, owner.role,
        &owner.input.order.as_ref().unwrap().policy, &owner.own_salt).unwrap());
    fill.packet.terms_commitment = aggregate_commitment(&fill.packet, execution, &leaves).unwrap();
    for owner in [&mut fill.a, &mut fill.b] {
        owner.packet = fill.packet.clone();
        owner.leaves = leaves;
        owner.consent = SigningKey::from_bytes(&owner.owner_seed)
            .sign(&fill_consent_message(&owner.packet, owner.role).unwrap()).to_bytes();
    }
}

/// Hostile single-owner rebind, not a valid paired baseline after B/E changes:
/// refresh only this owner's leaf/aggregate/packet/signature. The other leaf stays
/// opaque and can be stale; a counterparty must independently re-review its leg.
pub fn rebind(witness: &mut OwnerWitness) -> PublicPacket {
    witness.leaves[witness.role.index()] = owner_leaf(&witness.packet, &witness.execution,
        witness.role, &witness.input.order.as_ref().unwrap().policy, &witness.own_salt).unwrap();
    witness.packet.terms_commitment = aggregate_commitment(&witness.packet, &witness.execution,
        &witness.leaves).unwrap();
    witness.consent = SigningKey::from_bytes(&witness.owner_seed)
        .sign(&fill_consent_message(&witness.packet, witness.role).unwrap()).to_bytes();
    witness.packet.clone()
}

pub fn replace_note(witness: &mut OwnerWitness, owned_index: usize) {
    let entry = &witness.owned_outputs[owned_index];
    let tag = 110 + owned_index as u8;
    witness.packet.outputs[entry.manifest_index as usize] =
        prepare_output(&entry.note, witness.role, &entry.recovery_key, [tag; 24]).unwrap();
}

pub fn cancel_exit(fill: &KnownFill, action: Action) -> CancelExitWitness {
    let source = &fill.a;
    let mut outputs = vec![];
    let mut owned = vec![];
    add_note(&mut outputs, &mut owned, Role::A, note(Role::A, 71, Asset::Native,
        U256::from(100), None), 99);
    outputs.push(OutputDescriptor::Exit { role: Role::A, asset: Asset::Native,
        recipient: [9; 20], amount: U256::from(5) });
    let blind = [103; 32];
    let input = source.packet.inputs[0];
    let deployment = deployment();
    let expiry = 501;
    let terms_commitment = single_terms_commitment(&deployment, &input, &outputs, expiry, &blind).unwrap();
    let packet = SingleOwnerPacket { deployment, input, outputs, expiry, terms_commitment };
    let consent = SigningKey::from_bytes(&source.owner_seed)
        .sign(&single_consent_message(&packet, Role::A, action).unwrap()).to_bytes();
    CancelExitWitness { packet, blind, role: Role::A, action, owner_seed: source.owner_seed,
        input: source.input.clone(), membership: source.membership.clone(), consent, owned_outputs: owned }
}

/// Controlled fixture only: selected decrypted remainder and mathematical path.
/// Cancel and Exit are alternatives spending the same input, not two executions.
pub fn cancel_exit_from_note(input: NoteOpening, membership: MerkleMembership,
    role: Role, owner_seed: [u8; 32], action: Action) -> CancelExitWitness
{
    let mut outputs = vec![];
    let mut owned_outputs = vec![];
    if action == Action::Cancel {
        let mut returned = input.clone();
        returned.order = None;
        returned.nf_key = [171 + role as u8; 32];
        returned.nonce = [173 + role as u8; 32];
        returned.salt = [175 + role as u8; 32];
        add_note(&mut outputs, &mut owned_outputs, role, returned, 177 + role as u8);
    } else {
        outputs.push(OutputDescriptor::Exit { role, asset: input.asset,
            recipient: [9; 20], amount: input.value });
    }
    let deployment = deployment();
    let descriptor = descriptor(&input, &membership);
    let blind = [179 + role as u8; 32];
    let expiry = 502;
    let terms_commitment = single_terms_commitment(
        &deployment, &descriptor, &outputs, expiry, &blind).unwrap();
    let packet = SingleOwnerPacket { deployment, input: descriptor, outputs,
        expiry, terms_commitment };
    let consent = SigningKey::from_bytes(&owner_seed)
        .sign(&single_consent_message(&packet, role, action).unwrap()).to_bytes();
    CancelExitWitness { packet, blind, role, action, owner_seed, input,
        membership, consent, owned_outputs }
}

/// Both exact products are close to 2^512; sold/input atoms stay full U256.
pub fn wide_fill() -> KnownFill {
    let mut fixture = known_fill();
    let max = U256::MAX;
    fixture.a.input.value = max;
    fixture.b.input.value = max;
    fixture.a.input.order.as_mut().unwrap().remaining_sell = max;
    fixture.b.input.order.as_mut().unwrap().remaining_sell = max;
    for witness in [&mut fixture.a, &mut fixture.b] {
        let order = witness.input.order.as_mut().unwrap();
        order.policy.min_buy_num = max;
        order.policy.min_sell_den = max;
        order.policy.fee_policy.entries.clear();
    }
    fixture.packet.inputs = [descriptor(&fixture.a.input, &fixture.a.membership),
        descriptor(&fixture.b.input, &fixture.b.membership)];
    for owner in [&mut fixture.a, &mut fixture.b] {
        owner.execution.sell_a = max;
        owner.execution.sell_b = max;
    }
    let a_note = note(Role::A, 121, Asset::Token([7; 20]), max, None);
    let b_note = note(Role::B, 131, Asset::Native, max, None);
    fixture.packet.outputs = vec![
        prepare_output(&a_note, Role::A, &[141; 32], [142; 24]).unwrap(),
        prepare_output(&b_note, Role::B, &[143; 32], [144; 24]).unwrap(),
    ];
    fixture.a.owned_outputs = vec![PreparedOutputOpening { manifest_index: 0,
        note: a_note, recovery_key: [141; 32] }];
    fixture.b.owned_outputs = vec![PreparedOutputOpening { manifest_index: 1,
        note: b_note, recovery_key: [143; 32] }];
    bind_pair(&mut fixture);
    fixture
}
