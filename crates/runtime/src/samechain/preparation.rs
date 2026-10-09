//! Owner-local unsigned creation, withdrawal, cancel/exit, fill outputs and known-opening membership.
//! This creates neither bilateral execution approval nor consent, durable recovery,
//! proofs, root admission, authenticated spentness evidence or financial execution.
use ed25519_dalek::SigningKey;
use primitive_types::{U256, U512};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};
use ziquid_chains::samechain::{history::PublicHistory, inspection::InspectionScope};
use ziquid_proofs::samechain::{
    CancelExitWitness, MerkleMembership, NoteOpening, OrderState, PreparedOutputOpening, RelationError,
    prepare_output, review_owner_cancel_exit,
};
use ziquid_proofs::samechain::creation::{NoteCreationWitness, review_note_creation};
use ziquid_proofs::samechain::withdrawal::{NoteWithdrawalWitness, review_note_withdrawal};
use ziquid_protocol::samechain::creation::{InitialOrder, NoteCreationPacket};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, InputDescriptor, MAX_OUTPUTS, OrderPolicy, OutputDescriptor, Role,
    SamechainError, SingleOwnerPacket, single_terms_commitment,
};
use ziquid_protocol::samechain::tree::TREE_CAPACITY;
use ziquid_protocol::samechain::withdrawal::{
    NoteInputDescriptor, NoteWithdrawalPacket, note_withdrawal_terms_commitment,
};

/// Resolve a known opening's immutable historical insertion path through acquired
/// public history at independently selected exact final block and identity pins.
/// Later appends do not replace this path with one to the latest tree root.
///
/// Success means the opening matches retained membership and its NF is NOT
/// OBSERVED spent, under trusted-provider initial-boundary and log-completeness
/// assumptions. A coherent provider can omit an unqueried NF-only spend without
/// changing the tree. This is not global unspentness, current root eligibility,
/// backing, finality, owner consent, executable recovery or financial completion.
/// No public order-generation selection or caller-built getter evidence is used.
///
/// Invalid opening/policy errors propagate. Wrong scope, horizon, unknown opening
/// or observed spend returns `Input`; inconsistent retained path returns `Membership`.
pub fn prepare_note_membership(
    history: &PublicHistory, expected_scope: &InspectionScope, expected_number: U256,
    note: &NoteOpening,
) -> Result<MerkleMembership, RelationError> {
    expected_scope.validate().map_err(|_| RelationError::Input)?;
    let mut origin_scope = history.origin_scope();
    origin_scope.block_hash = expected_scope.block_hash;
    if origin_scope != *expected_scope {
        return Err(RelationError::Input);
    }
    let latest = history.latest_block().ok_or(RelationError::Input)?;
    if latest.number != expected_number || latest.hash != expected_scope.block_hash {
        return Err(RelationError::Input);
    }
    note.validate()?;
    let deployment = expected_scope.expected.digest()?;
    if note.deployment_digest != deployment {
        return Err(RelationError::Input);
    }
    let commitment = note.commitment()?;
    let nullifier = note.nullifier()?;
    let retained = history.note(&commitment).ok_or(RelationError::Input)?;
    if history.observed_spent(&nullifier) {
        return Err(RelationError::Input);
    }
    if let Some(order) = &note.order {
        order.policy.validate_for(retained.note.role)?;
    }
    let event = &retained.note;
    let insertion = &retained.insertion;
    if (event.tree_id, event.index, event.root, event.count)
        != (insertion.tree_id, insertion.index, insertion.root, insertion.count)
        || !(1..=TREE_CAPACITY).contains(&insertion.count)
        || insertion.count != u64::from(insertion.index) + 1
        || u64::from(insertion.index) >= insertion.count
        || history.root_count(insertion.tree_id, insertion.root) != insertion.count
    {
        return Err(RelationError::Membership);
    }
    let membership = MerkleMembership { tree_id: insertion.tree_id,
        index: insertion.index, siblings: insertion.siblings };
    if membership.root(&deployment, &commitment) != insertion.root {
        return Err(RelationError::Membership);
    }
    Ok(membership)
}

/// Public descriptors and confidential owner-local openings, not a wire format.
/// Opening indexes are local to `descriptors`; offset them when merging this
/// list into the full ordered manifest before constructing an OwnerWitness.
/// Retaining these erasing in-memory values does not qualify durable backup.
pub struct PreparedFillOutputs {
    pub descriptors: Vec<OutputDescriptor>,
    pub openings: Vec<PreparedOutputOpening>,
}

impl fmt::Debug for PreparedFillOutputs {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("PreparedFillOutputs([REDACTED])")
    }
}

/// Owner-local requested deposit terms, not a serializable private transport.
/// `amount` is public; optional capacity and policy remain owner-private.
pub struct CreationRequest {
    pub deployment: Deployment,
    pub token: [u8; 20],
    pub payer: [u8; 20],
    pub role: Role,
    pub asset: Asset,
    pub amount: U256,
    pub expiry: u64,
    pub order: Option<InitialOrderRequest>,
}

/// Initial private backing policy; identity is freshly generated, generation one.
pub struct InitialOrderRequest {
    pub remaining_sell: U256,
    pub policy: OrderPolicy,
}

impl fmt::Debug for CreationRequest {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("CreationRequest([REDACTED])")
    }
}

impl fmt::Debug for InitialOrderRequest {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("InitialOrderRequest([REDACTED])")
    }
}

impl Drop for InitialOrderRequest {
    fn drop(&mut self) {
        self.remaining_sell.0.zeroize();
        // The owned policy erases itself through its existing Drop.
    }
}

/// Construct and retain a fresh owner-local unsigned capability in erasing memory.
/// The caller must independently select/review its complete public packet before
/// consent. This self-check is not authorization, backup, proof or asset receipt.
pub fn prepare_note_creation(request: &CreationRequest)
    -> Result<NoteCreationWitness, RelationError>
{
    request.deployment.validate()?;
    if request.token == [0; 20]
        || matches!(request.asset, Asset::Token(token) if token != request.token)
    {
        return Err(SamechainError::InvalidAsset.into());
    }
    if request.payer == [0; 20] || request.amount.is_zero() || request.expiry == 0 {
        return Err(SamechainError::InvalidTerms.into());
    }
    if let Some(order) = &request.order {
        order.policy.validate_for(request.role)?;
        if order.remaining_sell.is_zero() || order.remaining_sell > request.amount
            || order.policy.sell_asset != request.asset
        {
            return Err(RelationError::Note);
        }
        let opposite = match request.asset {
            Asset::Native => Asset::Token(request.token),
            Asset::Token(_) => Asset::Native,
        };
        if order.policy.buy_asset != opposite { return Err(RelationError::Policy); }
    }
    // Install the complete erasing witness before any entropy or secret-bearing
    // fallible operation. Never validate, hash or encode this internal placeholder.
    let mut witness = NoteCreationWitness {
        packet: NoteCreationPacket {
            deployment: request.deployment, token: request.token, payer: request.payer,
            creation_nonce: [0; 32], owner_key: [0; 32], role: request.role,
            asset: request.asset, amount: request.amount, order: None,
            output: OutputDescriptor::Note { role: request.role, commitment: [0; 32],
                recovery_key_commitment: [0; 32], ciphertext_version: 0, ciphertext: Vec::new() },
            expiry: request.expiry, terms_commitment: [0; 32],
        },
        blind: [0; 32], owner_seed: [0; 32],
        note: NoteOpening { deployment_digest: [0; 32], owner_key: [0; 32],
            nf_key: [0; 32], nonce: [0; 32], salt: [0; 32], asset: request.asset,
            value: request.amount, order: request.order.as_ref().map(|order| OrderState {
                id: [0; 32], generation: 1, remaining_sell: order.remaining_sell,
                policy: order.policy.clone(),
            }) },
        recovery_key: [0; 32], consent: [0; 64],
    };
    witness.note.deployment_digest = request.deployment.digest()?;
    fill_nonzero(&mut witness.owner_seed)?;
    witness.packet.owner_key = SigningKey::from_bytes(&witness.owner_seed).verifying_key().to_bytes();
    witness.note.owner_key = witness.packet.owner_key;
    fill_nonzero(&mut witness.packet.creation_nonce)?;
    if let Some(order) = &mut witness.note.order {
        fill_nonzero(&mut order.id)?;
        witness.packet.order = Some(InitialOrder { id: order.id });
    }
    fill_nonzero(&mut witness.note.nf_key)?;
    fill_nonzero(&mut witness.note.nonce)?;
    fill_nonzero(&mut witness.note.salt)?;
    fill_nonzero(&mut witness.recovery_key)?;
    fill_nonzero(&mut witness.blind)?;
    let mut nonce = Zeroizing::new([0; 24]);
    fill_nonzero(&mut nonce[..])?;
    witness.packet.output = prepare_output(&witness.note, request.role,
        &witness.recovery_key, *nonce)?;
    witness.packet.terms_commitment = witness.packet.terms_commitment_for(&witness.blind)?;
    // Check against the borrowed selection, including the fixed token even for
    // Native creation and the private policy/capacity omitted from public terms.
    let packet = &witness.packet;
    if packet.deployment != request.deployment || packet.token != request.token
        || packet.payer != request.payer || packet.role != request.role
        || packet.asset != request.asset || packet.amount != request.amount
        || packet.expiry != request.expiry
    {
        return Err(RelationError::Manifest);
    }
    match (&request.order, &witness.note.order) {
        (None, None) => {}
        (Some(expected), Some(actual)) if actual.remaining_sell == expected.remaining_sell
            && actual.policy == expected.policy => {}
        _ => return Err(RelationError::Note),
    }
    // The generated nonce is a construction self-check input, not an independent
    // owner authorization choice; later packet selection freezes nonce/id/output.
    review_note_creation(packet, &witness, &request.deployment,
        request.payer, packet.creation_nonce)?;
    Ok(witness)
}

/// Independently selected public input and exact effects, not a private wire format.
/// The selected historical root must not be inferred from the supplied private path.
#[derive(Debug)]
pub struct WithdrawalRequest {
    pub deployment: Deployment,
    pub expected_input: NoteInputDescriptor,
    pub expiry: u64,
    pub effects: Vec<OutputDescriptor>,
}

/// Construct an ordinary-note unsigned withdrawal with zero or one fresh change.
/// Membership remains caller/provider-qualified, not root admission or spentness.
/// Independently select the complete resulting packet again before real consent;
/// retaining this erasing witness is neither durable backup nor financial execution.
pub fn prepare_note_withdrawal(
    request: WithdrawalRequest, input: NoteOpening, membership: MerkleMembership,
    owner_seed: Zeroizing<[u8; 32]>,
) -> Result<NoteWithdrawalWitness, RelationError> {
    let deployment = request.deployment;
    let expected_input = request.expected_input;
    // Move existing capabilities directly into their complete erasing witness.
    // The source seed stays guarded throughout construction, including allocation.
    let mut witness = NoteWithdrawalWitness {
        packet: NoteWithdrawalPacket { deployment, input: expected_input,
            outputs: request.effects, expiry: request.expiry, terms_commitment: [0; 32] },
        blind: [0; 32], owner_seed: *owner_seed, input, membership, consent: [0; 64],
        owned_outputs: Vec::with_capacity(1),
    };
    deployment.validate()?;
    if witness.packet.outputs.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    witness.input.validate()?;
    if witness.input.order.is_some() || witness.input.deployment_digest != deployment.digest()?
        || witness.input.owner_key != expected_input.owner_key
        || witness.input.commitment()? != expected_input.commitment
        || witness.input.nullifier()? != expected_input.nullifier
    { return Err(RelationError::Input); }
    if witness.owner_seed == [0; 32]
        || SigningKey::from_bytes(&witness.owner_seed).verifying_key().to_bytes()
            != witness.input.owner_key
    { return Err(RelationError::Key); }
    if witness.membership.tree_id != expected_input.tree_id
        || witness.membership.index != expected_input.index
        || witness.membership.root(&witness.input.deployment_digest, &expected_input.commitment)
            != expected_input.root
    { return Err(RelationError::Membership); }
    for output in &witness.packet.outputs {
        match output {
            OutputDescriptor::Exit { asset, .. } | OutputDescriptor::Fee { asset, .. }
                if *asset == witness.input.asset => {}
            _ => return Err(RelationError::Output),
        }
    }
    // Reuse the existing canonical body validator before entropy. This nonzero
    // internal placeholder is guarded and replaced before binding final terms.
    witness.blind = [1; 32];
    note_withdrawal_terms_commitment(&deployment, &expected_input,
        &witness.packet.outputs, witness.packet.expiry, &witness.blind)?;
    let mut spent = U512::zero();
    for output in &witness.packet.outputs {
        let amount = match output {
            OutputDescriptor::Exit { amount, .. } | OutputDescriptor::Fee { amount, .. } => *amount,
            _ => return Err(RelationError::Output),
        };
        spent = spent.checked_add(U512::from(amount)).ok_or(RelationError::Conservation)?;
    }
    let residual = U512::from(witness.input.value).checked_sub(spent)
        .ok_or(RelationError::Conservation)?;
    let residual = U256::try_from(residual).map_err(|_| RelationError::Conservation)?;
    if !residual.is_zero() {
        if witness.packet.outputs.len() == MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
        // Public effects move unchanged. Reserve the final manifest before any
        // fresh secret is filled; owned storage was fully allocated above.
        witness.packet.outputs.reserve_exact(1);
        let mut opening = PreparedOutputOpening {
            manifest_index: witness.packet.outputs.len() as u32,
            note: NoteOpening { deployment_digest: witness.input.deployment_digest,
                owner_key: witness.input.owner_key, nf_key: [0; 32], nonce: [0; 32], salt: [0; 32],
                asset: witness.input.asset, value: residual, order: None },
            recovery_key: [0; 32],
        };
        fill_nonzero(&mut opening.note.nf_key)?;
        fill_nonzero(&mut opening.note.nonce)?;
        fill_nonzero(&mut opening.note.salt)?;
        fill_nonzero(&mut opening.recovery_key)?;
        if opening.note.nullifier()? == expected_input.nullifier { return Err(RelationError::Output); }
        let mut nonce = Zeroizing::new([0; 24]);
        fill_nonzero(&mut nonce[..])?;
        let output = prepare_output(&opening.note, Role::A, &opening.recovery_key, *nonce)?;
        witness.packet.outputs.push(output);
        witness.owned_outputs.push(opening);
    }
    fill_nonzero(&mut witness.blind)?;
    witness.packet.terms_commitment = note_withdrawal_terms_commitment(&deployment,
        &expected_input, &witness.packet.outputs, witness.packet.expiry, &witness.blind)?;
    review_note_withdrawal(&witness.packet, &witness, &deployment, expected_input.commitment)?;
    Ok(witness)
}

/// Independently selected complete order input and exact own-role public effects.
/// The historical root is selected separately from the supplied private path.
#[derive(Debug)]
pub struct CancelExitRequest {
    pub deployment: Deployment,
    pub expected_input: InputDescriptor,
    pub role: Role,
    pub action: Action,
    pub expiry: u64,
    pub effects: Vec<OutputDescriptor>,
}

/// Construct an unsigned Cancel or Exit with zero or one fresh ordinary return.
/// Both actions use the existing relation's identical effect and fee rules.
/// Membership is not root admission or authenticated global spentness. Select
/// the complete resulting packet independently again before real consent;
/// retaining this erasing witness is neither durable backup nor execution.
pub fn prepare_cancel_exit(
    request: CancelExitRequest, input: NoteOpening, membership: MerkleMembership,
    owner_seed: Zeroizing<[u8; 32]>,
) -> Result<CancelExitWitness, RelationError> {
    let deployment = request.deployment;
    let expected_input = request.expected_input;
    let role = request.role;
    let action = request.action;
    // Install the complete erasing witness before any entropy or fallible private
    // operation, keeping the moved source owner capability guarded throughout.
    let mut witness = CancelExitWitness {
        packet: SingleOwnerPacket { deployment, input: expected_input,
            outputs: request.effects, expiry: request.expiry, terms_commitment: [0; 32] },
        blind: [0; 32], role, action, owner_seed: *owner_seed, input, membership,
        consent: [0; 64], owned_outputs: Vec::with_capacity(1),
    };
    deployment.validate()?;
    if witness.packet.outputs.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    witness.input.validate()?;
    let order = witness.input.order.as_ref().ok_or(RelationError::Input)?;
    order.policy.validate_for(role)?;
    if witness.input.deployment_digest != deployment.digest()?
        || witness.input.owner_key != expected_input.owner_key
        || witness.input.commitment()? != expected_input.commitment
        || witness.input.nullifier()? != expected_input.nullifier
        || order.id != expected_input.order_id || order.generation != expected_input.generation
    { return Err(RelationError::Input); }
    if witness.owner_seed == [0; 32]
        || SigningKey::from_bytes(&witness.owner_seed).verifying_key().to_bytes()
            != witness.input.owner_key
    { return Err(RelationError::Key); }
    if action == Action::Fill { return Err(RelationError::Action); }
    if witness.membership.tree_id != expected_input.tree_id
        || witness.membership.index != expected_input.index
        || witness.membership.root(&witness.input.deployment_digest, &expected_input.commitment)
            != expected_input.root
    { return Err(RelationError::Membership); }
    expected_input.validate()?;
    if witness.packet.expiry == 0 { return Err(SamechainError::InvalidTerms.into()); }
    for output in &witness.packet.outputs {
        match output {
            OutputDescriptor::Exit { asset, .. } | OutputDescriptor::Fee { asset, .. }
                if *asset == witness.input.asset => {}
            _ => return Err(RelationError::Output),
        }
        if output.role() != role { return Err(SamechainError::InvalidRole.into()); }
    }
    // Empty effects are a full ordinary return, not an empty final manifest.
    // The existing fee/canonical validator intentionally rejects an empty body.
    if !witness.packet.outputs.is_empty() {
        order.policy.fee_policy.validate_fees(role, &witness.packet.outputs)?;
    }
    let mut spent = U512::zero();
    for output in &witness.packet.outputs {
        let amount = match output {
            OutputDescriptor::Exit { amount, .. } | OutputDescriptor::Fee { amount, .. } => *amount,
            _ => return Err(RelationError::Output),
        };
        spent = spent.checked_add(U512::from(amount)).ok_or(RelationError::Conservation)?;
    }
    let residual = U512::from(witness.input.value).checked_sub(spent)
        .ok_or(RelationError::Conservation)?;
    let residual = U256::try_from(residual).map_err(|_| RelationError::Conservation)?;
    if !residual.is_zero() {
        if witness.packet.outputs.len() == MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
        // Reserve the complete public manifest before generating fresh secrets;
        // owned-return storage was already fully allocated in the witness.
        witness.packet.outputs.reserve_exact(1);
        let mut opening = PreparedOutputOpening {
            manifest_index: witness.packet.outputs.len() as u32,
            note: NoteOpening { deployment_digest: witness.input.deployment_digest,
                owner_key: witness.input.owner_key, nf_key: [0; 32], nonce: [0; 32], salt: [0; 32],
                asset: witness.input.asset, value: residual, order: None },
            recovery_key: [0; 32],
        };
        fill_nonzero(&mut opening.note.nf_key)?;
        fill_nonzero(&mut opening.note.nonce)?;
        fill_nonzero(&mut opening.note.salt)?;
        fill_nonzero(&mut opening.recovery_key)?;
        if opening.note.nullifier()? == expected_input.nullifier { return Err(RelationError::Output); }
        let mut nonce = Zeroizing::new([0; 24]);
        fill_nonzero(&mut nonce[..])?;
        let output = prepare_output(&opening.note, role, &opening.recovery_key, *nonce)?;
        witness.packet.outputs.push(output);
        witness.owned_outputs.push(opening);
    }
    fill_nonzero(&mut witness.blind)?;
    witness.packet.terms_commitment = single_terms_commitment(&deployment, &expected_input,
        &witness.packet.outputs, witness.packet.expiry, &witness.blind)?;
    review_owner_cancel_exit(&witness.packet, &witness, &deployment, expected_input.order_id, role, action)?;
    Ok(witness)
}

/// Prepare only this owner's recipient notes, with no other owner's secrets.
/// `fees` must be an explicit own-role Fee-only slice; returned descriptors do
/// not include those caller-owned fees. Exits are outside this API's scope.
/// Derive `sold`/`credit` from the independently approved FillExecution role pair
/// before preparation; review the assembled packet against that same execution
/// with `review_owner_fill` before authorizing anything.
pub fn prepare_fill_outputs(
    input: &NoteOpening, expected_deployment: &Deployment, expected_order_id: [u8; 32],
    role: Role, sold: U256, credit: U256, fees: &[OutputDescriptor],
) -> Result<PreparedFillOutputs, RelationError> {
    expected_deployment.validate()?;
    input.validate()?;
    let order = input.order.as_ref().ok_or(RelationError::Input)?;
    if input.deployment_digest != expected_deployment.digest()?
        || expected_order_id == [0; 32] || order.id != expected_order_id
    {
        return Err(RelationError::Input);
    }
    let policy = &order.policy;
    policy.validate_for(role)?;
    if sold.is_zero() || credit.is_zero() {
        return Err(SamechainError::InvalidTerms.into());
    }
    let remaining = order.remaining_sell.checked_sub(sold).ok_or(RelationError::Successor)?;
    if fees.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    let mut sell_fees = U512::zero();
    let mut buy_fees = U512::zero();
    for fee in fees {
        let OutputDescriptor::Fee { payer, asset, amount, .. } = fee else {
            return Err(RelationError::Output);
        };
        if *payer != role { return Err(RelationError::Output); }
        if *asset == policy.sell_asset {
            sell_fees += U512::from(*amount);
        } else if *asset == policy.buy_asset {
            buy_fees += U512::from(*amount);
        } else {
            return Err(RelationError::Output);
        }
    }
    // The existing validator requires a nonempty complete manifest. An empty
    // accepted fee-only slice is valid; never weaken the financial validator.
    if !fees.is_empty() { policy.fee_policy.validate_fees(role, fees)?; }
    let residual = U512::from(input.value).checked_sub(U512::from(sold))
        .and_then(|value| value.checked_sub(sell_fees)).ok_or(RelationError::Conservation)?;
    let proceeds = U512::from(credit).checked_sub(buy_fees).ok_or(RelationError::Conservation)?;
    if proceeds * U512::from(policy.min_sell_den) < sold.full_mul(policy.min_buy_num) {
        return Err(SamechainError::LimitNotMet.into());
    }
    let residual = U256::try_from(residual).map_err(|_| RelationError::Conservation)?;
    let proceeds = U256::try_from(proceeds).map_err(|_| RelationError::Conservation)?;
    let successor = if remaining.is_zero() {
        None
    } else {
        if residual < remaining { return Err(RelationError::Successor); }
        Some(OrderState { id: order.id,
            generation: order.generation.checked_add(1).ok_or(RelationError::Successor)?,
            remaining_sell: remaining, policy: policy.clone() })
    };
    let input_nullifier = input.nullifier()?;
    let mut previous_nullifier = None;
    // At most sell remainder/change and buy proceeds. Allocate the complete
    // secret-bearing vector before filling any secret; never grow it afterward.
    let mut prepared = PreparedFillOutputs {
        descriptors: Vec::with_capacity(2), openings: Vec::with_capacity(2),
    };
    for (asset, value, order) in [
        (policy.sell_asset, residual, successor), (policy.buy_asset, proceeds, None),
    ] {
        if value.is_zero() { continue; }
        // Install Drop erasure guards before entropy calls or any fallible
        // cryptography so partial entropy failures erase the filled fields.
        let mut opening = PreparedOutputOpening {
            manifest_index: prepared.descriptors.len() as u32,
            note: NoteOpening { deployment_digest: input.deployment_digest,
                owner_key: input.owner_key, nf_key: [0; 32], nonce: [0; 32], salt: [0; 32],
                asset, value, order },
            recovery_key: [0; 32],
        };
        fill_nonzero(&mut opening.note.nf_key)?;
        fill_nonzero(&mut opening.note.nonce)?;
        fill_nonzero(&mut opening.note.salt)?;
        fill_nonzero(&mut opening.recovery_key)?;
        let mut nonce = Zeroizing::new([0; 24]);
        fill_nonzero(&mut nonce[..])?;
        let nullifier = opening.note.nullifier()?;
        if nullifier == input_nullifier || previous_nullifier == Some(nullifier) {
            return Err(RelationError::Output);
        }
        let descriptor = prepare_output(&opening.note, role, &opening.recovery_key, *nonce)?;
        prepared.descriptors.push(descriptor);
        prepared.openings.push(opening);
        previous_nullifier = Some(nullifier);
    }
    Ok(prepared)
}

fn fill_nonzero(bytes: &mut [u8]) -> Result<(), RelationError> {
    getrandom::fill(bytes).map_err(|_| RelationError::Key)?;
    if bytes.iter().all(|byte| *byte == 0) { return Err(RelationError::Key); }
    Ok(())
}
