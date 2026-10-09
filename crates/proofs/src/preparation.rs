//! Deterministic, wallet-private P/Q preparation subrelation, shared with the SP1 guest.
//!
//! This checks local note ownership/openings, a path to the supplied anchor, exact
//! P/Q effects, authenticated recipient ciphertexts, conservation/fees and Q signatures.
//! It independently opens context input/payment commitments, aggregates every P
//! output, derives the note tag and exact solver capsule and verifies owner consent.
//! It does NOT establish accepted source history, anchor admissibility/unspentness,
//! Q Halo2 proof validity, finality, arbitrary payment classification, financial
//! entitlement or atomic tag consumption. Those remain REQUIRED composition gates.
//! Privacy assumes confidential high-entropy blinds/nk and Orchard/PRF binding;
//! FVK holders can correlate and same-note equality within a deployment is intentional.

use std::{fmt, io};
use crate::native_effects;

use orchard::{
    Address, Anchor, Note,
    bundle::BundleVersion,
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho, TransmittedNoteCiphertext},
    note_encryption::IronwoodDomain,
    pczt::{Action, Bundle},
    primitives::redpallas::{Signature, SpendAuth, VerificationKey},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    Pczt,
    common::determine_lock_time,
    roles::{
        creator::Creator,
        verifier::{OrchardError, Verifier},
    },
};
use zcash_note_encryption::{Domain, try_output_recovery_with_pkd_esk};
use zcash_primitives::transaction::{
    Transaction, TxVersion,
    components::orchard::{ACTION_SIZE, SPEND_AUTH_SIG_SIZE},
    txid::{TxIdDigester, to_txid},
    fees::{FeeRule as _, zip317},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, TEST_NETWORK},
    constants::{MAX_BLOCK_BYTES, V6_TX_VERSION, V6_VERSION_GROUP_ID},
    value::Zatoshis,
};
use zeroize::{Zeroize, Zeroizing};
use ziquid_protocol::{
    CONTEXT_ENCODED_LEN, MAX_QUOTED_RECEIVERS, MAX_SOURCE_AMOUNT, PreparationBinding,
    SolverCapsule, StatementContext, ValidatedContext, input_commitment, note_consumption_tag,
    payment_commitment, preparation_consent_digest, preparation_packet_binding,
    solver_capsule_commitment,
};

pub const JOURNAL_DOMAIN: &[u8] = b"ziquid.preparation.v3";
pub const JOURNAL_LEN: usize = JOURNAL_DOMAIN.len() + 128;
const PRIVATE_DOMAIN: &[u8] = b"ziquid.preparation.private.v3";
pub const MAX_TRANSACTION_BYTES: usize = MAX_BLOCK_BYTES;
/// Application resource ceiling, NOT a PCZT consensus limit. Private openings,
/// dummy witnesses and metadata exceed their corresponding transaction's size.
pub const MAX_PCZT_BYTES: usize = 16 * 1024 * 1024;
const FIXED_PRIVATE_LEN: usize = PRIVATE_DOMAIN.len() + CONTEXT_ENCODED_LEN
    + 4 + 43 + 8 + 32 + 32 + 96 + 4 + 32 * 32 + 32 + 32 + 32 + 32 + 32 + 64 + 2;
pub const MAX_PRIVATE_INPUT_BYTES: usize = FIXED_PRIVATE_LEN + 43 * MAX_QUOTED_RECEIVERS
    + 16 + 3 * MAX_PCZT_BYTES + MAX_TRANSACTION_BYTES;
// Consensus action widths come from the upstream transaction encoder, not a
// two-action assumption. Proof/header overhead only lowers the true maximum.
const MAX_ACTIONS: usize = MAX_TRANSACTION_BYTES / (ACTION_SIZE + SPEND_AUTH_SIG_SIZE);

/// Private caller/prover boundary only. U's FVK and all openings remain local;
/// never include this encoding with a public journal, export packet or log.
#[derive(Clone)]
pub struct PreparationWitness {
    pub context_bytes: [u8; CONTEXT_ENCODED_LEN],
    /// Claimed authoring height, not an authenticated current source height.
    pub source_target_height: u32,
    pub note_recipient: [u8; 43],
    pub note_value: u64,
    pub note_rho: [u8; 32],
    pub note_rseed: [u8; 32],
    pub full_viewing_key: [u8; 96],
    pub merkle_position: u32,
    pub merkle_siblings: [[u8; 32]; 32],
    pub anchor: [u8; 32],
    pub private_p_pczt: Vec<u8>,
    pub redacted_p_pczt: Vec<u8>,
    pub private_q_pczt: Vec<u8>,
    pub q_transaction: Vec<u8>,
    pub secret_blind: [u8; 32],
    /// Solver-private randomness independent of preparation/input/payment blinds.
    pub capsule_blind: [u8; 32],
    pub input_blind: [u8; 32],
    pub payment_blind: [u8; 32],
    pub quoted_receivers: Vec<[u8; 43]>,
    pub owner_intent_signature: [u8; 64],
}

impl fmt::Debug for PreparationWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparationWitness([REDACTED])")
    }
}

impl Drop for PreparationWitness {
    fn drop(&mut self) {
        self.context_bytes.zeroize();
        self.source_target_height.zeroize();
        self.note_recipient.zeroize();
        self.note_value.zeroize();
        self.note_rho.zeroize();
        self.note_rseed.zeroize();
        self.full_viewing_key.zeroize();
        self.merkle_position.zeroize();
        self.merkle_siblings.zeroize();
        self.anchor.zeroize();
        self.private_p_pczt.zeroize();
        self.redacted_p_pczt.zeroize();
        self.private_q_pczt.zeroize();
        self.q_transaction.zeroize();
        self.secret_blind.zeroize();
        self.capsule_blind.zeroize();
        self.input_blind.zeroize();
        self.payment_blind.zeroize();
        self.quoted_receivers.zeroize();
        self.owner_intent_signature.zeroize();
    }
}

/// Four public digests only: context, private binding, derived tag and capsule.
/// No NF, rk, receiver, path, blind or signature; decoding/matching is UNVERIFIED
/// value processing, never a wrapped proof or a financial/funding capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationJournal {
    context_digest: [u8; 32],
    packet_binding: [u8; 32],
    consumption_tag: [u8; 32],
    solver_capsule_commitment: [u8; 32],
}

impl PreparationJournal {
    pub fn encode(&self) -> [u8; JOURNAL_LEN] {
        let mut bytes = [0; JOURNAL_LEN];
        bytes[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
        bytes[JOURNAL_DOMAIN.len()..JOURNAL_DOMAIN.len() + 32]
            .copy_from_slice(&self.context_digest);
        bytes[JOURNAL_DOMAIN.len() + 32..JOURNAL_DOMAIN.len() + 64]
            .copy_from_slice(&self.packet_binding);
        bytes[JOURNAL_DOMAIN.len() + 64..JOURNAL_DOMAIN.len() + 96]
            .copy_from_slice(&self.consumption_tag);
        bytes[JOURNAL_DOMAIN.len() + 96..].copy_from_slice(&self.solver_capsule_commitment);
        bytes
    }

    /// Strict v3 public-value decoding only. No source or proof trust is promoted.
    pub fn decode(encoded: &[u8]) -> Result<Self, PreparationError> {
        if encoded.len() != JOURNAL_LEN || !encoded.starts_with(JOURNAL_DOMAIN) {
            return Err(PreparationError::Encoding);
        }
        let mut fields = &encoded[JOURNAL_DOMAIN.len()..];
        let journal = Self {
            context_digest: take(&mut fields)?,
            packet_binding: take(&mut fields)?,
            consumption_tag: take(&mut fields)?,
            solver_capsule_commitment: take(&mut fields)?,
        };
        if !fields.is_empty() || [
            &journal.context_digest, &journal.packet_binding,
            &journal.consumption_tag, &journal.solver_capsule_commitment,
        ].iter().any(|field| field.iter().all(|&byte| byte == 0)) {
            return Err(PreparationError::Encoding);
        }
        Ok(journal)
    }

    /// Exact exported-packet correspondence only. A security consumer must first
    /// authenticate this journal with an independently pinned wrapped proof and
    /// separately verify Q's full PostNu6_3 authorization; decode establishes neither.
    /// Neither a match nor this journal authorizes acceptance or funding.
    pub fn check_solver_capsule(&self, input: SolverCapsule<'_>) -> Result<(), PreparationError> {
        if self.context_digest != input.context.digest() {
            return Err(PreparationError::Context);
        }
        if self.packet_binding != *input.private_packet_binding {
            return Err(PreparationError::PacketBinding);
        }
        if self.consumption_tag != input.context.context().consumption_tag {
            return Err(PreparationError::ConsumptionTag);
        }
        if self.solver_capsule_commitment != solver_capsule_commitment(input)
            .map_err(|_| PreparationError::SolverCapsule)?
        {
            return Err(PreparationError::SolverCapsule);
        }
        Ok(())
    }

    pub const fn context_digest(&self) -> [u8; 32] { self.context_digest }
    pub const fn packet_binding(&self) -> [u8; 32] { self.packet_binding }
    pub const fn consumption_tag(&self) -> [u8; 32] { self.consumption_tag }
    pub const fn solver_capsule_commitment(&self) -> [u8; 32] { self.solver_capsule_commitment }
}

/// Sanitized failure categories never carry notes, keys, paths or packet bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationError {
    Encoding,
    ResourceLimit,
    Blind,
    ReceiverSet,
    InputCommitment,
    PaymentCommitment,
    ConsumptionTag,
    PacketBinding,
    SolverCapsule,
    OwnerConsent,
    Context,
    Source,
    Pczt,
    Transaction,
    UnsupportedComponents,
    Headers,
    Effects,
    Note,
    Ownership,
    Anchor,
    Action,
    PositiveInput,
    DuplicateNullifier,
    Ciphertext,
    Conservation,
    Fee,
    Signature,
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "preparation subrelation rejected: {self:?}")
    }
}

impl std::error::Error for PreparationError {}

impl PreparationWitness {
    /// One canonical guarded private buffer: fixed v3 fields, u16-LE receiver
    /// count and ordered 43-byte addresses, then four u32-LE length-framed blobs.
    /// Zero consent is allowed during preparation; verification still requires it.
    #[cfg(not(target_os = "zkvm"))]
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>, PreparationError> {
        check_lengths(self)?;
        check_private_header(self)?;
        check_receivers(&self.quoted_receivers)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            FIXED_PRIVATE_LEN + 43 * self.quoted_receivers.len() + 16
                + self.private_p_pczt.len() + self.redacted_p_pczt.len()
                + self.private_q_pczt.len() + self.q_transaction.len(),
        ));
        bytes.extend_from_slice(PRIVATE_DOMAIN);
        bytes.extend_from_slice(&self.context_bytes);
        bytes.extend_from_slice(&self.source_target_height.to_le_bytes());
        bytes.extend_from_slice(&self.note_recipient);
        bytes.extend_from_slice(&self.note_value.to_le_bytes());
        bytes.extend_from_slice(&self.note_rho);
        bytes.extend_from_slice(&self.note_rseed);
        bytes.extend_from_slice(&self.full_viewing_key);
        bytes.extend_from_slice(&self.merkle_position.to_le_bytes());
        for sibling in &self.merkle_siblings {
            bytes.extend_from_slice(sibling);
        }
        bytes.extend_from_slice(&self.anchor);
        bytes.extend_from_slice(&self.secret_blind);
        bytes.extend_from_slice(&self.capsule_blind);
        bytes.extend_from_slice(&self.input_blind);
        bytes.extend_from_slice(&self.payment_blind);
        bytes.extend_from_slice(&self.owner_intent_signature);
        bytes.extend_from_slice(&(self.quoted_receivers.len() as u16).to_le_bytes());
        for receiver in &self.quoted_receivers {
            bytes.extend_from_slice(receiver);
        }
        for blob in [
            &self.private_p_pczt,
            &self.redacted_p_pczt,
            &self.private_q_pczt,
            &self.q_transaction,
        ] {
            bytes.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            bytes.extend_from_slice(blob);
        }
        Ok(bytes)
    }

    pub fn decode_private(encoded: &[u8]) -> Result<Self, PreparationError> {
        if encoded.len() > MAX_PRIVATE_INPUT_BYTES {
            return Err(PreparationError::ResourceLimit);
        }
        if encoded.len() < FIXED_PRIVATE_LEN + 16 || !encoded.starts_with(PRIVATE_DOMAIN) {
            return Err(PreparationError::Encoding);
        }
        // Own guarded fields immediately: every `?` below drops and wipes all
        // already-decoded private data, including malformed/truncated frames.
        let mut witness = Self {
            context_bytes: [0; CONTEXT_ENCODED_LEN], source_target_height: 0,
            note_recipient: [0; 43], note_value: 0, note_rho: [0; 32],
            note_rseed: [0; 32], full_viewing_key: [0; 96], merkle_position: 0,
            merkle_siblings: [[0; 32]; 32], anchor: [0; 32], secret_blind: [0; 32],
            capsule_blind: [0; 32], input_blind: [0; 32], payment_blind: [0; 32],
            owner_intent_signature: [0; 64], quoted_receivers: Vec::new(),
            private_p_pczt: Vec::new(), redacted_p_pczt: Vec::new(),
            private_q_pczt: Vec::new(), q_transaction: Vec::new(),
        };
        let mut fields = &encoded[PRIVATE_DOMAIN.len()..];
        witness.context_bytes = take(&mut fields)?;
        witness.source_target_height = u32::from_le_bytes(take(&mut fields)?);
        witness.note_recipient = take(&mut fields)?;
        witness.note_value = u64::from_le_bytes(take(&mut fields)?);
        witness.note_rho = take(&mut fields)?;
        witness.note_rseed = take(&mut fields)?;
        witness.full_viewing_key = take(&mut fields)?;
        witness.merkle_position = u32::from_le_bytes(take(&mut fields)?);
        for sibling in &mut witness.merkle_siblings {
            *sibling = take(&mut fields)?;
        }
        witness.anchor = take(&mut fields)?;
        witness.secret_blind = take(&mut fields)?;
        witness.capsule_blind = take(&mut fields)?;
        witness.input_blind = take(&mut fields)?;
        witness.payment_blind = take(&mut fields)?;
        witness.owner_intent_signature = take(&mut fields)?;
        check_private_header(&witness)?;
        let receiver_count = usize::from(u16::from_le_bytes(take(&mut fields)?));
        if receiver_count == 0 || receiver_count > MAX_QUOTED_RECEIVERS {
            return Err(PreparationError::ReceiverSet);
        }
        let (receivers, remaining) = fields.split_at_checked(43 * receiver_count)
            .ok_or(PreparationError::Encoding)?;
        fields = remaining;
        let mut previous: Option<&[u8; 43]> = None;
        for raw in receivers.as_chunks::<43>().0 {
            if !canonical_address(raw)
                || previous.is_some_and(|previous| previous >= raw)
            {
                return Err(PreparationError::ReceiverSet);
            }
            previous = Some(raw);
        }
        // Validate ALL receiver/header/blob shapes and full consumption before
        // allocating or copying any receiver list or variable private blob.
        let private_p = frame(&mut fields, MAX_PCZT_BYTES)?;
        let redacted_p = frame(&mut fields, MAX_PCZT_BYTES)?;
        let private_q = frame(&mut fields, MAX_PCZT_BYTES)?;
        let q = frame(&mut fields, MAX_TRANSACTION_BYTES)?;
        if !fields.is_empty() {
            return Err(PreparationError::Encoding);
        }
        witness.quoted_receivers = receivers.as_chunks::<43>().0.to_vec();
        witness.private_p_pczt = private_p.to_vec();
        witness.redacted_p_pczt = redacted_p.to_vec();
        witness.private_q_pczt = private_q.to_vec();
        witness.q_transaction = q.to_vec();
        Ok(witness)
    }

    /// Pure, signature-independent packet frame for owner consent sequencing.
    /// This does not verify semantic openings, P/Q cryptography or ownership.
    #[cfg(not(target_os = "zkvm"))]
    pub fn preparation_binding(&self) -> Result<[u8; 32], PreparationError> {
        let context = ValidatedContext::decode(&self.context_bytes)
            .map_err(|_| PreparationError::Context)?;
        packet_binding(self, &context)
    }

    /// Signature-independent capsule derived from this witness's actual P/Q and
    /// private binding. Bootstrap may leave consent zero; the relation may not.
    #[cfg(not(target_os = "zkvm"))]
    pub fn solver_capsule_commitment(&self) -> Result<[u8; 32], PreparationError> {
        let context = check_private_header(self)?;
        let binding = packet_binding(self, &context)?;
        capsule_commitment(self, &context, &binding)
    }
}

fn take<const N: usize>(fields: &mut &[u8]) -> Result<[u8; N], PreparationError> {
    let (value, remaining) = fields
        .split_at_checked(N)
        .ok_or(PreparationError::Encoding)?;
    *fields = remaining;
    value.try_into().map_err(|_| PreparationError::Encoding)
}

fn frame<'a>(fields: &mut &'a [u8], cap: usize) -> Result<&'a [u8], PreparationError> {
    let len = u32::from_le_bytes(take(fields)?) as usize;
    if len == 0 || len > cap {
        return Err(PreparationError::ResourceLimit);
    }
    let (value, remaining) = fields
        .split_at_checked(len)
        .ok_or(PreparationError::Encoding)?;
    *fields = remaining;
    Ok(value)
}

fn check_lengths(witness: &PreparationWitness) -> Result<(), PreparationError> {
    for (blob, cap) in [
        (&witness.private_p_pczt, MAX_PCZT_BYTES),
        (&witness.redacted_p_pczt, MAX_PCZT_BYTES),
        (&witness.private_q_pczt, MAX_PCZT_BYTES),
        (&witness.q_transaction, MAX_TRANSACTION_BYTES),
    ] {
        if blob.is_empty() || blob.len() > cap {
            return Err(PreparationError::ResourceLimit);
        }
    }
    Ok(())
}

fn check_source(witness: &PreparationWitness, source: &StatementContext) -> Result<(), PreparationError> {
    if source.consensus_branch != u32::from(BranchId::Nu6_3)
        || !(4_134_000..4_465_026).contains(&witness.source_target_height)
        || source.source_expiry < witness.source_target_height
        || source.source_expiry >= 4_465_026
    {
        return Err(PreparationError::Source);
    }
    Ok(())
}

fn check_private_header(witness: &PreparationWitness) -> Result<ValidatedContext, PreparationError> {
    let context = ValidatedContext::decode(&witness.context_bytes)
        .map_err(|_| PreparationError::Context)?;
    check_source(witness, context.context())?;
    if witness.secret_blind == [0; 32] || witness.input_blind == [0; 32]
        || witness.payment_blind == [0; 32] || witness.input_blind == witness.payment_blind
        || witness.capsule_blind == [0; 32] || witness.capsule_blind == witness.secret_blind
        || witness.capsule_blind == witness.input_blind
        || witness.capsule_blind == witness.payment_blind
    {
        return Err(PreparationError::Blind);
    }
    if witness.note_value == 0 || witness.note_value > MAX_SOURCE_AMOUNT {
        return Err(PreparationError::PositiveInput);
    }
    if !canonical_address(&witness.note_recipient) {
        return Err(PreparationError::Note);
    }
    Ok(context)
}

fn check_receivers(receivers: &[[u8; 43]]) -> Result<(), PreparationError> {
    if receivers.is_empty() || receivers.len() > MAX_QUOTED_RECEIVERS
        || receivers.windows(2).any(|pair| pair[0] >= pair[1])
        || receivers.iter().any(|raw| !canonical_address(raw))
    {
        return Err(PreparationError::ReceiverSet);
    }
    Ok(())
}

fn canonical_address(raw: &[u8; 43]) -> bool {
    Address::from_raw_address_bytes(raw).into_option()
        .is_some_and(|address| *Zeroizing::new(address.to_raw_address_bytes()) == *raw)
}

/// Checks this bounded preparation subrelation only. In particular, successful
/// signature checks MUST NOT substitute for Q's separate PostNu6_3 Halo2 gate.
pub fn verify_preparation(
    witness: &PreparationWitness,
) -> Result<PreparationJournal, PreparationError> {
    check_lengths(witness)?;
    let context = check_private_header(witness)?;
    check_receivers(&witness.quoted_receivers)?;
    let source = context.context();
    let height = BlockHeight::from(witness.source_target_height);

    let note = reconstruct_note(
        witness.note_recipient,
        witness.note_value,
        witness.note_rho,
        witness.note_rseed,
    )?;
    let fvk =
        FullViewingKey::from_bytes(&witness.full_viewing_key).ok_or(PreparationError::Ownership)?;
    if fvk.scope_for_address(&note.recipient()).is_none() {
        return Err(PreparationError::Ownership);
    }
    let nf = Zeroizing::new(note.nullifier(&fvk).to_bytes());
    for raw in &witness.quoted_receivers {
        let receiver = Option::<Address>::from(Address::from_raw_address_bytes(raw))
            .ok_or(PreparationError::ReceiverSet)?;
        if fvk.scope_for_address(&receiver).is_some() {
            return Err(PreparationError::Ownership);
        }
    }
    let cmx = Zeroizing::new(ExtractedNoteCommitment::from(note.commitment()).to_bytes());
    if input_commitment(&witness.input_blind, &source.source_network, &source.source_pool,
        &witness.note_recipient, witness.note_value, &witness.note_rho, &witness.note_rseed,
        &cmx, &nf).map_err(|_| PreparationError::InputCommitment)? != source.real_input_commitment
    {
        return Err(PreparationError::InputCommitment);
    }
    let fvk_bytes = Zeroizing::new(fvk.to_bytes());
    let nk: &[u8; 32] = fvk_bytes[32..64].try_into().expect("canonical FVK nk width");
    let consumption_tag = note_consumption_tag(&source.source_network, &source.source_pool,
        source.evm_chain_id, &source.escrow, nk, &nf)
        .map_err(|_| PreparationError::ConsumptionTag)?;
    if consumption_tag != source.consumption_tag {
        return Err(PreparationError::ConsumptionTag);
    }
    let binding = packet_binding(witness, &context)?;
    let capsule = capsule_commitment(witness, &context, &binding)?;
    let consent_digest = Zeroizing::new(preparation_consent_digest(&context, &binding, &capsule)
        .map_err(|_| PreparationError::OwnerConsent)?);
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(witness.anchor))
        .ok_or(PreparationError::Anchor)?;
    let mut siblings = [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32];
    for (sibling, bytes) in siblings.iter_mut().zip(&witness.merkle_siblings) {
        *sibling = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
            .ok_or(PreparationError::Anchor)?;
    }
    let path = MerklePath::from_parts(witness.merkle_position, siblings);
    if path.root(note.commitment().into()) != anchor {
        return Err(PreparationError::Anchor);
    }

    // The v5 Creator supplies the actual canonical EMPTY other-pool values,
    // including hidden proof/binding-key fields; checking vectors alone is unsafe.
    let empty = Creator::new(
        BranchId::Nu6_2.into(),
        source.source_expiry,
        133,
        None,
        None,
    )
    .map_err(|_| PreparationError::Pczt)?
    .build()
    .map_err(|_| PreparationError::Pczt)?;
    let private_p = parse_pczt(&witness.private_p_pczt, source, &empty)?;
    let redacted_p = parse_pczt(&witness.redacted_p_pczt, source, &empty)?;
    let private_q = parse_pczt(&witness.private_q_pczt, source, &empty)?;
    if !redacted_p.global().proprietary().is_empty() {
        return Err(PreparationError::Pczt);
    }
    let lock_time = determine_lock_time(private_p.global(), private_p.transparent().inputs())
        .ok_or(PreparationError::Headers)?;
    for pczt in [&redacted_p, &private_q] {
        if determine_lock_time(pczt.global(), pczt.transparent().inputs()) != Some(lock_time) {
            return Err(PreparationError::Headers);
        }
    }
    let transaction = parse_transaction(&witness.q_transaction, source, lock_time)?;

    let verified_p = Verifier::new(private_p)
        .with_ironwood::<PreparationError, _>(|p| {
            verify_bundle(p, &note, &fvk, &path, anchor, height, source, false,
                &witness.quoted_receivers)
                .map_err(OrchardError::Custom)?;
            Verifier::new(redacted_p)
                .with_ironwood::<PreparationError, _>(|export| {
                    compare_pczt_effects(p, export).map_err(OrchardError::Custom)?;
                    check_redacted(export).map_err(OrchardError::Custom)
                })
                .map_err(|error| OrchardError::Custom(role_error(error)))?
                .finish();
            Ok(())
        })
        .map_err(role_error)?
        .finish();
    let effects = verified_p.into_effects().map_err(|_| PreparationError::Effects)?;
    let effect_id: [u8; 32] = to_txid(effects.version(), effects.consensus_branch_id(),
        &effects.digest(TxIdDigester)).into();
    if payment_commitment(&witness.payment_blind, &source.source_network, &source.source_pool,
        &effect_id, &witness.quoted_receivers, source.source_quoted_amount)
        .map_err(|_| PreparationError::PaymentCommitment)? != source.source_payment_commitment
    {
        return Err(PreparationError::PaymentCommitment);
    }

    Verifier::new(private_q)
        .with_ironwood::<PreparationError, _>(|q| {
            let real_rk = verify_bundle(q, &note, &fvk, &path, anchor, height, source, true, &[])
                .map_err(OrchardError::Custom)?;
            compare_q_effects(q, &transaction).map_err(OrchardError::Custom)?;
            real_rk.verify(&*consent_digest, &Signature::<SpendAuth>::from(witness.owner_intent_signature))
                .map_err(|_| OrchardError::Custom(PreparationError::OwnerConsent))
        })
        .map_err(role_error)?
        .finish();
    verify_q_signatures(&transaction)?;

    Ok(PreparationJournal {
        context_digest: context.digest(),
        packet_binding: binding,
        consumption_tag,
        solver_capsule_commitment: capsule,
    })
}

fn role_error(error: OrchardError<PreparationError>) -> PreparationError {
    match error {
        OrchardError::Custom(error) => error,
        OrchardError::Verify(_) => PreparationError::Action,
        OrchardError::Parse(_) | OrchardError::UnsupportedConsensusBranchId => {
            PreparationError::Pczt
        }
    }
}

fn parse_pczt(
    bytes: &[u8],
    context: &StatementContext,
    empty: &Pczt,
) -> Result<Pczt, PreparationError> {
    if bytes.is_empty() || bytes.len() > MAX_PCZT_BYTES {
        return Err(PreparationError::ResourceLimit);
    }
    let pczt = Pczt::parse(bytes).map_err(|_| PreparationError::Pczt)?;
    // Check exact bytes BEFORE role normalization/resolution. Postcard's parse
    // alone permits suffixes; consuming serialize also checks pool canonicality.
    let canonical = Zeroizing::new(pczt.clone().serialize().map_err(|_| PreparationError::Pczt)?);
    if canonical.as_slice() != bytes
    {
        return Err(PreparationError::Encoding);
    }
    if pczt.transparent() != empty.transparent()
        || pczt.sapling() != empty.sapling()
        || pczt.orchard() != empty.orchard()
    {
        return Err(PreparationError::UnsupportedComponents);
    }
    if *pczt.global().tx_version() != V6_TX_VERSION
        || *pczt.global().version_group_id() != V6_VERSION_GROUP_ID
        || *pczt.global().consensus_branch_id() != u32::from(BranchId::Nu6_3)
        || *pczt.global().expiry_height() != context.source_expiry
    {
        return Err(PreparationError::Headers);
    }
    // Typed pre-authorization parsing substitutes a valid zero placeholder for
    // a missing v6 anchor. Presence of the RAW wire anchor is independently required.
    if pczt.ironwood().anchor().is_none() {
        return Err(PreparationError::Anchor);
    }
    if pczt.ironwood().actions().is_empty() || pczt.ironwood().actions().len() > MAX_ACTIONS {
        return Err(PreparationError::ResourceLimit);
    }
    Ok(pczt)
}

fn parse_transaction(
    bytes: &[u8],
    context: &StatementContext,
    lock_time: u32,
) -> Result<Transaction, PreparationError> {
    let mut remaining = bytes;
    let transaction = Transaction::read(&mut remaining, BranchId::Nu6_3)
        .map_err(|_| PreparationError::Transaction)?;
    if !remaining.is_empty() {
        return Err(PreparationError::Encoding);
    }
    // Streaming exact comparison avoids allocating a second complete Q buffer.
    let mut exact = ExactWriter(bytes);
    transaction
        .write(&mut exact)
        .map_err(|_| PreparationError::Encoding)?;
    if !exact.0.is_empty() {
        return Err(PreparationError::Encoding);
    }
    if transaction.version() != TxVersion::V6
        || transaction.consensus_branch_id() != BranchId::Nu6_3
        || u32::from(transaction.expiry_height()) != context.source_expiry
        || transaction.lock_time() != lock_time
    {
        return Err(PreparationError::Headers);
    }
    if transaction.transparent_bundle().is_some()
        || transaction.sprout_bundle().is_some()
        || transaction.sapling_bundle().is_some()
        || transaction.orchard_bundle().is_some()
    {
        return Err(PreparationError::UnsupportedComponents);
    }
    let bundle = transaction
        .ironwood_bundle()
        .ok_or(PreparationError::Transaction)?;
    if bundle.bundle_version() != BundleVersion::ironwood_v3()
        || bundle.actions().len() > MAX_ACTIONS
    {
        return Err(PreparationError::Transaction);
    }
    Ok(transaction)
}

struct ExactWriter<'a>(&'a [u8]);

impl io::Write for ExactWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let (expected, remaining) = self
            .0
            .split_at_checked(bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if expected != bytes {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0 = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn reconstruct_note(
    recipient: [u8; 43],
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
) -> Result<Note, PreparationError> {
    Zatoshis::from_u64(value).map_err(|_| PreparationError::Note)?;
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient))
        .ok_or(PreparationError::Note)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho)).ok_or(PreparationError::Note)?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho))
        .ok_or(PreparationError::Note)?;
    Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .ok_or(PreparationError::Note)
}

fn spend_note(action: &Action) -> Result<Note, PreparationError> {
    let spend = action.spend();
    if *spend.note_version() != NoteVersion::V3 {
        return Err(PreparationError::Note);
    }
    reconstruct_note(
        spend
            .recipient()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .to_raw_address_bytes(),
        spend
            .value()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .inner(),
        spend
            .rho()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .to_bytes(),
        *spend
            .rseed()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .as_bytes(),
    )
}

fn output_note(action: &Action) -> Result<Note, PreparationError> {
    let output = action.output();
    if *output.note_version() != NoteVersion::V3 {
        return Err(PreparationError::Note);
    }
    reconstruct_note(
        output
            .recipient()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .to_raw_address_bytes(),
        output
            .value()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .inner(),
        action.spend().nullifier().to_bytes(),
        *output
            .rseed()
            .as_ref()
            .ok_or(PreparationError::Note)?
            .as_bytes(),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_bundle(
    bundle: &Bundle,
    real_note: &Note,
    fvk: &FullViewingKey,
    path: &MerklePath,
    anchor: Anchor,
    height: BlockHeight,
    context: &StatementContext,
    recovery: bool,
    receivers: &[[u8; 43]],
) -> Result<VerificationKey<SpendAuth>, PreparationError> {
    if *bundle.bundle_version() != BundleVersion::ironwood_v3() || bundle.flag_byte() & 3 != 3 {
        return Err(PreparationError::Action);
    }
    if bundle.anchor() != &anchor {
        return Err(PreparationError::Anchor);
    }
    bundle
        .verify_cross_address_restriction()
        .map_err(|_| PreparationError::Action)?;
    let mut positive_spends = 0usize;
    let mut input_total = 0u64;
    let mut output_total = 0u64;
    let mut payment_total = 0u64;
    let mut real_rk = None;
    // One bounded allocation for distinctness, instead of O(actions²) or
    // per-action tree allocations. Sort after all nullifiers are reconstructed.
    let mut nullifiers = Zeroizing::new(Vec::with_capacity(bundle.actions().len()));
    let real_nullifier = real_note.nullifier(fvk);
    for action in bundle.actions() {
        action
            .verify_cv_net()
            .map_err(|_| PreparationError::Action)?;
        action
            .spend()
            .verify_nullifier(Some(fvk))
            .map_err(|_| PreparationError::Ownership)?;
        action
            .spend()
            .verify_rk(Some(fvk))
            .map_err(|_| PreparationError::Action)?;
        action
            .output()
            .verify_note_commitment(action.spend())
            .map_err(|_| PreparationError::Action)?;
        // Upstream rk identity check; full sender recovery below constrains the
        // ephemeral key to the nonzero key derived from the reconstructed note.
        if action.spend().rk().is_identity() {
            return Err(PreparationError::Action);
        }
        let spent = spend_note(action)?;
        let spent_value = spent.value().inner();
        input_total = bounded_sum(input_total, spent_value)?;
        nullifiers.push(action.spend().nullifier().to_bytes());
        if spent_value != 0 {
            positive_spends += 1;
            if positive_spends != 1
                || spent.recipient() != real_note.recipient()
                || spent.value() != real_note.value()
                || spent.rho() != real_note.rho()
                || spent.rseed().as_bytes() != real_note.rseed().as_bytes()
                || ExtractedNoteCommitment::from(spent.commitment())
                    != ExtractedNoteCommitment::from(real_note.commitment())
                || action.spend().nullifier() != &real_nullifier
            {
                return Err(PreparationError::PositiveInput);
            }
            let actual_path = action
                .spend()
                .witness()
                .as_ref()
                .ok_or(PreparationError::Anchor)?;
            if actual_path.position() != path.position()
                || actual_path.auth_path() != path.auth_path()
                || actual_path.root(spent.commitment().into()) != anchor
            {
                return Err(PreparationError::Anchor);
            }
            if fvk.scope_for_address(&spent.recipient()).is_none() {
                return Err(PreparationError::Ownership);
            }
            real_rk = Some(action.spend().rk().clone());
        }
        // Zero dummies still require all note/cv/nf/rk openings above. Their
        // random paths need not reach the anchor; dummy_sk is never zero evidence.
        let output = output_note(action)?;
        let domain = IronwoodDomain::for_pczt_action(action);
        let esk = IronwoodDomain::derive_esk(&output).ok_or(PreparationError::Ciphertext)?;
        let (recovered, recipient, memo) = try_output_recovery_with_pkd_esk(
            &domain,
            IronwoodDomain::get_pk_d(&output),
            esk,
            action,
        )
        .ok_or(PreparationError::Ciphertext)?;
        let _memo = Zeroizing::new(memo);
        if recovered != output
            || recipient != output.recipient()
            || recovered.value() != output.value()
            || recovered.rho() != output.rho()
            || recovered.rseed().as_bytes() != output.rseed().as_bytes()
            || recovered.version() != NoteVersion::V3
        {
            return Err(PreparationError::Ciphertext);
        }
        let output_value = output.value().inner();
        if recovery && output_value != 0 && fvk.scope_for_address(&recipient).is_none() {
            return Err(PreparationError::Ownership);
        }
        let raw_recipient = Zeroizing::new(recipient.to_raw_address_bytes());
        if !recovery && receivers.binary_search(&*raw_recipient).is_ok() {
            payment_total = bounded_sum(payment_total, output_value)?;
        }
        output_total = bounded_sum(output_total, output_value)?;
    }
    if positive_spends != 1 {
        return Err(PreparationError::PositiveInput);
    }
    nullifiers.sort_unstable();
    if nullifiers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PreparationError::DuplicateNullifier);
    }
    if !recovery && payment_total != context.source_quoted_amount {
        return Err(PreparationError::PaymentCommitment);
    }
    let fee = input_total
        .checked_sub(output_total)
        .ok_or(PreparationError::Conservation)?;
    let declared =
        i64::try_from(*bundle.value_sum()).map_err(|_| PreparationError::Conservation)?;
    if u64::try_from(declared).ok() != Some(fee)
        || output_total.checked_add(fee) != Some(real_note.value().inner())
    {
        return Err(PreparationError::Conservation);
    }
    let required = zip317::FeeRule::standard()
        .fee_required(
            &TEST_NETWORK,
            height,
            std::iter::empty(),
            std::iter::empty(),
            0,
            0,
            0,
            bundle.actions().len(),
        )
        .map_err(|_| PreparationError::Fee)?;
    if fee != u64::from(required) || fee > context.source_fee_cap {
        return Err(PreparationError::Fee);
    }
    real_rk.ok_or(PreparationError::PositiveInput)
}

fn bounded_sum(sum: u64, value: u64) -> Result<u64, PreparationError> {
    let sum = sum
        .checked_add(value)
        .ok_or(PreparationError::Conservation)?;
    Zatoshis::from_u64(sum).map_err(|_| PreparationError::Conservation)?;
    Ok(sum)
}

fn check_redacted(bundle: &Bundle) -> Result<(), PreparationError> {
    if bundle.bsk().is_some() || bundle.zkproof().is_some() {
        return Err(PreparationError::Pczt);
    }
    for action in bundle.actions() {
        let spend = action.spend();
        let output = action.output();
        if action.rcv().is_some()
            || spend.spend_auth_sig().is_some()
            || spend.recipient().is_some()
            || spend.value().is_some()
            || spend.rho().is_some()
            || spend.rseed().is_some()
            || spend.fvk().is_some()
            || spend.witness().is_some()
            || spend.alpha().is_some()
            || spend.dummy_sk().is_some()
            || spend.zip32_derivation().is_some()
            || !spend.proprietary().is_empty()
            || output.recipient().is_some()
            || output.value().is_some()
            || output.rseed().is_some()
            || output.ock().is_some()
            || output.zip32_derivation().is_some()
            || output.user_address().is_some()
            || !output.proprietary().is_empty()
        {
            return Err(PreparationError::Pczt);
        }
    }
    Ok(())
}

fn same_ciphertext(left: &TransmittedNoteCiphertext, right: &TransmittedNoteCiphertext) -> bool {
    left.epk_bytes == right.epk_bytes
        && left.enc_ciphertext == right.enc_ciphertext
        && left.out_ciphertext == right.out_ciphertext
}

fn compare_pczt_effects(private: &Bundle, export: &Bundle) -> Result<(), PreparationError> {
    if private.bundle_version() != export.bundle_version()
        || private.flag_byte() != export.flag_byte()
        || private.anchor() != export.anchor()
        || private.value_sum() != export.value_sum()
        || private.actions().len() != export.actions().len()
    {
        return Err(PreparationError::Effects);
    }
    for (left, right) in private.actions().iter().zip(export.actions()) {
        if left.cv_net().to_bytes() != right.cv_net().to_bytes()
            || left.spend().nullifier() != right.spend().nullifier()
            || left.spend().rk() != right.spend().rk()
            || left.output().cmx() != right.output().cmx()
            || !same_ciphertext(
                left.output().encrypted_note(),
                right.output().encrypted_note(),
            )
        {
            return Err(PreparationError::Effects);
        }
    }
    Ok(())
}

fn compare_q_effects(private: &Bundle, transaction: &Transaction) -> Result<(), PreparationError> {
    if !native_effects::matches(private, transaction, *private.anchor()) {
        return Err(PreparationError::Effects);
    }
    Ok(())
}

fn verify_q_signatures(transaction: &Transaction) -> Result<(), PreparationError> {
    let bundle = transaction
        .ironwood_bundle()
        .ok_or(PreparationError::Transaction)?;
    // Parsing already rejected EVERY other pool. For pure shielded v6 the txid
    // equals the shielded signature digest (upstream to_txid/sighash_v6).
    let effect_id: [u8; 32] = transaction.txid().into();
    for action in bundle.actions().iter() {
        action
            .rk()
            .verify(&effect_id, action.authorization())
            .map_err(|_| PreparationError::Signature)?;
    }
    bundle
        .binding_validating_key()
        .verify(&effect_id, bundle.authorization().binding_signature())
        .map_err(|_| PreparationError::Signature)
}

fn packet_binding(witness: &PreparationWitness, context: &ValidatedContext) -> Result<[u8; 32], PreparationError> {
    preparation_packet_binding(PreparationBinding {
        context,
        preparation_blind: &witness.secret_blind,
        redacted_payment: &witness.redacted_p_pczt,
        recovery_transaction: &witness.q_transaction,
        note_recipient: &witness.note_recipient,
        note_value: witness.note_value,
        note_rho: &witness.note_rho,
        note_rseed: &witness.note_rseed,
        full_viewing_key: &witness.full_viewing_key,
        merkle_position: witness.merkle_position,
        merkle_siblings: &witness.merkle_siblings,
        anchor: &witness.anchor,
        source_target_height: witness.source_target_height,
    }).map_err(|_| PreparationError::Context)
}

fn capsule_commitment(
    witness: &PreparationWitness,
    context: &ValidatedContext,
    binding: &[u8; 32],
) -> Result<[u8; 32], PreparationError> {
    solver_capsule_commitment(SolverCapsule {
        context,
        private_packet_binding: binding,
        capsule_blind: &witness.capsule_blind,
        redacted_payment: &witness.redacted_p_pczt,
        recovery_transaction: &witness.q_transaction,
    }).map_err(|_| PreparationError::SolverCapsule)
}
