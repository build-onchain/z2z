//! Immutable owner-operation capabilities, not an inventory or financial journal.
//!
//! Independent pins are descriptors, not chain authentication, artifact availability,
//! current root eligibility or unspentness. Restore preserves consent; it never signs,
//! proves, releases capacity or marks an operation completed.
use std::{fmt, path::Path};

use primitive_types::U256;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{
    CancelExitWitness, MAX_PRIVATE_INPUT_BYTES, NoteOpening, OwnerWitness,
    PreparedOutputOpening, RelationError, review_owner_cancel_exit, review_owner_fill,
    verify_cancel_exit_relation, verify_owner_relation,
    creation::{NoteCreationWitness, review_note_creation, verify_note_creation_relation},
    withdrawal::{NoteWithdrawalWitness, review_note_withdrawal, verify_note_withdrawal_relation},
};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, OutputDescriptor, Role, SamechainError, fill::FillExecution,
};

use super::OwnedOwnerInput;
use crate::custody::{CustodyError, EnvelopeFormat, load_encrypted, save_encrypted};

const ENVELOPE_DOMAIN: &[u8] = b"ziquid.samechain.backup.v1";
const PAYLOAD_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_PRIVATE_SNAPSHOT\0";
const CONTEXT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_PRIVATE_SNAPSHOT_CONTEXT\0";
const VERSION: u16 = 1;
const MAX_DEPLOYMENT_BYTES: usize = b"Z2Z_SAMECHAIN_DEPLOYMENT\0".len() + 2 + 146;
const MAX_EXECUTION_BYTES: usize = b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len() + 2 + 106;
// Include both optional payloads for the conservative finite layout bound.
const MAX_SELECTION_BYTES: usize = 1 + 4 + MAX_DEPLOYMENT_BYTES + 20 + 32 + 32 + 1 + 1
    + 32 + 1 + 4 + MAX_EXECUTION_BYTES + 1 + 32 + 32 + 32 + 32;
const MAX_PLAINTEXT_BYTES: usize = PAYLOAD_DOMAIN.len() + 2 + 4 + MAX_SELECTION_BYTES
    + 1 + 4 + MAX_PRIVATE_INPUT_BYTES;
const FORMAT: EnvelopeFormat = EnvelopeFormat {
    domain: ENVELOPE_DOMAIN,
    max_plaintext_bytes: MAX_PLAINTEXT_BYTES,
};

/// Snapshot selection codes are distinct from the existing guest mode codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SnapshotOperation {
    Fill = 0,
    Cancel = 1,
    Exit = 2,
    Withdrawal = 3,
    Creation = 4,
}

/// A label alone establishes no trust or eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SnapshotScope {
    ControlledGenerated = 0,
    IndependentlySelected = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryPin {
    pub block_hash: [u8; 32],
    pub block_number: U256,
}

/// Independently selected public descriptors; all bytes remain encrypted on disk.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotSelection {
    pub scope: SnapshotScope,
    pub deployment: Deployment,
    pub token: [u8; 20],
    pub token_code: [u8; 32],
    pub policy_id: [u8; 32],
    pub operation: SnapshotOperation,
    pub role: Role,
    pub packet_digest: [u8; 32],
    pub execution: Option<FillExecution>,
    pub history: Option<HistoryPin>,
    pub elf_sha256: [u8; 32],
    pub kit_manifest_digest: [u8; 32],
}

impl fmt::Debug for SnapshotSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SnapshotSelection")
            .field("scope", &self.scope)
            .field("operation", &self.operation)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Categories only: no private path, value or source error is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    Selection,
    Encoding,
    Material,
    ResourceLimit,
    Custody(CustodyError),
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection => formatter.write_str("samechain snapshot selection rejected"),
            Self::Encoding => formatter.write_str("samechain snapshot encoding rejected"),
            Self::Material => formatter.write_str("samechain snapshot material rejected"),
            Self::ResourceLimit => formatter.write_str("samechain snapshot exceeds its resource bound"),
            Self::Custody(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for BackupError {}

/// Validate complete material, then publish through the native immutable publisher.
pub fn save_snapshot(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    selection: &SnapshotSelection, material: &OwnedOwnerInput,
) -> Result<(), BackupError> {
    if !nonzero(&namespace) { return Err(BackupError::Selection); }
    let selected = encode_selection(selection)?;
    validate_material(selection, material)?;
    let (mode, witness) = encode_witness(material)?;
    if witness.len() > MAX_PRIVATE_INPUT_BYTES { return Err(BackupError::ResourceLimit); }
    let length = PAYLOAD_DOMAIN.len() + 2 + 4 + selected.len() + 1 + 4 + witness.len();
    if length > MAX_PLAINTEXT_BYTES { return Err(BackupError::ResourceLimit); }
    // This allocation is complete before any private append. Detached AEAD in the
    // shared publisher does not append a tag or grow the filled secret allocation.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(length));
    plaintext.extend_from_slice(PAYLOAD_DOMAIN);
    plaintext.extend_from_slice(&VERSION.to_be_bytes());
    append_length(&mut plaintext, selected.len())?;
    plaintext.extend_from_slice(&selected);
    plaintext.push(mode);
    append_length(&mut plaintext, witness.len())?;
    plaintext.extend_from_slice(&witness);
    drop(witness);
    save_encrypted(path.as_ref(), key, namespace, context(&selected), FORMAT, plaintext)
        .map_err(BackupError::Custody)
}

/// Authenticate against an independent selection and re-review actual capabilities.
pub fn load_snapshot(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    expected: &SnapshotSelection,
) -> Result<OwnedOwnerInput, BackupError> {
    if !nonzero(&namespace) { return Err(BackupError::Selection); }
    let selected = encode_selection(expected)?;
    let plaintext = load_encrypted(path.as_ref(), key, namespace, context(&selected), FORMAT)
        .map_err(BackupError::Custody)?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES { return Err(BackupError::ResourceLimit); }
    let mut reader = Reader(&plaintext);
    if reader.take(PAYLOAD_DOMAIN.len())? != PAYLOAD_DOMAIN || reader.u16()? != VERSION {
        return Err(BackupError::Encoding);
    }
    let decoded = decode_selection(reader.blob(MAX_SELECTION_BYTES)?)?;
    if decoded != *expected { return Err(BackupError::Selection); }
    let mode = reader.byte()?;
    let witness = reader.blob(MAX_PRIVATE_INPUT_BYTES)?;
    reader.finish()?;
    // The existing strict decoders own erasing fields, reject unknown tags and
    // exhaust their complete bounded frame. No secret re-encoding is needed.
    let material = match mode {
        0 => OwnedOwnerInput::Fill(OwnerWitness::decode(witness).map_err(codec_error)?),
        1 => OwnedOwnerInput::CancelExit(CancelExitWitness::decode(witness).map_err(codec_error)?),
        2 => OwnedOwnerInput::Withdrawal(NoteWithdrawalWitness::decode(witness).map_err(codec_error)?),
        3 => OwnedOwnerInput::Creation(NoteCreationWitness::decode(witness).map_err(codec_error)?),
        _ => return Err(BackupError::Encoding),
    };
    validate_material(expected, &material)?;
    Ok(material)
}

fn nonzero(bytes: &[u8]) -> bool { bytes.iter().any(|byte| *byte != 0) }

fn validate_selection(selection: &SnapshotSelection) -> Result<(), BackupError> {
    selection.deployment.validate().map_err(|_| BackupError::Selection)?;
    if !nonzero(&selection.token) || !nonzero(&selection.token_code)
        || !nonzero(&selection.policy_id) || !nonzero(&selection.packet_digest)
        || !nonzero(&selection.elf_sha256) || !nonzero(&selection.kit_manifest_digest)
    { return Err(BackupError::Selection); }
    match (selection.operation, &selection.execution) {
        (SnapshotOperation::Fill, Some(execution)) => {
            execution.validate().map_err(|_| BackupError::Selection)?;
        }
        (SnapshotOperation::Fill, None) => return Err(BackupError::Selection),
        (_, Some(_)) => return Err(BackupError::Selection),
        (_, None) => {}
    }
    match (selection.operation, &selection.history) {
        (SnapshotOperation::Creation, None) => {}
        (SnapshotOperation::Creation, Some(_)) => return Err(BackupError::Selection),
        (_, Some(history)) if nonzero(&history.block_hash) => {}
        _ => return Err(BackupError::Selection),
    }
    if selection.operation == SnapshotOperation::Withdrawal && selection.role != Role::A {
        return Err(BackupError::Selection);
    }
    Ok(())
}

// One canonical encoder supplies both the encrypted metadata and its context hash.
fn encode_selection(selection: &SnapshotSelection) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    validate_selection(selection)?;
    let deployment = Zeroizing::new(selection.deployment.encode().map_err(|_| BackupError::Selection)?);
    if deployment.len() > MAX_DEPLOYMENT_BYTES { return Err(BackupError::ResourceLimit); }
    let execution = selection.execution.as_ref().map(|execution|
        execution.encode().map(Zeroizing::new).map_err(|_| BackupError::Selection)).transpose()?;
    if execution.as_ref().is_some_and(|bytes| bytes.len() > MAX_EXECUTION_BYTES) {
        return Err(BackupError::ResourceLimit);
    }
    let length = 1 + 4 + deployment.len() + 20 + 32 + 32 + 1 + 1 + 32 + 1
        + execution.as_ref().map_or(0, |bytes| 4 + bytes.len())
        + 1 + if selection.history.is_some() { 64 } else { 0 } + 32 + 32;
    if length > MAX_SELECTION_BYTES { return Err(BackupError::ResourceLimit); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    bytes.push(selection.scope as u8);
    append_length(&mut bytes, deployment.len())?;
    bytes.extend_from_slice(&deployment);
    bytes.extend_from_slice(&selection.token);
    bytes.extend_from_slice(&selection.token_code);
    bytes.extend_from_slice(&selection.policy_id);
    bytes.extend_from_slice(&[selection.operation as u8, selection.role as u8]);
    bytes.extend_from_slice(&selection.packet_digest);
    match execution {
        None => bytes.push(0),
        Some(execution) => {
            bytes.push(1);
            append_length(&mut bytes, execution.len())?;
            bytes.extend_from_slice(&execution);
        }
    }
    match selection.history {
        None => bytes.push(0),
        Some(history) => {
            bytes.push(1);
            bytes.extend_from_slice(&history.block_hash);
            let mut number = [0; 32];
            history.block_number.to_big_endian(&mut number);
            bytes.extend_from_slice(&number);
        }
    }
    bytes.extend_from_slice(&selection.elf_sha256);
    bytes.extend_from_slice(&selection.kit_manifest_digest);
    Ok(bytes)
}

fn decode_selection(bytes: &[u8]) -> Result<SnapshotSelection, BackupError> {
    if bytes.len() > MAX_SELECTION_BYTES { return Err(BackupError::ResourceLimit); }
    let mut reader = Reader(bytes);
    let scope = match reader.byte()? {
        0 => SnapshotScope::ControlledGenerated,
        1 => SnapshotScope::IndependentlySelected,
        _ => return Err(BackupError::Encoding),
    };
    let frame = reader.blob(MAX_DEPLOYMENT_BYTES)?;
    let deployment = Deployment::decode(frame).map_err(|_| BackupError::Encoding)?;
    let canonical = Zeroizing::new(deployment.encode().map_err(|_| BackupError::Encoding)?);
    if canonical.as_slice() != frame { return Err(BackupError::Encoding); }
    let token = reader.array()?;
    let token_code = reader.array()?;
    let policy_id = reader.array()?;
    let operation = match reader.byte()? {
        0 => SnapshotOperation::Fill,
        1 => SnapshotOperation::Cancel,
        2 => SnapshotOperation::Exit,
        3 => SnapshotOperation::Withdrawal,
        4 => SnapshotOperation::Creation,
        _ => return Err(BackupError::Encoding),
    };
    let role = match reader.byte()? {
        0 => Role::A,
        1 => Role::B,
        _ => return Err(BackupError::Encoding),
    };
    let packet_digest = reader.array()?;
    let execution = match reader.byte()? {
        0 => None,
        1 => {
            let frame = reader.blob(MAX_EXECUTION_BYTES)?;
            let execution = FillExecution::decode(frame).map_err(|_| BackupError::Encoding)?;
            let canonical = Zeroizing::new(execution.encode().map_err(|_| BackupError::Encoding)?);
            if canonical.as_slice() != frame { return Err(BackupError::Encoding); }
            Some(execution)
        }
        _ => return Err(BackupError::Encoding),
    };
    let history = match reader.byte()? {
        0 => None,
        1 => Some(HistoryPin { block_hash: reader.array()?,
            block_number: U256::from_big_endian(reader.take(32)?) }),
        _ => return Err(BackupError::Encoding),
    };
    let selection = SnapshotSelection { scope, deployment, token, token_code, policy_id,
        operation, role, packet_digest, execution, history,
        elf_sha256: reader.array()?, kit_manifest_digest: reader.array()? };
    reader.finish()?;
    validate_selection(&selection)?;
    Ok(selection)
}

fn context(selection: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT_DOMAIN);
    hash.update(VERSION.to_be_bytes());
    hash.update(selection);
    hash.finalize().into()
}

fn append_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), BackupError> {
    let length = u32::try_from(length).map_err(|_| BackupError::ResourceLimit)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn encode_witness(material: &OwnedOwnerInput) -> Result<(u8, Zeroizing<Vec<u8>>), BackupError> {
    let (mode, bytes) = match material {
        OwnedOwnerInput::Fill(witness) => (0, witness.encode()),
        OwnedOwnerInput::CancelExit(witness) => (1, witness.encode()),
        OwnedOwnerInput::Withdrawal(witness) => (2, witness.encode()),
        OwnedOwnerInput::Creation(witness) => (3, witness.encode()),
    };
    Ok((mode, bytes.map_err(codec_error)?))
}

fn codec_error(error: RelationError) -> BackupError {
    match error {
        RelationError::ResourceLimit => BackupError::ResourceLimit,
        RelationError::Encoding => BackupError::Encoding,
        RelationError::Protocol(error) => match error {
            SamechainError::WrongDomain | SamechainError::UnsupportedSchema
            | SamechainError::InvalidLength | SamechainError::TrailingBytes
            | SamechainError::NonCanonical | SamechainError::Encoding => BackupError::Encoding,
            SamechainError::Oversize => BackupError::ResourceLimit,
            SamechainError::InvalidDeployment | SamechainError::InvalidAsset
            | SamechainError::InvalidRole | SamechainError::InvalidAction
            | SamechainError::InvalidFeePolicy | SamechainError::UnlistedFee
            | SamechainError::FeeCapExceeded | SamechainError::InvalidPolicy
            | SamechainError::InvalidInput | SamechainError::OverlappingInputs
            | SamechainError::InvalidOutput | SamechainError::DuplicateOutput
            | SamechainError::InvalidTerms | SamechainError::LimitNotMet
            | SamechainError::InvalidBlind | SamechainError::OpeningMismatch
            | SamechainError::InvalidJournal | SamechainError::JournalMismatch => BackupError::Material,
        },
        RelationError::Note | RelationError::Key | RelationError::Input
        | RelationError::Membership | RelationError::Policy | RelationError::Signature
        | RelationError::Manifest | RelationError::Output | RelationError::Ciphertext
        | RelationError::Conservation | RelationError::Successor | RelationError::Action => BackupError::Material,
    }
}

fn validate_material(selection: &SnapshotSelection, material: &OwnedOwnerInput) -> Result<(), BackupError> {
    match (selection.operation, material) {
        (SnapshotOperation::Fill, OwnedOwnerInput::Fill(witness)) => {
            let execution = selection.execution.as_ref().ok_or(BackupError::Selection)?;
            if witness.packet.digest().map_err(|_| BackupError::Material)? != selection.packet_digest {
                return Err(BackupError::Material);
            }
            check_asset(execution.asset_a, &selection.token)?;
            check_asset(execution.asset_b, &selection.token)?;
            check_note(&witness.input, &selection.token)?;
            check_outputs(&witness.packet.outputs, &witness.owned_outputs, &selection.token)?;
            review_owner_fill(&witness.packet, witness, &selection.deployment,
                witness.packet.inputs[selection.role.index()].order_id, selection.role, execution)
                .map_err(|_| BackupError::Material)?;
            if nonzero(&witness.consent) {
                verify_owner_relation(&witness.packet, witness).map_err(|_| BackupError::Material)?;
            }
        }
        (SnapshotOperation::Cancel | SnapshotOperation::Exit, OwnedOwnerInput::CancelExit(witness)) => {
            let action = if selection.operation == SnapshotOperation::Cancel { Action::Cancel } else { Action::Exit };
            if witness.packet.digest().map_err(|_| BackupError::Material)? != selection.packet_digest {
                return Err(BackupError::Material);
            }
            check_note(&witness.input, &selection.token)?;
            check_outputs(&witness.packet.outputs, &witness.owned_outputs, &selection.token)?;
            review_owner_cancel_exit(&witness.packet, witness, &selection.deployment,
                witness.packet.input.order_id, selection.role, action).map_err(|_| BackupError::Material)?;
            if nonzero(&witness.consent) {
                verify_cancel_exit_relation(witness).map_err(|_| BackupError::Material)?;
            }
        }
        (SnapshotOperation::Withdrawal, OwnedOwnerInput::Withdrawal(witness)) => {
            if witness.packet.digest().map_err(|_| BackupError::Material)? != selection.packet_digest {
                return Err(BackupError::Material);
            }
            check_note(&witness.input, &selection.token)?;
            check_outputs(&witness.packet.outputs, &witness.owned_outputs, &selection.token)?;
            review_note_withdrawal(&witness.packet, witness, &selection.deployment,
                witness.packet.input.commitment).map_err(|_| BackupError::Material)?;
            if nonzero(&witness.consent) {
                verify_note_withdrawal_relation(witness).map_err(|_| BackupError::Material)?;
            }
        }
        (SnapshotOperation::Creation, OwnedOwnerInput::Creation(witness)) => {
            if witness.packet.digest().map_err(|_| BackupError::Material)? != selection.packet_digest
                || witness.packet.token != selection.token || witness.packet.role != selection.role
            { return Err(BackupError::Material); }
            check_asset(witness.packet.asset, &selection.token)?;
            check_note(&witness.note, &selection.token)?;
            review_note_creation(&witness.packet, witness, &selection.deployment,
                witness.packet.payer, witness.packet.creation_nonce).map_err(|_| BackupError::Material)?;
            if nonzero(&witness.consent) {
                verify_note_creation_relation(witness).map_err(|_| BackupError::Material)?;
            }
        }
        _ => return Err(BackupError::Material),
    }
    Ok(())
}

fn check_asset(asset: Asset, token: &[u8; 20]) -> Result<(), BackupError> {
    if matches!(asset, Asset::Token(address) if address != *token) {
        return Err(BackupError::Material);
    }
    Ok(())
}

fn check_note(note: &NoteOpening, token: &[u8; 20]) -> Result<(), BackupError> {
    check_asset(note.asset, token)?;
    if let Some(order) = &note.order {
        check_asset(order.policy.sell_asset, token)?;
        check_asset(order.policy.buy_asset, token)?;
        for fee in &order.policy.fee_policy.entries { check_asset(fee.asset, token)?; }
    }
    Ok(())
}

fn check_outputs(
    outputs: &[OutputDescriptor], owned: &[PreparedOutputOpening], token: &[u8; 20],
) -> Result<(), BackupError> {
    for output in outputs {
        match output {
            OutputDescriptor::Exit { asset, .. } | OutputDescriptor::Fee { asset, .. } => {
                check_asset(*asset, token)?;
            }
            OutputDescriptor::Note { .. } => {}
        }
    }
    for opening in owned { check_note(&opening.note, token)?; }
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], BackupError> {
        if length > self.0.len() { return Err(BackupError::Encoding); }
        let (front, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(front)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupError> {
        self.take(N)?.try_into().map_err(|_| BackupError::Encoding)
    }
    fn byte(&mut self) -> Result<u8, BackupError> { Ok(self.array::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, BackupError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], BackupError> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        if length > max { return Err(BackupError::ResourceLimit); }
        self.take(length)
    }
    fn finish(&self) -> Result<(), BackupError> {
        if self.0.is_empty() { Ok(()) } else { Err(BackupError::Encoding) }
    }
}
