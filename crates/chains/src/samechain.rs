//! Bounded PUBLIC unsigned calls for the immutable samechain authority.
//!
//! Canonical packets and descriptive journals are not financial authority.
//! Proof checks below inspect only the pinned public wrapper's framing, never
//! pairing validity or its binding to a program/journal. Deployment authenticity,
//! root eligibility, spentness, asset backing and execution remain UNVERIFIED.

use std::{error::Error, fmt};

use primitive_types::U256;
use tiny_keccak::{Hasher, Keccak};
use ziquid_protocol::samechain::{
    creation::{NoteCreationJournal, NoteCreationPacket},
    withdrawal::{NoteWithdrawalJournal, NoteWithdrawalPacket},
    Action, Asset, Deployment, OutputDescriptor, OwnerJournal, PublicPacket, Role,
    SamechainError, SingleOwnerPacket, MAX_PACKET_BYTES,
};

const MAX_CALLDATA_BYTES: usize = 70 * 1024;
const PROOF_BYTES: usize = 356;
const PROOF_SELECTOR: [u8; 4] = [0x43, 0x88, 0xa2, 0x1c];
const VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d,
    0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28,
    0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallBuildError {
    InvalidPacket,
    WrongDeployment,
    InvalidSender,
    WrongToken,
    InvalidRoleAction,
    InvalidProofFrame,
    InputBounds,
    Encoding,
}

impl fmt::Display for CallBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPacket => "invalid public samechain packet",
            Self::WrongDeployment => "samechain deployment mismatch",
            Self::InvalidSender => "invalid public sender",
            Self::WrongToken => "samechain token mismatch",
            Self::InvalidRoleAction => "invalid samechain role or action",
            Self::InvalidProofFrame => "invalid public wrapped proof frame",
            Self::InputBounds => "samechain call input exceeds bounds",
            Self::Encoding => "samechain call encoding failed",
        })
    }
}

impl Error for CallBuildError {}

/// Unsigned proposal only. Journals/outputs are exact public review descriptions,
/// not certificates of current rights or evidence of a completed transfer.
#[derive(Debug)]
pub struct UnsignedCall {
    from: [u8; 20],
    to: [u8; 20],
    value: U256,
    data: Vec<u8>,
    deployment: Deployment,
    packet_digest: [u8; 32],
    expected_journals: Vec<Vec<u8>>,
    outputs: Vec<OutputDescriptor>,
}

impl UnsignedCall {
    pub fn from(&self) -> [u8; 20] { self.from }
    pub fn to(&self) -> [u8; 20] { self.to }
    pub fn value(&self) -> U256 { self.value }
    pub fn data(&self) -> &[u8] { &self.data }
    pub fn deployment(&self) -> &Deployment { &self.deployment }
    pub fn packet_digest(&self) -> [u8; 32] { self.packet_digest }
    pub fn expected_journals(&self) -> &[Vec<u8>] { &self.expected_journals }
    pub fn outputs(&self) -> &[OutputDescriptor] { &self.outputs }
}

/// The packet payer is the sender. Only native creation carries an exact value;
/// token creation requires a separately supplied matching fixed token and zero value.
pub fn build_creation_call(
    expected: &Deployment,
    expected_token: [u8; 20],
    packet: &NoteCreationPacket,
    proof: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_deployment(expected, &packet.deployment)?;
    if expected_token == [0; 20] || packet.token != expected_token {
        return Err(CallBuildError::WrongToken);
    }
    check_sender(packet.payer)?;
    packet.validate().map_err(packet_error)?;
    check_proof(proof)?;
    let journal = NoteCreationJournal::from_packet(packet).map_err(packet_error)?;
    let encoded = packet.encode().map_err(packet_error)?;
    let data = encode_call(b"create(bytes,bytes)", &[Arg::Bytes(&encoded), Arg::Bytes(proof)])?;
    Ok(UnsignedCall {
        from: packet.payer,
        to: expected.authority,
        value: if packet.asset == Asset::Native { packet.amount } else { U256::zero() },
        data,
        deployment: *expected,
        packet_digest: journal.packet_digest,
        expected_journals: vec![journal.encode().map_err(packet_error)?],
        outputs: vec![packet.output.clone()],
    })
}

/// A nonzero independent relayer is permitted. Identical proof frames are not
/// arbitrarily rejected: only the actual verifier can authenticate either journal.
pub fn build_fill_call(
    expected: &Deployment,
    packet: &PublicPacket,
    sender: [u8; 20],
    proof_a: &[u8],
    proof_b: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_deployment(expected, &packet.deployment)?;
    check_sender(sender)?;
    packet.validate().map_err(packet_error)?;
    check_proof(proof_a)?;
    check_proof(proof_b)?;
    let journal_a = OwnerJournal::from_packet(packet, Role::A, Action::Fill).map_err(packet_error)?;
    let journal_b = OwnerJournal::from_packet(packet, Role::B, Action::Fill).map_err(packet_error)?;
    let encoded = packet.encode().map_err(packet_error)?;
    let data = encode_call(b"fill(bytes,bytes,bytes)", &[
        Arg::Bytes(&encoded), Arg::Bytes(proof_a), Arg::Bytes(proof_b),
    ])?;
    Ok(UnsignedCall {
        from: sender,
        to: expected.authority,
        value: U256::zero(),
        data,
        deployment: *expected,
        packet_digest: journal_a.packet_digest,
        expected_journals: vec![
            journal_a.encode().map_err(packet_error)?,
            journal_b.encode().map_err(packet_error)?,
        ],
        outputs: packet.outputs.clone(),
    })
}

/// Cancellation/exit uses a single real input and the exact role/action words.
pub fn build_single_call(
    expected: &Deployment,
    packet: &SingleOwnerPacket,
    sender: [u8; 20],
    role: Role,
    action: Action,
    proof: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_deployment(expected, &packet.deployment)?;
    check_sender(sender)?;
    if action == Action::Fill { return Err(CallBuildError::InvalidRoleAction); }
    packet.validate_for(role).map_err(|error| match error {
        SamechainError::InvalidRole => CallBuildError::InvalidRoleAction,
        other => packet_error(other),
    })?;
    check_proof(proof)?;
    let journal = OwnerJournal::from_single_packet(packet, role, action).map_err(packet_error)?;
    let encoded = packet.encode().map_err(packet_error)?;
    let data = encode_call(b"cancelOrExit(bytes,uint8,uint8,bytes)", &[
        Arg::Bytes(&encoded), Arg::Uint8(role as u8), Arg::Uint8(action as u8), Arg::Bytes(proof),
    ])?;
    Ok(UnsignedCall {
        from: sender,
        to: expected.authority,
        value: U256::zero(),
        data,
        deployment: *expected,
        packet_digest: journal.packet_digest,
        expected_journals: vec![journal.encode().map_err(packet_error)?],
        outputs: packet.outputs.clone(),
    })
}

/// Ordinary-note withdrawal binds its distinct journal and full public manifest.
pub fn build_withdrawal_call(
    expected: &Deployment,
    packet: &NoteWithdrawalPacket,
    sender: [u8; 20],
    proof: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_deployment(expected, &packet.deployment)?;
    check_sender(sender)?;
    packet.validate().map_err(packet_error)?;
    check_proof(proof)?;
    let journal = NoteWithdrawalJournal::from_packet(packet).map_err(packet_error)?;
    let encoded = packet.encode().map_err(packet_error)?;
    let data = encode_call(b"withdraw(bytes,bytes)", &[Arg::Bytes(&encoded), Arg::Bytes(proof)])?;
    Ok(UnsignedCall {
        from: sender,
        to: expected.authority,
        value: U256::zero(),
        data,
        deployment: *expected,
        packet_digest: journal.packet_digest,
        expected_journals: vec![journal.encode().map_err(packet_error)?],
        outputs: packet.outputs.clone(),
    })
}

fn check_deployment(expected: &Deployment, actual: &Deployment) -> Result<(), CallBuildError> {
    if expected != actual || expected.validate().is_err() {
        return Err(CallBuildError::WrongDeployment);
    }
    Ok(())
}

fn check_sender(sender: [u8; 20]) -> Result<(), CallBuildError> {
    if sender == [0; 20] { return Err(CallBuildError::InvalidSender); }
    Ok(())
}

fn packet_error(error: SamechainError) -> CallBuildError {
    match error {
        SamechainError::Oversize => CallBuildError::InputBounds,
        SamechainError::Encoding => CallBuildError::Encoding,
        _ => CallBuildError::InvalidPacket,
    }
}

// Pinned contracts/evm/src/sp1/v6.1.0/SP1VerifierGroth16.sol public header only.
// Nonce and pairing words are preserved verbatim, not cryptographically checked.
fn check_proof(proof: &[u8]) -> Result<(), CallBuildError> {
    if proof.len() != PROOF_BYTES || proof[..4] != PROOF_SELECTOR
        || proof[4..36] != [0; 32] || proof[36..68] != VK_ROOT
    {
        return Err(CallBuildError::InvalidProofFrame);
    }
    Ok(())
}

fn selector(signature: &[u8]) -> [u8; 4] {
    let mut hash = [0; 32];
    let mut keccak = Keccak::v256();
    keccak.update(signature);
    keccak.finalize(&mut hash);
    [hash[0], hash[1], hash[2], hash[3]]
}

enum Arg<'a> {
    Bytes(&'a [u8]),
    Uint8(u8),
}

fn padded_len(length: usize) -> Result<usize, CallBuildError> {
    length.checked_add(31).map(|length| length & !31).ok_or(CallBuildError::InputBounds)
}

fn append_word(out: &mut Vec<u8>, value: usize) {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    out.extend_from_slice(&word);
}

// Fixed 2/3/4-head call templates only; no general transaction/ABI framework.
// All dynamic sizes are checked before the one final calldata allocation.
fn encode_call(signature: &[u8], args: &[Arg<'_>]) -> Result<Vec<u8>, CallBuildError> {
    let heads = args.len().checked_mul(32).ok_or(CallBuildError::InputBounds)?;
    let mut total = 4usize.checked_add(heads).ok_or(CallBuildError::InputBounds)?;
    for arg in args {
        if let Arg::Bytes(bytes) = arg {
            if bytes.len() > MAX_PACKET_BYTES { return Err(CallBuildError::InputBounds); }
            total = total.checked_add(32).and_then(|total| total.checked_add(padded_len(bytes.len()).ok()?))
                .ok_or(CallBuildError::InputBounds)?;
        }
    }
    if total > MAX_CALLDATA_BYTES { return Err(CallBuildError::InputBounds); }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&selector(signature));
    let mut offset = heads;
    for arg in args {
        match arg {
            Arg::Bytes(bytes) => {
                append_word(&mut out, offset);
                offset += 32 + padded_len(bytes.len())?;
            }
            Arg::Uint8(value) => append_word(&mut out, usize::from(*value)),
        }
    }
    for arg in args {
        if let Arg::Bytes(bytes) = arg {
            append_word(&mut out, bytes.len());
            out.extend_from_slice(bytes);
            let padding = padded_len(bytes.len())? - bytes.len();
            out.resize(out.len() + padding, 0);
        }
    }
    Ok(out)
}

#[path = "samechain/inspection.rs"]
pub mod inspection;

#[path = "samechain/history.rs"]
pub mod history;
