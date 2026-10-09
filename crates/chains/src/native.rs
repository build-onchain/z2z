//! Unsigned calls and explicit block-pinned public observations for the native ETH obligation.
//!
//! Expected journals describe exact public bytes, not certificates. Proof checks
//! inspect only the pinned SP1 v6.1.0 wrapper and scalar bounds; they do not check
//! pairing validity or program/journal binding. Independent deployment pins must
//! come from the caller's trusted configuration. Call builders establish no
//! chain identity or armed state; inspection is trusted-node observation only.
//! Neither establishes source finality, payment, entitlement or actual transfer.

use std::{error::Error, fmt};

use primitive_types::U256;
use tiny_keccak::{Hasher, Keccak};
use ziquid_protocol::{allocate, Allocation, NativeAmount, SourceAmount};
use ziquid_protocol::native::{
    ArmJournal, DeploymentDescriptor, OriginJournal, Resolution, ResolveJournal,
    SourceAcceptanceJournal, SourceBoundary, Statement,
};

pub mod inspection;

const PROOF_BYTES: usize = 356;
const PROOF_SELECTOR: [u8; 4] = [0x43, 0x88, 0xa2, 0x1c];
const VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d,
    0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28,
    0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];
// Vendored Groth16Verifier.sol R: public inputs are rejected, never reduced.
const SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallBuildError {
    WrongDeployment,
    InvalidStatement,
    InvalidBoundary,
    InvalidSender,
    InvalidResolution,
    InvalidProgram,
    InvalidProofFrame,
}

impl fmt::Display for CallBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongDeployment => "native deployment mismatch",
            Self::InvalidStatement => "invalid native statement",
            Self::InvalidBoundary => "invalid native source boundary",
            Self::InvalidSender => "invalid native resolve sender",
            Self::InvalidResolution => "invalid native resolution",
            Self::InvalidProgram => "native program outside SP1 scalar field",
            Self::InvalidProofFrame => "invalid native public wrapped proof frame",
        })
    }
}

impl Error for CallBuildError {}

/// Immutable unsigned proposal. Allocation is arithmetic for review only;
/// neither it nor the expected journals authorizes or records a transfer.
#[derive(Debug)]
pub struct UnsignedCall {
    from: [u8; 20],
    to: [u8; 20],
    value: U256,
    data: Vec<u8>,
    deployment: DeploymentDescriptor,
    context_digest: [u8; 32],
    expected_journals: Vec<Vec<u8>>,
    allocation: Option<Allocation>,
}

impl UnsignedCall {
    pub fn from(&self) -> [u8; 20] { self.from }
    pub fn to(&self) -> [u8; 20] { self.to }
    pub fn value(&self) -> U256 { self.value }
    pub fn data(&self) -> &[u8] { &self.data }
    pub fn deployment(&self) -> &DeploymentDescriptor { &self.deployment }
    pub fn context_digest(&self) -> [u8; 32] { self.context_digest }
    pub fn expected_journals(&self) -> &[Vec<u8>] { &self.expected_journals }
    pub fn allocation(&self) -> Option<Allocation> { self.allocation }
}

/// The exact statement payer funds the complete 256-bit D. Identical public
/// proof frames are permitted; actual verification remains the contract's job.
pub fn build_fund_and_arm_call(
    expected: &DeploymentDescriptor,
    statement: &Statement,
    boundary: &SourceBoundary,
    arm_proof: &[u8],
    origin_proof: &[u8],
    acceptance_proof: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_inputs(expected, statement, boundary)?;
    for proof in [arm_proof, origin_proof, acceptance_proof] { check_proof(proof)?; }
    let context_digest = statement.digest();
    // All fields have passed the protocol validators above. Reuse its concrete
    // encoders while computing the common context hash only once.
    let arm = ArmJournal {
        context_hash: context_digest, stable_jtag: statement.stable_jtag, boundary: *boundary,
    };
    let origin = OriginJournal {
        context_hash: context_digest, stable_jtag: statement.stable_jtag,
        joint_binding: statement.joint_binding, boundary: *boundary,
    };
    let acceptance = acceptance_journal(statement, boundary);
    let raw_statement = statement.encode();
    let raw_boundary = boundary.encode();
    // Five dynamic heads; canonical sizes fix every offset and total length.
    let mut data = calldata(b"fundAndArm(bytes,bytes,bytes,bytes,bytes)", 2244);
    for offset in [160, 832, 992, 1408, 1824] { append_word(&mut data, offset); }
    for bytes in [&raw_statement[..], &raw_boundary[..], arm_proof, origin_proof, acceptance_proof] {
        append_bytes(&mut data, bytes);
    }
    Ok(UnsignedCall {
        from: statement.payer, to: expected.obligation,
        value: NativeAmount::from_be_bytes(statement.d).get(), data,
        deployment: *expected, context_digest,
        expected_journals: vec![arm.encode().to_vec(), origin.encode().to_vec(), acceptance.encode().to_vec()],
        allocation: None,
    })
}

/// A nonzero relayer may resolve; only Completion with 1..=A or Recovery with
/// zero consideration is representable. No claim of currently armed state follows.
#[allow(clippy::too_many_arguments)]
pub fn build_resolve_call(
    expected: &DeploymentDescriptor,
    statement: &Statement,
    boundary: &SourceBoundary,
    sender: [u8; 20],
    outcome: Resolution,
    cnet: u64,
    financial_proof: &[u8],
    acceptance_proof: &[u8],
) -> Result<UnsignedCall, CallBuildError> {
    check_inputs(expected, statement, boundary)?;
    if sender == [0; 20] { return Err(CallBuildError::InvalidSender); }
    // This concrete protocol constructor owns the outcome/cnet predicate and
    // exact context digest; no Unknown/Other or excess can escape as a call.
    let financial = ResolveJournal::new(statement, *boundary, outcome, cnet)
        .map_err(|_| CallBuildError::InvalidResolution)?;
    check_proof(financial_proof)?;
    check_proof(acceptance_proof)?;
    let allocation = allocate(
        SourceAmount::new(statement.a).map_err(|_| CallBuildError::InvalidStatement)?,
        NativeAmount::from_be_bytes(statement.d),
        SourceAmount::new(cnet).map_err(|_| CallBuildError::InvalidResolution)?,
    ).map_err(|_| CallBuildError::InvalidResolution)?;
    let acceptance = acceptance_journal(statement, boundary);
    let raw_statement = statement.encode();
    let raw_boundary = boundary.encode();
    // Six heads: bytes, bytes, uint8, uint64, bytes, bytes.
    let mut data = calldata(b"resolve(bytes,bytes,uint8,uint64,bytes,bytes)", 1860);
    for value in [192, 864, outcome as u64, cnet, 1024, 1440] { append_word(&mut data, value); }
    for bytes in [&raw_statement[..], &raw_boundary[..], financial_proof, acceptance_proof] {
        append_bytes(&mut data, bytes);
    }
    Ok(UnsignedCall {
        from: sender, to: expected.obligation, value: U256::zero(), data,
        deployment: *expected, context_digest: financial.context_hash,
        expected_journals: vec![financial.encode().to_vec(), acceptance.encode().to_vec()],
        allocation: Some(allocation),
    })
}

fn check_statement(expected: &DeploymentDescriptor, statement: &Statement) -> Result<(), CallBuildError> {
    if expected.validate().is_err()
        || statement.schema_version != expected.schema_version
        || statement.source_network != expected.source_network
        || statement.source_pool != expected.source_pool
        || statement.transaction_version != expected.transaction_version
        || statement.consensus_branch != expected.consensus_branch
        || statement.financial_program != expected.financial_program
        || statement.origin_program != expected.origin_program
        || statement.source_acceptance_program != expected.source_acceptance_program
        || statement.source_policy_id != expected.source_policy_id
        || statement.target_chain_id != expected.target_chain_id
        || statement.obligation != expected.obligation
        || statement.deployment_descriptor != expected.digest()
    {
        return Err(CallBuildError::WrongDeployment);
    }
    statement.validate().map_err(|_| CallBuildError::InvalidStatement)?;
    Ok(())
}

fn check_inputs(
    expected: &DeploymentDescriptor, statement: &Statement, boundary: &SourceBoundary,
) -> Result<(), CallBuildError> {
    check_statement(expected, statement)?;
    boundary.validate().map_err(|_| CallBuildError::InvalidBoundary)?;
    for program in [expected.financial_program, expected.origin_program, expected.source_acceptance_program] {
        if program >= SCALAR_MODULUS { return Err(CallBuildError::InvalidProgram); }
    }
    Ok(())
}

fn acceptance_journal(statement: &Statement, boundary: &SourceBoundary) -> SourceAcceptanceJournal {
    SourceAcceptanceJournal {
        source_network: statement.source_network,
        source_policy_id: statement.source_policy_id,
        boundary: *boundary,
    }
}

// Public input shape only. Pairing words are preserved, never authenticated.
fn check_proof(proof: &[u8]) -> Result<(), CallBuildError> {
    if proof.len() != PROOF_BYTES || proof[..4] != PROOF_SELECTOR
        || proof[4..36] != [0; 32] || proof[36..68] != VK_ROOT
        || proof[68..100] >= SCALAR_MODULUS[..]
    {
        return Err(CallBuildError::InvalidProofFrame);
    }
    Ok(())
}

fn calldata(signature: &[u8], length: usize) -> Vec<u8> {
    let mut hash = [0; 32];
    let mut keccak = Keccak::v256();
    keccak.update(signature);
    keccak.finalize(&mut hash);
    let mut data = Vec::with_capacity(length);
    data.extend_from_slice(&hash[..4]);
    data
}

fn append_word(data: &mut Vec<u8>, value: u64) {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    data.extend_from_slice(&word);
}

fn append_bytes(data: &mut Vec<u8>, bytes: &[u8]) {
    append_word(data, bytes.len() as u64);
    data.extend_from_slice(bytes);
    data.resize(data.len() + (32 - bytes.len() % 32) % 32, 0);
}
