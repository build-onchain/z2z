//! Exact native financial statement and journal encodings.
//!
//! This module is a canonical shape and binding layer only. Decoding or
//! binding a frame does not establish source history, finality, payment,
//! ownership, entitlement, refund authority, or a completed transfer.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::{note_consumption_tag, NativeAmount, SemanticCommitmentError, SourceAmount, MAX_SOURCE_AMOUNT};

pub const STATEMENT_DOMAIN: &[u8] = b"ziquid.native.statement.v1";
pub const DEPLOYMENT_DOMAIN: &[u8] = b"ziquid.native.deployment.v1";
pub const ORIGIN_DOMAIN: &[u8] = b"ziquid.native.origin.v1";
pub const ARM_DOMAIN: &[u8] = b"ziquid.native.arm.v1";
pub const RESOLVE_DOMAIN: &[u8] = b"ziquid.native.resolve.v1";
pub const ACCEPTANCE_DOMAIN: &[u8] = b"ziquid.native.acceptance.v1";

pub const SCHEMA_VERSION: u16 = 1;
pub const SOURCE_NETWORK: u8 = 1;
pub const SOURCE_POOL: u8 = 3;
pub const TRANSACTION_VERSION: u32 = 6;
pub const CONSENSUS_BRANCH: u32 = 0x37a5_165b;
pub const IRONWOOD_ACTIVATION: u32 = 4_134_000;
pub const NEXT_UPGRADE: u32 = 4_465_026;
pub const DEPLOYMENT_ENCODED_LEN: usize = 279;
pub const STATEMENT_ENCODED_LEN: usize = 638;
pub const BOUNDARY_ENCODED_LEN: usize = 100;
pub const ARM_JOURNAL_ENCODED_LEN: usize = 184;
pub const ORIGIN_JOURNAL_ENCODED_LEN: usize = 219;
pub const RESOLVE_JOURNAL_ENCODED_LEN: usize = 197;
pub const ACCEPTANCE_JOURNAL_ENCODED_LEN: usize = 160;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeError {
    InvalidStatement,
    InvalidBoundary,
    InvalidDeployment,
    InvalidOutcome,
    InvalidJournal,
    Length,
    Mismatch,
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidStatement => "invalid native statement",
            Self::InvalidBoundary => "invalid source boundary",
            Self::InvalidDeployment => "invalid deployment descriptor",
            Self::InvalidOutcome => "invalid resolution outcome",
            Self::InvalidJournal => "invalid native journal",
            Self::Length => "invalid native frame length",
            Self::Mismatch => "native journal does not bind the statement",
        })
    }
}

impl Error for NativeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentDescriptor {
    pub schema_version: u16,
    pub source_network: u8,
    pub source_pool: u8,
    pub transaction_version: u32,
    pub consensus_branch: u32,
    pub financial_program: [u8; 32],
    pub origin_program: [u8; 32],
    pub source_acceptance_program: [u8; 32],
    pub source_policy_id: [u8; 32],
    pub target_chain_id: u64,
    pub obligation: [u8; 20],
    pub obligation_runtime_code: [u8; 32],
    pub verifier: [u8; 20],
    pub verifier_runtime_code: [u8; 32],
}

impl DeploymentDescriptor {
    pub fn validate(&self) -> Result<(), NativeError> {
        if self.schema_version != SCHEMA_VERSION
            || self.source_network != SOURCE_NETWORK
            || self.source_pool != SOURCE_POOL
            || self.transaction_version != TRANSACTION_VERSION
            || self.consensus_branch != CONSENSUS_BRANCH
            || is_zero(&self.financial_program)
            || is_zero(&self.origin_program)
            || is_zero(&self.source_acceptance_program)
            || is_zero(&self.source_policy_id)
            || self.target_chain_id == 0
            || is_zero(&self.obligation)
            || is_zero(&self.obligation_runtime_code)
            || is_zero(&self.verifier)
            || is_zero(&self.verifier_runtime_code)
        {
            return Err(NativeError::InvalidDeployment);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; DEPLOYMENT_ENCODED_LEN] {
        let mut out = [0u8; DEPLOYMENT_ENCODED_LEN];
        let mut offset = 0;
        put_bytes(&mut out, &mut offset, DEPLOYMENT_DOMAIN);
        put_u16(&mut out, &mut offset, self.schema_version);
        put_bytes(&mut out, &mut offset, &[self.source_network]);
        put_bytes(&mut out, &mut offset, &[self.source_pool]);
        put_u32(&mut out, &mut offset, self.transaction_version);
        put_u32(&mut out, &mut offset, self.consensus_branch);
        put_bytes(&mut out, &mut offset, &self.financial_program);
        put_bytes(&mut out, &mut offset, &self.origin_program);
        put_bytes(&mut out, &mut offset, &self.source_acceptance_program);
        put_bytes(&mut out, &mut offset, &self.source_policy_id);
        put_u64(&mut out, &mut offset, self.target_chain_id);
        put_bytes(&mut out, &mut offset, &self.obligation);
        put_bytes(&mut out, &mut offset, &self.obligation_runtime_code);
        put_bytes(&mut out, &mut offset, &self.verifier);
        put_bytes(&mut out, &mut offset, &self.verifier_runtime_code);
        debug_assert_eq!(offset, DEPLOYMENT_ENCODED_LEN);
        out
    }

    /// Exact public descriptor framing. Decoding does not authenticate code or programs.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if bytes.len() != DEPLOYMENT_ENCODED_LEN || !bytes.starts_with(DEPLOYMENT_DOMAIN) {
            return Err(NativeError::InvalidDeployment);
        }
        let mut reader = Reader::new(&bytes[DEPLOYMENT_DOMAIN.len()..]);
        let value = Self {
            schema_version: reader.u16()?, source_network: reader.u8()?, source_pool: reader.u8()?,
            transaction_version: reader.u32()?, consensus_branch: reader.u32()?,
            financial_program: reader.array()?, origin_program: reader.array()?,
            source_acceptance_program: reader.array()?, source_policy_id: reader.array()?,
            target_chain_id: reader.u64()?, obligation: reader.array()?,
            obligation_runtime_code: reader.array()?, verifier: reader.array()?,
            verifier_runtime_code: reader.array()?,
        };
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub schema_version: u16,
    pub source_network: u8,
    pub source_pool: u8,
    pub transaction_version: u32,
    pub consensus_branch: u32,
    pub financial_program: [u8; 32],
    pub origin_program: [u8; 32],
    pub source_acceptance_program: [u8; 32],
    pub source_policy_id: [u8; 32],
    pub window_policy_commitment: [u8; 32],
    pub target_chain_id: u64,
    pub obligation: [u8; 20],
    pub deployment_descriptor: [u8; 32],
    pub payer: [u8; 20],
    pub u_payee: [u8; 20],
    pub s_refund: [u8; 20],
    pub a: u64,
    pub d: [u8; 32],
    pub joint_value: u64,
    pub r_return: u64,
    pub targets: [u32; 3],
    pub expiries: [u32; 3],
    pub fees: [u64; 3],
    pub fee_caps: [u64; 3],
    pub quote_commitment: [u8; 32],
    pub agreement_commitment: [u8; 32],
    pub group_grant_commitment: [u8; 32],
    pub source_terms_commitment: [u8; 32],
    pub joint_binding: [u8; 32],
    pub stable_jtag: [u8; 32],
}

impl Statement {
    pub fn validate(&self) -> Result<(), NativeError> {
        if self.schema_version != SCHEMA_VERSION
            || self.source_network != SOURCE_NETWORK
            || self.source_pool != SOURCE_POOL
            || self.transaction_version != TRANSACTION_VERSION
            || self.consensus_branch != CONSENSUS_BRANCH
            || is_zero(&self.financial_program)
            || is_zero(&self.origin_program)
            || is_zero(&self.source_acceptance_program)
            || is_zero(&self.source_policy_id)
            || is_zero(&self.window_policy_commitment)
            || self.target_chain_id == 0
            || is_zero(&self.obligation)
            || is_zero(&self.deployment_descriptor)
            || is_zero(&self.payer)
            || is_zero(&self.u_payee)
            || is_zero(&self.s_refund)
            || self.u_payee == self.s_refund
            || is_zero(&self.quote_commitment)
            || is_zero(&self.agreement_commitment)
            || is_zero(&self.group_grant_commitment)
            || is_zero(&self.source_terms_commitment)
            || is_zero(&self.joint_binding)
            || is_zero(&self.stable_jtag)
            || !valid_source_amount(self.a)
            || NativeAmount::from_be_bytes(self.d).get().is_zero()
            || !valid_source_amount(self.joint_value)
            || !valid_source_amount(self.r_return)
        {
            return Err(NativeError::InvalidStatement);
        }
        for index in 0..3 {
            if !valid_window(self.targets[index], self.expiries[index])
                || self.fees[index] > self.fee_caps[index]
                || self.fee_caps[index] > MAX_SOURCE_AMOUNT
            {
                return Err(NativeError::InvalidStatement);
            }
        }
        let Some(joint_from_a) = self.a.checked_add(self.fees[1]) else {
            return Err(NativeError::InvalidStatement);
        };
        let Some(joint_from_return) = self.r_return.checked_add(self.fees[2]) else {
            return Err(NativeError::InvalidStatement);
        };
        if self.expiries[0] >= self.expiries[1]
            || self.expiries[0] >= self.expiries[2]
            || self.joint_value != joint_from_a
            || self.joint_value != joint_from_return
        {
            return Err(NativeError::InvalidStatement);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; STATEMENT_ENCODED_LEN] {
        let mut out = [0u8; STATEMENT_ENCODED_LEN];
        let mut offset = 0;
        put_bytes(&mut out, &mut offset, STATEMENT_DOMAIN);
        put_u16(&mut out, &mut offset, self.schema_version);
        put_bytes(&mut out, &mut offset, &[self.source_network]);
        put_bytes(&mut out, &mut offset, &[self.source_pool]);
        put_u32(&mut out, &mut offset, self.transaction_version);
        put_u32(&mut out, &mut offset, self.consensus_branch);
        put_bytes(&mut out, &mut offset, &self.financial_program);
        put_bytes(&mut out, &mut offset, &self.origin_program);
        put_bytes(&mut out, &mut offset, &self.source_acceptance_program);
        put_bytes(&mut out, &mut offset, &self.source_policy_id);
        put_bytes(&mut out, &mut offset, &self.window_policy_commitment);
        put_u64(&mut out, &mut offset, self.target_chain_id);
        put_bytes(&mut out, &mut offset, &self.obligation);
        put_bytes(&mut out, &mut offset, &self.deployment_descriptor);
        put_bytes(&mut out, &mut offset, &self.payer);
        put_bytes(&mut out, &mut offset, &self.u_payee);
        put_bytes(&mut out, &mut offset, &self.s_refund);
        put_u64(&mut out, &mut offset, self.a);
        put_bytes(&mut out, &mut offset, &self.d);
        put_u64(&mut out, &mut offset, self.joint_value);
        put_u64(&mut out, &mut offset, self.r_return);
        for target in self.targets { put_u32(&mut out, &mut offset, target); }
        for expiry in self.expiries { put_u32(&mut out, &mut offset, expiry); }
        for fee in self.fees { put_u64(&mut out, &mut offset, fee); }
        for cap in self.fee_caps { put_u64(&mut out, &mut offset, cap); }
        put_bytes(&mut out, &mut offset, &self.quote_commitment);
        put_bytes(&mut out, &mut offset, &self.agreement_commitment);
        put_bytes(&mut out, &mut offset, &self.group_grant_commitment);
        put_bytes(&mut out, &mut offset, &self.source_terms_commitment);
        put_bytes(&mut out, &mut offset, &self.joint_binding);
        put_bytes(&mut out, &mut offset, &self.stable_jtag);
        debug_assert_eq!(offset, STATEMENT_ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if bytes.len() != STATEMENT_ENCODED_LEN || !bytes.starts_with(STATEMENT_DOMAIN) {
            return Err(NativeError::InvalidStatement);
        }
        let mut reader = Reader::new(&bytes[STATEMENT_DOMAIN.len()..]);
        let statement = Self {
            schema_version: reader.u16()?,
            source_network: reader.u8()?,
            source_pool: reader.u8()?,
            transaction_version: reader.u32()?,
            consensus_branch: reader.u32()?,
            financial_program: reader.array()?,
            origin_program: reader.array()?,
            source_acceptance_program: reader.array()?,
            source_policy_id: reader.array()?,
            window_policy_commitment: reader.array()?,
            target_chain_id: reader.u64()?,
            obligation: reader.array()?,
            deployment_descriptor: reader.array()?,
            payer: reader.array()?,
            u_payee: reader.array()?,
            s_refund: reader.array()?,
            a: reader.u64()?,
            d: reader.array()?,
            joint_value: reader.u64()?,
            r_return: reader.u64()?,
            targets: [reader.u32()?, reader.u32()?, reader.u32()?],
            expiries: [reader.u32()?, reader.u32()?, reader.u32()?],
            fees: [reader.u64()?, reader.u64()?, reader.u64()?],
            fee_caps: [reader.u64()?, reader.u64()?, reader.u64()?],
            quote_commitment: reader.array()?,
            agreement_commitment: reader.array()?,
            group_grant_commitment: reader.array()?,
            source_terms_commitment: reader.array()?,
            joint_binding: reader.array()?,
            stable_jtag: reader.array()?,
        };
        reader.finish()?;
        statement.validate()?;
        Ok(statement)
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    pub const fn f_target(&self) -> u32 { self.targets[0] }
    pub const fn c_target(&self) -> u32 { self.targets[1] }
    pub const fn r_target(&self) -> u32 { self.targets[2] }
    pub const fn f_expiry(&self) -> u32 { self.expiries[0] }
    pub const fn c_expiry(&self) -> u32 { self.expiries[1] }
    pub const fn r_expiry(&self) -> u32 { self.expiries[2] }
    pub const fn fee_f(&self) -> u64 { self.fees[0] }
    pub const fn fee_c(&self) -> u64 { self.fees[1] }
    pub const fn fee_r(&self) -> u64 { self.fees[2] }
    pub const fn fee_cap_f(&self) -> u64 { self.fee_caps[0] }
    pub const fn fee_cap_c(&self) -> u64 { self.fee_caps[1] }
    pub const fn fee_cap_r(&self) -> u64 { self.fee_caps[2] }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceBoundary {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub cumulative_work: [u8; 32],
    pub ledger_journal_digest: [u8; 32],
}

impl SourceBoundary {
    pub fn validate(&self) -> Result<(), NativeError> {
        if self.height == 0
            || self.height >= NEXT_UPGRADE
            || is_zero(&self.block_hash)
            || is_zero(&self.cumulative_work)
            || is_zero(&self.ledger_journal_digest)
        {
            return Err(NativeError::InvalidBoundary);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; BOUNDARY_ENCODED_LEN] {
        let mut out = [0u8; BOUNDARY_ENCODED_LEN];
        let mut offset = 0;
        put_u32(&mut out, &mut offset, self.height);
        put_bytes(&mut out, &mut offset, &self.block_hash);
        put_bytes(&mut out, &mut offset, &self.cumulative_work);
        put_bytes(&mut out, &mut offset, &self.ledger_journal_digest);
        debug_assert_eq!(offset, BOUNDARY_ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if bytes.len() != BOUNDARY_ENCODED_LEN { return Err(NativeError::InvalidBoundary); }
        let mut reader = Reader::new(bytes);
        let boundary = Self {
            height: reader.u32()?,
            block_hash: reader.array()?,
            cumulative_work: reader.array()?,
            ledger_journal_digest: reader.array()?,
        };
        reader.finish()?;
        boundary.validate()?;
        Ok(boundary)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Resolution {
    Completion = 1,
    Recovery = 2,
}

impl TryFrom<u8> for Resolution {
    type Error = NativeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Completion),
            2 => Ok(Self::Recovery),
            _ => Err(NativeError::InvalidOutcome),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinancialJournalKind {
    Arm,
    Origin,
    Resolve { outcome: Resolution, cnet: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinancialJournal {
    pub kind: FinancialJournalKind,
    pub context_hash: [u8; 32],
    pub stable_jtag: [u8; 32],
    pub joint_binding: Option<[u8; 32]>,
    pub boundary: SourceBoundary,
}

impl FinancialJournal {
    fn new_common(statement: &Statement, boundary: SourceBoundary, kind: FinancialJournalKind, joint_binding: Option<[u8; 32]>) -> Result<Self, NativeError> {
        statement.validate()?;
        boundary.validate()?;
        if let FinancialJournalKind::Resolve { outcome, cnet } = kind {
            validate_resolution(outcome, cnet, statement.a)?;
        }
        Ok(Self { kind, context_hash: statement.digest(), stable_jtag: statement.stable_jtag, joint_binding, boundary })
    }


    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let (kind, prefix, extra) = if bytes.starts_with(ARM_DOMAIN) {
            (FinancialJournalKind::Arm, ARM_DOMAIN, 0usize)
        } else if bytes.starts_with(ORIGIN_DOMAIN) {
            (FinancialJournalKind::Origin, ORIGIN_DOMAIN, 32usize)
        } else if bytes.starts_with(RESOLVE_DOMAIN) {
            (FinancialJournalKind::Resolve { outcome: Resolution::Recovery, cnet: 0 }, RESOLVE_DOMAIN, 9usize)
        } else {
            return Err(NativeError::InvalidJournal);
        };
        let expected = prefix.len() + 64 + extra + BOUNDARY_ENCODED_LEN;
        if bytes.len() != expected { return Err(NativeError::InvalidJournal); }
        let mut reader = Reader::new(&bytes[prefix.len()..]);
        let context_hash: [u8; 32] = reader.array().map_err(|_| NativeError::InvalidJournal)?;
        let stable_jtag: [u8; 32] = reader.array().map_err(|_| NativeError::InvalidJournal)?;
        if is_zero(&context_hash) || is_zero(&stable_jtag) { return Err(NativeError::InvalidJournal); }
        let joint_binding = if matches!(kind, FinancialJournalKind::Origin) {
            let value: [u8; 32] = reader.array().map_err(|_| NativeError::InvalidJournal)?;
            if is_zero(&value) { return Err(NativeError::InvalidJournal); }
            Some(value)
        } else { None };
        let boundary_bytes = reader.take::<BOUNDARY_ENCODED_LEN>().map_err(|_| NativeError::InvalidJournal)?;
        let boundary = SourceBoundary::decode(&boundary_bytes).map_err(|_| NativeError::InvalidJournal)?;
        let kind = if prefix == RESOLVE_DOMAIN {
            let outcome = reader.u8().map_err(|_| NativeError::InvalidJournal)?;
            let outcome = Resolution::try_from(outcome).map_err(|_| NativeError::InvalidJournal)?;
            let cnet = reader.u64().map_err(|_| NativeError::InvalidJournal)?;
            validate_resolution(outcome, cnet, MAX_SOURCE_AMOUNT).map_err(|_| NativeError::InvalidJournal)?;
            FinancialJournalKind::Resolve { outcome, cnet }
        } else { kind };
        reader.finish().map_err(|_| NativeError::InvalidJournal)?;
        Ok(Self { kind, context_hash, stable_jtag, joint_binding, boundary })
    }

    pub fn check_statement(&self, statement: &Statement) -> Result<(), NativeError> {
        statement.validate()?;
        if self.context_hash != statement.digest() || self.stable_jtag != statement.stable_jtag {
            return Err(NativeError::Mismatch);
        }
        match self.kind {
            FinancialJournalKind::Origin => {
                if self.joint_binding != Some(statement.joint_binding) { return Err(NativeError::Mismatch); }
            }
            FinancialJournalKind::Resolve { outcome, cnet } => validate_resolution(outcome, cnet, statement.a)?,
            FinancialJournalKind::Arm => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmJournal {
    pub context_hash: [u8; 32],
    pub stable_jtag: [u8; 32],
    pub boundary: SourceBoundary,
}

impl ArmJournal {
    pub fn new(statement: &Statement, boundary: SourceBoundary) -> Result<Self, NativeError> {
        let journal = FinancialJournal::new_common(statement, boundary, FinancialJournalKind::Arm, None)?;
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, boundary: journal.boundary })
    }

    pub fn encode(&self) -> [u8; ARM_JOURNAL_ENCODED_LEN] {
        encode_arm(self.context_hash, self.stable_jtag, self.boundary)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let journal = FinancialJournal::decode(bytes)?;
        if !matches!(journal.kind, FinancialJournalKind::Arm) { return Err(NativeError::InvalidJournal); }
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, boundary: journal.boundary })
    }

    pub fn check_statement(&self, statement: &Statement) -> Result<(), NativeError> {
        FinancialJournal { kind: FinancialJournalKind::Arm, context_hash: self.context_hash, stable_jtag: self.stable_jtag, joint_binding: None, boundary: self.boundary }.check_statement(statement)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginJournal {
    pub context_hash: [u8; 32],
    pub stable_jtag: [u8; 32],
    pub joint_binding: [u8; 32],
    pub boundary: SourceBoundary,
}

impl OriginJournal {
    pub fn new(statement: &Statement, boundary: SourceBoundary) -> Result<Self, NativeError> {
        let journal = FinancialJournal::new_common(statement, boundary, FinancialJournalKind::Origin, Some(statement.joint_binding))?;
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, joint_binding: statement.joint_binding, boundary: journal.boundary })
    }

    pub fn encode(&self) -> [u8; ORIGIN_JOURNAL_ENCODED_LEN] {
        encode_origin(self.context_hash, self.stable_jtag, self.joint_binding, self.boundary)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let journal = FinancialJournal::decode(bytes)?;
        if !matches!(journal.kind, FinancialJournalKind::Origin) { return Err(NativeError::InvalidJournal); }
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, joint_binding: journal.joint_binding.ok_or(NativeError::InvalidJournal)?, boundary: journal.boundary })
    }

    pub fn check_statement(&self, statement: &Statement) -> Result<(), NativeError> {
        FinancialJournal { kind: FinancialJournalKind::Origin, context_hash: self.context_hash, stable_jtag: self.stable_jtag, joint_binding: Some(self.joint_binding), boundary: self.boundary }.check_statement(statement)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveJournal {
    pub context_hash: [u8; 32],
    pub stable_jtag: [u8; 32],
    pub boundary: SourceBoundary,
    pub outcome: Resolution,
    pub cnet: u64,
}

impl ResolveJournal {
    pub fn new(statement: &Statement, boundary: SourceBoundary, outcome: Resolution, cnet: u64) -> Result<Self, NativeError> {
        let journal = FinancialJournal::new_common(statement, boundary, FinancialJournalKind::Resolve { outcome, cnet }, None)?;
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, boundary: journal.boundary, outcome, cnet })
    }

    pub fn encode(&self) -> [u8; RESOLVE_JOURNAL_ENCODED_LEN] {
        encode_resolve(self.context_hash, self.stable_jtag, self.boundary, self.outcome, self.cnet)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let journal = FinancialJournal::decode(bytes)?;
        let FinancialJournalKind::Resolve { outcome, cnet } = journal.kind else { return Err(NativeError::InvalidJournal); };
        Ok(Self { context_hash: journal.context_hash, stable_jtag: journal.stable_jtag, boundary: journal.boundary, outcome, cnet })
    }

    pub fn check_statement(&self, statement: &Statement) -> Result<(), NativeError> {
        FinancialJournal { kind: FinancialJournalKind::Resolve { outcome: self.outcome, cnet: self.cnet }, context_hash: self.context_hash, stable_jtag: self.stable_jtag, joint_binding: None, boundary: self.boundary }.check_statement(statement)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAcceptanceJournal {
    pub source_network: u8,
    pub source_policy_id: [u8; 32],
    pub boundary: SourceBoundary,
}

impl SourceAcceptanceJournal {
    pub fn new(statement: &Statement, boundary: SourceBoundary) -> Result<Self, NativeError> {
        statement.validate()?;
        boundary.validate()?;
        Ok(Self { source_network: statement.source_network, source_policy_id: statement.source_policy_id, boundary })
    }

    pub fn encode(&self) -> [u8; ACCEPTANCE_JOURNAL_ENCODED_LEN] {
        let mut out = [0u8; ACCEPTANCE_JOURNAL_ENCODED_LEN];
        let mut offset = 0;
        put_bytes(&mut out, &mut offset, ACCEPTANCE_DOMAIN);
        put_bytes(&mut out, &mut offset, &[self.source_network]);
        put_bytes(&mut out, &mut offset, &self.source_policy_id);
        put_bytes(&mut out, &mut offset, &self.boundary.encode());
        debug_assert_eq!(offset, ACCEPTANCE_JOURNAL_ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if bytes.len() != ACCEPTANCE_JOURNAL_ENCODED_LEN || !bytes.starts_with(ACCEPTANCE_DOMAIN) { return Err(NativeError::InvalidJournal); }
        let mut reader = Reader::new(&bytes[ACCEPTANCE_DOMAIN.len()..]);
        let source_network = reader.u8().map_err(|_| NativeError::InvalidJournal)?;
        let source_policy_id: [u8; 32] = reader.array().map_err(|_| NativeError::InvalidJournal)?;
        let boundary_bytes = reader.take::<BOUNDARY_ENCODED_LEN>().map_err(|_| NativeError::InvalidJournal)?;
        reader.finish().map_err(|_| NativeError::InvalidJournal)?;
        if source_network != SOURCE_NETWORK || is_zero(&source_policy_id) { return Err(NativeError::InvalidJournal); }
        Ok(Self { source_network, source_policy_id, boundary: SourceBoundary::decode(&boundary_bytes).map_err(|_| NativeError::InvalidJournal)? })
    }

    pub fn check_statement(&self, statement: &Statement) -> Result<(), NativeError> {
        statement.validate()?;
        if self.source_network != statement.source_network || self.source_policy_id != statement.source_policy_id {
            return Err(NativeError::Mismatch);
        }
        Ok(())
    }
}

/// Stable one-note/one-obligation tag using the existing keyed BLAKE2b helper.
/// This is a binding primitive, not proof of uniqueness, ownership, payment or
/// an entitlement.
pub fn stable_j_tag(
    target_chain_id: u64,
    obligation: &[u8; 20],
    nk: &[u8; 32],
    nf: &[u8; 32],
) -> Result<[u8; 32], NativeError> {
    note_consumption_tag(
        &crate::SOURCE_TESTNET,
        &crate::IRONWOOD_POOL,
        target_chain_id,
        obligation,
        nk,
        nf,
    )
    .map_err(|error| match error {
        SemanticCommitmentError::InvalidDeployment | SemanticCommitmentError::InvalidDomain => NativeError::InvalidDeployment,
        _ => NativeError::InvalidDeployment,
    })
}

fn valid_source_amount(value: u64) -> bool {
    SourceAmount::new(value).is_ok() && value != 0
}

fn valid_window(target: u32, expiry: u32) -> bool {
    target >= IRONWOOD_ACTIVATION && target <= expiry && expiry < NEXT_UPGRADE
}

fn validate_resolution(outcome: Resolution, cnet: u64, amount: u64) -> Result<(), NativeError> {
    match outcome {
        Resolution::Completion if cnet != 0 && cnet <= amount => Ok(()),
        Resolution::Recovery if cnet == 0 => Ok(()),
        _ => Err(NativeError::InvalidOutcome),
    }
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool { bytes.iter().all(|byte| *byte == 0) }

fn sha256(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

fn put_bytes<const N: usize>(out: &mut [u8; N], offset: &mut usize, bytes: &[u8]) {
    out[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    *offset += bytes.len();
}

fn put_u16<const N: usize>(out: &mut [u8; N], offset: &mut usize, value: u16) {
    put_bytes(out, offset, &value.to_be_bytes());
}

fn put_u32<const N: usize>(out: &mut [u8; N], offset: &mut usize, value: u32) {
    put_bytes(out, offset, &value.to_be_bytes());
}

fn put_u64<const N: usize>(out: &mut [u8; N], offset: &mut usize, value: u64) {
    put_bytes(out, offset, &value.to_be_bytes());
}

fn encode_arm(
    context_hash: [u8; 32],
    stable_jtag: [u8; 32],
    boundary: SourceBoundary,
) -> [u8; ARM_JOURNAL_ENCODED_LEN] {
    let mut out = [0u8; ARM_JOURNAL_ENCODED_LEN];
    let mut offset = 0;
    put_bytes(&mut out, &mut offset, ARM_DOMAIN);
    put_bytes(&mut out, &mut offset, &context_hash);
    put_bytes(&mut out, &mut offset, &stable_jtag);
    let boundary = boundary.encode();
    put_bytes(&mut out, &mut offset, &boundary);
    debug_assert_eq!(offset, ARM_JOURNAL_ENCODED_LEN);
    out
}

fn encode_origin(
    context_hash: [u8; 32],
    stable_jtag: [u8; 32],
    joint_binding: [u8; 32],
    boundary: SourceBoundary,
) -> [u8; ORIGIN_JOURNAL_ENCODED_LEN] {
    let mut out = [0u8; ORIGIN_JOURNAL_ENCODED_LEN];
    let mut offset = 0;
    put_bytes(&mut out, &mut offset, ORIGIN_DOMAIN);
    put_bytes(&mut out, &mut offset, &context_hash);
    put_bytes(&mut out, &mut offset, &stable_jtag);
    put_bytes(&mut out, &mut offset, &joint_binding);
    let boundary = boundary.encode();
    put_bytes(&mut out, &mut offset, &boundary);
    debug_assert_eq!(offset, ORIGIN_JOURNAL_ENCODED_LEN);
    out
}

fn encode_resolve(
    context_hash: [u8; 32],
    stable_jtag: [u8; 32],
    boundary: SourceBoundary,
    outcome: Resolution,
    cnet: u64,
) -> [u8; RESOLVE_JOURNAL_ENCODED_LEN] {
    let mut out = [0u8; RESOLVE_JOURNAL_ENCODED_LEN];
    let mut offset = 0;
    put_bytes(&mut out, &mut offset, RESOLVE_DOMAIN);
    put_bytes(&mut out, &mut offset, &context_hash);
    put_bytes(&mut out, &mut offset, &stable_jtag);
    let boundary = boundary.encode();
    put_bytes(&mut out, &mut offset, &boundary);
    put_bytes(&mut out, &mut offset, &[outcome as u8]);
    put_u64(&mut out, &mut offset, cnet);
    debug_assert_eq!(offset, RESOLVE_JOURNAL_ENCODED_LEN);
    out
}

struct Reader<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NativeError> {
        let end = self.offset.checked_add(N).ok_or(NativeError::Length)?;
        if end > self.bytes.len() { return Err(NativeError::Length); }
        let mut value = [0u8; N];
        value.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeError> { self.take() }
    fn u8(&mut self) -> Result<u8, NativeError> { Ok(self.take::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, NativeError> { Ok(u16::from_be_bytes(self.take()?)) }
    fn u32(&mut self) -> Result<u32, NativeError> { Ok(u32::from_be_bytes(self.take()?)) }
    fn u64(&mut self) -> Result<u64, NativeError> { Ok(u64::from_be_bytes(self.take()?)) }

    fn finish(&self) -> Result<(), NativeError> {
        if self.offset == self.bytes.len() { Ok(()) } else { Err(NativeError::Length) }
    }
}
