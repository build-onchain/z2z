use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::{MAX_SOURCE_AMOUNT, NativeAmount};

/// DEX-specific, native-EVM-only domain. This is neither EVM ABI nor an agreed
/// Zoss common encoding. Native wei is the sole asset; no token selector exists.
pub const DEX_CONTEXT_DOMAIN: &[u8; 21] = b"ZIQUID_DEX_STATEMENT\0";
pub const CONTEXT_SCHEMA_VERSION: u16 = 1;
pub const SOURCE_TESTNET: [u8; 7] = *b"testnet";
pub const IRONWOOD_POOL: [u8; 8] = *b"ironwood";
pub const SOURCE_TRANSACTION_VERSION: u32 = 6;
pub const CONTEXT_ENCODED_LEN: usize = 474;

/// Application quote ceiling, not a consensus limit. Raise it only for an
/// actual quote requirement; the canonical receiver-count encoding is u16 BE.
pub const MAX_QUOTED_RECEIVERS: usize = 64;

/// Shape failures only; no private opening or caller bytes appear in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticCommitmentError {
    InvalidDomain,
    ZeroBlind,
    InvalidAmount,
    InvalidPaymentEffect,
    InvalidReceiverSet,
    InvalidPacketBinding,
    InvalidCapsuleCommitment,
    InvalidDeployment,
    InvalidPacket,
    InvalidSource,
}

impl fmt::Display for SemanticCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDomain => "unsupported semantic commitment domain",
            Self::ZeroBlind => "semantic commitment blind must be nonzero",
            Self::InvalidAmount => "semantic commitment amount is out of range",
            Self::InvalidPaymentEffect => "payment effect must be nonzero",
            Self::InvalidReceiverSet => "quoted receiver set must be bounded and strictly sorted",
            Self::InvalidPacketBinding => "preparation packet binding must be nonzero",
            Self::InvalidCapsuleCommitment => "solver capsule commitment must be nonzero",
            Self::InvalidDeployment => "consumption deployment must be nonzero",
            Self::InvalidPacket => "preparation packet is empty or exceeds its resource bounds",
            Self::InvalidSource => "preparation height and expiry must be finite supported heights",
        })
    }
}

impl Error for SemanticCommitmentError {}

/// SHA-256 of `b"ziquid.semantic.input.v1" || blind32 || network7 || pool8 ||
/// 3u8 || recipient43 || value-u64-BE || rho32 || rseed32 || cmx32 || nullifier32`.
/// Only testnet/Ironwood, a nonzero blind, and value `1..=MAX_SOURCE_AMOUNT`
/// are accepted. Hashing streams fixed-width fields without allocating.
///
/// The caller/proof must reconstruct the V3 note, its authenticated commitment,
/// and its FVK-derived nullifier, and validate the recipient with Orchard APIs.
/// This helper does not validate curves, ownership, membership, or entitlement.
/// Hiding requires a fresh confidential high-entropy blind; rejecting zero
/// cannot certify entropy. Use an independent blind for the payment commitment.
///
/// Recipient width is enforced by the type, not padded or truncated:
/// ```compile_fail
/// use ziquid_protocol::input_commitment;
/// let _ = input_commitment(&[1; 32], b"testnet", b"ironwood", &[2; 42],
///     1, &[3; 32], &[4; 32], &[5; 32], &[6; 32]);
/// ```
#[allow(clippy::too_many_arguments)]
pub fn input_commitment(
    blind: &[u8; 32],
    network: &[u8; 7],
    pool: &[u8; 8],
    recipient: &[u8; 43],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
    cmx: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<[u8; 32], SemanticCommitmentError> {
    if *network != SOURCE_TESTNET || *pool != IRONWOOD_POOL {
        return Err(SemanticCommitmentError::InvalidDomain);
    }
    if blind.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::ZeroBlind);
    }
    if value == 0 || value > MAX_SOURCE_AMOUNT {
        return Err(SemanticCommitmentError::InvalidAmount);
    }
    let mut hash = Sha256::new();
    hash.update(b"ziquid.semantic.input.v1");
    hash.update(blind);
    hash.update(network);
    hash.update(pool);
    hash.update([3]);
    hash.update(recipient);
    hash.update(value.to_be_bytes());
    hash.update(rho);
    hash.update(rseed);
    hash.update(cmx);
    hash.update(nullifier);
    Ok(hash.finalize().into())
}

/// SHA-256 of `b"ziquid.semantic.payment.v1" || blind32 || network7 || pool8 ||
/// payment-effect32 || receiver-count-u16-BE || each-receiver43 || quoted-u64-BE`.
/// Requires testnet/Ironwood, a nonzero blind/effect, quote
/// `1..=MAX_SOURCE_AMOUNT`, and `1..=MAX_QUOTED_RECEIVERS` receivers in strict
/// lexicographic order. Duplicates/unordered input are rejected, never sorted,
/// copied, or normalized. Hashing streams the borrowed set without allocating.
///
/// The blind must be fresh, confidential, high entropy, and independent of the
/// input blind. The caller/wallet must validate canonical Orchard addresses;
/// fixed width is not curve validity or proof of exclusive recipient ownership.
/// The proof must bind the actual P effect and recover/count every P output to
/// check the exact quoted total. Solver authorization of these destinations is
/// separate: this helper establishes no payment or financial fact.
///
/// ```compile_fail
/// use ziquid_protocol::payment_commitment;
/// let _ = payment_commitment(&[1; 32], b"testnet", b"ironwood", &[2; 32],
///     &[[3; 44]], 1);
/// ```
pub fn payment_commitment(
    blind: &[u8; 32],
    network: &[u8; 7],
    pool: &[u8; 8],
    payment_effect: &[u8; 32],
    receivers: &[[u8; 43]],
    quoted: u64,
) -> Result<[u8; 32], SemanticCommitmentError> {
    if *network != SOURCE_TESTNET || *pool != IRONWOOD_POOL {
        return Err(SemanticCommitmentError::InvalidDomain);
    }
    if blind.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::ZeroBlind);
    }
    if quoted == 0 || quoted > MAX_SOURCE_AMOUNT {
        return Err(SemanticCommitmentError::InvalidAmount);
    }
    if payment_effect.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::InvalidPaymentEffect);
    }
    if receivers.is_empty()
        || receivers.len() > MAX_QUOTED_RECEIVERS
        || receivers.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SemanticCommitmentError::InvalidReceiverSet);
    }
    let mut hash = Sha256::new();
    hash.update(b"ziquid.semantic.payment.v1");
    hash.update(blind);
    hash.update(network);
    hash.update(pool);
    hash.update(payment_effect);
    hash.update((receivers.len() as u16).to_be_bytes());
    for receiver in receivers {
        hash.update(receiver);
    }
    hash.update(quoted.to_be_bytes());
    Ok(hash.finalize().into())
}

/// Borrowed solver-private export. It contains neither U's note/FVK/path,
/// preparation/input/payment blinds nor the separate owner-consent signature.
/// Keep the capsule blind confidential to U and S; Debug never reveals bytes.
pub struct SolverCapsule<'a> {
    pub context: &'a ValidatedContext,
    pub private_packet_binding: &'a [u8; 32],
    pub capsule_blind: &'a [u8; 32],
    pub redacted_payment: &'a [u8],
    pub recovery_transaction: &'a [u8],
}

impl fmt::Debug for SolverCapsule<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SolverCapsule([REDACTED])")
    }
}

/// SHA-256 of `b"ziquid.preparation.solver-capsule.v1" || context.digest32 ||
/// private-packet-binding32 || capsule-blind32 || P-length-u32-LE || exact-P ||
/// Q-length-u32-LE || exact-Q`. Streams borrowed bytes without copying/allocating.
/// Requires a nonzero binding/blind, P in `1..=16 MiB` and Q in `1..=2 MiB`.
/// Hiding needs fresh confidential high-entropy randomness independent of U's
/// other blinds; shape checks cannot certify entropy, source validity, owner
/// consent, a wrapped preparation proof or any financial/funding capability.
pub fn solver_capsule_commitment(
    input: SolverCapsule<'_>,
) -> Result<[u8; 32], SemanticCommitmentError> {
    if input.private_packet_binding.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::InvalidPacketBinding);
    }
    if input.capsule_blind.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::ZeroBlind);
    }
    if input.redacted_payment.is_empty()
        || input.redacted_payment.len() > 16 * 1024 * 1024
        || input.recovery_transaction.is_empty()
        || input.recovery_transaction.len() > 2 * 1024 * 1024
    {
        return Err(SemanticCommitmentError::InvalidPacket);
    }
    let mut hash = Sha256::new();
    hash.update(b"ziquid.preparation.solver-capsule.v1");
    hash.update(input.context.digest());
    hash.update(input.private_packet_binding);
    hash.update(input.capsule_blind);
    for blob in [input.redacted_payment, input.recovery_transaction] {
        hash.update((blob.len() as u32).to_le_bytes());
        hash.update(blob);
    }
    Ok(hash.finalize().into())
}

/// SHA-256 of `b"ziquid.semantic.owner-consent.v2" || context.digest32 ||
/// private-packet-binding32 || solver-capsule-commitment32`. Both commitments
/// must be nonzero. Construct semantic openings/context, then the signature-
/// and capsule-blind-free packet.v2 binding, then capsule, then owner consent:
/// excluding the signature from both commitments avoids a construction cycle.
/// The context's shape validation and existing schema/encoding are unchanged.
///
/// This forms a message only: it neither signs nor proves owner approval,
/// authenticates the packet, or establishes a financially verified fact.
pub fn preparation_consent_digest(
    context: &ValidatedContext,
    packet_binding: &[u8; 32],
    capsule_commitment: &[u8; 32],
) -> Result<[u8; 32], SemanticCommitmentError> {
    if packet_binding.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::InvalidPacketBinding);
    }
    if capsule_commitment.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::InvalidCapsuleCommitment);
    }
    let mut hash = Sha256::new();
    hash.update(b"ziquid.semantic.owner-consent.v2");
    hash.update(context.digest());
    hash.update(packet_binding);
    hash.update(capsule_commitment);
    Ok(hash.finalize().into())
}

/// Borrowed private packet fields. Debug never reveals notes, keys, paths or bytes.
/// This frame excludes semantic-opening blinds, capsule randomness, receivers
/// and owner consent: context, private binding, capsule, then owner signature.
pub struct PreparationBinding<'a> {
    pub context: &'a ValidatedContext,
    pub preparation_blind: &'a [u8; 32],
    pub redacted_payment: &'a [u8],
    pub recovery_transaction: &'a [u8],
    pub note_recipient: &'a [u8; 43],
    pub note_value: u64,
    pub note_rho: &'a [u8; 32],
    pub note_rseed: &'a [u8; 32],
    pub full_viewing_key: &'a [u8; 96],
    pub merkle_position: u32,
    pub merkle_siblings: &'a [[u8; 32]; 32],
    pub anchor: &'a [u8; 32],
    pub source_target_height: u32,
}

impl fmt::Debug for PreparationBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparationBinding([REDACTED])")
    }
}

/// SHA-256 over the v2 packet domain, context digest, preparation blind,
/// u32-LE length-framed exact P/Q bytes, then the fixed u32-LE input-frame
/// length and recipient/value-LE/rho/rseed/FVK/position-LE/path/anchor/height-LE.
/// Streaming shape checks only; no source validity, ownership, consent or money fact.
/// P is bounded by 16 MiB, Q by 2 MiB, and height/expiry by the finite testnet
/// NU6.3 interval. The blind must be fresh, confidential and high entropy.
pub fn preparation_packet_binding(
    input: PreparationBinding<'_>,
) -> Result<[u8; 32], SemanticCommitmentError> {
    if input.preparation_blind.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::ZeroBlind);
    }
    if input.redacted_payment.is_empty()
        || input.redacted_payment.len() > 16 * 1024 * 1024
        || input.recovery_transaction.is_empty()
        || input.recovery_transaction.len() > 2 * 1024 * 1024
    {
        return Err(SemanticCommitmentError::InvalidPacket);
    }
    if input.note_value == 0 || input.note_value > MAX_SOURCE_AMOUNT {
        return Err(SemanticCommitmentError::InvalidAmount);
    }
    let expiry = input.context.context().source_expiry;
    if !(4_134_000..4_465_026).contains(&input.source_target_height)
        || expiry < input.source_target_height
        || expiry >= 4_465_026
    {
        return Err(SemanticCommitmentError::InvalidSource);
    }
    let mut hash = Sha256::new();
    hash.update(b"ziquid.preparation.packet.v2");
    hash.update(input.context.digest());
    hash.update(input.preparation_blind);
    for blob in [input.redacted_payment, input.recovery_transaction] {
        hash.update((blob.len() as u32).to_le_bytes());
        hash.update(blob);
    }
    const INPUT_FRAME_LEN: u32 = 43 + 8 + 32 + 32 + 96 + 4 + 32 * 32 + 32 + 4;
    hash.update(INPUT_FRAME_LEN.to_le_bytes());
    hash.update(input.note_recipient);
    hash.update(input.note_value.to_le_bytes());
    hash.update(input.note_rho);
    hash.update(input.note_rseed);
    hash.update(input.full_viewing_key);
    hash.update(input.merkle_position.to_le_bytes());
    for sibling in input.merkle_siblings {
        hash.update(sibling);
    }
    hash.update(input.anchor);
    hash.update(input.source_target_height.to_le_bytes());
    Ok(hash.finalize().into())
}

/// Keyed BLAKE2b configured for 32 output bytes, key = authentic FVK nk, over
/// `b"ziquid.semantic.consumption.v1" || network7 || pool8 || chain-u64-BE ||
/// escrow20 || authentic-note-NF32`. No order, salt, version, branch, codehash
/// or authorizing bytes enter the stream: same-note equality is intentional
/// within a deployment. Canonical FVK/note linkage belongs to the caller.
///
/// Privacy assumes a confidential high-entropy nk from honest wallet generation,
/// keyed-BLAKE2b PRF security and Orchard note/CommitIvk binding. FVK holders can
/// correlate; canonical key decoding (or rejecting zero) does not prove entropy.
/// This helper deliberately does not act as an entropy or ownership oracle.
pub fn note_consumption_tag(
    network: &[u8; 7],
    pool: &[u8; 8],
    evm_chain_id: u64,
    escrow: &[u8; 20],
    nk: &[u8; 32],
    nf: &[u8; 32],
) -> Result<[u8; 32], SemanticCommitmentError> {
    if *network != SOURCE_TESTNET || *pool != IRONWOOD_POOL {
        return Err(SemanticCommitmentError::InvalidDomain);
    }
    if evm_chain_id == 0 || escrow.iter().all(|&byte| byte == 0) {
        return Err(SemanticCommitmentError::InvalidDeployment);
    }
    let mut hash = blake2b_simd::Params::new().hash_length(32).key(nk).to_state();
    hash.update(b"ziquid.semantic.consumption.v1");
    hash.update(network);
    hash.update(pool);
    hash.update(&evm_chain_id.to_be_bytes());
    hash.update(escrow);
    hash.update(nf);
    Ok(hash.finalize().as_bytes().try_into().expect("configured 32-byte tag"))
}

/// Caller-supplied public bindings. Shape validation cannot establish approved
/// policy/program identities, source consensus validity, payment, or entitlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementContext {
    pub schema_version: u16,
    pub source_network: [u8; 7],
    pub source_pool: [u8; 8],
    pub transaction_version: u32,
    pub consensus_branch: u32,
    pub source_policy_id: [u8; 32],
    pub preparation_program: [u8; 32],
    pub settlement_program: [u8; 32],
    pub order_id: [u8; 32],
    pub consumption_tag: [u8; 32],
    pub source_payment_commitment: [u8; 32],
    pub real_input_commitment: [u8; 32],
    pub source_quoted_amount: u64,
    pub source_fee_cap: u64,
    pub source_expiry: u32,
    pub evm_chain_id: u64,
    pub escrow: [u8; 20],
    pub escrow_code_hash: [u8; 32],
    pub verifier: [u8; 20],
    pub verifier_code_hash: [u8; 32],
    pub u_payee: [u8; 20],
    pub s_refund: [u8; 20],
    pub native_amount: NativeAmount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextField {
    ConsensusBranch,
    SourcePolicyId,
    PreparationProgram,
    SettlementProgram,
    OrderId,
    ConsumptionTag,
    SourcePaymentCommitment,
    RealInputCommitment,
    SourceQuotedAmount,
    SourceFeeCap,
    SourceExpiry,
    EvmChainId,
    Escrow,
    EscrowCodeHash,
    Verifier,
    VerifierCodeHash,
    UPayee,
    SRefund,
    NativeAmount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextError {
    InvalidLength { expected: usize, actual: usize },
    WrongDomain,
    UnsupportedSchema(u16),
    UnsupportedNetwork,
    UnsupportedPool,
    UnsupportedTransactionVersion(u32),
    ZeroField(ContextField),
    OutOfRange(ContextField),
    SameBeneficiary,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "context requires {expected} bytes, received {actual}")
            }
            Self::WrongDomain => f.write_str("unsupported DEX context domain"),
            Self::UnsupportedSchema(version) => write!(f, "unsupported context schema {version}"),
            Self::UnsupportedNetwork => f.write_str("source network must be testnet"),
            Self::UnsupportedPool => f.write_str("source pool must be Ironwood"),
            Self::UnsupportedTransactionVersion(version) => {
                write!(f, "unsupported source transaction version {version}")
            }
            Self::ZeroField(field) => write!(f, "context field {field:?} must be nonzero"),
            Self::OutOfRange(field) => write!(f, "context field {field:?} is out of range"),
            Self::SameBeneficiary => f.write_str("payout and refund beneficiaries must differ"),
        }
    }
}

impl Error for ContextError {}

/// Owned immutable context with validated shape only. Construction remains
/// private; this type intentionally carries no financially verified fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedContext(StatementContext);

impl StatementContext {
    /// Check field shape/ranges only. In particular, any nonzero branch/policy/
    /// program/code identity passes; actual source/target verification must pin
    /// trusted values and authenticate all private source relations separately.
    pub fn validate(&self) -> Result<ValidatedContext, ContextError> {
        if self.schema_version != CONTEXT_SCHEMA_VERSION {
            return Err(ContextError::UnsupportedSchema(self.schema_version));
        }
        if self.source_network != SOURCE_TESTNET {
            return Err(ContextError::UnsupportedNetwork);
        }
        if self.source_pool != IRONWOOD_POOL {
            return Err(ContextError::UnsupportedPool);
        }
        if self.transaction_version != SOURCE_TRANSACTION_VERSION {
            return Err(ContextError::UnsupportedTransactionVersion(
                self.transaction_version,
            ));
        }
        if self.consensus_branch == 0 {
            return Err(ContextError::ZeroField(ContextField::ConsensusBranch));
        }
        for (value, field) in [
            (&self.source_policy_id, ContextField::SourcePolicyId),
            (&self.preparation_program, ContextField::PreparationProgram),
            (&self.settlement_program, ContextField::SettlementProgram),
            (&self.order_id, ContextField::OrderId),
            (&self.consumption_tag, ContextField::ConsumptionTag),
            (
                &self.source_payment_commitment,
                ContextField::SourcePaymentCommitment,
            ),
            (
                &self.real_input_commitment,
                ContextField::RealInputCommitment,
            ),
        ] {
            require_nonzero(value, field)?;
        }
        if self.source_quoted_amount == 0 {
            return Err(ContextError::ZeroField(ContextField::SourceQuotedAmount));
        }
        if self.source_quoted_amount > MAX_SOURCE_AMOUNT {
            return Err(ContextError::OutOfRange(ContextField::SourceQuotedAmount));
        }
        if self.source_fee_cap > MAX_SOURCE_AMOUNT {
            return Err(ContextError::OutOfRange(ContextField::SourceFeeCap));
        }
        // Consensus height-based finite expiry; zero has indefinite semantics.
        if self.source_expiry == 0 || self.source_expiry >= 500_000_000 {
            return Err(ContextError::OutOfRange(ContextField::SourceExpiry));
        }
        if self.evm_chain_id == 0 {
            return Err(ContextError::ZeroField(ContextField::EvmChainId));
        }
        require_nonzero(&self.escrow, ContextField::Escrow)?;
        require_nonzero(&self.escrow_code_hash, ContextField::EscrowCodeHash)?;
        require_nonzero(&self.verifier, ContextField::Verifier)?;
        require_nonzero(&self.verifier_code_hash, ContextField::VerifierCodeHash)?;
        require_nonzero(&self.u_payee, ContextField::UPayee)?;
        require_nonzero(&self.s_refund, ContextField::SRefund)?;
        if self.u_payee == self.s_refund {
            return Err(ContextError::SameBeneficiary);
        }
        if self.native_amount.get().is_zero() {
            return Err(ContextError::ZeroField(ContextField::NativeAmount));
        }
        Ok(ValidatedContext(*self))
    }
}

fn require_nonzero(value: &[u8], field: ContextField) -> Result<(), ContextError> {
    if value.iter().all(|&byte| byte == 0) {
        Err(ContextError::ZeroField(field))
    } else {
        Ok(())
    }
}

impl ValidatedContext {
    pub const fn context(&self) -> &StatementContext {
        &self.0
    }

    /// Exact canonical wire layout: domain; u16 schema; 7-byte testnet; 8-byte
    /// Ironwood; u32 transaction version/branch; seven 32-byte identities; u64
    /// source quote/fee cap; u32 expiry; u64 EVM chain; 20-byte escrow/32-byte
    /// code hash; 20-byte verifier/32-byte code hash; 20-byte U/S beneficiaries;
    /// 32-byte native wei. Numbers are unsigned big-endian, without padding,
    /// length prefixes, optional fields, or trailing bytes.
    pub fn canonical_bytes(&self) -> [u8; CONTEXT_ENCODED_LEN] {
        let context = &self.0;
        let mut bytes = [0; CONTEXT_ENCODED_LEN];
        let mut offset = 0;
        append(&mut bytes, &mut offset, DEX_CONTEXT_DOMAIN);
        append(
            &mut bytes,
            &mut offset,
            &context.schema_version.to_be_bytes(),
        );
        append(&mut bytes, &mut offset, &context.source_network);
        append(&mut bytes, &mut offset, &context.source_pool);
        append(
            &mut bytes,
            &mut offset,
            &context.transaction_version.to_be_bytes(),
        );
        append(
            &mut bytes,
            &mut offset,
            &context.consensus_branch.to_be_bytes(),
        );
        append(&mut bytes, &mut offset, &context.source_policy_id);
        append(&mut bytes, &mut offset, &context.preparation_program);
        append(&mut bytes, &mut offset, &context.settlement_program);
        append(&mut bytes, &mut offset, &context.order_id);
        append(&mut bytes, &mut offset, &context.consumption_tag);
        append(&mut bytes, &mut offset, &context.source_payment_commitment);
        append(&mut bytes, &mut offset, &context.real_input_commitment);
        append(
            &mut bytes,
            &mut offset,
            &context.source_quoted_amount.to_be_bytes(),
        );
        append(
            &mut bytes,
            &mut offset,
            &context.source_fee_cap.to_be_bytes(),
        );
        append(
            &mut bytes,
            &mut offset,
            &context.source_expiry.to_be_bytes(),
        );
        append(&mut bytes, &mut offset, &context.evm_chain_id.to_be_bytes());
        append(&mut bytes, &mut offset, &context.escrow);
        append(&mut bytes, &mut offset, &context.escrow_code_hash);
        append(&mut bytes, &mut offset, &context.verifier);
        append(&mut bytes, &mut offset, &context.verifier_code_hash);
        append(&mut bytes, &mut offset, &context.u_payee);
        append(&mut bytes, &mut offset, &context.s_refund);
        append(
            &mut bytes,
            &mut offset,
            &context.native_amount.to_be_bytes(),
        );
        bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        self.canonical_bytes().to_vec()
    }

    /// SHA-256 of exact canonical bytes, never of an observation or proof.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Reject any malformed width/domain/field shape rather than normalizing
    /// caller bytes. No policy/source/proof trust is promoted by decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContextError> {
        if bytes.len() != CONTEXT_ENCODED_LEN {
            return Err(ContextError::InvalidLength {
                expected: CONTEXT_ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        if !bytes.starts_with(DEX_CONTEXT_DOMAIN) {
            return Err(ContextError::WrongDomain);
        }
        let mut fields = &bytes[DEX_CONTEXT_DOMAIN.len()..];
        let context = StatementContext {
            schema_version: u16::from_be_bytes(take(&mut fields)),
            source_network: take(&mut fields),
            source_pool: take(&mut fields),
            transaction_version: u32::from_be_bytes(take(&mut fields)),
            consensus_branch: u32::from_be_bytes(take(&mut fields)),
            source_policy_id: take(&mut fields),
            preparation_program: take(&mut fields),
            settlement_program: take(&mut fields),
            order_id: take(&mut fields),
            consumption_tag: take(&mut fields),
            source_payment_commitment: take(&mut fields),
            real_input_commitment: take(&mut fields),
            source_quoted_amount: u64::from_be_bytes(take(&mut fields)),
            source_fee_cap: u64::from_be_bytes(take(&mut fields)),
            source_expiry: u32::from_be_bytes(take(&mut fields)),
            evm_chain_id: u64::from_be_bytes(take(&mut fields)),
            escrow: take(&mut fields),
            escrow_code_hash: take(&mut fields),
            verifier: take(&mut fields),
            verifier_code_hash: take(&mut fields),
            u_payee: take(&mut fields),
            s_refund: take(&mut fields),
            native_amount: NativeAmount::from_be_bytes(take(&mut fields)),
        };
        context.validate()
    }
}

fn append(bytes: &mut [u8], offset: &mut usize, value: &[u8]) {
    bytes[*offset..*offset + value.len()].copy_from_slice(value);
    *offset += value.len();
}

// The exact total width is checked before consuming any caller bytes.
fn take<const N: usize>(fields: &mut &[u8]) -> [u8; N] {
    let (value, rest) = fields.split_at(N);
    let mut result = [0; N];
    result.copy_from_slice(value);
    *fields = rest;
    result
}
