//! Deterministic private F/J/C/R semantics shared by wallets and zkVM consumers.
//!
//! Actual openings and complete effects are checked, not caller assertions.
//! This establishes no source history, quote authenticity, finality, release
//! right or asset transfer. Checked accounting is not a financial certificate.

use std::fmt;
use orchard::{
    Address, Anchor, Note, bundle::BundleVersion, keys::FullViewingKey,
    note::{ExtractedNoteCommitment, NoteVersion, Rho},
    tree::MerklePath,
};
use pczt::{Pczt, roles::{creator::Creator, verifier::{OrchardError, Verifier}}};
use zcash_primitives::transaction::{
    Authorization, Transaction, TransactionData, TxVersion,
    components::orchard::{ACTION_SIZE, SPEND_AUTH_SIG_SIZE},
    fees::{FeeRule as _, zip317}, sighash::SignableInput,
    sighash_v6::v6_signature_hash, txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    constants::{MAX_BLOCK_BYTES, V6_TX_VERSION, V6_VERSION_GROUP_ID}, value::Zatoshis,
};
use zeroize::Zeroizing;
pub use self::projection::GlobalMarkers;

#[path = "native_relation/projection.rs"]
mod projection;
use crate::{canonical_bytes, native_effects as effects};
#[cfg(feature = "native-relation-smoke")]
#[path = "native_relation/smoke.rs"]
pub mod smoke;
#[cfg(not(target_os = "zkvm"))]
#[path = "native_relation/source.rs"]
pub mod source;
pub const MAX_PCZT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACTIONS: usize = MAX_BLOCK_BYTES / (ACTION_SIZE + SPEND_AUTH_SIG_SIZE);

/// Redacted failure categories: no private bytes or upstream diagnostic strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRelationError {
    InvalidPczt, UnsupportedProfile, UnsupportedPool, GlobalMetadata,
    MissingMetadata, NativeVerification, InputMismatch, OutputMismatch,
    ChangeOwnership, CiphertextMismatch, ValueBalanceMismatch, FeeMismatch,
    AmountOutOfRange, EffectExtraction, SighashEncoding, DummySpendKey,
    InvalidHeight, WrongBranch, TestnetRequired, WrongNoteVersion,
    InvalidInputValue, InputNotOwned, AnchorMismatch, GroupMismatch,
    InvalidPayout, UnbalancedTerms, InvalidOutputIndex, EffectsChanged,
    InvalidSignature, InvalidMembership, MalformedTransaction,
    NonCanonicalEncoding, WrongVersion, MissingIronwood, WrongBundleVersion,
    InvalidAuthorization,
}
impl fmt::Display for NativeRelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native relation rejected: {self:?}")
    }
}
impl std::error::Error for NativeRelationError {}
type Error = NativeRelationError;

/// Borrowed native facts; market/source-domain testimony stays in host adapters.
#[derive(Clone, Copy)]
pub struct NativeInputFacts<'a> {
    pub nullifier: &'a [u8; 32],
    pub note_commitment: &'a [u8; 32],
    pub value: u64,
    pub trusted_fvk: &'a FullViewingKey,
}
#[derive(Clone, Copy)]
pub struct NativeOutputFacts<'a> {
    pub recipient: Address,
    pub value: u64,
    /// Some is required for route F/C/R terms. Inventory inspection has no memo policy.
    pub memo: Option<&'a [u8; 512]>,
}
pub struct CheckedOutput {
    pub recipient: Address,
    pub value: u64,
    pub action_index: u32,
    pub note_commitment: [u8; 32],
    pub nullifier: Option<[u8; 32]>,
}
#[derive(Clone, Copy)]
pub struct SourceFacts<'a> {
    pub network: Network,
    pub target_height: BlockHeight,
    pub expiry_height: BlockHeight,
    pub consensus_branch: BranchId,
    pub fee_rule: &'a zip317::FeeRule,
}
#[derive(Clone, Copy)]
pub struct OwnedInputFacts<'a> {
    pub note: &'a Note,
    pub full_viewing_key: &'a FullViewingKey,
    pub merkle_path: &'a MerklePath,
    pub anchor: Anchor,
}
#[derive(Clone, Copy)]
pub struct JointSpendFacts<'a> {
    pub source: SourceFacts<'a>,
    pub note: &'a Note,
    pub full_viewing_key: &'a FullViewingKey,
    pub group_ak: [u8; 32],
    pub payout: NativeOutputFacts<'a>,
    pub fee: u64,
}
#[derive(Clone, Copy)]
pub struct FundingFacts<'a> {
    pub source: SourceFacts<'a>,
    pub input: OwnedInputFacts<'a>,
    pub private_pczt: &'a [u8],
    pub requested_output_actions: &'a [usize],
    pub joint_requested_index: usize,
    pub joint_full_viewing_key: &'a FullViewingKey,
    pub group_ak: [u8; 32],
    pub fee: u64,
}

/// Upstream Note equality compares commitments, not exact private openings.
pub fn same_note(a: &Note, b: &Note) -> bool {
    a.version() == b.version()
        && a.recipient().to_raw_address_bytes() == b.recipient().to_raw_address_bytes()
        && a.value().inner() == b.value().inner()
        && a.rho().to_bytes() == b.rho().to_bytes()
        && a.rseed().as_bytes() == b.rseed().as_bytes()
}
pub fn validate_source(source: &SourceFacts<'_>) -> Result<(), Error> {
    if u32::from(source.target_height) == 0 || u32::from(source.expiry_height) == 0
        || source.expiry_height < source.target_height || u32::from(source.expiry_height) >= 500_000_000
    { return Err(Error::InvalidHeight); }
    // Same installed-cohort NU7 fence as the native authoring path.
    if source.consensus_branch != BranchId::Nu6_3
        || BranchId::for_height(&source.network, source.target_height) != source.consensus_branch
        || BranchId::for_height(&source.network, source.expiry_height) != source.consensus_branch
        || (source.network == Network::TestNetwork && u32::from(source.expiry_height) >= 4_465_026)
    { return Err(Error::WrongBranch); }
    Ok(())
}
pub fn validate_owned_input(input: &OwnedInputFacts<'_>) -> Result<(), Error> {
    if input.note.version() != NoteVersion::V3 { return Err(Error::WrongNoteVersion); }
    if input.note.value().inner() == 0 || Zatoshis::from_u64(input.note.value().inner()).is_err() {
        return Err(Error::InvalidInputValue);
    }
    if input.full_viewing_key.scope_for_address(&input.note.recipient()).is_none() {
        return Err(Error::InputNotOwned);
    }
    if input.merkle_path.root(input.note.commitment().into()) != input.anchor {
        return Err(Error::AnchorMismatch);
    }
    Ok(())
}
pub fn validate_group(note: &Note, fvk: &FullViewingKey, group_ak: &[u8; 32]) -> Result<(), Error> {
    if note.version() != NoteVersion::V3 { return Err(Error::WrongNoteVersion); }
    if note.value().inner() == 0 || Zatoshis::from_u64(note.value().inner()).is_err() {
        return Err(Error::InvalidInputValue);
    }
    if fvk.scope_for_address(&note.recipient()).is_none() { return Err(Error::InputNotOwned); }
    if Zeroizing::new(fvk.to_bytes())[..32] != *group_ak { return Err(Error::GroupMismatch); }
    Ok(())
}
fn bounded_sum(sum: u64, value: u64) -> Result<u64, Error> {
    let sum = sum.checked_add(value).ok_or(Error::AmountOutOfRange)?;
    Zatoshis::from_u64(sum).map_err(|_| Error::AmountOutOfRange)?;
    Ok(sum)
}
fn spend_note(action: &orchard::pczt::Action) -> Result<Note, Error> {
    let spend = action.spend();
    if *spend.note_version() != NoteVersion::V3 { return Err(Error::UnsupportedProfile); }
    Note::from_parts(
        spend.recipient().ok_or(Error::MissingMetadata)?,
        spend.value().ok_or(Error::MissingMetadata)?, spend.rho().ok_or(Error::MissingMetadata)?,
        spend.rseed().ok_or(Error::MissingMetadata)?, *spend.note_version(),
    ).into_option().ok_or(Error::NativeVerification)
}
pub fn recover_output(action: &orchard::pczt::Action) -> Result<(Note, Zeroizing<[u8; 512]>), Error> {
    // With OVK=None upstream deliberately randomizes outgoing ciphertext and
    // retains no OCK. Recipient ciphertext/memo are authenticated below; the
    // complete outgoing bytes are bound separately as transaction effects.
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::{Domain as _, try_output_recovery_with_pkd_esk};
    let output = action.output();
    let rho = Rho::from_bytes(&action.spend().nullifier().to_bytes()).into_option()
        .ok_or(Error::NativeVerification)?;
    let note = Note::from_parts(
        output.recipient().ok_or(Error::MissingMetadata)?, output.value().ok_or(Error::MissingMetadata)?,
        rho, output.rseed().ok_or(Error::MissingMetadata)?, *output.note_version(),
    ).into_option().ok_or(Error::NativeVerification)?;
    let (recovered, receiver, memo) = try_output_recovery_with_pkd_esk(
        &IronwoodDomain::for_pczt_action(action), IronwoodDomain::get_pk_d(&note),
        IronwoodDomain::derive_esk(&note).ok_or(Error::MissingMetadata)?, action,
    ).ok_or(Error::CiphertextMismatch)?;
    let memo = Zeroizing::new(memo);
    if !same_note(&recovered, &note) || receiver != note.recipient() { return Err(Error::CiphertextMismatch); }
    Ok((note, memo))
}
pub fn recover_action_output<A>(
    action: &orchard::Action<A>, note: &Note, expected_memo: Option<&[u8; 512]>,
) -> Result<Zeroizing<[u8; 512]>, Error> {
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::{Domain as _, try_output_recovery_with_pkd_esk};
    if note.version() != NoteVersion::V3 || note.rho() != action.rho()
        || ExtractedNoteCommitment::from(note.commitment()) != *action.cmx()
    { return Err(Error::OutputMismatch); }
    let (recovered, receiver, memo) = try_output_recovery_with_pkd_esk(
        &IronwoodDomain::for_action(action), IronwoodDomain::get_pk_d(note),
        IronwoodDomain::derive_esk(note).ok_or(Error::MissingMetadata)?, action,
    ).ok_or(Error::CiphertextMismatch)?;
    let memo = Zeroizing::new(memo);
    if !same_note(&recovered, note) || receiver != note.recipient()
        || expected_memo.is_some_and(|expected| expected != &*memo)
    { return Err(Error::CiphertextMismatch); }
    Ok(memo)
}

/// Finalized native inventory predicate. Unsigned F legitimately retains dummy
/// keys and uses restore_funding instead; do not relax this received-C/R boundary.
pub fn verify_source_bundle<'a>(
    bundle: &orchard::pczt::Bundle,
    inputs: impl Clone + ExactSizeIterator<Item = NativeInputFacts<'a>>,
    requested_outputs: impl Clone + ExactSizeIterator<Item = NativeOutputFacts<'a>>,
    fee: u64, outputs: &mut Vec<CheckedOutput>,
) -> Result<(), Error> {
    if *bundle.bundle_version() != BundleVersion::ironwood_v3() { return Err(Error::UnsupportedProfile); }
    bundle.verify_cross_address_restriction().map_err(|_| Error::NativeVerification)?;
    let mut input_total = 0;
    let mut output_total = 0;
    let mut input_count = 0;
    let mut matched_outputs = vec![false; requested_outputs.len()];
    for (index, action) in bundle.actions().iter().enumerate() {
        action.verify_cv_net().map_err(|_| Error::NativeVerification)?;
        let spend = action.spend();
        if spend.dummy_sk().is_some() { return Err(Error::DummySpendKey); }
        if *spend.note_version() != NoteVersion::V3 || *action.output().note_version() != NoteVersion::V3 {
            return Err(Error::UnsupportedProfile);
        }
        let value = spend.value().ok_or(Error::MissingMetadata)?.inner();
        if value != 0 && !bundle.flags().spends_enabled() { return Err(Error::NativeVerification); }
        let nf = spend.nullifier().to_bytes();
        if bundle.actions()[..index].iter().any(|prior| prior.spend().nullifier() == spend.nullifier()) {
            return Err(Error::InputMismatch);
        }
        let reserved = if value == 0 { None } else {
            Some(inputs.clone().find(|input| input.nullifier == &nf).ok_or(Error::InputMismatch)?)
        };
        spend.verify_nullifier(reserved.map(|input| input.trusted_fvk)).map_err(|_| Error::NativeVerification)?;
        spend.verify_rk(reserved.map(|input| input.trusted_fvk)).map_err(|_| Error::NativeVerification)?;
        let note = spend_note(action)?;
        if let Some(input) = reserved {
            if input.value != note.value().inner() || *input.note_commitment != ExtractedNoteCommitment::from(note.commitment()).to_bytes() {
                return Err(Error::InputMismatch);
            }
            input_count += 1;
        }
        input_total = bounded_sum(input_total, value)?;
        action.output().verify_note_commitment(spend).map_err(|_| Error::NativeVerification)?;
        let (note, memo) = recover_output(action)?; // All ciphertexts, including zero padding.
        let recipient = note.recipient();
        let value = note.value().inner();
        if value != 0 && !bundle.flags().outputs_enabled() { return Err(Error::NativeVerification); }
        if value != 0 {
            let expected_count = requested_outputs.clone().filter(|expected| expected.recipient == recipient && expected.value == value).count();
            let actual_count = outputs.iter().filter(|prior| prior.recipient == recipient && prior.value == value).count();
            if actual_count >= expected_count { return Err(Error::OutputMismatch); }
            let matching = |exact_memo: bool| requested_outputs.clone().enumerate().find(|(index, expected)| {
                !matched_outputs[*index] && expected.recipient == recipient && expected.value == value
                    && if exact_memo { expected.memo == Some(&*memo) } else { expected.memo.is_none() }
            }).map(|(index, _)| index);
            let matched = matching(true).or_else(|| matching(false)).ok_or(Error::CiphertextMismatch)?;
            matched_outputs[matched] = true;
            let mut nullifier = None;
            for (i, input) in inputs.clone().enumerate() {
                if inputs.clone().take(i).any(|prior| prior.trusted_fvk == input.trusted_fvk) { continue; }
                if input.trusted_fvk.scope_for_address(&recipient).is_some() {
                    let candidate = note.nullifier(input.trusted_fvk).to_bytes();
                    if nullifier.is_some_and(|prior| prior != candidate) { return Err(Error::ChangeOwnership); }
                    nullifier = Some(candidate);
                }
            }
            outputs.push(CheckedOutput { recipient, value,
                action_index: index.try_into().map_err(|_| Error::AmountOutOfRange)?,
                note_commitment: action.output().cmx().to_bytes(), nullifier });
        }
        output_total = bounded_sum(output_total, value)?;
    }
    if input_count != inputs.len() || outputs.len() != requested_outputs.len() { return Err(Error::InputMismatch); }
    check_balance(bundle, input_total, output_total, fee)
}
fn check_balance(bundle: &orchard::pczt::Bundle, input: u64, output: u64, fee: u64) -> Result<(), Error> {
    let balance = input.checked_sub(output).ok_or(Error::ValueBalanceMismatch)?;
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    if matches!(sign, orchard::value::Sign::Negative) || balance != magnitude { return Err(Error::ValueBalanceMismatch); }
    if balance != fee { return Err(Error::FeeMismatch); }
    Ok(())
}

pub fn parse_canonical_pczt(bytes: &[u8]) -> Result<Pczt, Error> {
    if bytes.is_empty() || bytes.len() > MAX_PCZT_BYTES { return Err(Error::InvalidPczt); }
    let pczt = Pczt::parse(bytes).map_err(|_| Error::InvalidPczt)?;
    let canonical = Zeroizing::new(pczt.clone().serialize().map_err(|_| Error::InvalidPczt)?);
    if canonical.as_slice() != bytes { return Err(Error::InvalidPczt); }
    Ok(pczt)
}
fn role_error(error: OrchardError<Error>) -> Error {
    match error { OrchardError::Custom(error) => error, _ => Error::InvalidPczt }
}
pub fn effect_id<A: Authorization>(effects: &TransactionData<A>) -> [u8; 32] {
    to_txid(effects.version(), effects.consensus_branch_id(), &effects.digest(TxIdDigester)).into()
}
pub fn pczt_effect_identity(pczt: &Pczt) -> Result<([u8; 32], [u8; 32]), Error> {
    let effects = pczt.clone().into_effects().map_err(|_| Error::EffectExtraction)?;
    if effects.version() != TxVersion::V6 || effects.lock_time() != 0 { return Err(Error::InvalidPczt); }
    let digests = effects.digest(TxIdDigester);
    let id = to_txid(effects.version(), effects.consensus_branch_id(), &digests).into();
    let hash = v6_signature_hash(&effects, &SignableInput::Shielded, &digests);
    Ok((id, hash.as_ref().try_into().map_err(|_| Error::SighashEncoding)?))
}

/// Owner-local full output opening; neither Debug nor a public serialized form.
pub struct SenderOpening {
    pub action_index: usize,
    pub note: Note,
    pub memo: Zeroizing<[u8; 512]>,
}
pub struct RestoredFunding {
    pub effect_id: [u8; 32],
    pub outputs: Vec<SenderOpening>,
    pub input_total: u64,
    pub output_total: u64,
    pub fee: u64,
    pub lock_time: u32,
}

/// Reopen every unsigned-F action, including authentic zero dummies. No trusted
/// constructor or expected sighash is accepted as substitute private metadata.
pub fn restore_funding(
    bytes: &[u8], input: &OwnedInputFacts<'_>, requested_output_actions: &[usize],
) -> Result<RestoredFunding, Error> {
    restore_funding_pczt(parse_canonical_pczt(bytes)?, input, requested_output_actions).map(|(_, restored)| restored)
}

fn restore_funding_pczt(
    pczt: Pczt, input: &OwnedInputFacts<'_>, requested_output_actions: &[usize],
) -> Result<(Pczt, RestoredFunding), Error> {
    validate_owned_input(input)?;
    let empty = Creator::new(BranchId::Nu6_2.into(), 0, 133, None, None)
        .map_err(|_| Error::InvalidPczt)?.build().map_err(|_| Error::InvalidPczt)?;
    if pczt.transparent() != empty.transparent() || pczt.sapling() != empty.sapling()
        || pczt.orchard() != empty.orchard()
        || *pczt.global().tx_version() != V6_TX_VERSION
        || *pczt.global().version_group_id() != V6_VERSION_GROUP_ID
        || *pczt.global().consensus_branch_id() != u32::from(BranchId::Nu6_3)
        || pczt.ironwood().anchor().as_ref() != Some(&input.anchor.to_bytes())
        || pczt.ironwood().actions().is_empty() || pczt.ironwood().actions().len() > MAX_ACTIONS
    { return Err(Error::InvalidPczt); }
    let count = pczt.ironwood().actions().len();
    if requested_output_actions.is_empty() || requested_output_actions.len() > count {
        return Err(Error::InvalidOutputIndex);
    }
    let mut requested = vec![false; count];
    for &index in requested_output_actions {
        let seen = requested.get_mut(index).ok_or(Error::InvalidOutputIndex)?;
        if *seen { return Err(Error::InvalidOutputIndex); }
        *seen = true;
    }
    let effects = pczt.clone().into_effects().map_err(|_| Error::InvalidPczt)?;
    let mut checked = None;
    let verified = Verifier::new(pczt).with_ironwood(|bundle| {
        let check = || -> Result<RestoredFunding, Error> {
            if *bundle.bundle_version() != BundleVersion::ironwood_v3()
                || bundle.flag_byte() & 3 != 3 || bundle.anchor() != &input.anchor
                || bundle.zkproof().is_some() || bundle.bsk().is_some()
            { return Err(Error::InvalidPczt); }
            bundle.verify_cross_address_restriction().map_err(|_| Error::InputMismatch)?;
            let actual_actions = effects.ironwood_bundle().ok_or(Error::InvalidPczt)?.actions();
            let mut positive_spends = 0;
            let mut input_total = 0;
            let mut output_total = 0;
            let mut outputs = Vec::with_capacity(count);
            let mut nullifiers = Zeroizing::new(Vec::with_capacity(count));
            for (index, action) in bundle.actions().iter().enumerate() {
                let spend = action.spend();
                if *spend.note_version() != NoteVersion::V3 || spend.fvk().is_none()
                    || spend.spend_auth_sig().is_some() || spend.rk().is_identity()
                { return Err(Error::InputMismatch); }
                action.verify_cv_net().map_err(|_| Error::InputMismatch)?;
                spend.verify_nullifier(Some(input.full_viewing_key)).map_err(|_| Error::InputMismatch)?;
                spend.verify_rk(Some(input.full_viewing_key)).map_err(|_| Error::InputMismatch)?;
                let spent = spend_note(action).map_err(|_| Error::InputMismatch)?;
                let value = spent.value().inner();
                input_total = bounded_sum(input_total, value)?;
                nullifiers.push(spend.nullifier().to_bytes());
                if value != 0 {
                    positive_spends += 1;
                    let path = spend.witness().as_ref().ok_or(Error::InputMismatch)?;
                    if positive_spends != 1 || !same_note(&spent, input.note)
                        || spend.nullifier() != &input.note.nullifier(input.full_viewing_key)
                        || path.position() != input.merkle_path.position()
                        || path.auth_path() != input.merkle_path.auth_path()
                        || path.root(input.note.commitment().into()) != input.anchor
                    { return Err(Error::InputMismatch); }
                }
                if *action.output().note_version() != NoteVersion::V3 { return Err(Error::CiphertextMismatch); }
                action.output().verify_note_commitment(spend).map_err(|_| Error::CiphertextMismatch)?;
                let (note, memo) = recover_output(action).map_err(|_| Error::CiphertextMismatch)?;
                output_total = bounded_sum(output_total, note.value().inner())?;
                if !requested[index] && note.value().inner() != 0 { return Err(Error::InvalidOutputIndex); }
                recover_action_output(actual_actions.get(index).ok_or(Error::InvalidPczt)?, &note, Some(&memo))?;
                outputs.push(SenderOpening { action_index: index, note, memo });
            }
            if positive_spends != 1 { return Err(Error::InputMismatch); }
            nullifiers.sort_unstable();
            if nullifiers.windows(2).any(|pair| pair[0] == pair[1]) { return Err(Error::InputMismatch); }
            let fee = input_total.checked_sub(output_total).ok_or(Error::ValueBalanceMismatch)?;
            check_balance(bundle, input_total, output_total, fee)?;
            Ok(RestoredFunding { effect_id: effect_id(&effects), outputs, input_total, output_total, fee,
                lock_time: effects.lock_time() })
        };
        checked = Some(check().map_err(OrchardError::Custom)?);
        Ok(())
    }).map_err(role_error)?.finish();
    Ok((verified, checked.ok_or(Error::InvalidPczt)?))
}

fn validate_action_fee(source: &SourceFacts<'_>, actions: usize, fee: u64) -> Result<(), Error> {
    let required = source.fee_rule.fee_required(&source.network, source.target_height,
        std::iter::empty(), std::iter::empty(), 0, 0, 0, actions).map_err(|_| Error::FeeMismatch)?;
    if u64::from(required) != fee { return Err(Error::FeeMismatch); }
    Ok(())
}
pub struct CheckedFunding {
    pub effect_id: [u8; 32],
    pub input_debit: u64,
    pub owned_change: u64,
    pub fee: u64,
    pub joint_action_index: usize,
    pub joint_note: Note,
    pub outputs: Vec<SenderOpening>,
}

/// Exact requested-output order/multiplicity/full memo, authentic U-owned change
/// and F-generated J. Effects AND the separately retained anchor bind actual F.
pub fn verify_funding<'a>(
    facts: &FundingFacts<'_>,
    requested_outputs: impl ExactSizeIterator<Item = NativeOutputFacts<'a>>,
    transaction: Option<&Transaction>,
) -> Result<CheckedFunding, Error> {
    validate_source(&facts.source)?;
    if facts.source.network != Network::TestNetwork { return Err(Error::TestnetRequired); }
    let (pczt, restored) = restore_funding_pczt(parse_canonical_pczt(facts.private_pczt)?,
        &facts.input, facts.requested_output_actions)?;
    if *pczt.global().expiry_height() != u32::from(facts.source.expiry_height)
        || *pczt.global().consensus_branch_id() != u32::from(facts.source.consensus_branch)
    { return Err(Error::GlobalMetadata); }
    if restored.lock_time != 0 { return Err(Error::GlobalMetadata); }
    validate_action_fee(&facts.source, restored.outputs.len(), facts.fee)?;
    if restored.fee != facts.fee { return Err(Error::FeeMismatch); }
    if requested_outputs.len() != facts.requested_output_actions.len() { return Err(Error::OutputMismatch); }
    for (index, expected) in facts.requested_output_actions.iter().zip(requested_outputs) {
        let output = restored.outputs.get(*index).ok_or(Error::InvalidOutputIndex)?;
        if output.note.recipient() != expected.recipient || output.note.value().inner() != expected.value {
            return Err(Error::OutputMismatch);
        }
        if expected.memo.ok_or(Error::MissingMetadata)? != &*output.memo { return Err(Error::CiphertextMismatch); }
    }
    let joint_action_index = *facts.requested_output_actions.get(facts.joint_requested_index)
        .ok_or(Error::InvalidOutputIndex)?;
    let joint_note = restored.outputs.get(joint_action_index).ok_or(Error::InvalidOutputIndex)?.note;
    validate_group(&joint_note, facts.joint_full_viewing_key, &facts.group_ak)?;
    let mut owned_change = 0;
    for output in &restored.outputs {
        if output.action_index != joint_action_index
            && facts.input.full_viewing_key.scope_for_address(&output.note.recipient()).is_some()
        { owned_change = bounded_sum(owned_change, output.note.value().inner())?; }
    }
    if let Some(transaction) = transaction {
        if transaction.lock_time() != 0 || transaction.expiry_height() != facts.source.expiry_height
            || effect_id(transaction) != restored.effect_id { return Err(Error::EffectsChanged); }
        let mut matched = false;
        Verifier::new(pczt).with_ironwood(|bundle| {
            compare_transaction_effects(bundle, transaction, facts.input.anchor).map_err(OrchardError::Custom)?;
            matched = true;
            Ok(())
        }).map_err(role_error)?;
        if !matched { return Err(Error::EffectsChanged); }
        verify_transaction_authorization(transaction)?;
    }
    Ok(CheckedFunding { effect_id: restored.effect_id, input_debit: restored.input_total,
        owned_change, fee: restored.fee, joint_action_index, joint_note, outputs: restored.outputs })
}

pub fn validate_joint_terms(terms: &JointSpendFacts<'_>) -> Result<(), Error> {
    validate_source(&terms.source)?;
    if terms.source.network != Network::TestNetwork { return Err(Error::TestnetRequired); }
    validate_group(terms.note, terms.full_viewing_key, &terms.group_ak)?;
    if terms.payout.value == 0 { return Err(Error::InvalidPayout); }
    Zatoshis::from_u64(terms.payout.value).map_err(|_| Error::AmountOutOfRange)?;
    Zatoshis::from_u64(terms.fee).map_err(|_| Error::AmountOutOfRange)?;
    if terms.payout.value.checked_add(terms.fee) != Some(terms.note.value().inner()) {
        return Err(Error::UnbalancedTerms);
    }
    terms.payout.memo.ok_or(Error::MissingMetadata)?;
    Ok(())
}
fn validate_joint_profile(pczt: &Pczt, terms: &JointSpendFacts<'_>) -> Result<(), Error> {
    let global = pczt.global();
    if *global.tx_version() != V6_TX_VERSION || *global.version_group_id() != V6_VERSION_GROUP_ID
        || *global.consensus_branch_id() != u32::from(terms.source.consensus_branch)
        || *global.expiry_height() != u32::from(terms.source.expiry_height)
    { return Err(Error::GlobalMetadata); }
    let markers = GlobalMarkers::read(global)?;
    if markers.coin_type != Some(1) || markers.tx_modifiable != Some(0)
        || markers.fallback_lock_time != Some(Some(0)) { return Err(Error::GlobalMetadata); }
    let empty = Creator::new(BranchId::Nu6_2.into(), 0, 1, None, None)
        .map_err(|_| Error::InvalidPczt)?.build().map_err(|_| Error::InvalidPczt)?;
    if pczt.transparent() != empty.transparent() || pczt.orchard() != empty.orchard()
        || !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty()
        || *pczt.sapling().value_sum() != 0 || pczt.sapling().anchor().is_some()
        || pczt.ironwood().actions().iter().any(|action| action.spend().dummy_sk().is_some())
        || pczt.ironwood().actions().is_empty() || pczt.ironwood().actions().len() > MAX_ACTIONS
        || pczt.ironwood().zkproof().is_some()
    { return Err(Error::UnsupportedPool); }
    validate_action_fee(&terms.source, pczt.ironwood().actions().len(), terms.fee)
}
pub struct ReviewedJointFacts {
    pub action_index: usize,
    pub alpha: [u8; 32],
    pub rk: [u8; 32],
    pub note_commitment: [u8; 32],
    pub effect_id: [u8; 32],
    pub shielded_sighash: [u8; 32],
}

/// Exact pre-parent J input and complete positive/zero action openings. Only
/// owner-local attach_membership may supply J's anchor/path after this review.
pub fn review_joint_pczt(pczt: Pczt, terms: &JointSpendFacts<'_>) -> Result<ReviewedJointFacts, Error> {
    review_joint_pczt_owned(pczt, terms).map(|(_, reviewed)| reviewed)
}

fn review_joint_pczt_owned(
    pczt: Pczt, terms: &JointSpendFacts<'_>,
) -> Result<(Pczt, ReviewedJointFacts), Error> {
    validate_joint_terms(terms)?;
    validate_joint_profile(&pczt, terms)?;
    if pczt.ironwood().anchor().is_some() { return Err(Error::InvalidMembership); }
    let nullifier = terms.note.nullifier(terms.full_viewing_key).to_bytes();
    let note_commitment = ExtractedNoteCommitment::from(terms.note.commitment()).to_bytes();
    let input = NativeInputFacts { nullifier: &nullifier, note_commitment: &note_commitment,
        value: terms.note.value().inner(), trusted_fvk: terms.full_viewing_key };
    let mut action_info = None;
    let verified = Verifier::new(pczt).with_sapling::<Error, _>(|bundle| {
        let bsk = bundle.bsk().as_ref().ok_or(
            pczt::roles::verifier::SaplingError::Custom(Error::MissingMetadata))?;
        if <[u8; 32]>::from(*bsk) != [0; 32] {
            return Err(pczt::roles::verifier::SaplingError::Custom(Error::UnsupportedPool));
        }
        Ok(())
    }).map_err(|_| Error::UnsupportedPool)?
    .with_ironwood(|bundle| {
        let check = || -> Result<_, Error> {
            let mut checked_outputs = Vec::with_capacity(1);
            verify_source_bundle(bundle, std::iter::once(input), std::iter::once(terms.payout),
                terms.fee, &mut checked_outputs)?;
            if bundle.zkproof().is_some() || bundle.bsk().is_none() || bundle.flag_byte() != 7 {
                return Err(Error::MissingMetadata);
            }
            let mut trapdoor = orchard::value::ValueCommitTrapdoor::from_bytes([0; 32])
                .into_option().ok_or(Error::NativeVerification)?;
            for action in bundle.actions() {
                trapdoor = trapdoor + action.rcv().as_ref().ok_or(Error::MissingMetadata)?;
            }
            if *Zeroizing::new(trapdoor.to_bytes()) != *Zeroizing::new(<[u8; 32]>::from(
                bundle.bsk().as_ref().ok_or(Error::MissingMetadata)?)) {
                return Err(Error::ValueBalanceMismatch);
            }
            let mut real = None;
            for (index, action) in bundle.actions().iter().enumerate() {
                let spend = action.spend();
                let value = spend.value().ok_or(Error::MissingMetadata)?.inner();
                Zatoshis::from_u64(value).map_err(|_| Error::AmountOutOfRange)?;
                let fvk = spend.fvk().as_ref().ok_or(Error::MissingMetadata)?;
                if spend.rk().is_identity() || bundle.actions()[..index].iter()
                    .any(|prior| prior.spend().nullifier() == spend.nullifier()) {
                    return Err(Error::InputMismatch);
                }
                if value != 0 {
                    if spend.witness().is_some() { return Err(Error::InputMismatch); }
                    if real.is_some() || fvk != terms.full_viewing_key
                        || spend.nullifier().to_bytes() != nullifier
                        || !same_note(&spend_note(action)?, terms.note) {
                        return Err(Error::InputMismatch);
                    }
                    let alpha = *spend.alpha().as_ref().ok_or(Error::MissingMetadata)?;
                    real = Some((index, <[u8; 32]>::from(alpha), <[u8; 32]>::from(spend.rk())));
                }
                if value == 0 && (spend.spend_auth_sig().is_none() || spend.witness().is_none()) {
                    return Err(Error::MissingMetadata);
                }
            }
            real.ok_or(Error::InputMismatch)
        };
        action_info = Some(check().map_err(OrchardError::Custom)?);
        Ok(())
    }).map_err(role_error)?.finish();
    let (effect_id, shielded_sighash) = pczt_effect_identity(&verified)?;
    let (action_index, alpha, rk) = action_info.ok_or(Error::InvalidPczt)?;
    for action in verified.ironwood().actions() {
        if let Some(signature) = action.spend().spend_auth_sig() {
            let rk = orchard::primitives::redpallas::VerificationKey::<
                orchard::primitives::redpallas::SpendAuth,
            >::try_from(*action.spend().rk()).map_err(|_| Error::InvalidSignature)?;
            rk.verify(&shielded_sighash, &orchard::primitives::redpallas::Signature::from(*signature))
                .map_err(|_| Error::InvalidSignature)?;
        }
    }
    Ok((verified, ReviewedJointFacts { action_index, alpha, rk, note_commitment, effect_id, shielded_sighash }))
}

/// Complete reviewed effects; the caller-selected anchor is deliberately
/// separate because V6 transaction effect identity does not bind it.
pub fn compare_transaction_effects(
    private: &orchard::pczt::Bundle, transaction: &Transaction, anchor: Anchor,
) -> Result<(), Error> {
    validate_transaction_profile(transaction)?;
    let finished = transaction.ironwood_bundle().ok_or(Error::MissingIronwood)?;
    if finished.anchor() != &anchor { return Err(Error::AnchorMismatch); }
    if !effects::matches(private, transaction, anchor) { return Err(Error::EffectsChanged); }
    Ok(())
}
pub fn validate_transaction_profile(transaction: &Transaction) -> Result<(), Error> {
    if transaction.version() != TxVersion::V6 { return Err(Error::WrongVersion); }
    if transaction.consensus_branch_id() != BranchId::Nu6_3 { return Err(Error::WrongBranch); }
    if transaction.transparent_bundle().is_some() || transaction.sprout_bundle().is_some()
        || transaction.sapling_bundle().is_some() || transaction.orchard_bundle().is_some()
    { return Err(Error::UnsupportedPool); }
    let bundle = transaction.ironwood_bundle().ok_or(Error::MissingIronwood)?;
    if bundle.bundle_version() != BundleVersion::ironwood_v3() { return Err(Error::WrongBundleVersion); }
    Ok(())
}
pub fn parse_transaction(bytes: &[u8]) -> Result<Transaction, Error> {
    if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES { return Err(Error::MalformedTransaction); }
    if TxVersion::read(bytes).map_err(|_| Error::MalformedTransaction)? != TxVersion::V6 { return Err(Error::WrongVersion); }
    let mut remaining = bytes;
    let transaction = Transaction::read(&mut remaining, BranchId::Nu6_3).map_err(|_| Error::MalformedTransaction)?;
    if !remaining.is_empty() { return Err(Error::NonCanonicalEncoding); }
    validate_transaction_profile(&transaction)?;
    let mut canonical = canonical_bytes::CanonicalBytes { remaining: bytes };
    transaction.write(&mut canonical).map_err(|_| Error::NonCanonicalEncoding)?;
    if !canonical.remaining.is_empty() { return Err(Error::NonCanonicalEncoding); }
    Ok(transaction)
}

/// Semantic finished handoff over borrowed actual bytes. This legacy host seam
/// requires an independently retained prior review; verify_joint_consumer below
/// performs that private review itself inside the shared/guest relation.
pub fn review_finished_semantics(
    transaction: &Transaction, terms: &JointSpendFacts<'_>, shielded_sighash: [u8; 32],
    anchor: Anchor, output_notes: &[Note],
) -> Result<(), Error> {
    validate_joint_terms(terms)?;
    validate_transaction_profile(transaction)?;
    let bundle = transaction.ironwood_bundle().ok_or(Error::MissingIronwood)?;
    if transaction.lock_time() != 0 || transaction.expiry_height() != terms.source.expiry_height
        || bundle.flag_byte() != 7 { return Err(Error::GlobalMetadata); }
    if bundle.anchor() != &anchor { return Err(Error::InvalidMembership); }
    let actions = bundle.actions();
    if actions.len() > MAX_ACTIONS || output_notes.len() != actions.len() { return Err(Error::OutputMismatch); }
    validate_action_fee(&terms.source, actions.len(), terms.fee)?;
    let balance = i64::from(*bundle.value_balance());
    if balance <= 0 || u64::try_from(balance).ok() != Some(terms.fee) { return Err(Error::ValueBalanceMismatch); }
    let nullifier = terms.note.nullifier(terms.full_viewing_key);
    let mut found_j = false;
    for (index, action) in actions.iter().enumerate() {
        if actions.iter().take(index).any(|prior| prior.nullifier() == action.nullifier()) { return Err(Error::InputMismatch); }
        found_j |= action.nullifier() == &nullifier;
    }
    if !found_j { return Err(Error::InputMismatch); }
    let mut found_payout = false;
    for (action, note) in actions.iter().zip(output_notes) {
        if note.version() != NoteVersion::V3 || note.rho() != action.rho()
            || ExtractedNoteCommitment::from(note.commitment()) != *action.cmx() { return Err(Error::OutputMismatch); }
        Zatoshis::from_u64(note.value().inner()).map_err(|_| Error::AmountOutOfRange)?;
        let memo = recover_action_output(action, note, None)?;
        if note.value().inner() != 0 {
            if found_payout || note.recipient() != terms.payout.recipient || note.value().inner() != terms.payout.value {
                return Err(Error::OutputMismatch);
            }
            if terms.payout.memo != Some(&*memo) { return Err(Error::CiphertextMismatch); }
            found_payout = true;
        }
    }
    if !found_payout { return Err(Error::OutputMismatch); }
    if effect_id(transaction) != shielded_sighash { return Err(Error::EffectsChanged); }
    Ok(())
}
pub struct CheckedJointConsumer {
    pub effect_id: [u8; 32],
    pub auth_digest: [u8; 32],
    pub input_total: u64,
    pub output_total: u64,
    pub fee: u64,
}

/// Reopen the retained pre-parent private PCZT, bind EVERY effect/ciphertext and
/// separate actual anchor, then verify full deterministic SpendAuth/binding/Halo2
/// authorization. No caller-controlled expected sighash can replace the review.
pub fn verify_joint_consumer(
    private_pczt: &[u8], terms: &JointSpendFacts<'_>, anchor: Anchor, transaction: &Transaction,
) -> Result<CheckedJointConsumer, Error> {
    let pczt = parse_canonical_pczt(private_pczt)?;
    let (pczt, reviewed) = review_joint_pczt_owned(pczt, terms)?;
    let mut checked = false;
    Verifier::new(pczt).with_ironwood(|bundle| {
        let check = || -> Result<(), Error> {
            compare_transaction_effects(bundle, transaction, anchor)?;
            if effect_id(transaction) != reviewed.effect_id || transaction.lock_time() != 0
                || transaction.expiry_height() != terms.source.expiry_height { return Err(Error::EffectsChanged); }
            let actions = transaction.ironwood_bundle().ok_or(Error::MissingIronwood)?.actions();
            for (private, actual) in bundle.actions().iter().zip(actions) {
                let (note, memo) = recover_output(private)?;
                recover_action_output(actual, &note, Some(&memo))?;
            }
            Ok(())
        };
        check().map_err(OrchardError::Custom)?;
        checked = true;
        Ok(())
    }).map_err(role_error)?;
    if !checked { return Err(Error::InvalidPczt); }
    verify_transaction_authorization(transaction)?;
    Ok(CheckedJointConsumer { effect_id: reviewed.effect_id,
        auth_digest: transaction.auth_commitment().as_bytes().try_into().map_err(|_| Error::InvalidAuthorization)?,
        input_total: terms.note.value().inner(), output_total: terms.payout.value, fee: terms.fee })
}
pub fn verify_transaction_authorization(transaction: &Transaction) -> Result<(), Error> {
    validate_transaction_profile(transaction)?;
    crate::zip244::verify_pure_v6_authorization(transaction).map_err(|_| Error::InvalidAuthorization)
}
