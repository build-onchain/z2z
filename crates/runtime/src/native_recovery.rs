//! Immutable, owner-local preservation of a fully signed source R capability.
//!
//! Envelope `ziquid.nativeR.v1\0` is prefix-disjoint from P/Q and samechain custody.
//! Payload: `ZIQUID_NATIVE_R_CAPSULE\0`, version LE16, stage u8, six fixed 32-byte
//! selection fields in declaration order, early-PCZT length LE32 and exact bytes;
//! Finished additionally carries anchor32, consensus length LE32 and exact bytes.
//! Bounds are 16 MiB for early PCZT and 2 MiB for finished consensus, with complete
//! frame exhaustion. Selection hashing uses the same fixed encoding in AEAD AAD;
//! the independently supplied namespace is a separate AAD component.
//!
//! Selection/quote labels are caller-controlled local pins, NOT an authenticated
//! quote protocol. Terms, prior semantic sighash, ciphertext digest and finished
//! anchor must survive independently of the capsule. No source parameters, raw
//! shares, nonces, DKG packets or duplicate output-note codecs are stored here.
//! Review uses the existing source reviewer and its recovered local output notes.
//!
//! Save returns a digest only after immutable encrypted publication, authenticated
//! exact semantic readback and the existing file/directory durability barriers.
//! Keep Preauthorized and Finished at separate immutable caller-chosen filenames;
//! neither stage replaces the other or selects a directory's "latest" artifact.
//! A restored source capability is not permission to sign, send, release C, arm
//! ETH or settle. It proves no funding, admitted history/anchor, unspentness,
//! finality, winning C/R, financial entitlement, journal fence or full R5 kit.
//! Borrowed keys and independently retained pins are trust inputs. Guarded byte
//! buffers do not erase upstream typed notes/PCZTs, hash-state/compiler/register
//! copies, or protect against same-UID/root compromise and loss of every backup.

use std::{fmt, path::Path};

use orchard::{
    Anchor,
    circuit::{OrchardCircuitVersion, VerifyingKey},
    note::NoteVersion,
};
use pczt::Pczt;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zcash_protocol::consensus::Network;
use zeroize::Zeroizing;
use ziquid_zcash::{
    IronwoodTransaction,
    joint_spend::{
        FinishedJointSpendExpectation, JointSpendTerms, ReviewedJointSpend,
        review_finished_joint_spend, review_joint_spend,
    },
};

use crate::custody::{CustodyError, EnvelopeFormat, load_encrypted_with_digest, save_encrypted};

pub(crate) const ENVELOPE_DOMAIN: &[u8] = b"ziquid.nativeR.v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"ZIQUID_NATIVE_R_CAPSULE\0";
const CONTEXT_DOMAIN: &[u8] = b"ZIQUID_NATIVE_R_SELECTION\0";
const TERMS_DOMAIN: &[u8] = b"ZIQUID_NATIVE_R_TERMS\0";
const VERSION: u16 = 1;
const SELECTION_BYTES: usize = 1 + 6 * 32;
const MAX_EARLY_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINISHED_BYTES: usize = 2 * 1024 * 1024;
const AEAD_TAG_BYTES: usize = 16;
const MAX_PLAINTEXT_BYTES: usize = PAYLOAD_DOMAIN.len() + 2 + SELECTION_BYTES
    + 4 + MAX_EARLY_BYTES + 32 + 4 + MAX_FINISHED_BYTES;
const FORMAT: EnvelopeFormat = EnvelopeFormat {
    domain: ENVELOPE_DOMAIN, max_plaintext_bytes: MAX_PLAINTEXT_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStage {
    Preauthorized = 0,
    Finished = 1,
}

/// Caller-held local pins; equality of session and quote IDs is permitted.
/// `shielded_sighash` comes from prior independent semantic source review, never
/// from the stored transaction ID. No label itself grants financial authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoverySelection {
    pub session_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub terms_digest: [u8; 32],
    pub chain_context: [u8; 32],
    pub deployment_context: [u8; 32],
    pub shielded_sighash: [u8; 32],
    pub stage: RecoveryStage,
}

impl fmt::Debug for RecoverySelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverySelection").field("stage", &self.stage).finish_non_exhaustive()
    }
}

/// Sanitized categories only; no private paths, source material or upstream error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Selection,
    Terms,
    Digest,
    Encoding,
    ResourceLimit,
    Capability,
    Custody(CustodyError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection => f.write_str("native R recovery selection rejected"),
            Self::Terms => f.write_str("native R recovery independent terms rejected"),
            Self::Digest => f.write_str("native R recovery ciphertext digest rejected"),
            Self::Encoding => f.write_str("native R recovery encoding rejected"),
            Self::ResourceLimit => f.write_str("native R recovery exceeds its resource bound"),
            Self::Capability => f.write_str("native R recovery source capability rejected"),
            Self::Custody(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Source-only capabilities. Private early PCZT stays in the existing guarded
/// reviewed artifact; optional finished bytes are the existing checked transaction.
/// Access is explicit and does not advance a lifecycle or financial state.
pub struct RestoredRecovery {
    preauthorized: ReviewedJointSpend,
    finished: Option<IronwoodTransaction>,
}

impl fmt::Debug for RestoredRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RestoredRecovery([redacted])")
    }
}

impl RestoredRecovery {
    pub fn private_pczt_bytes(&self) -> &[u8] {
        self.preauthorized.private_pczt_bytes()
    }

    pub fn finished_transaction(&self) -> Option<&IronwoodTransaction> {
        self.finished.as_ref()
    }

    /// Recover the already authorized source capability for caller-local actual
    /// membership attachment and completion; this creates no new signing authority.
    pub fn into_preauthorized(self) -> ReviewedJointSpend {
        self.preauthorized
    }

    pub fn into_finished(self) -> Option<IronwoodTransaction> {
        self.finished
    }
}

/// Canonical SHA256 commitment to explicit caller terms, not a generic nonzero
/// label. Versioned field order: network u8 (main=0/test=1), target/expiry/branch
/// LE32, ZIP317 marginal fee/grace/input-size/output-size LE64, note version u8
/// (2/3), note recipient43/valueLE64/rho32/rseed32, FVK96, group ak32, payout
/// recipient43/valueLE64/full memo512, and exact feeLE64. No source types are
/// serde-dumped. Hashing itself does not replace source semantic validation.
pub fn joint_spend_terms_digest(terms: &JointSpendTerms<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(TERMS_DOMAIN);
    hash.update(VERSION.to_le_bytes());
    hash.update([match terms.source.network { Network::MainNetwork => 0, Network::TestNetwork => 1 }]);
    hash.update(u32::from(terms.source.target_height).to_le_bytes());
    hash.update(u32::from(terms.source.expiry_height).to_le_bytes());
    hash.update(u32::from(terms.source.consensus_branch).to_le_bytes());
    hash.update(u64::from(terms.source.fee_rule.marginal_fee()).to_le_bytes());
    hash.update((terms.source.fee_rule.grace_actions() as u64).to_le_bytes());
    hash.update((terms.source.fee_rule.p2pkh_standard_input_size() as u64).to_le_bytes());
    hash.update((terms.source.fee_rule.p2pkh_standard_output_size() as u64).to_le_bytes());
    hash.update([match terms.note.version() { NoteVersion::V2 => 2, NoteVersion::V3 => 3 }]);
    hash.update(Zeroizing::new(terms.note.recipient().to_raw_address_bytes()).as_slice());
    hash.update(Zeroizing::new(terms.note.value().inner().to_le_bytes()).as_slice());
    hash.update(Zeroizing::new(terms.note.rho().to_bytes()).as_slice());
    hash.update(terms.note.rseed().as_bytes());
    hash.update(Zeroizing::new(terms.full_viewing_key.to_bytes()).as_slice());
    hash.update(terms.group_ak);
    hash.update(Zeroizing::new(terms.payout.recipient().to_raw_address_bytes()).as_slice());
    hash.update(Zeroizing::new(u64::from(terms.payout.value()).to_le_bytes()).as_slice());
    hash.update(terms.payout.memo().as_array());
    hash.update(Zeroizing::new(u64::from(terms.fee).to_le_bytes()).as_slice());
    hash.finalize().into()
}

fn selection_bytes(selection: &RecoverySelection) -> Zeroizing<[u8; SELECTION_BYTES]> {
    let mut bytes = Zeroizing::new([0; SELECTION_BYTES]);
    bytes[0] = selection.stage as u8;
    for (index, field) in [&selection.session_id, &selection.quote_id, &selection.terms_digest,
        &selection.chain_context, &selection.deployment_context, &selection.shielded_sighash]
        .into_iter().enumerate()
    {
        bytes[1 + index * 32..1 + (index + 1) * 32].copy_from_slice(field);
    }
    bytes
}

fn context(selection: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT_DOMAIN);
    hash.update(VERSION.to_le_bytes());
    hash.update(Sha256::digest(selection));
    hash.finalize().into()
}

fn validate_selection(
    namespace: &[u8; 32], selection: &RecoverySelection, stage: RecoveryStage,
    terms: &JointSpendTerms<'_>, verifying_key: &VerifyingKey,
) -> Result<(), RecoveryError> {
    if selection.stage != stage || [namespace, &selection.session_id, &selection.quote_id,
        &selection.terms_digest, &selection.chain_context, &selection.deployment_context,
        &selection.shielded_sighash].iter().any(|field| **field == [0; 32])
    {
        return Err(RecoveryError::Selection);
    }
    if !bool::from(selection.terms_digest.ct_eq(&joint_spend_terms_digest(terms))) {
        return Err(RecoveryError::Terms);
    }
    if verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3 {
        return Err(RecoveryError::Capability);
    }
    Ok(())
}

fn review_early(
    bytes: &[u8], terms: &JointSpendTerms<'_>, selection: &RecoverySelection,
) -> Result<ReviewedJointSpend, RecoveryError> {
    if bytes.is_empty() || bytes.len() > MAX_EARLY_BYTES { return Err(RecoveryError::ResourceLimit); }
    let reviewed = review_joint_spend(bytes, terms).map_err(|_| RecoveryError::Capability)?;
    if !bool::from(reviewed.shielded_sighash().ct_eq(&selection.shielded_sighash)) {
        return Err(RecoveryError::Capability);
    }
    // The generic pre-parent reviewer also admits an unsigned real J before
    // signing. Custody MUST require its signature as well as genuine padding.
    let pczt = Pczt::parse(reviewed.private_pczt_bytes()).map_err(|_| RecoveryError::Capability)?;
    if pczt.ironwood().actions().iter().any(|action| action.spend().spend_auth_sig().is_none()) {
        return Err(RecoveryError::Capability);
    }
    Ok(reviewed)
}

fn review_finished<R: RngCore + CryptoRng>(
    reviewed: &ReviewedJointSpend, bytes: &[u8], anchor: Anchor,
    terms: &JointSpendTerms<'_>, verifying_key: &VerifyingKey, rng: &mut R,
) -> Result<IronwoodTransaction, RecoveryError> {
    if bytes.is_empty() || bytes.len() > MAX_FINISHED_BYTES { return Err(RecoveryError::ResourceLimit); }
    let notes = reviewed.output_notes().map_err(|_| RecoveryError::Capability)?;
    review_finished_joint_spend(bytes, &FinishedJointSpendExpectation {
        terms: *terms, shielded_sighash: reviewed.shielded_sighash(), anchor, output_notes: &notes,
    }, verifying_key, rng).map_err(|_| RecoveryError::Capability)
}

fn encode(
    selection: &[u8; SELECTION_BYTES], early: &[u8], finished: Option<(Anchor, &[u8])>,
) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    if early.is_empty() || early.len() > MAX_EARLY_BYTES
        || finished.is_some_and(|(_, bytes)| bytes.is_empty() || bytes.len() > MAX_FINISHED_BYTES)
    { return Err(RecoveryError::ResourceLimit); }
    let length = PAYLOAD_DOMAIN.len() + 2 + SELECTION_BYTES + 4 + early.len()
        + finished.map_or(0, |(_, bytes)| 32 + 4 + bytes.len());
    // Complete capacity, including tag space, is reserved BEFORE private filling.
    // The shared publisher uses detached AEAD and never grows this allocation.
    let mut bytes = Zeroizing::new(Vec::with_capacity(length + AEAD_TAG_BYTES));
    bytes.extend_from_slice(PAYLOAD_DOMAIN);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(selection);
    bytes.extend_from_slice(&(early.len() as u32).to_le_bytes());
    bytes.extend_from_slice(early);
    if let Some((anchor, consensus)) = finished {
        bytes.extend_from_slice(&anchor.to_bytes());
        bytes.extend_from_slice(&(consensus.len() as u32).to_le_bytes());
        bytes.extend_from_slice(consensus);
    }
    Ok(bytes)
}

struct Frame<'a> {
    early: &'a [u8],
    finished: Option<(&'a [u8], &'a [u8])>,
}

fn decode<'a>(
    bytes: &'a [u8], selection: &RecoverySelection, selected: &[u8; SELECTION_BYTES],
) -> Result<Frame<'a>, RecoveryError> {
    if bytes.len() > MAX_PLAINTEXT_BYTES { return Err(RecoveryError::ResourceLimit); }
    let mut reader = Reader(bytes);
    if reader.take(PAYLOAD_DOMAIN.len())? != PAYLOAD_DOMAIN
        || reader.take(2)? != VERSION.to_le_bytes()
    { return Err(RecoveryError::Encoding); }
    if !bool::from(reader.take(SELECTION_BYTES)?.ct_eq(selected)) { return Err(RecoveryError::Selection); }
    let early = reader.blob(MAX_EARLY_BYTES)?;
    let finished = match selection.stage {
        RecoveryStage::Preauthorized => None,
        RecoveryStage::Finished => Some((reader.take(32)?, reader.blob(MAX_FINISHED_BYTES)?)),
    };
    if !reader.0.is_empty() { return Err(RecoveryError::Encoding); }
    Ok(Frame { early, finished })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], RecoveryError> {
        if length > self.0.len() { return Err(RecoveryError::Encoding); }
        let (bytes, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(bytes)
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], RecoveryError> {
        let length = u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| RecoveryError::Encoding)?) as usize;
        if length == 0 || length > maximum { return Err(RecoveryError::ResourceLimit); }
        self.take(length)
    }
}

/// Validate fully authorized pre-parent R, publish immutably and authenticate/review
/// the installed exact bytes before returning the exact encrypted-file SHA256.
pub fn save_preauthorized(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    selection: &RecoverySelection, terms: &JointSpendTerms<'_>, early: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<[u8; 32], RecoveryError> {
    validate_selection(&namespace, selection, RecoveryStage::Preauthorized, terms, verifying_key)?;
    drop(review_early(early, terms, selection)?);
    let selected = selection_bytes(selection);
    let context = context(&*selected);
    let payload = encode(&selected, early, None)?;
    save_encrypted(path.as_ref(), key, namespace, context, FORMAT, payload).map_err(RecoveryError::Custody)?;
    let (readback, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context, FORMAT)
        .map_err(RecoveryError::Custody)?;
    let frame = decode(&readback, selection, &selected)?;
    if !bool::from(frame.early.ct_eq(early)) { return Err(RecoveryError::Custody(CustodyError::Conflict)); }
    drop(review_early(frame.early, terms, selection)?);
    Ok(digest)
}

/// Restore only against separately retained selection, complete caller terms and
/// the exact expected ciphertext digest. No anchor is invented for pre-parent R.
pub fn load_preauthorized(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    expected: &RecoverySelection, expected_digest: [u8; 32], terms: &JointSpendTerms<'_>,
    verifying_key: &VerifyingKey,
) -> Result<RestoredRecovery, RecoveryError> {
    validate_selection(&namespace, expected, RecoveryStage::Preauthorized, terms, verifying_key)?;
    let selected = selection_bytes(expected);
    let (bytes, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context(&*selected), FORMAT)
        .map_err(RecoveryError::Custody)?;
    if !bool::from(digest.ct_eq(&expected_digest)) { return Err(RecoveryError::Digest); }
    let frame = decode(&bytes, expected, &selected)?;
    Ok(RestoredRecovery { preauthorized: review_early(frame.early, terms, expected)?, finished: None })
}

/// Publish finished R at a DIFFERENT immutable artifact identity. Both early
/// authorizations and finished consensus/Halo2/binding signatures are reviewed
/// before publication and again after authenticated exact readback. RNG is used
/// only by the actual upstream authorization/proof verification.
#[allow(clippy::too_many_arguments)]
pub fn save_finished<R: RngCore + CryptoRng>(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    selection: &RecoverySelection, terms: &JointSpendTerms<'_>, early: &[u8],
    anchor: Anchor, consensus: &[u8], verifying_key: &VerifyingKey, rng: &mut R,
) -> Result<[u8; 32], RecoveryError> {
    validate_selection(&namespace, selection, RecoveryStage::Finished, terms, verifying_key)?;
    let reviewed = review_early(early, terms, selection)?;
    drop(review_finished(&reviewed, consensus, anchor, terms, verifying_key, rng)?);
    drop(reviewed);
    let selected = selection_bytes(selection);
    let context = context(&*selected);
    let payload = encode(&selected, early, Some((anchor, consensus)))?;
    save_encrypted(path.as_ref(), key, namespace, context, FORMAT, payload).map_err(RecoveryError::Custody)?;
    let (readback, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context, FORMAT)
        .map_err(RecoveryError::Custody)?;
    let frame = decode(&readback, selection, &selected)?;
    let (stored_anchor, finished) = frame.finished.ok_or(RecoveryError::Encoding)?;
    if !bool::from(frame.early.ct_eq(early) & stored_anchor.ct_eq(&anchor.to_bytes()) & finished.ct_eq(consensus)) {
        return Err(RecoveryError::Custody(CustodyError::Conflict));
    }
    let reviewed = review_early(frame.early, terms, selection)?;
    drop(review_finished(&reviewed, finished, anchor, terms, verifying_key, rng)?);
    Ok(digest)
}

/// Authenticate the exact encrypted artifact, re-review fully signed early R and
/// verify finished R against the independently selected anchor and authentic prior
/// semantic sighash. The anchor serialized inside the capsule is NOT its own trust
/// source, and this check does not qualify history, source finality or target rights.
#[allow(clippy::too_many_arguments)]
pub fn load_finished<R: RngCore + CryptoRng>(
    path: impl AsRef<Path>, key: &[u8; 32], namespace: [u8; 32],
    expected: &RecoverySelection, expected_digest: [u8; 32], terms: &JointSpendTerms<'_>,
    expected_anchor: Anchor, verifying_key: &VerifyingKey, rng: &mut R,
) -> Result<RestoredRecovery, RecoveryError> {
    validate_selection(&namespace, expected, RecoveryStage::Finished, terms, verifying_key)?;
    let selected = selection_bytes(expected);
    let (bytes, digest) = load_encrypted_with_digest(path.as_ref(), key, namespace, context(&*selected), FORMAT)
        .map_err(RecoveryError::Custody)?;
    if !bool::from(digest.ct_eq(&expected_digest)) { return Err(RecoveryError::Digest); }
    let frame = decode(&bytes, expected, &selected)?;
    let (anchor, finished) = frame.finished.ok_or(RecoveryError::Encoding)?;
    if !bool::from(anchor.ct_eq(&expected_anchor.to_bytes())) { return Err(RecoveryError::Capability); }
    let preauthorized = review_early(frame.early, terms, expected)?;
    let finished = review_finished(&preauthorized, finished, expected_anchor, terms, verifying_key, rng)?;
    Ok(RestoredRecovery { preauthorized, finished: Some(finished) })
}
