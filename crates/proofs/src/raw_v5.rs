//! Bounded original-byte NU5–NU6.3 V5 parsing, Orchard authentication and coinbase recovery.
//!
//! The owned maintained transaction data is a transparent/Sapling projection,
//! never a complete `Transaction`: it is not frozen, serialized or used as the
//! original transaction's identity. Orchard actions, ciphertexts, proof and
//! signatures borrow their exact transmitted bytes. Historical ordinary EPKs
//! remain opaque; NU6.2/NU6.3 require canonical nonidentity EPK/rk and exact proof
//! framing. Neither encoding predicate proves encryption correctness.
//!
//! Separate checks cover historical, NU6.2 fixed and NU6.3 restricted Halo2,
//! every signature, and zero-OVK coinbase output recovery. None proves current
//! anchors, nullifier uniqueness, money conservation, reward validity,
//! history, finality or asset transfers. Pre-NU6.2 identity rk remains parseable
//! but is a typed unsupported historical node-crash domain at verification,
//! not a claim of mathematical/specification rejection.
//!
//! Narrow Orchard ZIP244 hashing adapts orchard 0.15.5 `bundle/commitments.rs`
//! (29d1d55db62153dcaeef8ef631c8991c53ed1248). All other serializers, digests,
//! composite roots and actual-prevout signature hashing remain upstream-owned.
/*
The MIT License (MIT)
Copyright (c) 2020-2025 The Electric Coin Company
Copyright (c) 2026 Zcash Open Development Lab
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

use std::fmt;

use blake2b_simd::{Hash, Params};
use corez::io::ErrorKind;
use orchard::{
    Proof,
    bundle::{BundleVersion, Flags},
    circuit::Instance,
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, OrchardDomain},
    primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey},
    tree::Anchor,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use zcash_encoding::CompactSize;
use zcash_note_encryption::{Domain, EphemeralKeyBytes, ShieldedOutput, try_output_recovery_with_ovk};
use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TransactionDigest, TxDigests, TxVersion,
    txid::{BlockTxCommitmentDigester, TxIdDigester, to_txid},
};
use zcash_protocol::{consensus::{BlockHeight, BranchId}, value::ZatBalance};
use zcash_transparent::bundle::{self as transparent, TxIn, TxOut};

use crate::{
    orchard_original::{FixedOrchardError, FixedOrchardVerifier, OriginalOrchardVerifier,
        PostNu63OrchardError, PostNu63OrchardVerifier},
    zip244::{PostNu5SignatureHash, PostNu5SighashError},
};

const MAX_TRANSACTION_BYTES: usize = 2_000_000;
const MAX_SHIELDED_COUNT: usize = 65_535;
const ACTION_BYTES: usize = 820;

/// Redacted wire/resource/cryptographic failures; no supplied bytes are stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawV5Error {
    Truncated,
    TrailingBytes,
    TransactionTooLarge,
    InvalidCompactSize,
    UnsupportedVersion,
    UnsupportedVersionGroup,
    UnsupportedBranch,
    InvalidTransparentData,
    InvalidSaplingData,
    InvalidSaplingValueBalance,
    TooManySaplingSpends,
    TooManySaplingOutputs,
    TooManyOrchardActions,
    InvalidOrchardFlags,
    InvalidOrchardValueBalance,
    InvalidOrchardAnchor,
    InvalidOrchardValueCommitment { index: usize },
    InvalidOrchardNullifier { index: usize },
    InvalidOrchardRandomizedKey { index: usize },
    InvalidOrchardEphemeralKey { index: usize },
    InvalidOrchardNoteCommitment { index: usize },
    /// Original node proof construction crashed here; this is not spec rejection.
    UnsupportedHistoricalIdentityRk { index: usize },
    InvalidOrchardSpendAuth { index: usize },
    InvalidOrchardBindingSignature,
    InvalidOrchardProof,
    InvalidOrchardProofLength,
    OrchardVerifierModeMismatch,
    /// Redacted ciphertext/context failure, including undefined note commitment.
    CoinbaseRecovery { index: usize },
}

impl fmt::Display for RawV5Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrchardValueCommitment { index } => write!(formatter, "invalid Orchard action {index} value commitment encoding"),
            Self::InvalidOrchardNullifier { index } => write!(formatter, "invalid Orchard action {index} nullifier encoding"),
            Self::InvalidOrchardRandomizedKey { index } => write!(formatter, "invalid Orchard action {index} randomized key encoding"),
            Self::InvalidOrchardEphemeralKey { index } => write!(formatter, "invalid strict Orchard action {index} ephemeral key encoding"),
            Self::InvalidOrchardNoteCommitment { index } => write!(formatter, "invalid Orchard action {index} note commitment encoding"),
            Self::UnsupportedHistoricalIdentityRk { index } => write!(formatter, "unsupported historical Orchard action {index} identity randomized key"),
            Self::InvalidOrchardSpendAuth { index } => write!(formatter, "Orchard action {index} SpendAuth verification failed"),
            Self::CoinbaseRecovery { index } => write!(formatter, "Orchard action {index} coinbase output recovery failed"),
            _ => formatter.write_str(match self {
                Self::Truncated => "truncated original V5 transaction",
                Self::TrailingBytes => "trailing bytes after original V5 transaction",
                Self::TransactionTooLarge => "original V5 transaction exceeds 2,000,000-byte bound",
                Self::InvalidCompactSize => "noncanonical or oversized original V5 CompactSize",
                Self::UnsupportedVersion => "raw transaction requires exact V5 header",
                Self::UnsupportedVersionGroup => "raw V5 transaction has wrong version group",
                Self::UnsupportedBranch => "raw V5 profile requires NU5 through NU6.3 consensus branch",
                Self::InvalidTransparentData => "invalid original V5 transparent encoding or value",
                Self::InvalidSaplingData => "invalid original V5 Sapling encoding",
                Self::InvalidSaplingValueBalance => "original V5 Sapling value balance is out of range",
                Self::TooManySaplingSpends => "original V5 Sapling spend count exceeds 65,535",
                Self::TooManySaplingOutputs => "original V5 Sapling output count exceeds 65,535",
                Self::TooManyOrchardActions => "original V5 Orchard action count exceeds 65,535",
                Self::InvalidOrchardFlags => "invalid or empty original Orchard bundle flags for its consensus branch",
                Self::InvalidOrchardValueBalance => "original Orchard value balance is out of range",
                Self::InvalidOrchardAnchor => "invalid original Orchard anchor encoding",
                Self::InvalidOrchardBindingSignature => "original Orchard binding signature verification failed",
                Self::InvalidOrchardProof => "original Orchard Halo2 proof verification failed",
                Self::InvalidOrchardProofLength => "invalid fixed Orchard proof length",
                Self::OrchardVerifierModeMismatch => "Orchard verifier does not match the encoded consensus branch",
                _ => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for RawV5Error {}

/// Exact original bytes and real owned transparent/Sapling projections.
/// No full typed transaction, partial-transaction serializer or ordinary txid
/// accessor is exposed. Effect/auth identities include the raw Orchard bundle.
pub struct RawV5<'a> {
    original: &'a [u8],
    context: TransactionData<Authorized>,
    orchard: Option<RawOrchard<'a>>,
    txid_parts: TxDigests<Hash>,
    effect_id: [u8; 32],
    auth_digest: [u8; 32],
}

impl fmt::Debug for RawV5<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RawV5")
            .field("consumed_bytes", &self.original.len())
            .field("orchard_actions", &self.orchard.map_or(0, |bundle| bundle.action_count()))
            .finish_non_exhaustive()
    }
}

impl<'a> RawV5<'a> {
    /// Parses exactly one NU5–NU6.3 V5 transaction with complete consumption.
    /// Count/script/proof framing is preflighted before any projection allocation.
    /// No candidate-height admission is implied. Individual balances/outputs
    /// are bounded, not aggregate financial validity or contextual Orchard rules.
    pub fn parse_exact(original: &'a [u8]) -> Result<Self, RawV5Error> {
        let mut reader = original;
        let transaction = Self::parse(&mut reader)?;
        if !reader.is_empty() {
            return Err(RawV5Error::TrailingBytes);
        }
        Ok(transaction)
    }

    /// Consumes exactly one transaction only on success, permitting a full block
    /// caller to retain its next transaction. The cap applies to consumed bytes,
    /// not to the possibly larger enclosing block remainder.
    pub fn parse(reader: &mut &'a [u8]) -> Result<Self, RawV5Error> {
        let original = *reader;
        let window = &original[..original.len().min(MAX_TRANSACTION_BYTES)];
        let transaction = Self::parse_bounded(window).map_err(|error| {
            if error == RawV5Error::Truncated && original.len() > MAX_TRANSACTION_BYTES {
                RawV5Error::TransactionTooLarge
            } else {
                error
            }
        })?;
        *reader = &original[transaction.consumed_bytes()..];
        Ok(transaction)
    }

    fn parse_bounded(original: &'a [u8]) -> Result<Self, RawV5Error> {
        let mut reader = original;
        let version = take(&mut reader, 4)?;
        if version != TxVersion::V5.header().to_le_bytes() {
            return Err(RawV5Error::UnsupportedVersion);
        }
        if take(&mut reader, 4)? != TxVersion::V5.version_group_id().to_le_bytes() {
            return Err(RawV5Error::UnsupportedVersionGroup);
        }
        let branch = BranchId::try_from(u32::from_le_bytes(
            take(&mut reader, 4)?.try_into().expect("four-byte consensus branch"),
        )).map_err(|_| RawV5Error::UnsupportedBranch)?;
        if !matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
            return Err(RawV5Error::UnsupportedBranch);
        }
        let lock_time = u32::from_le_bytes(take(&mut reader, 4)?.try_into().expect("four-byte lock time"));
        let expiry_height = u32::from_le_bytes(take(&mut reader, 4)?.try_into().expect("four-byte expiry"));

        let vin_count = compact_size(&mut reader)?;
        require_width(reader, vin_count, 41)?;
        let vin_start = reader;
        for _ in 0..vin_count {
            take(&mut reader, 36)?;
            let script_length = compact_size(&mut reader)?;
            take(&mut reader, script_length)?;
            take(&mut reader, 4)?;
        }
        let vin_bytes = &vin_start[..vin_start.len() - reader.len()];
        let vout_count = compact_size(&mut reader)?;
        require_width(reader, vout_count, 9)?;
        let vout_start = reader;
        for _ in 0..vout_count {
            take(&mut reader, 8)?;
            let script_length = compact_size(&mut reader)?;
            take(&mut reader, script_length)?;
        }
        let vout_bytes = &vout_start[..vout_start.len() - reader.len()];

        let sapling_start = reader;
        let spend_count = compact_size(&mut reader)?;
        if spend_count > MAX_SHIELDED_COUNT {
            return Err(RawV5Error::TooManySaplingSpends);
        }
        take_counted(&mut reader, spend_count, 96)?;
        let output_count = compact_size(&mut reader)?;
        if output_count > MAX_SHIELDED_COUNT {
            return Err(RawV5Error::TooManySaplingOutputs);
        }
        take_counted(&mut reader, output_count, 756)?;
        if spend_count != 0 || output_count != 0 {
            ZatBalance::from_i64_le_bytes(take(&mut reader, 8)?.try_into().expect("eight-byte Sapling balance"))
                .map_err(|_| RawV5Error::InvalidSaplingValueBalance)?;
            if spend_count != 0 {
                take(&mut reader, 32)?;
            }
            take_counted(&mut reader, spend_count, 192)?;
            take_counted(&mut reader, spend_count, 64)?;
            take_counted(&mut reader, output_count, 192)?;
            take(&mut reader, 64)?;
        }
        let sapling_bytes = &sapling_start[..sapling_start.len() - reader.len()];
        let orchard = RawOrchard::read(&mut reader, branch)?;
        let consumed = original.len() - reader.len();

        // Every count and variable-sized field in the entire transaction has
        // been bounded before these actual maintained owned readers allocate.
        let mut vin_reader = vin_bytes;
        let mut vin = Vec::with_capacity(vin_count);
        for _ in 0..vin_count {
            vin.push(TxIn::read(&mut vin_reader).map_err(|_| RawV5Error::InvalidTransparentData)?);
        }
        let mut vout_reader = vout_bytes;
        let mut vout = Vec::with_capacity(vout_count);
        for _ in 0..vout_count {
            vout.push(TxOut::read(&mut vout_reader).map_err(|_| RawV5Error::InvalidTransparentData)?);
        }
        if !vin_reader.is_empty() || !vout_reader.is_empty() {
            return Err(RawV5Error::InvalidTransparentData);
        }
        let transparent_bundle = if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle { vin, vout, authorization: transparent::Authorized })
        };
        let mut sapling_reader = sapling_bytes;
        let sapling_bundle = Transaction::temporary_zcashd_read_v5_sapling(&mut sapling_reader)
            .map_err(|_| RawV5Error::InvalidSaplingData)?;
        if !sapling_reader.is_empty() {
            return Err(RawV5Error::InvalidSaplingData);
        }
        let context = TransactionData::from_parts(
            TxVersion::V5, branch, lock_time, expiry_height.into(),
            transparent_bundle, None, sapling_bundle, None,
        );
        let mut txid_parts = context.digest(TxIdDigester);
        txid_parts.orchard_digest = orchard.map(|bundle| bundle.effect_hash());
        let effect_id = to_txid(TxVersion::V5, branch, &txid_parts).into();
        let auth = BlockTxCommitmentDigester;
        let orchard_auth = orchard.map_or_else(
            || auth.digest_orchard(TxVersion::V5, None),
            |bundle| bundle.auth_hash(),
        );
        let auth_digest = *auth.combine(
            (TxVersion::V5, branch),
            auth.digest_transparent(context.transparent_bundle()),
            auth.digest_sapling(TxVersion::V5, context.sapling_bundle()),
            orchard_auth, auth.digest_ironwood(None),
        ).as_bytes().first_chunk::<32>().expect("32-byte auth commitment");
        Ok(Self {
            original: &original[..consumed], context, orchard, txid_parts, effect_id, auth_digest,
        })
    }

    pub fn original_bytes(&self) -> &'a [u8] {
        self.original
    }

    pub fn consumed_bytes(&self) -> usize {
        self.original.len()
    }

    pub fn version(&self) -> TxVersion {
        self.context.version()
    }

    pub fn consensus_branch_id(&self) -> BranchId {
        self.context.consensus_branch_id()
    }

    pub fn lock_time(&self) -> u32 {
        self.context.lock_time()
    }

    pub fn expiry_height(&self) -> BlockHeight {
        self.context.expiry_height()
    }

    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<transparent::Authorized>> {
        self.context.transparent_bundle()
    }

    pub fn sapling_bundle(&self) -> Option<&sapling_crypto::Bundle<sapling_crypto::bundle::Authorized, ZatBalance>> {
        self.context.sapling_bundle()
    }

    pub fn orchard(&self) -> Option<&RawOrchard<'a>> {
        self.orchard.as_ref()
    }

    /// Original full effect ID in raw BLAKE2b byte order, not display reversal.
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Original full authorizing commitment, including every proof suffix byte.
    pub fn auth_digest(&self) -> [u8; 32] {
        self.auth_digest
    }

    /// Moves the real owned projection once into the shared ZIP244 authorization
    /// adapter. Supply every actual previous output in original vin order; no
    /// amount/script substitution or whole-transaction cloning occurs.
    /// Copy the borrowed `RawOrchard` before consuming `self` for later crypto.
    pub fn into_signature_context(self, previous_outputs: Vec<TxOut>) -> Result<PostNu5SignatureHash, PostNu5SighashError> {
        PostNu5SignatureHash::from_projection(self.context, previous_outputs, self.txid_parts, self.auth_digest)
    }

    /// Checks every present historical Orchard authorization against the supplied
    /// actual shielded signature message; NU6.2/NU6.3 descriptors reject this
    /// method. Absence succeeds. Mixed inputs must first bind actual prevouts.
    pub fn verify_orchard(&self, verifier: &OriginalOrchardVerifier, shielded_sighash: &[u8; 32]) -> Result<(), RawV5Error> {
        self.orchard.as_ref().map_or(Ok(()), |bundle| bundle.verify_orchard(verifier, shielded_sighash))
    }
}

/// Borrowed exact original Orchard wire fields with their actual branch context.
/// No maintained `Action` constructor or encryption-validity claim is involved.
#[derive(Clone, Copy)]
pub struct RawOrchard<'a> {
    consensus_branch_id: BranchId,
    actions: &'a [u8],
    flag_byte: u8,
    flags: Flags,
    value_balance: ZatBalance,
    anchor: Anchor,
    proof: &'a [u8],
    spend_sigs: &'a [u8],
    binding_sig: &'a [u8; 64],
}

impl fmt::Debug for RawOrchard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RawOrchard")
            .field("action_count", &self.action_count())
            .field("proof_bytes", &self.proof.len())
            .finish_non_exhaustive()
    }
}

impl<'a> RawOrchard<'a> {
    fn read(reader: &mut &'a [u8], consensus_branch_id: BranchId) -> Result<Option<Self>, RawV5Error> {
        let action_count = compact_size(reader)?;
        if action_count > MAX_SHIELDED_COUNT {
            return Err(RawV5Error::TooManyOrchardActions);
        }
        if action_count == 0 {
            return Ok(None);
        }
        let actions = take_counted(reader, action_count, ACTION_BYTES)?;
        let flag_byte = take(reader, 1)?[0];
        let strict = matches!(consensus_branch_id, BranchId::Nu6_2 | BranchId::Nu6_3);
        let version = match consensus_branch_id {
            BranchId::Nu6_3 => BundleVersion::orchard_v3(),
            BranchId::Nu6_2 => BundleVersion::orchard_v2(),
            _ => BundleVersion::orchard_insecure_v1(),
        };
        let flags = Flags::from_byte(flag_byte, version)
            .filter(|flags| flags.spends_enabled() || flags.outputs_enabled())
            .ok_or(RawV5Error::InvalidOrchardFlags)?;
        let value_balance = ZatBalance::from_i64_le_bytes(take(reader, 8)?.try_into().expect("eight-byte Orchard balance"))
            .map_err(|_| RawV5Error::InvalidOrchardValueBalance)?;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(take(reader, 32)?.try_into().expect("32-byte Orchard anchor")))
            .ok_or(RawV5Error::InvalidOrchardAnchor)?;
        let proof_length = compact_size(reader)?;
        // Check strict framing before projection allocation, Action decoding or
        // any proof-owned copy. The count cap already bounds the size formula.
        if strict && proof_length != Proof::expected_proof_size(action_count) {
            return Err(RawV5Error::InvalidOrchardProofLength);
        }
        let proof = take(reader, proof_length)?;
        let spend_sigs = take_counted(reader, action_count, 64)?;
        let binding_sig = take(reader, 64)?.try_into().expect("64-byte binding signature");
        for (index, action) in actions.as_chunks::<ACTION_BYTES>().0.iter().enumerate() {
            let decoded = decode_action(action, index)?;
            if strict {
                if decoded.rk.is_identity() {
                    return Err(RawV5Error::InvalidOrchardRandomizedKey { index });
                }
                let epk = EphemeralKeyBytes(action[128..160].try_into().expect("32-byte raw ephemeral key"));
                if <OrchardDomain as Domain>::epk(&epk).is_none() {
                    return Err(RawV5Error::InvalidOrchardEphemeralKey { index });
                }
            }
        }
        Ok(Some(Self { consensus_branch_id, actions, flag_byte, flags, value_balance, anchor, proof, spend_sigs, binding_sig }))
    }

    pub fn action_count(&self) -> usize {
        self.actions.len() / ACTION_BYTES
    }

    pub fn actions(&self) -> &'a [u8] {
        self.actions
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn value_balance(&self) -> ZatBalance {
        self.value_balance
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    pub fn proof(&self) -> &'a [u8] {
        self.proof
    }

    pub fn spend_auth_signatures(&self) -> &'a [u8] {
        self.spend_sigs
    }

    pub fn binding_signature(&self) -> &'a [u8; 64] {
        self.binding_sig
    }

    /// Recovers EVERY action with the original coinbase zero OVK, including
    /// dummy/zero-valued notes and actions with outputs disabled. Flags,
    /// authorization, state and reward validity require separate checks.
    /// Recovered values are not summed or subjected to a per-note money cap.
    pub fn verify_coinbase_outputs(&self) -> Result<(), RawV5Error> {
        for (index, action) in self.actions.as_chunks::<ACTION_BYTES>().0.iter().enumerate() {
            recover_orchard_coinbase_action(action)
                .map_err(|_| RawV5Error::CoinbaseRecovery { index })?;
        }
        Ok(())
    }

    fn effect_hash(&self) -> Hash {
        let mut compact = hasher(b"ZTxIdOrcActCHash");
        let mut memos = hasher(b"ZTxIdOrcActMHash");
        let mut noncompact = hasher(b"ZTxIdOrcActNHash");
        for action in self.actions.as_chunks::<ACTION_BYTES>().0.iter() {
            compact.update(&action[32..64]);
            compact.update(&action[96..212]);
            memos.update(&action[212..724]);
            noncompact.update(&action[..32]);
            noncompact.update(&action[64..96]);
            noncompact.update(&action[724..820]);
        }
        let mut root = hasher(b"ZTxIdOrchardHash");
        root.update(compact.finalize().as_bytes());
        root.update(memos.finalize().as_bytes());
        root.update(noncompact.finalize().as_bytes());
        root.update(&[self.flag_byte]);
        root.update(&self.value_balance.to_i64_le_bytes());
        root.update(&self.anchor.to_bytes());
        root.finalize()
    }

    fn auth_hash(&self) -> Hash {
        let mut auth = hasher(b"ZTxAuthOrchaHash");
        auth.update(self.proof);
        auth.update(self.spend_sigs);
        auth.update(self.binding_sig);
        auth.finalize()
    }

    /// Actual original Halo2 plus EVERY SpendAuth and binding signature,
    /// including disabled/dummy actions. Does not check state or encryption.
    /// No modern exact proof-size rule, suffix stripping or binding-key
    /// nonidentity restriction is added to the historical relation.
    pub fn verify_orchard(&self, verifier: &OriginalOrchardVerifier, shielded_sighash: &[u8; 32]) -> Result<(), RawV5Error> {
        if matches!(self.consensus_branch_id, BranchId::Nu6_2 | BranchId::Nu6_3) {
            return Err(RawV5Error::OrchardVerifierModeMismatch);
        }
        // Classify the historical crash domain before any signature/proof check.
        for (index, action) in self.actions.as_chunks::<ACTION_BYTES>().0.iter().enumerate() {
            if action[64..96] == [0; 32] {
                return Err(RawV5Error::UnsupportedHistoricalIdentityRk { index });
            }
        }
        let instances = self.authorized_instances(shielded_sighash)?;
        // Historical lenient proof framing and key are deliberately unchanged.
        Proof::new(self.proof.to_vec()).verify(verifier.verifying_key(), &instances)
            .map_err(|_| RawV5Error::InvalidOrchardProof)
    }

    /// NU6.2 fixed Halo2 plus EVERY SpendAuth and binding signature. The parsed
    /// descriptor already enforces V2 flags, exact proof length and strict EPK/rk.
    /// Wrong encoded era rejects before authorization; no historical fallback.
    /// Candidate-height/parent-state admission must precede caller key selection.
    pub fn verify_orchard_fixed(&self, verifier: &FixedOrchardVerifier, shielded_sighash: &[u8; 32]) -> Result<(), RawV5Error> {
        if self.consensus_branch_id != BranchId::Nu6_2 {
            return Err(RawV5Error::OrchardVerifierModeMismatch);
        }
        if self.proof.len() != Proof::expected_proof_size(self.action_count()) {
            return Err(RawV5Error::InvalidOrchardProofLength);
        }
        let instances = self.authorized_instances(shielded_sighash)?;
        verifier.verify_instances(&instances, self.proof).map_err(|error| match error {
            FixedOrchardError::InvalidProofLength => RawV5Error::InvalidOrchardProofLength,
            _ => RawV5Error::InvalidOrchardProof,
        })
    }

    /// NU6.3 PostNu6_3 Halo2 plus EVERY SpendAuth and binding signature. V5
    /// Orchard requires the restricted V3 statement; there is no Ironwood slot.
    /// Wrong encoded branch rejects before authorization, with no old-key fallback.
    pub fn verify_orchard_post_nu63(&self, verifier: &PostNu63OrchardVerifier, shielded_sighash: &[u8; 32]) -> Result<(), RawV5Error> {
        if self.consensus_branch_id != BranchId::Nu6_3 {
            return Err(RawV5Error::OrchardVerifierModeMismatch);
        }
        if self.proof.len() != Proof::expected_proof_size(self.action_count()) {
            return Err(RawV5Error::InvalidOrchardProofLength);
        }
        let instances = self.authorized_instances(shielded_sighash)?;
        verifier.verify_instances(&instances, self.proof).map_err(|error| match error {
            PostNu63OrchardError::InvalidProofLength => RawV5Error::InvalidOrchardProofLength,
            _ => RawV5Error::InvalidOrchardProof,
        })
    }

    // Shared actual signatures and typed statement construction: one bounded
    // Instance Vec, no Action/ciphertext/proof copy or duplicate field decode.
    fn authorized_instances(&self, shielded_sighash: &[u8; 32]) -> Result<Vec<Instance>, RawV5Error> {
        let mut instances = Vec::with_capacity(self.action_count());
        let mut cv_sum: ValueCommitment = std::iter::empty::<ValueCommitment>().sum();
        for (index, (action, signature)) in self.actions.as_chunks::<ACTION_BYTES>().0.iter()
            .zip(self.spend_sigs.as_chunks::<64>().0.iter()).enumerate()
        {
            let decoded = decode_action(action, index)?;
            decoded.rk.verify(shielded_sighash, &Signature::<SpendAuth>::from(
                *signature,
            )).map_err(|_| RawV5Error::InvalidOrchardSpendAuth { index })?;
            cv_sum = cv_sum + &decoded.cv_net;
            instances.push(Instance::from_parts(
                self.anchor, decoded.cv_net, decoded.nullifier, decoded.rk, decoded.cmx, self.flags,
            ).ok_or(if matches!(self.consensus_branch_id, BranchId::Nu6_2 | BranchId::Nu6_3) {
                RawV5Error::InvalidOrchardRandomizedKey { index }
            } else {
                RawV5Error::UnsupportedHistoricalIdentityRk { index }
            })?);
        }
        let balance = i64::from(self.value_balance);
        let signed_value = if balance < 0 {
            NoteValue::ZERO - NoteValue::from_raw(balance.unsigned_abs())
        } else {
            NoteValue::from_raw(balance as u64) - NoteValue::ZERO
        };
        let zero_trapdoor = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes([0; 32]))
            .expect("zero is a canonical Pallas scalar");
        let binding_point = cv_sum - ValueCommitment::derive(signed_value, zero_trapdoor);
        VerificationKey::<Binding>::try_from(binding_point.to_bytes())
            .map_err(|_| RawV5Error::InvalidOrchardBindingSignature)?
            .verify(shielded_sighash, &Signature::<Binding>::from(*self.binding_sig))
            .map_err(|_| RawV5Error::InvalidOrchardBindingSignature)?;

        Ok(instances)
    }
}

/// Original NU5 coinbase ciphertext subrelation on one exact raw action.
/// The actual nf supplies rho even for dummy spends; rk is irrelevant here.
/// Full 580-byte note and 80-byte outgoing ciphertexts are authenticated by
/// upstream recovery with zero OVK. No Action/VK construction, proof check,
/// recovered-value cap or reward-validity claim is involved.
///
/// Failure is redacted and indexed at zero for this standalone helper. An
/// undefined note commitment fails typed through maintained Note construction;
/// the original implementation panicked there, not successfully recovered.
pub fn recover_orchard_coinbase_action(action: &[u8; ACTION_BYTES]) -> Result<u64, RawV5Error> {
    let failure = RawV5Error::CoinbaseRecovery { index: 0 };
    let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(
        action[..32].try_into().expect("32-byte value commitment"),
    )).ok_or(failure)?;
    let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(
        action[32..64].try_into().expect("32-byte nullifier"),
    )).ok_or(failure)?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
        action[96..128].try_into().expect("32-byte note commitment"),
    )).ok_or(failure)?;
    let output = CoinbaseOutput(action);
    // CompactAction supplies only the public rho-domain constructor. Recovery
    // below uses the borrowed FULL ciphertext, never compact trial decryption.
    let compact = CompactAction::from_parts(
        nullifier, cmx, output.ephemeral_key(),
        action[160..212].try_into().expect("52-byte compact ciphertext"),
    );
    let domain = OrchardDomain::for_compact_action(&compact);
    let (note, _, _) = try_output_recovery_with_ovk(
        &domain, &OutgoingViewingKey::from([0; 32]), &output, &cv,
        action[740..820].try_into().expect("80-byte outgoing ciphertext"),
    ).ok_or(failure)?;
    Ok(note.value().inner())
}

struct CoinbaseOutput<'a>(&'a [u8; ACTION_BYTES]);

impl ShieldedOutput<OrchardDomain, 580> for CoinbaseOutput<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0[128..160].try_into().expect("32-byte raw ephemeral key"))
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.0[96..128].try_into().expect("32-byte raw note commitment")
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.0[160..740].try_into().expect("580-byte full note ciphertext")
    }
}

struct DecodedAction {
    cv_net: ValueCommitment,
    nullifier: Nullifier,
    rk: VerificationKey<SpendAuth>,
    cmx: ExtractedNoteCommitment,
}

fn decode_action(action: &[u8], index: usize) -> Result<DecodedAction, RawV5Error> {
    let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(
        action[..32].try_into().expect("32-byte value commitment"),
    )).ok_or(RawV5Error::InvalidOrchardValueCommitment { index })?;
    let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(
        action[32..64].try_into().expect("32-byte nullifier"),
    )).ok_or(RawV5Error::InvalidOrchardNullifier { index })?;
    let rk = VerificationKey::<SpendAuth>::try_from(
        <[u8; 32]>::try_from(&action[64..96]).expect("32-byte randomized key"),
    ).map_err(|_| RawV5Error::InvalidOrchardRandomizedKey { index })?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
        action[96..128].try_into().expect("32-byte note commitment"),
    )).ok_or(RawV5Error::InvalidOrchardNoteCommitment { index })?;
    Ok(DecodedAction { cv_net, nullifier, rk, cmx })
}

fn hasher(personalization: &[u8; 16]) -> blake2b_simd::State {
    Params::new().hash_length(32).personal(personalization).to_state()
}

fn compact_size(reader: &mut &[u8]) -> Result<usize, RawV5Error> {
    CompactSize::read_t(reader).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            RawV5Error::Truncated
        } else {
            RawV5Error::InvalidCompactSize
        }
    })
}

fn require_width(reader: &[u8], count: usize, width: usize) -> Result<usize, RawV5Error> {
    let length = count.checked_mul(width).ok_or(RawV5Error::TransactionTooLarge)?;
    if reader.len() < length {
        return Err(RawV5Error::Truncated);
    }
    Ok(length)
}

fn take_counted<'a>(reader: &mut &'a [u8], count: usize, width: usize) -> Result<&'a [u8], RawV5Error> {
    let length = require_width(reader, count, width)?;
    take(reader, length)
}

fn take<'a>(reader: &mut &'a [u8], length: usize) -> Result<&'a [u8], RawV5Error> {
    if reader.len() < length {
        return Err(RawV5Error::Truncated);
    }
    let (field, remaining) = reader.split_at(length);
    *reader = remaining;
    Ok(field)
}
