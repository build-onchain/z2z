//! Finite NU5–NU6.3 V5/V6 digests in raw BLAKE2b byte order.
//!
//! Actual previous outputs must be supplied in original `vin` order, after UTXO
//! resolution and before marking inputs spent. This primitive binds that data;
//! it does not prove UTXO existence, source validity, proofs or signatures.
//! Callers parsing bytes must exhaust the reader and check canonical round-trip
//! equality. The maintained typed parser's historical Orchard acceptance limits
//! are not repaired or bypassed here.

use std::{cell::Cell, fmt};

use blake2b_simd::Hash as Blake2bHash;
use zcash_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData, TxDigests, TxVersion,
    sighash::{SignableInput, signature_hash},
    txid::{TxIdDigester, to_txid},
};
use orchard::{ValuePool, bundle::BundleVersion};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{
    address::Script,
    bundle::{self as transparent, TxOut},
    sighash::{
        SIGHASH_MASK, SIGHASH_SINGLE, SighashType,
        SignableInput as TransparentInput, TransparentAuthorizingContext,
    },
};

use crate::orchard_original::{PostNu63OrchardError, PostNu63OrchardVerifier};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostNu5SighashError {
    UnsupportedVersion,
    UnsupportedBranch,
    IncompatibleTransaction,
    PrevoutCountMismatch { expected: usize, actual: usize },
    InvalidHashType,
    InputIndexOutOfRange,
    SingleOutputMissing,
}

impl fmt::Display for PostNu5SighashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrevoutCountMismatch { expected, actual } => write!(
                formatter, "expected {expected} actual transparent previous outputs, got {actual}",
            ),
            _ => formatter.write_str(match self {
                Self::UnsupportedVersion => "not an exact V5 or V6 transaction",
                Self::UnsupportedBranch => "post-NU5 digest profile requires V5 NU5 through NU6.3 or V6 NU6.3",
                Self::IncompatibleTransaction => "transaction contains incompatible shielded bundle data",
                Self::InvalidHashType => "invalid ZIP244 transparent hash type",
                Self::InputIndexOutOfRange => "transparent spend input index is out of range",
                Self::SingleOutputMissing => "SIGHASH_SINGLE has no same-index output",
                Self::PrevoutCountMismatch { .. } => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for PostNu5SighashError {}

/// Authorized transparent input bytes plus all actual previous outputs.
/// Constructed only by the checked transaction-owning digest context.
#[derive(Debug)]
pub struct PostNu5TransparentContext {
    previous_outputs: Vec<TxOut>,
}

impl transparent::Authorization for PostNu5TransparentContext {
    type ScriptSig = Script;
}

impl TransparentAuthorizingContext for PostNu5TransparentContext {
    // The maintained trait requires owned Vecs. Amount collection and locking
    // script clones per non-ANYONECANPAY hash are unavoidable through this API;
    // the full transaction and cached effect digests are never cloned per call.
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.previous_outputs.iter().map(TxOut::value).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.previous_outputs.iter().map(|output| output.script_pubkey().clone()).collect()
    }
}

/// Keeps actual transparent scriptSigs and fully authorized Sapling/both typed pools.
#[derive(Debug)]
pub struct PostNu5Authorization;

impl Authorization for PostNu5Authorization {
    type TransparentAuth = PostNu5TransparentContext;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

// MapAuth borrows its mapper but transfers authorization once per bundle. Cell
// moves the owned previous outputs at that exact point without cloning them.
struct AttachPrevouts(Cell<Vec<TxOut>>);

impl transparent::MapAuth<transparent::Authorized, PostNu5TransparentContext> for AttachPrevouts {
    fn map_script_sig(&self, script_sig: Script) -> Script {
        script_sig
    }

    fn map_authorization(&self, _: transparent::Authorized) -> PostNu5TransparentContext {
        PostNu5TransparentContext { previous_outputs: self.0.take() }
    }
}

/// Owns actual V5/NU5–NU6.3 or V6/NU6.3 data and its complete original identity.
/// Actual previous outputs follow original `vin` order, including inputs other
/// than the selected transparent spend. Coinbase requires an empty context.
#[derive(Debug)]
pub struct PostNu5SignatureHash {
    transaction: TransactionData<PostNu5Authorization>,
    txid_parts: TxDigests<Blake2bHash>,
    effect_id: [u8; 32],
    auth_digest: [u8; 32],
    shielded: [u8; 32],
}

impl PostNu5SignatureHash {
    fn check_context(transaction: &TransactionData<Authorized>, previous_output_count: usize) -> Result<(), PostNu5SighashError> {
        match transaction.version() {
            TxVersion::V5 => {
                if !matches!(transaction.consensus_branch_id(),
                    BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3)
                {
                    return Err(PostNu5SighashError::UnsupportedBranch);
                }
            }
            TxVersion::V6 => {
                if transaction.consensus_branch_id() != BranchId::Nu6_3 {
                    return Err(PostNu5SighashError::UnsupportedBranch);
                }
            }
            _ => return Err(PostNu5SighashError::UnsupportedVersion),
        }
        if transaction.sprout_bundle().is_some()
            || (transaction.version() == TxVersion::V5 && transaction.ironwood_bundle().is_some())
        {
            return Err(PostNu5SighashError::IncompatibleTransaction);
        }
        let expected = transaction.transparent_bundle().map_or(0, |bundle| {
            if bundle.is_coinbase() { 0 } else { bundle.vin.len() }
        });
        if previous_output_count != expected {
            return Err(PostNu5SighashError::PrevoutCountMismatch {
                expected, actual: previous_output_count,
            });
        }
        Ok(())
    }

    pub fn new(transaction: Transaction, previous_outputs: Vec<TxOut>) -> Result<Self, PostNu5SighashError> {
        Self::check_context(&transaction, previous_outputs.len())?;

        // The original authorized data owns the auth commitment; the context
        // adapter deliberately is not a substitute BlockTxCommitmentDigester.
        let effect_id = transaction.txid().into();
        let auth_digest = transaction.auth_commitment().as_bytes().try_into()
            .expect("ZIP244 authorizing commitment is 32 bytes");
        let txid_parts = transaction.digest(TxIdDigester);
        Ok(Self::from_checked_parts(
            transaction.into_data(), previous_outputs, txid_parts, effect_id, auth_digest,
        ))
    }

    /// Internal raw-byte Orchard adapter seam. The projection retains all other
    /// original bundles/auth bytes; the raw owner supplies FULL actual effect
    /// parts and auth commitment, never the projection's incomplete identities.
    /// This deliberately is not a public caller-controlled digest override.
    pub(crate) fn from_projection(
        transaction: TransactionData<Authorized>,
        previous_outputs: Vec<TxOut>,
        txid_parts: TxDigests<Blake2bHash>,
        auth_digest: [u8; 32],
    ) -> Result<Self, PostNu5SighashError> {
        if transaction.version() != TxVersion::V5 {
            return Err(PostNu5SighashError::UnsupportedVersion);
        }
        Self::check_context(&transaction, previous_outputs.len())?;
        if transaction.transparent_bundle().is_some() != txid_parts.transparent_digests.is_some()
            || txid_parts.ironwood_digest.is_some()
        {
            return Err(PostNu5SighashError::IncompatibleTransaction);
        }
        let effect_id = to_txid(transaction.version(), transaction.consensus_branch_id(), &txid_parts).into();
        Ok(Self::from_checked_parts(transaction, previous_outputs, txid_parts, effect_id, auth_digest))
    }

    fn from_checked_parts(
        transaction: TransactionData<Authorized>,
        previous_outputs: Vec<TxOut>,
        txid_parts: TxDigests<Blake2bHash>,
        effect_id: [u8; 32],
        auth_digest: [u8; 32],
    ) -> Self {
        let transaction = transaction.map_authorization::<PostNu5Authorization>(
            AttachPrevouts(Cell::new(previous_outputs)), (), (),
        );
        let shielded = *signature_hash(&transaction, &SignableInput::Shielded, &txid_parts).as_ref();
        Self { transaction, txid_parts, effect_id, auth_digest, shielded }
    }

    /// Signature message for shielded authorization, committing every actual
    /// transparent prevout amount and scriptPubKey for mixed-input transactions.
    pub fn shielded(&self) -> [u8; 32] {
        self.shielded
    }

    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    pub fn auth_digest(&self) -> [u8; 32] {
        self.auth_digest
    }

    /// Only 01/02/03/81/82/83 are legal. The selected input uses its actual
    /// previous output scriptPubKey, never the evaluator's P2SH redeemscript.
    /// Missing SINGLE outputs reject before the maintained helper's empty hash.
    pub fn transparent(&self, input_index: usize, raw_hash_type: u8) -> Result<[u8; 32], PostNu5SighashError> {
        let hash_type = SighashType::parse(raw_hash_type).ok_or(PostNu5SighashError::InvalidHashType)?;
        let bundle = self.transaction.transparent_bundle()
            .ok_or(PostNu5SighashError::InputIndexOutOfRange)?;
        let previous_output = bundle.authorization.previous_outputs.get(input_index)
            .ok_or(PostNu5SighashError::InputIndexOutOfRange)?;
        if raw_hash_type & SIGHASH_MASK == SIGHASH_SINGLE && input_index >= bundle.vout.len() {
            return Err(PostNu5SighashError::SingleOutputMissing);
        }
        let input = TransparentInput::from_parts(
            bundle, hash_type, input_index, previous_output.script_pubkey(),
            previous_output.script_pubkey(), previous_output.value(),
        ).map_err(|_| PostNu5SighashError::InputIndexOutOfRange)?;
        Ok(*signature_hash(&self.transaction, &SignableInput::Transparent(input), &self.txid_parts).as_ref())
    }

    /// Typed construction retains all original effects and authorizing bytes.
    /// Internal raw-Orchard construction retains the transparent/Sapling
    /// projection here: its raw owner must keep the actual Orchard data for
    /// crypto/ledger consumers. Cached roots always describe the full transaction.
    pub fn transaction(&self) -> &TransactionData<PostNu5Authorization> {
        &self.transaction
    }

    /// Move all actual owned bundles without copying outputs. A raw V5 caller
    /// must retain its borrowed Orchard descriptor and the full cached effect ID.
    pub(crate) fn into_transaction(self) -> TransactionData<PostNu5Authorization> {
        self.transaction
    }
}

/// Verifies actual Sapling proofs, SpendAuth and binding signatures using this
/// guarded context's complete shielded ALL message. Absence of Sapling succeeds;
/// this does not verify Orchard, UTXO/anchor availability or ledger admission.
pub fn verify_sapling_post_nu5_crypto(hashes: &PostNu5SignatureHash) -> Result<(), crate::sapling_crypto::SaplingCryptoError> {
    let transaction = hashes.transaction();
    let Some(bundle) = transaction.sapling_bundle() else { return Ok(()); };
    crate::sapling_crypto::verify_sapling_bundle_crypto(
        bundle, transaction.consensus_branch_id(), hashes.shielded(),
    )
}

/// Redacted actual-transaction route, signature and proof failures. Pool tags
/// distinguish independent bundle slots; supplied bytes are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostNu63CryptoError {
    UnsupportedVersion,
    UnsupportedBranch,
    IncompleteTransaction,
    InvalidBundleVersion { pool: ValuePool },
    InvalidFlags { pool: ValuePool },
    InvalidSpendAuth { pool: ValuePool, index: usize },
    InvalidBindingSignature { pool: ValuePool },
    Proof { pool: ValuePool, error: PostNu63OrchardError },
}

impl fmt::Display for PostNu63CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("NU6.3 crypto requires an actual V5 or V6 transaction"),
            Self::UnsupportedBranch => formatter.write_str("NU6.3 crypto requires the encoded NU6.3 consensus branch"),
            Self::IncompleteTransaction => formatter.write_str("typed NU6.3 crypto cannot verify a raw Orchard projection"),
            Self::InvalidBundleVersion { pool } => write!(formatter, "wrong NU6.3 {pool:?} bundle version"),
            Self::InvalidFlags { pool } => write!(formatter, "invalid NU6.3 {pool:?} bundle flags"),
            Self::InvalidSpendAuth { pool, index } => write!(formatter, "NU6.3 {pool:?} action {index} SpendAuth verification failed"),
            Self::InvalidBindingSignature { pool } => write!(formatter, "NU6.3 {pool:?} binding signature verification failed"),
            Self::Proof { pool, error } => write!(formatter, "NU6.3 {pool:?}: {error}"),
        }
    }
}

impl std::error::Error for PostNu63CryptoError {}

/// Verifies BOTH actual typed NU6.3 pools: every Halo2 proof, every Action's
/// SpendAuth (including disabled/padding spends), and every binding signature.
/// The one cached PostNu6_3 key is shared across both slots. Orchard must be
/// restricted V3; Ironwood V3 permits either cross-address setting. This is not
/// Sapling verification, zero-OVK recovery, anchor/spentness or ledger admission.
pub fn verify_post_nu63_crypto(hashes: &PostNu5SignatureHash) -> Result<(), PostNu63CryptoError> {
    let transaction = hashes.transaction();
    if !matches!(transaction.version(), TxVersion::V5 | TxVersion::V6) {
        return Err(PostNu63CryptoError::UnsupportedVersion);
    }
    if transaction.consensus_branch_id() != BranchId::Nu6_3 {
        return Err(PostNu63CryptoError::UnsupportedBranch);
    }
    if transaction.orchard_bundle().is_some() != hashes.txid_parts.orchard_digest.is_some()
        || transaction.ironwood_bundle().is_some() != hashes.txid_parts.ironwood_digest.is_some()
    {
        return Err(PostNu63CryptoError::IncompleteTransaction);
    }
    // Check both routes before expensive key setup or any cryptographic work.
    for (pool, bundle, version) in [
        (ValuePool::Orchard, transaction.orchard_bundle(), BundleVersion::orchard_v3()),
        (ValuePool::Ironwood, transaction.ironwood_bundle(), BundleVersion::ironwood_v3()),
    ] {
        let Some(bundle) = bundle else { continue; };
        if bundle.bundle_version() != version {
            return Err(PostNu63CryptoError::InvalidBundleVersion { pool });
        }
        if (!bundle.flags().spends_enabled() && !bundle.flags().outputs_enabled())
            || (pool == ValuePool::Orchard && bundle.flags().cross_address_enabled())
        {
            return Err(PostNu63CryptoError::InvalidFlags { pool });
        }
    }
    verify_post_nu63_bundles([
        (ValuePool::Orchard, transaction.orchard_bundle()),
        (ValuePool::Ironwood, transaction.ironwood_bundle()),
    ], hashes.shielded())
}

/// Borrowed pure-Ironwood V6 seam: avoids cloning a complete retained host
/// transaction just to attach an empty transparent authorization context.
/// Other legs are rejected before using the pure-shielded effect/sighash equality.
pub fn verify_pure_v6_authorization(transaction: &Transaction) -> Result<(), PostNu63CryptoError> {
    if transaction.version() != TxVersion::V6 { return Err(PostNu63CryptoError::UnsupportedVersion); }
    if transaction.consensus_branch_id() != BranchId::Nu6_3 { return Err(PostNu63CryptoError::UnsupportedBranch); }
    if transaction.transparent_bundle().is_some() || transaction.sprout_bundle().is_some()
        || transaction.sapling_bundle().is_some() || transaction.orchard_bundle().is_some()
        || transaction.ironwood_bundle().is_none()
    { return Err(PostNu63CryptoError::IncompleteTransaction); }
    let bundle = transaction.ironwood_bundle().expect("checked Ironwood presence");
    if bundle.bundle_version() != BundleVersion::ironwood_v3() {
        return Err(PostNu63CryptoError::InvalidBundleVersion { pool: ValuePool::Ironwood });
    }
    if !bundle.flags().spends_enabled() && !bundle.flags().outputs_enabled() {
        return Err(PostNu63CryptoError::InvalidFlags { pool: ValuePool::Ironwood });
    }
    verify_post_nu63_bundles([
        (ValuePool::Orchard, None), (ValuePool::Ironwood, Some(bundle)),
    ], transaction.txid().into())
}

fn verify_post_nu63_bundles(
    bundles: [(ValuePool, Option<&orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>>); 2],
    shielded: [u8; 32],
) -> Result<(), PostNu63CryptoError> {
    // Validate both actual slots before key setup or signature/proof work.
    for (pool, bundle) in bundles {
        let Some(bundle) = bundle else { continue; };
        let count = bundle.actions().len();
        let proof_length = bundle.authorization().proof().as_ref().len();
        let shape_error = if count > 65_535 { Some(PostNu63OrchardError::TooManyInstances) }
            else if proof_length > 2 * 1024 * 1024 { Some(PostNu63OrchardError::ProofTooLarge) }
            else if proof_length != orchard::Proof::expected_proof_size(count) { Some(PostNu63OrchardError::InvalidProofLength) }
            else { None };
        if let Some(error) = shape_error { return Err(PostNu63CryptoError::Proof { pool, error }); }
    }
    for (pool, bundle) in bundles {
        let Some(bundle) = bundle else { continue; };
        for (index, action) in bundle.actions().iter().enumerate() {
            action.rk().verify(&shielded, action.authorization())
                .map_err(|_| PostNu63CryptoError::InvalidSpendAuth { pool, index })?;
        }
        bundle.binding_validating_key().verify(&shielded, bundle.authorization().binding_signature())
            .map_err(|_| PostNu63CryptoError::InvalidBindingSignature { pool })?;
        let instances: Vec<_> = bundle.actions().iter()
            .map(|action| action.to_instance(*bundle.flags(), *bundle.anchor())).collect();
        // The maintained Proof API owns its input: one bounded proof-byte copy
        // is unavoidable through the existing cached-key typed consumer seam.
        PostNu63OrchardVerifier::new().verify_instances(&instances, bundle.authorization().proof().as_ref())
            .map_err(|error| PostNu63CryptoError::Proof { pool, error })?;
    }
    Ok(())
}
