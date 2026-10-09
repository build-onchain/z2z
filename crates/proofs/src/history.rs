//! Deterministic full-body subrelations, NOT source-history validity or finality.
//!
//! The leaf count and both ordered digest trees come from complete parsed transaction
//! bodies; this API never accepts a caller's txid list, Merkle path, or state snapshot.
//! `ParsedBlockBody` remains an observation, including when its commitment equation
//! matches. It cannot authorize settlement and has no conversion to a verified fact.
//!
//! Missing full-validity checks: genesis bootstrap/predecessor-proof authentication,
//! connected chain selection, PoW/difficulty/time/work, subsidy/fees, transparent UTXOs
//! and scripts, all pool proofs/signatures/value transitions/nullifiers/trees/anchors,
//! history/upgrade transitions, competing-fork availability/freshness and finality.
//! Claimed height/branch consistency is structural, not a proven chain height.
//!
//! Consensus hash algorithms are taken from Zebra v6.4.2, commit
//! e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291:
//! `zebra-chain/src/block/{merkle,commitment}.rs` and
//! `zebra-consensus/src/block/check.rs::merkle_root_validity`.
//! Transaction parsing/digests use the pinned zcash_primitives 0.30.1 APIs.
//! Its block parser currently rejects genesis; no unauthenticated replacement is used.

use std::fmt;

pub(crate) use crate::canonical_bytes::CanonicalBytes;
use sha2::{Digest, Sha256};
use zcash_primitives::{
    block::Block,
    transaction::{Transaction, TxVersion},
};
use zcash_protocol::{
    consensus::{BranchId, NetworkType, NetworkUpgrade, Parameters},
    constants::MAX_BLOCK_BYTES,
};

/// Structural errors only. No error value represents a full consensus decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyError {
    BlockTooLarge,
    MalformedBlock,
    InvalidHeader,
    TrailingBytes,
    NoncanonicalEncoding,
    WrongConsensusBranch,
    DuplicateTransaction,
    MutatedMerkleTree,
    MerkleRootMismatch,
    BlockCommitmentMismatch,
    NotPostNu5,
    TransactionIndexOutOfBounds,
    MalformedSelectedTransaction,
    SelectedTransactionMismatch,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BlockTooLarge => "body exceeds maximum block size",
            Self::MalformedBlock => "malformed complete block body",
            Self::InvalidHeader => "invalid structural block header",
            Self::TrailingBytes => "bytes remain after complete body",
            Self::NoncanonicalEncoding => "body encoding is not canonical",
            Self::WrongConsensusBranch => {
                "transaction version or branch conflicts with claimed height"
            }
            Self::DuplicateTransaction => "duplicate transaction effect identity",
            Self::MutatedMerkleTree => "ambiguous transaction Merkle structure",
            Self::MerkleRootMismatch => "transaction Merkle root does not match header",
            Self::BlockCommitmentMismatch => {
                "history/auth commitment equation does not match header"
            }
            Self::NotPostNu5 => "header has no post-NU5 history/auth commitment",
            Self::TransactionIndexOutOfBounds => "selected transaction index is outside full body",
            Self::MalformedSelectedTransaction => "malformed selected transaction body",
            Self::SelectedTransactionMismatch => {
                "selected effect/auth body does not match block position"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BodyError {}

/// Effect and authorization digests derived together from ONE parsed transaction.
/// These bytes are private proof-witness material, not a public settlement journal.
pub struct BodyTransaction {
    effect_id: [u8; 32],
    auth_digest: Option<[u8; 32]>,
}

impl BodyTransaction {
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// `None` for pre-v5: its txid already commits to the complete transaction.
    pub fn auth_digest(&self) -> Option<[u8; 32]> {
        self.auth_digest
    }

    fn derive(transaction: &Transaction) -> Self {
        let auth_digest = match transaction.version() {
            TxVersion::V5 | TxVersion::V6 => Some(
                transaction
                    .auth_commitment()
                    .as_bytes()
                    .try_into()
                    .expect("upstream transaction auth digest has 32 bytes"),
            ),
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => None,
        };
        Self {
            effect_id: transaction.txid().into(),
            auth_digest,
        }
    }
}

/// Immutable, canonically parsed full body with checked transaction Merkle structure.
/// NOT a verified block, a history proof, or an authenticated predecessor state.
pub struct ParsedBlockBody {
    block: Block,
    transactions: Vec<BodyTransaction>,
    auth_data_root: [u8; 32],
    branch: BranchId,
    post_nu5: bool,
}

impl ParsedBlockBody {
    /// Parses every transaction, consumes every byte, checks canonical encoding,
    /// first/only coinbase (upstream), claimed-height branch consistency, uniqueness
    /// and the full effect-tree equation. No cryptographic authorization is verified.
    /// Network parameters are witness context; the eventual full guest must pin them.
    pub fn parse<P: Parameters>(bytes: &[u8], parameters: &P) -> Result<Self, BodyError> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(BodyError::BlockTooLarge);
        }
        let mut remaining = bytes;
        let block =
            Block::read(&mut remaining, parameters).map_err(|_| BodyError::MalformedBlock)?;
        if !remaining.is_empty() {
            return Err(BodyError::TrailingBytes);
        }
        let expected_solution_size = match parameters.network_type() {
            NetworkType::Regtest => 36,
            NetworkType::Main | NetworkType::Test => 1344,
        };
        if block.header().version < 4 || block.header().solution.len() != expected_solution_size {
            return Err(BodyError::InvalidHeader);
        }
        let mut canonical = CanonicalBytes { remaining: bytes };
        block
            .write(&mut canonical)
            .map_err(|_| BodyError::NoncanonicalEncoding)?;
        if !canonical.remaining.is_empty() {
            return Err(BodyError::NoncanonicalEncoding);
        }

        let branch = BranchId::for_height(parameters, block.claimed_height());
        let post_nu5 = parameters.is_nu_active(NetworkUpgrade::Nu5, block.claimed_height());
        let mut transactions = Vec::with_capacity(block.vtx().len());
        for transaction in block.vtx().iter() {
            if !transaction.version().valid_in_branch(branch)
                || transaction.consensus_branch_id() != branch
            {
                return Err(BodyError::WrongConsensusBranch);
            }
            transactions.push(BodyTransaction::derive(transaction));
        }

        // One reusable buffer: duplicate detection, effect tree, then auth tree.
        let padded_len = transactions.len().next_power_of_two();
        let mut nodes = Vec::with_capacity(padded_len);
        nodes.extend(transactions.iter().map(|tx| tx.effect_id));
        nodes.sort_unstable();
        if nodes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BodyError::DuplicateTransaction);
        }
        for (node, transaction) in nodes.iter_mut().zip(&transactions) {
            *node = transaction.effect_id;
        }
        let effect_root = effect_merkle_root(&mut nodes)?;
        if effect_root != block.header().merkle_root {
            return Err(BodyError::MerkleRootMismatch);
        }
        nodes.clear();
        nodes.extend(
            transactions
                .iter()
                .map(|tx| tx.auth_digest.unwrap_or([0xff; 32])),
        );
        nodes.resize(padded_len, [0; 32]);
        let auth_data_root = auth_merkle_root(&mut nodes);

        Ok(Self {
            block,
            transactions,
            auth_data_root,
            branch,
            post_nu5,
        })
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Both digests at the SAME full-body position; no caller-supplied leaves/count.
    pub fn transaction(&self, index: usize) -> Option<&BodyTransaction> {
        self.transactions.get(index)
    }

    /// Borrow the full parsed block for subsequent semantic/contextual relations.
    /// This immutable reference is not an assertion that any such checks ran.
    pub fn block(&self) -> &Block {
        &self.block
    }

    pub(crate) fn into_block(self) -> Block {
        self.block
    }

    pub fn auth_data_root(&self) -> [u8; 32] {
        self.auth_data_root
    }

    /// Checks the selected body's paired effect AND authorizing digest at its exact
    /// full-block position. Upstream `Transaction::PartialEq` compares txid only and
    /// is deliberately not used. This authenticates correspondence, not signatures.
    pub fn check_selected_transaction(&self, index: usize, bytes: &[u8]) -> Result<(), BodyError> {
        let expected = self
            .transactions
            .get(index)
            .ok_or(BodyError::TransactionIndexOutOfBounds)?;
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(BodyError::BlockTooLarge);
        }
        let mut remaining = bytes;
        let transaction = Transaction::read(&mut remaining, self.branch)
            .map_err(|_| BodyError::MalformedSelectedTransaction)?;
        if !remaining.is_empty() {
            return Err(BodyError::TrailingBytes);
        }
        let mut canonical = CanonicalBytes { remaining: bytes };
        transaction
            .write(&mut canonical)
            .map_err(|_| BodyError::NoncanonicalEncoding)?;
        if !canonical.remaining.is_empty() {
            return Err(BodyError::NoncanonicalEncoding);
        }
        let selected = BodyTransaction::derive(&transaction);
        if selected.effect_id != expected.effect_id || selected.auth_digest != expected.auth_digest
        {
            return Err(BodyError::SelectedTransactionMismatch);
        }
        Ok(())
    }

    /// Checks ONLY `hashBlockCommitments = H(history_root || auth_root || 0^256)`.
    /// `untrusted_history_root` is explicitly unauthenticated: a matching equation
    /// DOES NOT validate its ancestry, predecessor state, canonicality or finality.
    /// A future complete guest must derive it from genesis/verified predecessor proof.
    /// Never use this equation alone to admit a checkpoint or authorize settlement.
    pub fn check_post_nu5_commitment_equation(
        &self,
        untrusted_history_root: &[u8; 32],
    ) -> Result<(), BodyError> {
        if !self.post_nu5 {
            return Err(BodyError::NotPostNu5);
        }
        let computed = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZcashBlockCommit")
            .to_state()
            .update(untrusted_history_root)
            .update(&self.auth_data_root)
            .update(&[0; 32])
            .finalize();
        if computed.as_bytes() != self.block.header().final_sapling_root {
            return Err(BodyError::BlockCommitmentMismatch);
        }
        Ok(())
    }
}


pub(crate) fn effect_merkle_root(nodes: &mut Vec<[u8; 32]>) -> Result<[u8; 32], BodyError> {
    while nodes.len() > 1 {
        let width = nodes.len();
        for parent in 0..width.div_ceil(2) {
            let left = nodes[parent * 2];
            let right = nodes.get(parent * 2 + 1).copied().unwrap_or(left);
            if parent * 2 + 1 < width && left == right {
                return Err(BodyError::MutatedMerkleTree);
            }
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            nodes[parent] = Sha256::digest(hasher.finalize()).into();
        }
        nodes.truncate(width.div_ceil(2));
    }
    Ok(nodes[0]) // upstream Block::read guarantees a non-empty transaction set
}

pub(crate) fn auth_merkle_root(nodes: &mut Vec<[u8; 32]>) -> [u8; 32] {
    while nodes.len() > 1 {
        let width = nodes.len();
        for parent in 0..width / 2 {
            let hash = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"ZcashAuthDatHash")
                .to_state()
                .update(&nodes[parent * 2])
                .update(&nodes[parent * 2 + 1])
                .finalize();
            nodes[parent] = hash.as_bytes().try_into().expect("32-byte auth tree node");
        }
        nodes.truncate(width / 2);
    }
    nodes[0]
}
