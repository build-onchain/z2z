use std::fmt;

use orchard::{
    bundle::BatchValidator,
    circuit::{OrchardCircuitVersion, VerifyingKey},
};
use rand_core::{CryptoRng, RngCore};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

/// Parsing and local cryptographic checks are not chain admission or settlement facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    MalformedTransaction,
    NonCanonicalEncoding,
    WrongVersion,
    WrongBranch,
    UnsupportedComponents,
    MissingIronwood,
    WrongBundleVersion,
    WrongCircuitVersion,
    InvalidAuthorization,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ironwood transaction check failed: {self:?}")
    }
}

impl std::error::Error for ValidationError {}

/// A canonically parsed, Ironwood-only v6 transaction. No history validity is implied.
pub struct IronwoodTransaction {
    transaction: Transaction,
}

impl fmt::Debug for IronwoodTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IronwoodTransaction([redacted])")
    }
}

impl IronwoodTransaction {
    pub fn parse(bytes: &[u8], expected_branch: BranchId) -> Result<Self, ValidationError> {
        if expected_branch != BranchId::Nu6_3 { return Err(ValidationError::WrongBranch); }
        let transaction = ziquid_proofs::native_relation::parse_transaction(bytes).map_err(|error| {
            use ziquid_proofs::native_relation::NativeRelationError as E;
            match error {
                E::WrongVersion => ValidationError::WrongVersion,
                E::WrongBranch => ValidationError::WrongBranch,
                E::UnsupportedPool => ValidationError::UnsupportedComponents,
                E::MissingIronwood => ValidationError::MissingIronwood,
                E::WrongBundleVersion => ValidationError::WrongBundleVersion,
                E::NonCanonicalEncoding => ValidationError::NonCanonicalEncoding,
                _ => ValidationError::MalformedTransaction,
            }
        })?;
        Ok(Self { transaction })
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Consensus effect identifier; not a hiding payment commitment.
    pub fn effect_id(&self) -> [u8; 32] {
        self.transaction.txid().into()
    }

    /// Consensus authorizing-data digest, separately binding proof, anchor and signatures.
    pub fn authorization_id(&self) -> [u8; 32] {
        self.transaction
            .auth_commitment()
            .as_bytes()
            .try_into()
            .expect("upstream authorizing digest is 32 bytes")
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ValidationError> {
        let mut bytes = Vec::new();
        self.transaction
            .write(&mut bytes)
            .map_err(|_| ValidationError::MalformedTransaction)?;
        Ok(bytes)
    }

    /// Verifies every action SpendAuth, binding signature and Ironwood Halo2 proof.
    /// Does not establish admissible anchor, unspent status, finality, fees or U ownership.
    pub fn verify_authorization<R: RngCore + CryptoRng>(
        &self,
        verifying_key: &VerifyingKey,
        rng: &mut R,
    ) -> Result<(), ValidationError> {
        if verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3 {
            return Err(ValidationError::WrongCircuitVersion);
        }
        let bundle = self
            .transaction
            .ironwood_bundle()
            .ok_or(ValidationError::MissingIronwood)?;
        // For v6 without transparent components the shielded signature digest equals
        // the txid: sighash_v6 and to_txid use identical empty-transparent digests.
        let mut validator = BatchValidator::new(verifying_key);
        validator
            .add_bundle(bundle, self.effect_id())
            .map_err(|_| ValidationError::InvalidAuthorization)?;
        if validator.validate(rng) {
            Ok(())
        } else {
            Err(ValidationError::InvalidAuthorization)
        }
    }
}
