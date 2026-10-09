//! Stateless verification of original, NU6.2 fixed and post-NU6.3 Orchard proofs.
//!
//! The fixed `InsecurePreNu6_2` circuit is historically unsound; reproducing its
//! deployed verifying key is replay compatibility, not a repair or financial
//! validity claim. Public inputs are anchor, cv_net coordinates, nullifier, rk
//! coordinates, cmx, enableSpend and enableOutput. No EPK, ciphertext, signature,
//! transaction digest, history, spentness or asset-transfer fact is checked.
//!
//! Identity rk is an explicitly unsupported domain: the old node's affine
//! coordinate extraction crashed there, and the maintained public constructor
//! cannot represent it. This is not a claim that the original mathematical
//! relation or specification rejected identity rk.
//!
//! [`FixedOrchardVerifier`] pins `FixedPostNu6_2`, rejects identity rk and
//! enforces exact Action-count-dependent proof framing. It still checks only
//! the Action proof relation, not transaction authorization or ledger validity.
//!
//! [`PostNu63OrchardVerifier`] pins the `PostNu6_3` key shared by the Orchard
//! and Ironwood proof relation. It binds the supplied cross-address restriction
//! but does not identify a pool: an Orchard transaction consumer must separately
//! require that restriction, authenticate its transaction and enforce ledger rules.

use std::{fmt, sync::LazyLock};

use orchard::{
    Proof,
    bundle::{BundleVersion, Flags},
    circuit::{Instance, OrchardCircuitVersion, VerifyingKey},
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas::{SpendAuth, VerificationKey},
    tree::Anchor,
    value::ValueCommitment,
};

// Local resource limits, not claimed historical consensus/proof-size rules.
const MAX_INSTANCES: usize = 65_535;
const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;

// Orchard builds deterministic Halo2 Params with K=11 and keygen_vk over the
// historical empty circuit. No proving key, ceremony artifact or RNG is needed.
static ORIGINAL_VK: LazyLock<VerifyingKey> =
    LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::InsecurePreNu6_2));

/// Canonical encodings of one original Orchard Action's public inputs.
///
/// `flags` must be 1, 2 or 3: bit 0 enables spends and bit 1 enables outputs.
/// The caller supplies instances only; this type is not a parsed transaction or
/// proof of a valid historical bundle (whose anchor/flags are shared).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OriginalActionInstance {
    pub anchor: [u8; 32],
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub flags: u8,
}

/// Redacted failure categories; no raw public inputs, proof bytes or library
/// transcript diagnostics are retained or exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalOrchardError {
    EmptyInstances,
    TooManyInstances,
    ProofTooLarge,
    InvalidFlags { index: usize },
    InvalidAnchor { index: usize },
    InvalidValueCommitment { index: usize },
    InvalidNullifier { index: usize },
    InvalidRandomizedKey { index: usize },
    InvalidNoteCommitment { index: usize },
    /// Unsupported historical node-crash domain, not a spec rejection claim.
    UnsupportedIdentityKey { index: usize },
    InvalidProof,
}

impl fmt::Display for OriginalOrchardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInstances => formatter.write_str("original Orchard proof requires at least one action"),
            Self::TooManyInstances => formatter.write_str("original Orchard action resource limit exceeded"),
            Self::ProofTooLarge => formatter.write_str("original Orchard proof resource limit exceeded"),
            Self::InvalidFlags { index } => write!(formatter, "invalid original Orchard action {index} flags"),
            Self::InvalidAnchor { index } => write!(formatter, "invalid original Orchard action {index} anchor encoding"),
            Self::InvalidValueCommitment { index } => write!(formatter, "invalid original Orchard action {index} value commitment encoding"),
            Self::InvalidNullifier { index } => write!(formatter, "invalid original Orchard action {index} nullifier encoding"),
            Self::InvalidRandomizedKey { index } => write!(formatter, "invalid original Orchard action {index} randomized key encoding"),
            Self::InvalidNoteCommitment { index } => write!(formatter, "invalid original Orchard action {index} note commitment encoding"),
            Self::UnsupportedIdentityKey { index } => write!(formatter, "unsupported original Orchard action {index} identity randomized key"),
            Self::InvalidProof => formatter.write_str("original Orchard Halo2 proof verification failed"),
        }
    }
}

impl std::error::Error for OriginalOrchardError {}

/// Verifier pinned to the original deployed Orchard circuit, with no caller
/// key selection, later-circuit fallback, prover, mock or randomized batching.
pub struct OriginalOrchardVerifier {
    vk: &'static VerifyingKey,
}

impl Default for OriginalOrchardVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl OriginalOrchardVerifier {
    /// Builds the original deterministic verifying key once per process; later
    /// verifier construction and verification reuse the same cached key.
    pub fn new() -> Self {
        Self { vk: &ORIGINAL_VK }
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        self.vk
    }

    /// Verifies a nonempty, bounded list of canonical original public inputs
    /// against the borrowed proof using the actual Halo2 single-proof verifier.
    ///
    /// This checks only the original proof subrelation. The local resource caps
    /// are 65,535 instances and 2 MiB of proof bytes, checked before allocation.
    /// No exact proof-length rule is imposed: original transcript acceptance,
    /// including any trailing-byte behavior, is delegated to Halo2.
    pub fn verify(
        &self,
        instances: &[OriginalActionInstance],
        proof: &[u8],
    ) -> Result<(), OriginalOrchardError> {
        if instances.is_empty() {
            return Err(OriginalOrchardError::EmptyInstances);
        }
        if instances.len() > MAX_INSTANCES {
            return Err(OriginalOrchardError::TooManyInstances);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(OriginalOrchardError::ProofTooLarge);
        }

        let mut decoded = Vec::with_capacity(instances.len());
        for (index, instance) in instances.iter().enumerate() {
            // Flags::from_byte permits 00; a nonempty original bundle must
            // enable spends or outputs, so reject that additional case here.
            let flags = Flags::from_byte(instance.flags, BundleVersion::orchard_insecure_v1())
                .filter(|flags| flags.spends_enabled() || flags.outputs_enabled())
                .ok_or(OriginalOrchardError::InvalidFlags { index })?;
            let anchor = Option::<Anchor>::from(Anchor::from_bytes(instance.anchor))
                .ok_or(OriginalOrchardError::InvalidAnchor { index })?;
            let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&instance.cv_net))
                .ok_or(OriginalOrchardError::InvalidValueCommitment { index })?;
            let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&instance.nullifier))
                .ok_or(OriginalOrchardError::InvalidNullifier { index })?;
            let rk = VerificationKey::<SpendAuth>::try_from(instance.rk)
                .map_err(|_| OriginalOrchardError::InvalidRandomizedKey { index })?;
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&instance.cmx))
                .ok_or(OriginalOrchardError::InvalidNoteCommitment { index })?;
            decoded.push(
                Instance::from_parts(anchor, cv_net, nullifier, rk, cmx, flags)
                    .ok_or(OriginalOrchardError::UnsupportedIdentityKey { index })?,
            );
        }

        // The maintained Proof API owns a Vec, requiring this one bounded copy;
        // no further proof copy, exact-size gate or alternate relation is added.
        Proof::new(proof.to_vec())
            .verify(self.vk, &decoded)
            .map_err(|_| OriginalOrchardError::InvalidProof)
    }
}

// Deterministic NU6.2 circuit key, independently cached from historical replay.
static FIXED_VK: LazyLock<VerifyingKey> =
    LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2));

/// Redacted fixed-era input, framing and Halo2 proof failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedOrchardError {
    EmptyInstances,
    TooManyInstances,
    ProofTooLarge,
    InvalidProofLength,
    InvalidFlags { index: usize },
    InvalidAnchor { index: usize },
    InvalidValueCommitment { index: usize },
    InvalidNullifier { index: usize },
    /// Includes a canonically encoded identity randomized key.
    InvalidRandomizedKey { index: usize },
    InvalidNoteCommitment { index: usize },
    InvalidProof,
}

impl fmt::Display for FixedOrchardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInstances => formatter.write_str("fixed Orchard proof requires at least one action"),
            Self::TooManyInstances => formatter.write_str("fixed Orchard action resource limit exceeded"),
            Self::ProofTooLarge => formatter.write_str("fixed Orchard proof resource limit exceeded"),
            Self::InvalidProofLength => formatter.write_str("invalid fixed Orchard proof length"),
            Self::InvalidFlags { index } => write!(formatter, "invalid fixed Orchard action {index} flags"),
            Self::InvalidAnchor { index } => write!(formatter, "invalid fixed Orchard action {index} anchor encoding"),
            Self::InvalidValueCommitment { index } => write!(formatter, "invalid fixed Orchard action {index} value commitment encoding"),
            Self::InvalidNullifier { index } => write!(formatter, "invalid fixed Orchard action {index} nullifier encoding"),
            Self::InvalidRandomizedKey { index } => write!(formatter, "invalid fixed Orchard action {index} randomized key"),
            Self::InvalidNoteCommitment { index } => write!(formatter, "invalid fixed Orchard action {index} note commitment encoding"),
            Self::InvalidProof => formatter.write_str("fixed Orchard Halo2 proof verification failed"),
        }
    }
}

impl std::error::Error for FixedOrchardError {}

/// Action proof verifier pinned to `FixedPostNu6_2`, without caller key or
/// version selection. This does not admit a transaction or authenticate its
/// EPKs, ciphertexts, signatures, value balance, history or spentness.
pub struct FixedOrchardVerifier {
    vk: &'static VerifyingKey,
}

impl Default for FixedOrchardVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl FixedOrchardVerifier {
    /// Builds the deterministic fixed verifying key once per process.
    pub fn new() -> Self {
        Self { vk: &FIXED_VK }
    }

    /// Verifies canonical Action public inputs using the NU6.2 fixed key.
    ///
    /// Nonempty/count/local 2 MiB bounds and exact `2720 + 2272 * n` proof
    /// length are checked before allocating decoded instances. Fixed V2 flags
    /// enable cross-address transfers, leaving the tenth instance row zero.
    pub fn verify(
        &self,
        instances: &[OriginalActionInstance],
        proof: &[u8],
    ) -> Result<(), FixedOrchardError> {
        Self::check_shape(instances.len(), proof.len())?;

        let mut decoded = Vec::with_capacity(instances.len());
        for (index, instance) in instances.iter().enumerate() {
            let flags = Flags::from_byte(instance.flags, BundleVersion::orchard_v2())
                .filter(|flags| flags.spends_enabled() || flags.outputs_enabled())
                .ok_or(FixedOrchardError::InvalidFlags { index })?;
            let anchor = Option::<Anchor>::from(Anchor::from_bytes(instance.anchor))
                .ok_or(FixedOrchardError::InvalidAnchor { index })?;
            let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&instance.cv_net))
                .ok_or(FixedOrchardError::InvalidValueCommitment { index })?;
            let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&instance.nullifier))
                .ok_or(FixedOrchardError::InvalidNullifier { index })?;
            let rk = VerificationKey::<SpendAuth>::try_from(instance.rk)
                .map_err(|_| FixedOrchardError::InvalidRandomizedKey { index })?;
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&instance.cmx))
                .ok_or(FixedOrchardError::InvalidNoteCommitment { index })?;
            decoded.push(
                Instance::from_parts(anchor, cv_net, nullifier, rk, cmx, flags)
                    .ok_or(FixedOrchardError::InvalidRandomizedKey { index })?,
            );
        }

        self.verify_instances(&decoded, proof)
    }

    /// Typed consumer seam: preserves the same framing/resource gate without
    /// re-decoding or copying instances. Only the maintained Proof API's owned
    /// proof-byte copy is required before checking all supplied instances.
    pub(crate) fn verify_instances(
        &self,
        instances: &[Instance],
        proof: &[u8],
    ) -> Result<(), FixedOrchardError> {
        Self::check_shape(instances.len(), proof.len())?;
        Proof::new(proof.to_vec())
            .verify(self.vk, instances)
            .map_err(|_| FixedOrchardError::InvalidProof)
    }

    fn check_shape(count: usize, proof_len: usize) -> Result<(), FixedOrchardError> {
        if count == 0 {
            return Err(FixedOrchardError::EmptyInstances);
        }
        if count > MAX_INSTANCES {
            return Err(FixedOrchardError::TooManyInstances);
        }
        if proof_len > MAX_PROOF_BYTES {
            return Err(FixedOrchardError::ProofTooLarge);
        }
        // The count gate bounds this computation before multiplication.
        if proof_len != Proof::expected_proof_size(count) {
            return Err(FixedOrchardError::InvalidProofLength);
        }
        Ok(())
    }
}

// The post-NU6.3 circuit key is shared by the Orchard and Ironwood relations;
// pool/epoch selection and pool-specific rules belong to transaction consumers.
static POST_NU63_VK: LazyLock<VerifyingKey> =
    LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));

/// Canonical public inputs for one post-NU6.3 Action proof instance.
///
/// `flags` contains only the spend/output bits and must be 1, 2 or 3.
/// `disable_cross_address` is the actual circuit DISABLE input, not the V3
/// serialized flag byte's ENABLE bit. This type does not authenticate a pool,
/// transaction or bundle-wide uniformity of anchors and flags.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PostNu63ActionInstance {
    pub anchor: [u8; 32],
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub flags: u8,
    pub disable_cross_address: bool,
}

/// Redacted post-NU6.3 input, framing and Halo2 proof failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostNu63OrchardError {
    EmptyInstances,
    TooManyInstances,
    ProofTooLarge,
    InvalidProofLength,
    InvalidFlags { index: usize },
    InvalidAnchor { index: usize },
    InvalidValueCommitment { index: usize },
    InvalidNullifier { index: usize },
    /// Includes a canonically encoded identity randomized key.
    InvalidRandomizedKey { index: usize },
    InvalidNoteCommitment { index: usize },
    InvalidProof,
}

impl fmt::Display for PostNu63OrchardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInstances => formatter.write_str("post-NU6.3 Orchard proof requires at least one action"),
            Self::TooManyInstances => formatter.write_str("post-NU6.3 Orchard action resource limit exceeded"),
            Self::ProofTooLarge => formatter.write_str("post-NU6.3 Orchard proof resource limit exceeded"),
            Self::InvalidProofLength => formatter.write_str("invalid post-NU6.3 Orchard proof length"),
            Self::InvalidFlags { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} flags"),
            Self::InvalidAnchor { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} anchor encoding"),
            Self::InvalidValueCommitment { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} value commitment encoding"),
            Self::InvalidNullifier { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} nullifier encoding"),
            Self::InvalidRandomizedKey { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} randomized key"),
            Self::InvalidNoteCommitment { index } => write!(formatter, "invalid post-NU6.3 Orchard action {index} note commitment encoding"),
            Self::InvalidProof => formatter.write_str("post-NU6.3 Orchard Halo2 proof verification failed"),
        }
    }
}

impl std::error::Error for PostNu63OrchardError {}

/// Action proof verifier pinned to `PostNu6_3`, with no caller key selection.
///
/// Both restricted and unrestricted statements use this key. An Orchard
/// transaction consumer must separately require `disable_cross_address = true`;
/// accepting an unrestricted proof here is not Orchard pool authorization.
/// EPKs, ciphertexts, signatures, history, spentness and transfers are not checked.
pub struct PostNu63OrchardVerifier {
    vk: &'static VerifyingKey,
}

impl Default for PostNu63OrchardVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PostNu63OrchardVerifier {
    /// Builds the deterministic post-NU6.3 key once per process and reuses it.
    pub fn new() -> Self {
        Self { vk: &POST_NU63_VK }
    }

    /// Verifies canonical Action public inputs and their supplied restriction.
    ///
    /// Nonempty/count/local 2 MiB caps and exact `2720 + 2272 * n` framing are
    /// checked before allocating decoded instances or copying proof bytes.
    /// Identity value commitments are permitted; identity randomized keys are not.
    pub fn verify(
        &self,
        instances: &[PostNu63ActionInstance],
        proof: &[u8],
    ) -> Result<(), PostNu63OrchardError> {
        Self::check_shape(instances.len(), proof.len())?;

        let mut decoded = Vec::with_capacity(instances.len());
        for (index, instance) in instances.iter().enumerate() {
            if !matches!(instance.flags, 1..=3) {
                return Err(PostNu63OrchardError::InvalidFlags { index });
            }
            // V3 serializes ENABLE cross-address, while the public input and
            // frozen fixtures store DISABLE. Ironwood V3 can represent both;
            // using Orchard V3 here would silently impose pool authority.
            let flag_byte = instance.flags | (u8::from(!instance.disable_cross_address) << 2);
            let flags = Flags::from_byte(flag_byte, BundleVersion::ironwood_v3())
                .ok_or(PostNu63OrchardError::InvalidFlags { index })?;
            let anchor = Option::<Anchor>::from(Anchor::from_bytes(instance.anchor))
                .ok_or(PostNu63OrchardError::InvalidAnchor { index })?;
            let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&instance.cv_net))
                .ok_or(PostNu63OrchardError::InvalidValueCommitment { index })?;
            let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&instance.nullifier))
                .ok_or(PostNu63OrchardError::InvalidNullifier { index })?;
            let rk = VerificationKey::<SpendAuth>::try_from(instance.rk)
                .map_err(|_| PostNu63OrchardError::InvalidRandomizedKey { index })?;
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&instance.cmx))
                .ok_or(PostNu63OrchardError::InvalidNoteCommitment { index })?;
            decoded.push(
                Instance::from_parts(anchor, cv_net, nullifier, rk, cmx, flags)
                    .ok_or(PostNu63OrchardError::InvalidRandomizedKey { index })?,
            );
        }

        self.verify_instances(&decoded, proof)
    }

    /// Typed consumer seam with the same count/framing/resource gate before
    /// the maintained Proof API's bounded owned-byte copy. `Instance` already
    /// guarantees decoded canonical fields and a nonidentity randomized key.
    pub(crate) fn verify_instances(
        &self,
        instances: &[Instance],
        proof: &[u8],
    ) -> Result<(), PostNu63OrchardError> {
        Self::check_shape(instances.len(), proof.len())?;
        Proof::new(proof.to_vec())
            .verify(self.vk, instances)
            .map_err(|_| PostNu63OrchardError::InvalidProof)
    }

    fn check_shape(count: usize, proof_len: usize) -> Result<(), PostNu63OrchardError> {
        if count == 0 {
            return Err(PostNu63OrchardError::EmptyInstances);
        }
        if count > MAX_INSTANCES {
            return Err(PostNu63OrchardError::TooManyInstances);
        }
        if proof_len > MAX_PROOF_BYTES {
            return Err(PostNu63OrchardError::ProofTooLarge);
        }
        // The count gate bounds multiplication in the maintained size formula.
        if proof_len != Proof::expected_proof_size(count) {
            return Err(PostNu63OrchardError::InvalidProofLength);
        }
        Ok(())
    }
}


#[cfg(test)]
mod fixed_tests {
    use super::*;

    fn fixture_instance() -> (Instance, &'static [u8]) {
        let raw = include_bytes!("../tests/fixtures/orchard-fixed-proof.bin");
        let field = |offset| raw[offset..offset + 32].try_into().unwrap();
        let instance = Instance::from_parts(
            Option::<Anchor>::from(Anchor::from_bytes(field(0))).unwrap(),
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&field(32))).unwrap(),
            Option::<Nullifier>::from(Nullifier::from_bytes(&field(64))).unwrap(),
            VerificationKey::<SpendAuth>::try_from(field(96)).unwrap(),
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&field(128))).unwrap(),
            Flags::from_byte(raw[160] | (raw[161] << 1), BundleVersion::orchard_v2()).unwrap(),
        ).unwrap();
        (instance, &raw[162..])
    }

    #[test]
    fn typed_fixed_seam_checks_the_actual_proof_and_every_instance() {
        let (instance, proof) = fixture_instance();
        let verifier = FixedOrchardVerifier::default();
        verifier.verify_instances(std::slice::from_ref(&instance), proof).unwrap();
        let mut mutated = proof.to_vec();
        mutated[0] ^= 1;
        assert_eq!(
            verifier.verify_instances(std::slice::from_ref(&instance), &mutated),
            Err(FixedOrchardError::InvalidProof),
        );
        assert_eq!(
            verifier.verify_instances(&[instance.clone(), instance.clone()], proof),
            Err(FixedOrchardError::InvalidProofLength),
        );
        let mut framed = proof.to_vec();
        framed.resize(7264, 0);
        assert_eq!(
            verifier.verify_instances(&[instance.clone(), instance], &framed),
            Err(FixedOrchardError::InvalidProof),
        );
    }

    #[test]
    fn typed_fixed_seam_cannot_bypass_length_or_local_resource_guards() {
        let (instance, proof) = fixture_instance();
        let verifier = FixedOrchardVerifier::new();
        assert_eq!(
            verifier.verify_instances(&[], proof),
            Err(FixedOrchardError::EmptyInstances),
        );
        for length in [0, 1, 4991, 4993] {
            assert_eq!(
                verifier.verify_instances(std::slice::from_ref(&instance), &vec![0; length]),
                Err(FixedOrchardError::InvalidProofLength),
            );
        }
        let mut instances = vec![instance.clone(); 65_535];
        assert_eq!(
            verifier.verify_instances(&instances, &[]),
            Err(FixedOrchardError::InvalidProofLength),
        );
        instances.push(instance);
        assert_eq!(
            verifier.verify_instances(&instances, &[]),
            Err(FixedOrchardError::TooManyInstances),
        );
        let mut bytes = vec![0; 2 * 1024 * 1024];
        assert_eq!(
            verifier.verify_instances(&instances[..1], &bytes),
            Err(FixedOrchardError::InvalidProofLength),
        );
        bytes.push(0);
        assert_eq!(
            verifier.verify_instances(&instances[..1], &bytes),
            Err(FixedOrchardError::ProofTooLarge),
        );
    }
}

#[cfg(test)]
mod post_nu63_tests {
    use super::*;

    fn typed_fixture(raw: &'static [u8], flip_disable: bool) -> (Instance, &'static [u8]) {
        let field = |offset| raw[offset..offset + 32].try_into().unwrap();
        // The upstream fixture stores DISABLE; the V3 flag byte encodes ENABLE.
        let disable = (raw[162] != 0) ^ flip_disable;
        let flags = raw[160] | (raw[161] << 1) | (u8::from(!disable) << 2);
        let instance = Instance::from_parts(
            Option::<Anchor>::from(Anchor::from_bytes(field(0))).unwrap(),
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&field(32))).unwrap(),
            Option::<Nullifier>::from(Nullifier::from_bytes(&field(64))).unwrap(),
            VerificationKey::<SpendAuth>::try_from(field(96)).unwrap(),
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&field(128))).unwrap(),
            Flags::from_byte(flags, BundleVersion::ironwood_v3()).unwrap(),
        ).unwrap();
        (instance, &raw[163..])
    }

    #[test]
    fn typed_post_nu63_seam_binds_both_actual_proofs_and_disable_bits() {
        let verifier = PostNu63OrchardVerifier::default();
        for raw in [
            include_bytes!("../tests/fixtures/orchard-post-nu63.bin").as_slice(),
            include_bytes!("../tests/fixtures/orchard-post-nu63_restricted.bin").as_slice(),
        ] {
            let (instance, proof) = typed_fixture(raw, false);
            verifier.verify_instances(std::slice::from_ref(&instance), proof).unwrap();
            let (changed, _) = typed_fixture(raw, true);
            assert_eq!(
                verifier.verify_instances(&[changed], proof),
                Err(PostNu63OrchardError::InvalidProof),
            );
            let mut mutated = proof.to_vec();
            mutated[0] ^= 1;
            assert_eq!(
                verifier.verify_instances(std::slice::from_ref(&instance), &mutated),
                Err(PostNu63OrchardError::InvalidProof),
            );
            assert_eq!(
                verifier.verify_instances(&[instance.clone(), instance.clone()], proof),
                Err(PostNu63OrchardError::InvalidProofLength),
            );
            let mut framed = proof.to_vec();
            framed.resize(7264, 0);
            assert_eq!(
                verifier.verify_instances(&[instance.clone(), instance], &framed),
                Err(PostNu63OrchardError::InvalidProof),
            );
        }
    }

    #[test]
    fn typed_post_nu63_seam_cannot_bypass_framing_or_local_resource_guards() {
        let (instance, proof) = typed_fixture(
            include_bytes!("../tests/fixtures/orchard-post-nu63_restricted.bin"), false,
        );
        let verifier = PostNu63OrchardVerifier::new();
        assert_eq!(
            verifier.verify_instances(&[], proof),
            Err(PostNu63OrchardError::EmptyInstances),
        );
        for length in [0, 1, 4991, 4993, 7264] {
            assert_eq!(
                verifier.verify_instances(std::slice::from_ref(&instance), &vec![0; length]),
                Err(PostNu63OrchardError::InvalidProofLength),
            );
        }
        let mut instances = vec![instance.clone(); 65_535];
        assert_eq!(
            verifier.verify_instances(&instances, &[]),
            Err(PostNu63OrchardError::InvalidProofLength),
        );
        instances.push(instance);
        assert_eq!(
            verifier.verify_instances(&instances, &[]),
            Err(PostNu63OrchardError::TooManyInstances),
        );
        let mut bytes = vec![0; 2 * 1024 * 1024];
        assert_eq!(
            verifier.verify_instances(&instances[..1], &bytes),
            Err(PostNu63OrchardError::InvalidProofLength),
        );
        bytes.push(0);
        assert_eq!(
            verifier.verify_instances(&instances[..1], &bytes),
            Err(PostNu63OrchardError::ProofTooLarge),
        );
        assert_eq!(
            verifier.verify_instances(&instances[..921], &vec![0; 2_095_232]),
            Err(PostNu63OrchardError::InvalidProof),
        );
        assert_eq!(
            verifier.verify_instances(&instances[..922], &vec![0; 2_097_504]),
            Err(PostNu63OrchardError::ProofTooLarge),
        );
    }
}
