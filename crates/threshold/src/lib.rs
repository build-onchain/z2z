//! Fresh-J 2-of-2 threshold machinery for the route-1a construction family.
//!
//! **Status: implemented primitives for investigation.** This module wraps the
//! installed cohort's FROST building blocks (reddsa 0.5.2 `frost::redpallas`
//! ciphersuite over frost-core 3.0.0) into the two ceremonies route 1a needs:
//!
//! 1. a **no-dealer 2-of-2 DKG** for the fresh joint-note key J (`ask` is
//!    never held complete by any party — the requirement that rules out the
//!    trusted dealer); and
//! 2. **external-alpha re-randomized signing**: the randomizer ("alpha", the
//!    future PCZT spend randomizer) is fixed before the signing session, both
//!    participants sign over it, and aggregation yields one 64-byte RedPallas
//!    SpendAuth signature — the artifact `pczt::...apply_orchard_spend_auth_signature`
//!    consumes after verifying it against the action's `rk`.
//!
//! Not reviewed as a composition, not audited beyond the upstream statuses
//! recorded in `docs/research/SETTLEMENT-RESEARCH.md` §10, and **not wired to
//! any wallet, chain, proof or financial flow**.
//!
//! **Audit surface:** unlike the earlier test-only setup, this crate carries
//! `reddsa` (with the `frost` feature) and `frost-rerandomized` as regular
//! dependencies of a workspace member, so their code is now part of the
//! workspace build. Upstream audit status (recorded in §10.4): NCC covers
//! frost-core at v0.6.0 only — not the installed 3.0.0 delta, not the reddsa
//! RedPallas ciphersuite, and not the re-randomized variant.
//!
//! **Secret handling:** `KeyShare` (the long-lived signing-share bytes) and
//! `Nonces` are owner-local secret material of the same guard class as the
//! workspace's other custody artifacts — never transmitted, never logged,
//! never persisted outside owner custody. `Nonces` deliberately exposes no
//! serialization API, so it cannot be placed on the wire by mistake; only
//! round packages, commitments, shares and the aggregate are exchanged.
//!
//! 3. the **§11.3 C-share release gate** ([`ShareGate`]) that withholds every
//!    usable C-side contribution until a caller-asserted verified target
//!    arming, and the **§11.2 signer semantic-review checks**
//!    ([`check_action_rk`], [`check_effects`]) each signer runs before
//!    emitting a share.
//!
//! Design notes recorded in §11 of the research doc:
//! - alpha MUST be freshly generated per spend and never reused across spends
//!   of the same key (linkability);
//! - nonces are one-use;
//! - the only installed entry point that expresses a fixed external alpha is
//!   the deprecated `frost_rerandomized::sign`; this module isolates that
//!   dependency so a future supported path can replace it in one place.

use std::collections::BTreeMap;

mod gate;
mod review;

pub use gate::{ArmingEvidence, GateError, Phase, ShareGate};
pub use review::{check_action_rk, check_effects, Effects, OutputEffect, ReviewError};

use rand_core::{CryptoRng, RngCore};
use reddsa::frost::redpallas::{
    self as rp, Ciphersuite, Field, Group, PallasBlake2b512,
    keys::{EvenY, dkg::{part1, part2, part3, round1 as dkg_round1, round2 as dkg_round2}},
    rerandomized::{RandomizedParams, Randomizer},
};
use zeroize::Zeroizing;

const MIN_SIGNERS: u16 = 2;
const MAX_SIGNERS: u16 = 2;

type Suite = PallasBlake2b512;

/// Failure classes surfaced by this module; the ciphersuite internals are
/// deliberately not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdError {
    /// The provided identifier or restored participant set does not match the session.
    Identifier,
    /// The session has fewer than 2 commitments, or too few shares to
    /// aggregate (2-of-2 quorum not met).
    InsufficientQuorum,
    /// Share and commitment sets disagree (missing, extra or duplicate
    /// participant).
    ShareSetMismatch,
    /// A share, the aggregate, or the final verification failed.
    InvalidShare,
    /// Malformed or non-canonical serialized material.
    Encode,
    /// Any other ciphersuite/session failure.
    Session,
}

fn map_error(error: rp::Error) -> ThresholdError {
    match error {
        rp::Error::IncorrectNumberOfCommitments | rp::Error::IncorrectNumberOfShares => {
            ThresholdError::InsufficientQuorum
        }
        rp::Error::UnknownIdentifier => ThresholdError::ShareSetMismatch,
        rp::Error::InvalidSignatureShare { .. } => ThresholdError::InvalidShare,
        rp::Error::SerializationError | rp::Error::DeserializationError => ThresholdError::Encode,
        _ => ThresholdError::Session,
    }
}

/// One of the two fixed participants of a fresh-J session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Participant {
    First,
    Second,
}

impl Participant {
    fn frost(self) -> rp::Identifier {
        let index: u16 = match self {
            Participant::First => 1,
            Participant::Second => 2,
        };
        rp::Identifier::try_from(index).expect("nonzero constant")
    }
}

/// A participant's long-lived DKG output: the group key share plus its
/// identifier. Owner-local secret material — never transmit or log.
pub struct KeyShare {
    participant: Participant,
    bytes: Zeroizing<Vec<u8>>,
}

impl KeyShare {
    /// Restores canonical 2-of-2 bytes for the embedded participant, checking
    /// the local signing/verifying share and normalized group-key encoding.
    /// The caller must still establish correspondence with the separately
    /// restored [`GroupPublicKey`] and the intended ceremony.
    pub fn from_bytes(
        participant: Participant,
        bytes: Vec<u8>,
    ) -> Result<Self, ThresholdError> {
        let bytes = Zeroizing::new(bytes);
        let package = rp::keys::KeyPackage::deserialize(&bytes)
            .map_err(|_| ThresholdError::Encode)?;
        let canonical = package.serialize().map(Zeroizing::new)
            .map_err(|_| ThresholdError::Encode)?;
        if canonical.as_slice() != bytes.as_slice() {
            return Err(ThresholdError::Encode);
        }
        if *package.identifier() != participant.frost() {
            return Err(ThresholdError::Identifier);
        }
        if *package.min_signers() != MIN_SIGNERS
            || *package.verifying_share() != rp::keys::VerifyingShare::from(*package.signing_share())
        {
            return Err(ThresholdError::Session);
        }
        // Canonical serialization rejects the identity; EvenY implements the
        // installed RedPallas group's normalized Orchard ak encoding.
        if !package.has_even_y() {
            return Err(ThresholdError::Encode);
        }
        Ok(Self { participant, bytes })
    }

    /// Exports the share bytes (owner-local handling only).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn participant(&self) -> Participant {
        self.participant
    }

    fn package(&self) -> Result<rp::keys::KeyPackage, ThresholdError> {
        rp::keys::KeyPackage::deserialize(&self.bytes).map_err(|_| ThresholdError::Encode)
    }
}

/// The group-level public state (identifiers, verifying shares, group
/// verifying key). Public — this is what the counterparty and the quote layer
/// may see.
pub struct GroupPublicKey {
    bytes: Vec<u8>,
}

impl GroupPublicKey {
    /// Restores a canonical public package for exactly identifiers 1 and 2,
    /// threshold 2, with a nonidentity, even-Y RedPallas group key.
    /// Correspondence with a separate [`KeyShare`] and ceremony remains the
    /// caller's responsibility; these independent constructors cannot prove it.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ThresholdError> {
        let package = rp::keys::PublicKeyPackage::deserialize(&bytes)
            .map_err(|_| ThresholdError::Encode)?;
        if package.serialize().map_err(|_| ThresholdError::Encode)? != bytes {
            return Err(ThresholdError::Encode);
        }
        let shares = package.verifying_shares();
        if shares.len() != MAX_SIGNERS as usize
            || !shares.contains_key(&Participant::First.frost())
            || !shares.contains_key(&Participant::Second.frost())
        {
            return Err(ThresholdError::Identifier);
        }
        if package.min_signers() != Some(MIN_SIGNERS) {
            return Err(ThresholdError::Session);
        }
        if !package.has_even_y() {
            return Err(ThresholdError::Encode);
        }
        Ok(Self { bytes })
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The 32-byte serialized group verifying key (the future Orchard `ak`
    /// component, even-Y normalized by the ciphersuite's post-DKG hook).
    pub fn verifying_key_bytes(&self) -> Result<[u8; 32], ThresholdError> {
        let package = rp::keys::PublicKeyPackage::deserialize(&self.bytes)
            .map_err(|_| ThresholdError::Encode)?;
        package
            .verifying_key()
            .serialize()
            .map_err(|_| ThresholdError::Encode)?
            .try_into()
            .map_err(|_| ThresholdError::Encode)
    }

    fn package(&self) -> Result<rp::keys::PublicKeyPackage, ThresholdError> {
        rp::keys::PublicKeyPackage::deserialize(&self.bytes).map_err(|_| ThresholdError::Encode)
    }
}

/// External randomizer ("alpha") — the future PCZT spend randomizer, fixed
/// before the signing session begins. Must be uniformly random and freshly
/// generated per spend.
#[derive(Clone)]
pub struct Alpha(Randomizer);

impl Alpha {
    /// Uniformly random alpha.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = <<Suite as Ciphersuite>::Group as Group>::Field::random(rng);
        Self(Randomizer::from_scalar(scalar))
    }

    /// Parses alpha from its canonical serialized scalar bytes (as a
    /// counterparty would receive it).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        Randomizer::deserialize(bytes).map(Self).map_err(|_| ThresholdError::Encode)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// The randomized group verifying key (`rk = ak + alpha*G`) — must equal
    /// the `rk` recorded in the transaction being signed.
    pub fn randomized_public_key(
        &self,
        group: &GroupPublicKey,
    ) -> Result<[u8; 32], ThresholdError> {
        let package = group.package()?;
        RandomizedParams::from_randomizer(package.verifying_key(), self.0)
            .randomized_verifying_key()
            .serialize()
            .map_err(|_| ThresholdError::Encode)?
            .try_into()
            .map_err(|_| ThresholdError::Encode)
    }
}

/// A participant's round-1 nonce commitment, as broadcast to the counterparty.
pub struct Commitment {
    participant: Participant,
    bytes: Vec<u8>,
}

impl Commitment {
    pub fn participant(&self) -> Participant {
        self.participant
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstructs a counterparty commitment from the wire bytes.
    pub fn from_bytes(
        participant: Participant,
        bytes: Vec<u8>,
    ) -> Result<Self, ThresholdError> {
        let _ = rp::round1::SigningCommitments::deserialize(&bytes)
            .map_err(|_| ThresholdError::Encode)?;
        Ok(Self { participant, bytes })
    }
}

/// A participant's one-use signing nonces. Owner-local secret material: the
/// inner value is private and no serialization API is exposed, so nonces
/// cannot transit any channel from this API surface. [`sign_share`] consumes
/// them on every attempt, including failures; retries need a fresh commitment pair.
pub struct Nonces(rp::round1::SigningNonces);

/// A participant's spending authorization share for one signing session.
#[derive(Clone)]
pub struct Share {
    participant: Participant,
    bytes: Vec<u8>,
}

impl Share {
    pub fn participant(&self) -> Participant {
        self.participant
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(participant: Participant, bytes: Vec<u8>) -> Result<Self, ThresholdError> {
        let _ = rp::round2::SignatureShare::deserialize(&bytes)
            .map_err(|_| ThresholdError::Encode)?;
        Ok(Self { participant, bytes })
    }
}

/// The DKG state machine for one participant of a fresh-J 2-of-2 session.
pub struct DkgSession {
    participant: Participant,
    round1_secret: Option<dkg_round1::SecretPackage>,
    round2_secret: Option<dkg_round2::SecretPackage>,
    /// Exact authenticated round-1 bytes consumed by round2.
    peer_round1: Option<Vec<u8>>,
}

impl DkgSession {
    /// Round 1: returns the session and the round-1 package bytes to send to
    /// the counterparty over an authenticated channel.
    pub fn start<R: RngCore + CryptoRng>(
        participant: Participant,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), ThresholdError> {
        let (secret, package) = part1(participant.frost(), MAX_SIGNERS, MIN_SIGNERS, rng)
            .map_err(map_error)?;
        Ok((
            Self {
                participant,
                round1_secret: Some(secret),
                round2_secret: None,
                peer_round1: None,
            },
            package.serialize().map_err(|_| ThresholdError::Encode)?,
        ))
    }

    /// Round 2: consumes the counterparty's round-1 package and returns this
    /// participant's round-2 package bytes for the counterparty (targeted,
    /// confidential delivery). The returned buffer holds a per-recipient
    /// secret share contribution and is zeroized on drop — it must never be
    /// persisted, logged or journaled (§12.1 rule 3).
    pub fn round2(&mut self, peer_round1: &[u8]) -> Result<Zeroizing<Vec<u8>>, ThresholdError> {
        let peer = opposite(self.participant);
        if peer_round1.len() != 135 {
            return Err(ThresholdError::Encode);
        }
        let peer_package = dkg_round1::Package::deserialize(peer_round1)
            .map_err(|_| ThresholdError::Encode)?;
        if peer_package.serialize().map_err(|_| ThresholdError::Encode)?.as_slice() != peer_round1 {
            return Err(ThresholdError::Encode);
        }
        let secret = self.round1_secret.take().ok_or(ThresholdError::Session)?;
        let round1_packages: BTreeMap<_, _> = [(peer.frost(), peer_package)].into();
        let (round2_secret, mut round2_packages) =
            part2(secret, &round1_packages).map_err(map_error)?;
        let package = round2_packages
            .remove(&peer.frost())
            .ok_or(ThresholdError::Session)?;
        self.round2_secret = Some(round2_secret);
        self.peer_round1 = Some(peer_round1.to_vec());
        package
            .serialize()
            .map(Zeroizing::new)
            .map_err(|_| ThresholdError::Encode)
    }

    /// Final: consumes the session and produces this participant's `KeyShare`
    /// plus the public group state (both participants derive the same group
    /// state).
    pub fn finalize(
        self,
        peer_round1: &[u8],
        peer_round2: &[u8],
    ) -> Result<(KeyShare, GroupPublicKey), ThresholdError> {
        let peer = opposite(self.participant);
        if peer_round1.len() != 135 || peer_round2.len() != 37 {
            return Err(ThresholdError::Encode);
        }
        if self.peer_round1.as_deref() != Some(peer_round1) {
            return Err(ThresholdError::Session);
        }
        let peer_round1_package = dkg_round1::Package::deserialize(peer_round1)
            .map_err(|_| ThresholdError::Encode)?;
        let peer_round2_package = dkg_round2::Package::deserialize(peer_round2)
            .map_err(|_| ThresholdError::Encode)?;
        let canonical = Zeroizing::new(peer_round2_package.serialize().map_err(|_| ThresholdError::Encode)?);
        if canonical.as_slice() != peer_round2 {
            return Err(ThresholdError::Encode);
        }
        let round2_secret = self.round2_secret.ok_or(ThresholdError::Session)?;
        let round1_packages: BTreeMap<_, _> = [(peer.frost(), peer_round1_package)].into();
        let round2_packages: BTreeMap<_, _> = [(peer.frost(), peer_round2_package)].into();
        let (key_package, public_key_package) =
            part3(&round2_secret, &round1_packages, &round2_packages).map_err(map_error)?;
        let key_bytes = key_package.serialize().map_err(|_| ThresholdError::Encode)?;
        let group_bytes = public_key_package
            .serialize()
            .map_err(|_| ThresholdError::Encode)?;
        Ok((
            KeyShare {
                participant: self.participant,
                bytes: Zeroizing::new(key_bytes),
            },
            GroupPublicKey { bytes: group_bytes },
        ))
    }
}

/// Round 1 of a signing session: one-use nonces (kept local) and the
/// commitment to broadcast.
pub fn commit<R: RngCore + CryptoRng>(
    key_share: &KeyShare,
    rng: &mut R,
) -> Result<(Nonces, Commitment), ThresholdError> {
    let package = key_share.package()?;
    let (nonces, commitments) = rp::round1::commit(package.signing_share(), rng);
    Ok((
        Nonces(nonces),
        Commitment {
            participant: key_share.participant,
            bytes: commitments.serialize().map_err(|_| ThresholdError::Encode)?,
        },
    ))
}

fn signing_package(
    message: &[u8; 32],
    commitments: &[Commitment],
) -> Result<rp::SigningPackage, ThresholdError> {
    if commitments.len() != MIN_SIGNERS as usize {
        return Err(ThresholdError::InsufficientQuorum);
    }
    let mut map: BTreeMap<_, _> = BTreeMap::new();
    for commitment in commitments {
        let parsed = rp::round1::SigningCommitments::deserialize(&commitment.bytes)
            .map_err(|_| ThresholdError::Encode)?;
        if map.insert(commitment.participant.frost(), parsed).is_some() {
            return Err(ThresholdError::ShareSetMismatch);
        }
    }
    Ok(rp::SigningPackage::new(map, message))
}

/// Round 2: produces this participant's authorization share over the given
/// message under the externally fixed alpha. `commitments` must be the full
/// 2-participant commitment set for this session.
///
/// This consumes `nonces` even if signing fails. Generate fresh nonces and
/// commitments with [`commit`] for every new attempt; never retry with the
/// same nonce pair.
///
/// ```no_run
/// use ziquid_threshold::{sign_share, Alpha, Commitment, KeyShare, Nonces, Share, ThresholdError};
///
/// fn sign_once(
///     key: &KeyShare,
///     nonces: Nonces,
///     alpha: &Alpha,
///     commitments: &[Commitment],
/// ) -> Result<Share, ThresholdError> {
///     sign_share(key, nonces, &[1; 32], alpha, commitments)
/// }
/// ```
///
/// A nonce pair must not authorize two different messages:
///
/// ```compile_fail,E0382
/// use ziquid_threshold::{sign_share, Alpha, Commitment, KeyShare, Nonces};
///
/// fn reuse(key: &KeyShare, nonces: Nonces, alpha: &Alpha, commitments: &[Commitment]) {
///     let _ = sign_share(key, nonces, &[1; 32], alpha, commitments);
///     let _ = sign_share(key, nonces, &[2; 32], alpha, commitments);
/// }
/// ```
///
/// A rejected attempt must not leave nonces available for a retry either:
///
/// ```compile_fail,E0382
/// use ziquid_threshold::{sign_share, Alpha, Commitment, KeyShare, Nonces};
///
/// fn retry(key: &KeyShare, nonces: Nonces, alpha: &Alpha, commitments: &[Commitment]) {
///     let _ = sign_share(key, nonces, &[1; 32], alpha, &[]);
///     let _ = sign_share(key, nonces, &[2; 32], alpha, commitments);
/// }
/// ```
pub fn sign_share(
    key_share: &KeyShare,
    nonces: Nonces,
    message: &[u8; 32],
    alpha: &Alpha,
    commitments: &[Commitment],
) -> Result<Share, ThresholdError> {
    let package = signing_package(message, commitments)?;
    let key_package = key_share.package()?;
    // The non-deprecated seed flow cannot express a randomizer fixed before
    // the commitments exist; the explicit-randomizer entry point is the only
    // installed API that matches the PCZT-alpha pattern (§10.3).
    #[allow(deprecated)]
    let share = frost_rerandomized::sign::<Suite>(&package, &nonces.0, &key_package, alpha.0)
        .map_err(map_error)?;
    Ok(Share {
        participant: key_share.participant,
        bytes: share.serialize(),
    })
}

/// Aggregation: consumes the full share set, verifies the aggregate against
/// the randomized group key, and returns the final 64-byte signature.
pub fn aggregate(
    group: &GroupPublicKey,
    message: &[u8; 32],
    alpha: &Alpha,
    commitments: &[Commitment],
    shares: &[Share],
) -> Result<[u8; 64], ThresholdError> {
    if shares.len() != MIN_SIGNERS as usize {
        return Err(ThresholdError::InsufficientQuorum);
    }
    let package = signing_package(message, commitments)?;
    let mut share_map: BTreeMap<_, _> = BTreeMap::new();
    for share in shares {
        let parsed = rp::round2::SignatureShare::deserialize(&share.bytes)
            .map_err(|_| ThresholdError::Encode)?;
        if share_map.insert(share.participant.frost(), parsed).is_some() {
            return Err(ThresholdError::ShareSetMismatch);
        }
    }
    let group_package = group.package()?;
    let params = RandomizedParams::from_randomizer(group_package.verifying_key(), alpha.0);
    let signature = reddsa::frost::redpallas::rerandomized::aggregate(
        &package,
        &share_map,
        &group_package,
        &params,
    )
    .map_err(map_error)?;
    params
        .randomized_verifying_key()
        .verify(message, &signature)
        .map_err(|_| ThresholdError::InvalidShare)?;
    signature
        .serialize()
        .map_err(|_| ThresholdError::Encode)?
        .try_into()
        .map_err(|_| ThresholdError::Encode)
}

fn opposite(participant: Participant) -> Participant {
    match participant {
        Participant::First => Participant::Second,
        Participant::Second => Participant::First,
    }
}
// Manual Debug impls: secret-bearing types must never expose their bytes in
// logs or panic messages, so only identifiers are printed.

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyShare")
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Alpha {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Alpha(<redacted>)")
    }
}

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Commitment")
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for GroupPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupPublicKey")
            .finish_non_exhaustive()
    }
}
