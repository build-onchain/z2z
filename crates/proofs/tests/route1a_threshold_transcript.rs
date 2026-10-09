//! Route-1a qualification transcript (R1.3 Q1/Q2) — research evidence only.
//!
//! Exercises, entirely offline and with fresh test keys:
//! 1. a 2-of-2 DKG over the RedPallas FROST ciphersuite (`PallasBlake2b512`,
//!    the exact ciphersuite reddsa 0.5.2 ships for Zcash — ZIP312 hash domains,
//!    even-Y group-key normalization) — the Q1 "no dealer" primitive;
//! 2. the external-alpha re-randomized signing flow PR593 uses: a randomizer
//!    (the future PCZT `alpha`) fixed before signing, both participants
//!    producing shares over it, aggregation into one 64-byte signature;
//! 3. verification of that signature both at the FROST level and via
//!    `reddsa::VerificationKey<orchard::SpendAuth>` — the artifact shape that
//!    `pczt::roles::signer::Signer::apply_orchard_spend_auth_signature`
//!    consumes.
//!
//! Negative checks: a single share cannot aggregate; shares signed under one
//! alpha do not aggregate under another alpha's parameters; a tampered message
//! fails verification.
//!
//! NOT covered here: DKG transport/authentication, key storage, the orchard
//! threshold-FVK construction, PCZT integration, any chain or wallet action.

use std::collections::BTreeMap;

use rand_core::OsRng;

use reddsa::frost::redpallas::{
    rerandomized::{aggregate, Randomizer, RandomizedParams},
    Ciphersuite, Field, Group, PallasBlake2b512,
};
use reddsa::frost::redpallas::frost::{
    self as frost,
    keys::dkg::{part1, part2, part3},
    round1,
};

type Suite = PallasBlake2b512;

struct Dkg {
    keys: BTreeMap<frost::Identifier<Suite>, frost::keys::KeyPackage<Suite>>,
    pubkeys: frost::keys::PublicKeyPackage<Suite>,
}

/// A full 2-of-2 DKG transcript between two simulated participants.
fn run_two_of_two_dkg() -> Dkg {
    let mut rng = OsRng;
    let id1 = frost::Identifier::<Suite>::try_from(1u16).expect("nonzero id");
    let id2 = frost::Identifier::<Suite>::try_from(2u16).expect("nonzero id");

    // Round 1.
    let (secret1, package1) = part1::<Suite, _>(id1, 2, 2, &mut rng).expect("part1");
    let (secret2, package2) = part1::<Suite, _>(id2, 2, 2, &mut rng).expect("part1");

    // Simulated broadcast.
    let received_round1_1: BTreeMap<_, _> = [(id2, package2.clone())].into();
    let received_round1_2: BTreeMap<_, _> = [(id1, package1.clone())].into();

    // Round 2.
    let (r2_secret1, r2_packages_1) = part2::<Suite>(secret1, &received_round1_1).expect("part2");
    let (r2_secret2, r2_packages_2) = part2::<Suite>(secret2, &received_round1_2).expect("part2");

    // Simulated targeted delivery: part2 returns packages keyed by receiver.
    let received_round2_1: BTreeMap<_, _> = [(id2, r2_packages_2[&id1].clone())].into();
    let received_round2_2: BTreeMap<_, _> = [(id1, r2_packages_1[&id2].clone())].into();

    // Final computation.
    let (key1, pubkeys1) =
        part3::<Suite>(&r2_secret1, &received_round1_1, &received_round2_1).expect("part3");
    let (key2, pubkeys2) =
        part3::<Suite>(&r2_secret2, &received_round1_2, &received_round2_2).expect("part3");

    // Both participants must derive the same group public state.
    assert_eq!(
        pubkeys1.verifying_key().serialize().expect("serialize vk"),
        pubkeys2.verifying_key().serialize().expect("serialize vk"),
        "group verifying keys diverge"
    );
    assert_eq!(pubkeys1, pubkeys2, "public key packages diverge");

    // ZIP312/orchard ak encoding: group key must be even-Y (nonidentity).
    let vk_bytes = pubkeys1.verifying_key().serialize().expect("serialize vk");
    assert_eq!(vk_bytes[31] & 0x80, 0, "group key must have even Y");

    let mut keys = BTreeMap::new();
    keys.insert(id1, key1);
    keys.insert(id2, key2);
    Dkg { keys, pubkeys: pubkeys1 }
}

/// One participant's round-1 nonce commitment.
fn commit(
    key_package: &frost::keys::KeyPackage<Suite>,
) -> (
    round1::SigningNonces<Suite>,
    round1::SigningCommitments<Suite>,
) {
    let mut rng = OsRng;
    round1::commit(key_package.signing_share(), &mut rng)
}

fn external_alpha() -> Randomizer {
    // The future PCZT alpha is an externally fixed scalar (RedDSA.GenRandom at
    // construction time) — model it directly rather than the seed flow.
    let mut rng = OsRng;
    let scalar = <<Suite as Ciphersuite>::Group as Group>::Field::random(&mut rng);
    Randomizer::from_scalar(scalar)
}

#[test]
fn route1a_two_of_two_dkg_and_external_alpha_signing_transcript() {
    let dkg = run_two_of_two_dkg();
    let id1 = frost::Identifier::<Suite>::try_from(1u16).expect("id");
    let id2 = frost::Identifier::<Suite>::try_from(2u16).expect("id");

    // A 32-byte message, the shape of a shielded sighash.
    let message = [0xAA_u8; 32];

    // Alpha is fixed BEFORE the signing session (the PCZT pattern).
    let alpha = external_alpha();

    // Round 1 commitments.
    let (nonces1, commitments1) = commit(&dkg.keys[&id1]);
    let (nonces2, commitments2) = commit(&dkg.keys[&id2]);
    let commitments: BTreeMap<_, _> = [(id1, commitments1), (id2, commitments2)].into();
    let signing_package = frost::SigningPackage::new(commitments, &message);

    // Round 2, each participant signs over the externally fixed alpha.
    // The non-deprecated seed flow cannot express a randomizer fixed before
    // the commitments exist, so the explicit-randomizer entry point is used
    // deliberately (this is the same path PR593 drives).
    #[allow(deprecated)]
    let share1 = frost_rerandomized::sign::<Suite>(&signing_package, &nonces1, &dkg.keys[&id1], alpha)
        .expect("share1");
    #[allow(deprecated)]
    let share2 = frost_rerandomized::sign::<Suite>(&signing_package, &nonces2, &dkg.keys[&id2], alpha)
        .expect("share2");

    let params = RandomizedParams::from_randomizer(dkg.pubkeys.verifying_key(), alpha);

    // A lone participant cannot even produce a share for a 2-of-2 session:
    // the signer enforces the minimum commitment count (pinned variant).
    let (lone_nonces, lone_commitment) = commit(&dkg.keys[&id1]);
    let lone_package = frost::SigningPackage::new([(id1, lone_commitment)].into(), &message);
    #[allow(deprecated)]
    match frost_rerandomized::sign::<Suite>(&lone_package, &lone_nonces, &dkg.keys[&id1], alpha) {
        Err(frost::Error::IncorrectNumberOfCommitments) => {}
        other => panic!("expected IncorrectNumberOfCommitments, got {other:?}"),
    }

    // Aggregation refuses an incomplete share set through its set-equality
    // guard (pinned variant). The cryptographic share check is exercised
    // separately by the tampered-share negative below.
    let lone: BTreeMap<_, _> = [(id1, share1)].into();
    match aggregate(&signing_package, &lone, &dkg.pubkeys, &params) {
        Err(frost::Error::UnknownIdentifier) => {}
        other => panic!("expected UnknownIdentifier for an incomplete share set, got {other:?}"),
    }

    // A tampered share must fail the cryptographic share verification
    // (cheater detection identifies it), not an input-set guard.
    let mut tampered_bytes = share2.serialize();
    tampered_bytes[0] ^= 1;
    let tampered_share =
        frost::round2::SignatureShare::deserialize(&tampered_bytes).expect("still a scalar");
    let tampered: BTreeMap<_, _> = [(id1, share1), (id2, tampered_share)].into();
    match aggregate(&signing_package, &tampered, &dkg.pubkeys, &params) {
        Err(frost::Error::InvalidSignatureShare { .. }) => {}
        other => panic!("expected InvalidSignatureShare, got {other:?}"),
    }

    // Shares signed under a different alpha must not aggregate under `params`.
    let other_alpha = external_alpha();
    let other_params =
        RandomizedParams::from_randomizer(dkg.pubkeys.verifying_key(), other_alpha);
    let both: BTreeMap<_, _> = [(id1, share1), (id2, share2)].into();
    assert!(
        aggregate(&signing_package, &both, &dkg.pubkeys, &other_params).is_err(),
        "shares bound to one alpha must not aggregate under another"
    );

    // Correct aggregation.
    let signature = aggregate(&signing_package, &both, &dkg.pubkeys, &params).expect("aggregate");

    // FROST-level verification against the randomized group key.
    params
        .randomized_verifying_key()
        .verify(&message, &signature)
        .expect("frost-level verify under randomized key");

    // A tampered message must fail.
    let mut tampered = message;
    tampered[0] ^= 1;
    assert!(
        params
            .randomized_verifying_key()
            .verify(&tampered, &signature)
            .is_err(),
        "tampered message must not verify"
    );

    // RedDSA interop: the aggregated 64-byte signature verifies under the
    // installed `reddsa` SpendAuth verification key — the artifact shape
    // `apply_orchard_spend_auth_signature` consumes via orchard's rk check.
    let sig_bytes: [u8; 64] = signature
        .serialize()
        .expect("serialize signature")
        .try_into()
        .expect("64 bytes");
    let vk_bytes: [u8; 32] = params
        .randomized_verifying_key()
        .serialize()
        .expect("serialize randomized vk")
        .try_into()
        .expect("32 bytes");

    let reddsa_sig = reddsa::Signature::<reddsa::orchard::SpendAuth>::from(sig_bytes);
    let reddsa_vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(vk_bytes)
        .expect("randomized key must be a well-formed SpendAuth key");
    reddsa_vk
        .verify(&message, &reddsa_sig)
        .expect("reddsa SpendAuth interop verify");
    assert!(
        reddsa_vk.verify(&tampered, &reddsa_sig).is_err(),
        "reddsa interop must reject a tampered message"
    );
}
/// The remaining missing hook (§10.3): orchard 0.15.5 has no public
/// threshold-FVK constructor (upstream orchard#475 is open). This test
/// exercises the surrogate route entirely through public APIs: derive a
/// normal FVK, replace only its `ak` component with the DKG group key, and
/// require orchard's own parser (`FullViewingKey::from_bytes`, which
/// validates ak formatting/even-Y and non-zero ivk derivations) to accept it.
///
/// This converts the byte-swap feasibility from inference to locally-tested
/// for the acceptance criterion. It does NOT address the ZIP 2005
/// quantum-recoverability caveat or ak<->(nk,rivk) consistency beyond what
/// orchard's parser checks (the fork's constructor does not check more).
#[test]
fn route1a_fvk_byte_swap_accepts_dkg_group_key() {
    use orchard::keys::{FullViewingKey, SpendingKey};

    let dkg = run_two_of_two_dkg();
    let group_ak: [u8; 32] = dkg
        .pubkeys
        .verifying_key()
        .serialize()
        .expect("serialize group vk")
        .try_into()
        .expect("32 bytes");
    assert_eq!(group_ak[31] & 0x80, 0, "DKG group key must be even-Y");

    let sk: SpendingKey =
        Option::<SpendingKey>::from(SpendingKey::from_bytes([7_u8; 32]))
            .expect("valid test spending key");
    let base = FullViewingKey::from(&sk);
    let mut bytes = base.to_bytes();

    // Swap only the ak component for the FROST group key.
    bytes[..32].copy_from_slice(&group_ak);
    let swapped = FullViewingKey::from_bytes(&bytes).expect("orchard must accept swapped FVK");

    // The remaining components survive; ak serializes back to the group key.
    let roundtrip = swapped.to_bytes();
    assert_eq!(&roundtrip[..32], &group_ak[..]);
    assert_eq!(&roundtrip[32..], &base.to_bytes()[32..]);

    // Negative: the odd-Y encoding of the same point is rejected.
    bytes[31] |= 0x80;
    assert!(
        FullViewingKey::from_bytes(&bytes).is_none(),
        "odd-Y ak must be rejected"
    );
}
