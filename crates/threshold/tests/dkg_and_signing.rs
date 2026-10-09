//! Ceremony-level tests for `ziquid-threshold`: 2-of-2 DKG and
//! external-alpha re-randomized signing, including the negative paths pinned
//! by the route-1a review (quorum, set mismatch, tampered share, wrong alpha,
//! tampered message) plus the RedDSA SpendAuth interop check that ties the
//! aggregate to the artifact the PCZT signer consumes.

use rand_core::OsRng;
use reddsa::Signature;
use reddsa::VerificationKey;
use reddsa::orchard::SpendAuth;
use ziquid_threshold::{
    Alpha, Commitment, DkgSession, GroupPublicKey, KeyShare, Participant, ThresholdError,
    aggregate, commit, sign_share,
};

struct Ceremony {
    first: KeyShare,
    second: KeyShare,
    group: GroupPublicKey,
}

/// Runs the full two-participant DKG through the public API only.
fn run_dkg() -> Ceremony {
    let mut rng = OsRng;
    let (mut first, first_round1) = DkgSession::start(Participant::First, &mut rng).expect("start");
    let (mut second, second_round1) =
        DkgSession::start(Participant::Second, &mut rng).expect("start");

    let first_round2 = first.round2(&second_round1).expect("round2");
    let second_round2 = second.round2(&first_round1).expect("round2");

    let (first_share, first_group) = first
        .finalize(&second_round1, &second_round2)
        .expect("finalize");
    let (second_share, second_group) = second
        .finalize(&first_round1, &first_round2)
        .expect("finalize");

    assert_eq!(
        first_group.verifying_key_bytes().expect("vk"),
        second_group.verifying_key_bytes().expect("vk"),
        "both participants must derive the same group key"
    );
    assert_eq!(
        first_group.to_bytes(),
        second_group.to_bytes(),
        "public key packages must agree"
    );
    Ceremony {
        first: first_share,
        second: second_share,
        group: first_group,
    }
}

fn commit_pair(ceremony: &Ceremony) -> ((ziquid_threshold::Nonces, Commitment), (ziquid_threshold::Nonces, Commitment)) {
    let mut rng = OsRng;
    (
        commit(&ceremony.first, &mut rng).expect("commit"),
        commit(&ceremony.second, &mut rng).expect("commit"),
    )
}

#[test]
fn dkg_produces_equal_group_keys_and_even_y_ak() {
    let ceremony = run_dkg();
    let vk = ceremony.group.verifying_key_bytes().expect("vk");
    assert_eq!(vk[31] & 0x80, 0, "group key must be even-Y for orchard ak");
}

#[test]
fn restored_dkg_packages_preserve_participants_and_bytes() {
    let ceremony = run_dkg();
    for key in [&ceremony.first, &ceremony.second] {
        let restored = KeyShare::from_bytes(key.participant(), key.to_bytes().to_vec())
            .expect("same participant roundtrip");
        assert_eq!(restored.participant(), key.participant());
        assert!(restored.to_bytes() == key.to_bytes(), "canonical secret roundtrip");
    }
    let restored = GroupPublicKey::from_bytes(ceremony.group.to_bytes().to_vec())
        .expect("public roundtrip");
    assert_eq!(restored.to_bytes(), ceremony.group.to_bytes());
}

#[test]
fn restored_dkg_share_rejects_opposite_participant() {
    let ceremony = run_dkg();
    assert_eq!(
        KeyShare::from_bytes(Participant::Second, ceremony.first.to_bytes().to_vec()).err(),
        Some(ThresholdError::Identifier)
    );
    assert_eq!(
        KeyShare::from_bytes(Participant::First, ceremony.second.to_bytes().to_vec()).err(),
        Some(ThresholdError::Identifier)
    );
}

#[test]
fn restored_dkg_packages_reject_trailing_bytes() {
    let ceremony = run_dkg();
    let mut secret = Vec::with_capacity(ceremony.first.to_bytes().len() + 1);
    secret.extend_from_slice(ceremony.first.to_bytes());
    secret.push(0);
    assert_eq!(
        KeyShare::from_bytes(Participant::First, secret).err(),
        Some(ThresholdError::Encode)
    );
    let mut public = ceremony.group.to_bytes().to_vec();
    public.push(0);
    assert_eq!(
        GroupPublicKey::from_bytes(public).err(),
        Some(ThresholdError::Encode)
    );
}

#[test]
fn restored_key_share_rejects_wrong_threshold_and_verifying_share() {
    use reddsa::frost::redpallas::keys::KeyPackage;
    use zeroize::Zeroizing;

    let ceremony = run_dkg();
    let first = KeyPackage::deserialize(ceremony.first.to_bytes()).unwrap();
    let second = KeyPackage::deserialize(ceremony.second.to_bytes()).unwrap();
    for (threshold, verifying_share) in [
        (1, *first.verifying_share()),
        (3, *first.verifying_share()),
        (2, *second.verifying_share()),
    ] {
        let package = KeyPackage::new(
            *first.identifier(),
            *first.signing_share(),
            verifying_share,
            *first.verifying_key(),
            threshold,
        );
        let bytes = package.serialize().map(Zeroizing::new).unwrap();
        assert_eq!(
            KeyShare::from_bytes(Participant::First, bytes.to_vec()).err(),
            Some(ThresholdError::Session)
        );
    }
}

#[test]
fn restored_group_rejects_wrong_threshold_and_participant_set() {
    use reddsa::frost::redpallas::{Identifier, keys::PublicKeyPackage};

    let ceremony = run_dkg();
    let group = PublicKeyPackage::deserialize(ceremony.group.to_bytes()).unwrap();
    for threshold in [None, Some(1), Some(3)] {
        let package = PublicKeyPackage::new(
            group.verifying_shares().clone(),
            *group.verifying_key(),
            threshold,
        );
        assert_eq!(
            GroupPublicKey::from_bytes(package.serialize().unwrap()).err(),
            Some(ThresholdError::Session)
        );
    }
    let first = Identifier::try_from(1).unwrap();
    let second = Identifier::try_from(2).unwrap();
    let third = Identifier::try_from(3).unwrap();
    for shares in [
        [(first, group.verifying_shares()[&first])].into(),
        [
            (first, group.verifying_shares()[&first]),
            (third, group.verifying_shares()[&second]),
        ].into(),
        [
            (first, group.verifying_shares()[&first]),
            (second, group.verifying_shares()[&second]),
            (third, group.verifying_shares()[&second]),
        ].into(),
    ] {
        let package = PublicKeyPackage::new(shares, *group.verifying_key(), Some(2));
        assert_eq!(
            GroupPublicKey::from_bytes(package.serialize().unwrap()).err(),
            Some(ThresholdError::Identifier)
        );
    }
}

#[test]
fn restored_dkg_packages_reject_odd_y_group_key() {
    use reddsa::frost::redpallas::{VerifyingKey, keys::{KeyPackage, PublicKeyPackage}};
    use zeroize::Zeroizing;

    let ceremony = run_dkg();
    let group = PublicKeyPackage::deserialize(ceremony.group.to_bytes()).unwrap();
    let mut odd_bytes = group.verifying_key().serialize().unwrap();
    odd_bytes[31] |= 0x80;
    let odd_key = VerifyingKey::deserialize(&odd_bytes).unwrap();
    let odd_group = PublicKeyPackage::new(group.verifying_shares().clone(), odd_key, Some(2));
    assert_eq!(
        GroupPublicKey::from_bytes(odd_group.serialize().unwrap()).err(),
        Some(ThresholdError::Encode)
    );
    let first = KeyPackage::deserialize(ceremony.first.to_bytes()).unwrap();
    let odd_share = KeyPackage::new(
        *first.identifier(),
        *first.signing_share(),
        *first.verifying_share(),
        odd_key,
        2,
    );
    let secret = odd_share.serialize().map(Zeroizing::new).unwrap();
    assert_eq!(
        KeyShare::from_bytes(Participant::First, secret.to_vec()).err(),
        Some(ThresholdError::Encode)
    );
}

#[test]
fn external_alpha_signing_round_trip_and_reddsa_interop() {
    let ceremony = run_dkg();
    let mut rng = OsRng;
    let message = [0xAA_u8; 32];
    let alpha = Alpha::random(&mut rng);

    let ((nonces1, commitment1), (nonces2, commitment2)) = commit_pair(&ceremony);
    let commitments = [commitment1, commitment2];

    let share1 = sign_share(&ceremony.first, nonces1, &message, &alpha, &commitments)
        .expect("share1");
    let share2 = sign_share(&ceremony.second, nonces2, &message, &alpha, &commitments)
        .expect("share2");

    let signature = aggregate(
        &ceremony.group,
        &message,
        &alpha,
        &commitments,
        &[share1, share2],
    )
    .expect("aggregate");

    // The randomized public key must reproduce the future PCZT `rk`.
    let randomized = alpha
        .randomized_public_key(&ceremony.group)
        .expect("randomized key");
    let reddsa_vk = VerificationKey::<SpendAuth>::try_from(randomized).expect("well-formed rk");
    let reddsa_sig = Signature::<SpendAuth>::from(signature);
    reddsa_vk.verify(&message, &reddsa_sig).expect("reddsa interop verify");

    // Tampered message fails.
    let mut tampered = message;
    tampered[0] ^= 1;
    assert!(reddsa_vk.verify(&tampered, &reddsa_sig).is_err());

    // Alpha serialization round-trips.
    let alpha_bytes = alpha.to_bytes();
    let reparsed = Alpha::from_bytes(&alpha_bytes).expect("alpha roundtrip");
    assert_eq!(
        reparsed.randomized_public_key(&ceremony.group).expect("rk"),
        randomized
    );
}

#[test]
fn lone_participant_cannot_sign() {
    let ceremony = run_dkg();
    let mut rng = OsRng;
    let message = [0xBB_u8; 32];
    let alpha = Alpha::random(&mut rng);
    let (nonces, commitment) = commit(&ceremony.first, &mut rng).expect("commit");

    // A single commitment is below the 2-of-2 quorum.
    let err = sign_share(&ceremony.first, nonces, &message, &alpha, &[commitment])
        .expect_err("must reject");
    assert_eq!(err, ThresholdError::InsufficientQuorum);

    // A rejected signing attempt consumed its nonces. Retry only with a fresh pair.
    let ((nonces1, commitment1), (nonces2, commitment2)) = commit_pair(&ceremony);
    let commitments = [commitment1, commitment2];
    let share1 =
        sign_share(&ceremony.first, nonces1, &message, &alpha, &commitments).expect("share1");
    let share2 =
        sign_share(&ceremony.second, nonces2, &message, &alpha, &commitments).expect("share2");
    aggregate(
        &ceremony.group,
        &message,
        &alpha,
        &commitments,
        &[share1, share2],
    )
    .expect("fresh two-participant retry verifies");
}

#[test]
fn incomplete_share_set_and_tampered_share_are_rejected() {
    let ceremony = run_dkg();
    let mut rng = OsRng;
    let message = [0xCC_u8; 32];
    let alpha = Alpha::random(&mut rng);
    let ((nonces1, commitment1), (nonces2, commitment2)) = commit_pair(&ceremony);
    let commitments = [commitment1, commitment2];
    let share1 =
        sign_share(&ceremony.first, nonces1, &message, &alpha, &commitments).expect("share1");
    let share2 =
        sign_share(&ceremony.second, nonces2, &message, &alpha, &commitments).expect("share2");

    // One share is below quorum.
    let err = aggregate(
        &ceremony.group,
        &message,
        &alpha,
        &commitments,
        std::slice::from_ref(&share1),
    )
    .expect_err("must reject");
    assert_eq!(err, ThresholdError::InsufficientQuorum);

    // Tampered share bytes fail cryptographic verification (deserialization of
    // a scalar still succeeds; the share check itself must catch it).
    let mut tampered_bytes = share2.to_bytes().to_vec();
    tampered_bytes[0] ^= 1;
    let tampered = ziquid_threshold::Share::from_bytes(Participant::Second, tampered_bytes)
        .expect("still a scalar");
    let err = aggregate(
        &ceremony.group,
        &message,
        &alpha,
        &commitments,
        &[share1, tampered],
    )
    .expect_err("must reject");
    assert_eq!(err, ThresholdError::InvalidShare);
}

#[test]
fn shares_bound_to_one_alpha_reject_under_another() {
    let ceremony = run_dkg();
    let mut rng = OsRng;
    let message = [0xDD_u8; 32];
    let alpha = Alpha::random(&mut rng);
    let other = Alpha::random(&mut rng);
    let ((nonces1, commitment1), (nonces2, commitment2)) = commit_pair(&ceremony);
    let commitments = [commitment1, commitment2];
    let share1 =
        sign_share(&ceremony.first, nonces1, &message, &alpha, &commitments).expect("share1");
    let share2 =
        sign_share(&ceremony.second, nonces2, &message, &alpha, &commitments).expect("share2");

    let err = aggregate(
        &ceremony.group,
        &message,
        &other,
        &commitments,
        &[share1, share2],
    )
    .expect_err("must reject");
    assert_eq!(err, ThresholdError::InvalidShare);
}

#[test]
fn malformed_bytes_are_rejected() {
    assert_eq!(
        Alpha::from_bytes(&[0xFF; 32]).expect_err("non-canonical scalar"),
        ThresholdError::Encode
    );
    assert_eq!(
        KeyShare::from_bytes(Participant::First, vec![1, 2, 3]).expect_err("garbage"),
        ThresholdError::Encode
    );
    assert_eq!(
        GroupPublicKey::from_bytes(vec![0xAB; 8]).expect_err("garbage"),
        ThresholdError::Encode
    );
    assert_eq!(
        Commitment::from_bytes(Participant::First, vec![9; 5]).expect_err("garbage"),
        ThresholdError::Encode
    );
}

#[test]
fn dkg_rejects_trailing_bytes_and_transcript_substitution() {
    let mut rng = OsRng;
    let (mut first, first_r1) = DkgSession::start(Participant::First, &mut rng).unwrap();
    let (mut second, second_r1) = DkgSession::start(Participant::Second, &mut rng).unwrap();
    assert_eq!(first_r1.len(), 135, "pinned two-party wire encoding");
    let mut trailing = second_r1.clone();
    trailing.push(0);
    assert_eq!(first.round2(&trailing).err(), Some(ThresholdError::Encode));
    let first_r2 = first.round2(&second_r1).unwrap();
    let second_r2 = second.round2(&first_r1).unwrap();
    assert_eq!(first_r2.len(), 37, "pinned targeted share encoding");
    let mut trailing = second_r2.to_vec();
    trailing.push(0);
    assert_eq!(first.finalize(&second_r1, &trailing).err(), Some(ThresholdError::Encode));

    let (mut first, _) = DkgSession::start(Participant::First, &mut rng).unwrap();
    first.round2(&second_r1).unwrap();
    let (_, substitute) = DkgSession::start(Participant::Second, &mut rng).unwrap();
    assert_eq!(first.finalize(&substitute, &second_r2).err(), Some(ThresholdError::Session));
}