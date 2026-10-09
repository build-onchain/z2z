//! Route-1a §11.2/§11.3 tests: the C-share release gate's order, withholding
//! and zeroization guarantees, and the signer semantic-review checks
//! (rk/alpha binding on a real DKG group; effects-vs-terms mismatches).

use std::cell::Cell;
use std::rc::Rc;

use rand_core::OsRng;
use ziquid_threshold::{
    Alpha, ArmingEvidence, DkgSession, Effects, GateError, GroupPublicKey, KeyShare, OutputEffect,
    Participant, Phase, ReviewError, ShareGate, check_action_rk, check_effects,
};

/// A payload that records when the gate zeroizes it.
#[derive(Clone, Debug)]
struct SpyPayload {
    zeroized: Rc<Cell<bool>>,
}

impl SpyPayload {
    fn new() -> (Self, Rc<Cell<bool>>) {
        let flag = Rc::new(Cell::new(false));
        (Self { zeroized: flag.clone() }, flag)
    }
}

impl zeroize::Zeroize for SpyPayload {
    fn zeroize(&mut self) {
        self.zeroized.set(true);
    }
}

fn walk_to_arming(gate: &mut ShareGate<SpyPayload>) {
    gate.mark_keygen_verified().expect("step 1");
    gate.mark_r_preauthorized().expect("step 2");
    gate.mark_funding_released().expect("step 3");
    gate.mark_r_finalized_and_backed_up().expect("step 4");
    gate
        .mark_arming_verified(ArmingEvidence::from_verified_target_observation())
        .expect("step 5");
}

#[test]
fn gate_enforces_order_releases_once_and_refuses_peer_pre_gate() {
    let mut gate = ShareGate::<SpyPayload>::new();
    let (payload, zeroized) = SpyPayload::new();
    gate.deposit_local_c_material(payload).expect("deposit");

    // Out of order: release pre-arming, arming before R finalized, doubles.
    assert_eq!(
        gate.release_local_c_material().unwrap_err(),
        GateError::OutOfOrder { expected: Phase::Armed, actual: Phase::Created }
    );
    assert_eq!(
        gate.mark_arming_verified(ArmingEvidence::from_verified_target_observation())
            .unwrap_err(),
        GateError::OutOfOrder { expected: Phase::RFinalized, actual: Phase::Created }
    );
    // Peer material is refused before arming (no pre-gate aggregation).
    let (peer, _) = SpyPayload::new();
    assert_eq!(gate.accept_peer_c_material(peer).unwrap_err(), GateError::PeerMaterialRefused);

    walk_to_arming(&mut gate);
    assert_eq!(gate.phase(), Phase::Armed);

    // Second deposit is refused, peer material accepted exactly once.
    let (extra, _) = SpyPayload::new();
    assert_eq!(gate.deposit_local_c_material(extra).unwrap_err(), GateError::LocalMaterialPresent);
    let (peer, _) = SpyPayload::new();
    gate.accept_peer_c_material(peer).expect("post-arming peer material");
    let (peer2, _) = SpyPayload::new();
    assert_eq!(gate.accept_peer_c_material(peer2).unwrap_err(), GateError::PeerMaterialPresent);

    // The one-use release moves the payload and the phase; a second fails.
    let released = gate.release_local_c_material().expect("release");
    assert!(!zeroized.get(), "released material must not be zeroized");
    drop(released);
    assert_eq!(gate.phase(), Phase::CReleased);
    assert_eq!(gate.release_local_c_material().unwrap_err(), GateError::AlreadyReleased);

    gate.mark_c_completed().expect("step 7");
    assert_eq!(gate.phase(), Phase::CCompleted);
    assert_eq!(gate.mark_c_completed().unwrap_err(), GateError::OutOfOrder {
        expected: Phase::CReleased,
        actual: Phase::CCompleted,
    });
}

#[test]
fn gate_abort_zeroizes_pre_arming_and_is_forbidden_post_arming() {
    let mut gate = ShareGate::<SpyPayload>::new();
    let (payload, zeroized) = SpyPayload::new();
    gate.deposit_local_c_material(payload).expect("deposit");
    let (peer, peer_zeroized) = SpyPayload::new();
    // Pre-arming peer material cannot be accepted, so only local material is
    // held here; still assert the documented zeroize path on what is held.
    assert_eq!(gate.accept_peer_c_material(peer).unwrap_err(), GateError::PeerMaterialRefused);
    assert!(!peer_zeroized.get());

    gate.mark_keygen_verified().expect("step 1");
    gate.abort().expect("pre-arming abort");
    assert_eq!(gate.phase(), Phase::Aborted);
    assert!(zeroized.get(), "abort must zeroize held material");

    // Nothing proceeds after abort.
    assert_eq!(gate.release_local_c_material().unwrap_err(), GateError::Aborted);
    assert_eq!(gate.mark_keygen_verified().unwrap_err(), GateError::Aborted);
    assert_eq!(gate.abort().unwrap_err(), GateError::Aborted);
    let (late, _) = SpyPayload::new();
    assert_eq!(gate.deposit_local_c_material(late).unwrap_err(), GateError::Aborted);

    // Post-arming abort is refused: the winning source effect decides.
    let (payload, zeroized) = SpyPayload::new();
    let mut armed = ShareGate::<SpyPayload>::new();
    armed.deposit_local_c_material(payload).expect("deposit");
    walk_to_arming(&mut armed);
    assert_eq!(armed.abort().unwrap_err(), GateError::PostArmingAbort);
    assert!(!zeroized.get(), "post-arming abort must not zeroize material");
    assert_eq!(armed.phase(), Phase::Armed);
}

/// Full two-participant DKG through the public API (kept local to this file).
fn run_dkg() -> (KeyShare, GroupPublicKey) {
    let mut rng = OsRng;
    let (mut first, first_round1) = DkgSession::start(Participant::First, &mut rng).expect("start");
    let (mut second, second_round1) =
        DkgSession::start(Participant::Second, &mut rng).expect("start");
    let first_round2 = first.round2(&second_round1).expect("round2");
    let second_round2 = second.round2(&first_round1).expect("round2");
    let (first_share, group) = first
        .finalize(&second_round1, &second_round2)
        .expect("finalize");
    let (_, second_group) = second
        .finalize(&first_round1, &first_round2)
        .expect("finalize");
    assert_eq!(group.to_bytes(), second_group.to_bytes());
    (first_share, group)
}

#[test]
fn review_binds_rk_to_alpha_and_rejects_mismatched_effects() {
    let (_, group) = run_dkg();
    let mut rng = OsRng;
    let alpha = Alpha::random(&mut rng);
    let rk = alpha.randomized_public_key(&group).expect("rk");
    check_action_rk(&group, &alpha, &rk).expect("correct alpha accepted");

    let other = Alpha::random(&mut rng);
    assert_eq!(
        check_action_rk(&group, &other, &rk).unwrap_err(),
        ReviewError::AlphaMismatch
    );
    let mut tampered = rk;
    tampered[0] ^= 1;
    assert_eq!(
        check_action_rk(&group, &alpha, &tampered).unwrap_err(),
        ReviewError::AlphaMismatch
    );

    let agreed = Effects {
        outputs: vec![
            OutputEffect { recipient: [1; 43], value_zat: 50_000 },
            OutputEffect { recipient: [2; 43], value_zat: 30_000 },
        ],
        fee_zat: 1_000,
    };
    check_effects(&agreed, &agreed.clone()).expect("identical effects accepted");

    let mut wrong_value = agreed.clone();
    wrong_value.outputs[1].value_zat += 1;
    assert_eq!(
        check_effects(&agreed, &wrong_value).unwrap_err(),
        ReviewError::ValueMismatch { index: 1 }
    );
    let mut wrong_recipient = agreed.clone();
    wrong_recipient.outputs[0].recipient[42] ^= 1;
    assert_eq!(
        check_effects(&agreed, &wrong_recipient).unwrap_err(),
        ReviewError::RecipientMismatch { index: 0 }
    );
    let mut extra = agreed.clone();
    extra.outputs.push(OutputEffect { recipient: [3; 43], value_zat: 1 });
    assert_eq!(
        check_effects(&agreed, &extra).unwrap_err(),
        ReviewError::OutputCountMismatch
    );
    let mut wrong_fee = agreed.clone();
    wrong_fee.fee_zat += 1;
    assert_eq!(check_effects(&agreed, &wrong_fee).unwrap_err(), ReviewError::FeeMismatch);
    // Order matters: the canonical descriptor order is the agreement.
    let mut swapped = agreed.clone();
    swapped.outputs.swap(0, 1);
    assert_eq!(
        check_effects(&agreed, &swapped).unwrap_err(),
        ReviewError::RecipientMismatch { index: 0 }
    );
}