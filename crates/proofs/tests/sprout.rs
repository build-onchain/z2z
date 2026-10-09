//! Historical Sprout BCTV14 acceptance equations, not complete chain validity or
//! a repair of the legacy parameter-generation soundness flaw.

use ziquid_proofs::sprout::{LegacyError, LegacyJoinSplit, verify_sprout_legacy};

#[path = "fixtures/sprout-positive.rs"]
mod positive;
use positive::{PROOF_HEX, bytes, statement};

#[test]
fn authentic_original_key_accepts_existing_proof_and_complete_public_statement() {
    assert_eq!(verify_sprout_legacy(&statement(), &bytes::<296>(PROOF_HEX)), Ok(()));
}

#[test]
fn every_public_statement_field_is_bound_to_the_proof() {
    let proof = bytes::<296>(PROOF_HEX);
    for field in 0..11 {
        let mut changed = statement();
        match field {
            0 => changed.anchor[0] ^= 1,
            1 => changed.nullifiers[0][0] ^= 1,
            2 => changed.nullifiers[1][0] ^= 1,
            3 => changed.macs[0][0] ^= 1,
            4 => changed.macs[1][0] ^= 1,
            5 => changed.commitments[0][0] ^= 1,
            6 => changed.commitments[1][0] ^= 1,
            7 => changed.random_seed[0] ^= 1,
            8 => changed.joinsplit_pubkey[0] ^= 1,
            9 => changed.vpub_old += 1,
            10 => {
                changed.vpub_old = 0;
                changed.vpub_new = 14_250_000;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            verify_sprout_legacy(&changed, &proof),
            Err(LegacyError::InvalidProof),
            "unbound public field {field}",
        );
    }
}

#[test]
fn canonical_curve_point_replacement_rejects_each_proof_component() {
    // Existing MIT zcashd test_proofs.cpp::{g1_deserialization,g2_deserialization}
    // at commit 0512e9eb00f97172346e0fac854625d59771e4f7. These are valid finite
    // subgroup points, so failures must come from equations, not byte rejection.
    let g1 = bytes::<33>("0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46");
    let g2 = bytes::<65>("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a");
    for (start, end) in [(0, 33), (33, 66), (66, 131), (131, 164), (164, 197), (197, 230), (230, 263), (263, 296)] {
        let mut proof = bytes::<296>(PROOF_HEX);
        let replacement: &[u8] = if start == 66 { &g2 } else { &g1 };
        proof[start..end].copy_from_slice(replacement);
        assert_eq!(
            verify_sprout_legacy(&statement(), &proof),
            Err(LegacyError::InvalidProof),
            "accepted replaced component at {start}",
        );
    }
}

#[test]
fn rejects_noncanonical_truncated_and_extended_proof_encodings() {
    let proof = bytes::<296>(PROOF_HEX);
    for length in [0, 33, 295] {
        assert_eq!(verify_sprout_legacy(&statement(), &proof[..length]), Err(LegacyError::InvalidProofEncoding));
    }
    let mut extended = proof.to_vec();
    extended.push(0);
    assert_eq!(verify_sprout_legacy(&statement(), &extended), Err(LegacyError::InvalidProofEncoding));

    // Primary MIT decoder rejection vectors; q is rejected, not reduced modulo q.
    for point in [
        "ff30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        "0208c6d2adffacbc8438f09f321874ea66e2fcc29f8dcfec2caefa21ec8c96a77c",
        "0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    ] {
        let mut changed = proof;
        changed[..33].copy_from_slice(&bytes::<33>(point));
        assert_eq!(verify_sprout_legacy(&statement(), &changed), Err(LegacyError::InvalidProofEncoding));
    }
    for point in [
        "ff023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a",
        "0b023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984b",
        "0a0925c4b8763cbf9c599a6f7c0348d21cb00b85511637560626edfa5c34c6b38d04689e957a1242c84a50189c6d96cadca602072d09eac1013b5458a2275d69b1",
    ] {
        let mut changed = proof;
        changed[66..131].copy_from_slice(&bytes::<65>(point));
        assert_eq!(verify_sprout_legacy(&statement(), &changed), Err(LegacyError::InvalidProofEncoding));
    }
}

#[test]
fn public_amounts_obey_money_range_and_one_zero_consensus_rule() {
    let proof = bytes::<296>(PROOF_HEX);
    for (old, new) in [(1, 1), (2_100_000_000_000_001, 0), (0, 2_100_000_000_000_001), (u64::MAX, 0), (0, u64::MAX)] {
        let mut changed = statement();
        changed.vpub_old = old;
        changed.vpub_new = new;
        assert_eq!(verify_sprout_legacy(&changed, &proof), Err(LegacyError::InvalidStatement));
    }
}
