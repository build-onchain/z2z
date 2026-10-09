//! Original recorded Groth16 proof, not accepted history or financial fact.

use bls12_381::{Bls12, G1Affine, G2Affine};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{consensus::BranchId, value::MAX_MONEY};
use ziquid_proofs::{
    sprout::LegacyJoinSplit,
    sprout_groth16::{GrothError, verify_sprout_groth16},
};

#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod primary;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid primary hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

fn recorded() -> (LegacyJoinSplit, [u8; 192]) {
    let raw = bytes(primary::TRANSACTION_HEX);
    assert_eq!(raw.len(), 2005);
    let mut remaining = raw.as_slice();
    let transaction = Transaction::read(&mut remaining, BranchId::Sapling).unwrap();
    assert!(remaining.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    let bundle = transaction.sprout_bundle().unwrap();
    assert_eq!(bundle.joinsplits.len(), 1);
    let js = &bundle.joinsplits[0];
    let statement = LegacyJoinSplit {
        anchor: *js.anchor(),
        nullifiers: *js.nullifiers(),
        macs: *js.macs(),
        commitments: *js.commitments(),
        vpub_old: u64::try_from(i64::from(js.vpub_old())).unwrap(),
        vpub_new: u64::try_from(i64::from(js.vpub_new())).unwrap(),
        random_seed: *js.random_seed(),
        joinsplit_pubkey: bundle.joinsplit_pubkey,
    };
    (statement, *js.groth_proof_bytes().unwrap())
}

#[test]
fn original_recorded_v4_joinsplit_accepts_its_actual_proof_and_public_statement() {
    let (statement, proof) = recorded();
    assert_eq!(verify_sprout_groth16(&statement, &proof), Ok(()));
}

#[test]
fn every_public_statement_field_is_bound_to_the_recorded_proof() {
    let (statement, proof) = recorded();
    for field in 0..11 {
        let mut changed = statement;
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
            9 => {
                changed.vpub_old ^= 1;
                changed.vpub_new = 0;
            }
            10 => {
                changed.vpub_old = 0;
                changed.vpub_new = 1;
            }
            _ => unreachable!(),
        }
        assert_ne!(changed, statement);
        assert_eq!(
            verify_sprout_groth16(&changed, &proof),
            Err(GrothError::InvalidProof),
            "unbound public field {field}",
        );
    }
}

#[test]
fn canonical_finite_subgroup_replacement_rejects_each_proof_component_by_pairing() {
    let (statement, proof) = recorded();
    let g1 = G1Affine::generator().to_compressed();
    let g2 = G2Affine::generator().to_compressed();
    for (start, end) in [(0, 48), (48, 144), (144, 192)] {
        let replacement: &[u8] = if start == 48 { &g2 } else { &g1 };
        let mut changed = proof;
        assert_ne!(&changed[start..end], replacement);
        changed[start..end].copy_from_slice(replacement);
        bellman::groth16::Proof::<Bls12>::read(&changed[..]).unwrap();
        assert_eq!(
            verify_sprout_groth16(&statement, &changed),
            Err(GrothError::InvalidProof),
            "accepted replaced component at {start}",
        );
    }
}

#[test]
fn proof_encoding_rejects_truncation_and_every_suffix() {
    let (statement, proof) = recorded();
    for length in [0, 47, 48, 143, 144, 191] {
        assert_eq!(
            verify_sprout_groth16(&statement, &proof[..length]),
            Err(GrothError::InvalidProofEncoding),
            "accepted proof length {length}",
        );
    }
    for suffix in [0, 1, 255] {
        let mut extended = proof.to_vec();
        extended.push(suffix);
        assert_eq!(
            verify_sprout_groth16(&statement, &extended),
            Err(GrothError::InvalidProofEncoding),
        );
    }
}

#[test]
fn every_proof_point_rejects_infinity_invalid_flags_and_noncanonical_coordinates() {
    let (statement, proof) = recorded();
    // Canonical integer boundary from bls12_381 0.8.0's fp.rs::MODULUS.
    let modulus = bytes(concat!(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf",
        "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    ));
    for (start, end) in [(0, 48), (48, 144), (144, 192)] {
        let mut changed = proof;
        changed[start] &= 0x7f; // Required compressed flag removed.
        assert_eq!(verify_sprout_groth16(&statement, &changed), Err(GrothError::InvalidProofEncoding));

        for (flags, last) in [(0, 0), (0xc0, 0), (0xe0, 0), (0xc0, 1)] {
            let mut changed = proof;
            changed[start..end].fill(0);
            changed[start] = flags;
            changed[end - 1] = last;
            assert_eq!(
                verify_sprout_groth16(&statement, &changed),
                Err(GrothError::InvalidProofEncoding),
                "accepted infinity/flags at {start}: {flags:#x}/{last}",
            );
        }
        let mut changed = proof;
        changed[start..start + 48].copy_from_slice(&modulus);
        changed[start] |= 0x80;
        assert_eq!(verify_sprout_groth16(&statement, &changed), Err(GrothError::InvalidProofEncoding));
    }
    // G2's second coordinate must also be canonical, not reduced modulo p.
    let mut changed = proof;
    changed[96..144].copy_from_slice(&modulus);
    assert_eq!(verify_sprout_groth16(&statement, &changed), Err(GrothError::InvalidProofEncoding));
}

#[test]
fn canonical_coordinates_without_a_curve_point_are_rejected() {
    let (statement, proof) = recorded();
    // Deterministic regression data, not original-chain points or new crypto.
    let g1 = (0..64).find_map(|coordinate| {
        let mut point = [0; 48];
        point[0] = 0x80;
        point[47] = coordinate;
        bool::from(G1Affine::from_compressed_unchecked(&point).is_none()).then_some(point)
    }).unwrap();
    let g2 = (0..64).find_map(|coordinate| {
        let mut point = [0; 96];
        point[0] = 0x80;
        point[95] = coordinate;
        bool::from(G2Affine::from_compressed_unchecked(&point).is_none()).then_some(point)
    }).unwrap();
    for (start, end) in [(0, 48), (48, 144), (144, 192)] {
        let mut changed = proof;
        let replacement: &[u8] = if start == 48 { &g2 } else { &g1 };
        changed[start..end].copy_from_slice(replacement);
        assert_eq!(verify_sprout_groth16(&statement, &changed), Err(GrothError::InvalidProofEncoding));
    }
}

#[test]
fn on_curve_non_subgroup_points_are_rejected_for_all_proof_components() {
    let (statement, proof) = recorded();
    // x=0, y=2 is a finite order-three point on y^2=x^3+4, outside G1.
    let mut g1 = [0; 48];
    g1[0] = 0x80;
    let point = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&g1)).unwrap();
    assert!(bool::from(point.is_on_curve()));
    assert!(!bool::from(point.is_identity()));
    assert!(!bool::from(point.is_torsion_free()));
    // Bounded deterministic on-curve G2 regression data, not an upstream vector.
    let g2 = (0..64).find_map(|coordinate| {
        let mut encoded = [0; 96];
        encoded[0] = 0x80;
        encoded[95] = coordinate;
        let point = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&encoded))?;
        assert!(bool::from(point.is_on_curve()));
        (!bool::from(point.is_identity()) && !bool::from(point.is_torsion_free())).then_some(encoded)
    }).unwrap();
    for (start, end) in [(0, 48), (48, 144), (144, 192)] {
        let mut changed = proof;
        let replacement: &[u8] = if start == 48 { &g2 } else { &g1 };
        changed[start..end].copy_from_slice(replacement);
        assert_eq!(verify_sprout_groth16(&statement, &changed), Err(GrothError::InvalidProofEncoding));
    }
}

#[test]
fn public_amounts_obey_money_range_and_one_zero_rule_before_crypto() {
    let (statement, proof) = recorded();
    for (old, new) in [
        (1, 1), (MAX_MONEY + 1, 0), (0, MAX_MONEY + 1),
        (u64::MAX, 0), (0, u64::MAX),
    ] {
        let mut changed = statement;
        changed.vpub_old = old;
        changed.vpub_new = new;
        for encoding in [&proof[..], &[][..]] {
            assert_eq!(verify_sprout_groth16(&changed, encoding), Err(GrothError::InvalidStatement));
        }
    }
    // Valid boundary amounts must reach the real equation, not a range failure.
    for (old, new) in [(0, 0), (MAX_MONEY, 0), (0, MAX_MONEY)] {
        let mut changed = statement;
        changed.vpub_old = old;
        changed.vpub_new = new;
        assert_eq!(verify_sprout_groth16(&changed, &proof), Err(GrothError::InvalidProof));
        assert_eq!(verify_sprout_groth16(&changed, &[]), Err(GrothError::InvalidProofEncoding));
    }
}
