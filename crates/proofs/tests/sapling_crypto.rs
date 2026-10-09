//! Original mined transaction crypto, not connected history or settlement.

use bls12_381::{Bls12, G1Affine, G2Affine};
use group::GroupEncoding;
use sapling_crypto::{
    bundle::{Authorized as SaplingAuthorized, Bundle, OutputDescription, SpendDescription},
    constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
use zcash_protocol::{consensus::BranchId, value::ZatBalance};
use ziquid_proofs::{
    sapling_crypto::{SaplingCryptoError, verify_sapling_v4_crypto},
    sapling_sighash::{SaplingSignatureHash, SaplingSighashError},
};

#[path = "fixtures/sapling-mainnet-419202.rs"]
mod primary;

// Original V4 wire layout: 26B prefix, spend count, one384B spend, output
// count, two948B outputs, zero JoinSplit count, then64B binding signature.
const SPEND: usize = 27;
const OUTPUTS: [usize; 2] = [412, 1360];
const BINDING: usize = 2309;

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

fn parse(raw: &[u8], branch: BranchId) -> Transaction {
    let mut remaining = raw;
    let transaction = Transaction::read(&mut remaining, branch).unwrap();
    assert!(remaining.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn recorded() -> (Vec<u8>, Transaction) {
    let raw = bytes(primary::TRANSACTION_HEX);
    assert_eq!(raw.len(), 2373);
    let expected_hash: [u8; 32] = bytes("d081c5cf8f0d8db14f56adc1e8a259ed54f59353909c8b64402432fccaf1d59d").try_into().unwrap();
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&raw)), expected_hash);
    let transaction = parse(&raw, BranchId::Sapling);
    let bundle = transaction.sapling_bundle().unwrap();
    assert_eq!((bundle.shielded_spends().len(), bundle.shielded_outputs().len()), (1, 2));
    assert_eq!(&raw[SPEND + 128..SPEND + 320], bundle.shielded_spends()[0].zkproof());
    for (offset, output) in OUTPUTS.into_iter().zip(bundle.shielded_outputs()) {
        assert_eq!(&raw[offset + 756..offset + 948], output.zkproof());
    }
    (raw, transaction)
}

fn check(transaction: &Transaction) -> Result<(), SaplingCryptoError> {
    verify_sapling_v4_crypto(&SaplingSignatureHash::new(transaction).unwrap())
}

fn with_bundle(source: &Transaction, bundle: Option<Bundle<SaplingAuthorized, ZatBalance>>) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V4, source.consensus_branch_id(), source.lock_time(), source.expiry_height(),
        source.transparent_bundle().cloned(), source.sprout_bundle().cloned(), bundle, None,
    ).freeze().unwrap()
}

fn outputs_only(source: &Transaction) -> Transaction {
    let bundle = source.sapling_bundle().unwrap();
    with_bundle(source, Bundle::from_parts(
        vec![], bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization(),
    ))
}

#[test]
fn original_recorded_sapling_transaction_checks_every_proof_and_signature() {
    let (_, transaction) = recorded();
    assert_eq!(check(&transaction), Ok(()));
}

#[test]
fn every_spend_public_input_is_bound_to_the_original_proof() {
    let (raw, _) = recorded();
    for field in 0..7 {
        let mut changed = raw.clone();
        match field {
            0 => changed[SPEND..SPEND + 32].copy_from_slice(&SPENDING_KEY_GENERATOR.to_bytes()),
            1 => changed[SPEND + 32] ^= 1,
            2 => changed[SPEND + 64] ^= 1,
            3 => changed[SPEND + 95] ^= 0x40,
            4 => changed[SPEND + 95] ^= 0x80,
            5 => changed[SPEND + 96..SPEND + 128].copy_from_slice(&VALUE_COMMITMENT_RANDOMNESS_GENERATOR.to_bytes()),
            6 => {
                // Non-small-order with torsion is legal input, not a stronger
                // prime-subgroup predicate. Its changed coordinates fail the proof.
                let cv = jubjub::AffinePoint::from_bytes(changed[SPEND..SPEND + 32].try_into().unwrap()).unwrap();
                let order_two = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one());
                let mixed = jubjub::ExtendedPoint::from(cv) + jubjub::ExtendedPoint::from(order_two);
                assert!(!bool::from(mixed.is_small_order()));
                changed[SPEND..SPEND + 32].copy_from_slice(&mixed.to_bytes());
            }
            _ => unreachable!(),
        }
        assert_ne!(changed, raw);
        assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidSpendProof { index: 0 }), "field {field}");
    }
}

#[test]
fn every_output_and_its_five_public_inputs_reach_the_actual_pairing_check() {
    let (raw, original) = recorded();
    // Removing the spend invalidates binding, but leaves both actual output
    // proofs valid. This isolates proof failures from the original SpendAuth.
    assert_eq!(check(&outputs_only(&original)), Err(SaplingCryptoError::InvalidBindingSignature));
    for (index, offset) in OUTPUTS.into_iter().enumerate() {
        for field in 0..3 {
            let mut changed = raw.clone();
            match field {
                0 => changed[offset..offset + 32].copy_from_slice(&SPENDING_KEY_GENERATOR.to_bytes()),
                1 => changed[offset + 32] ^= 1,
                2 => changed[offset + 64..offset + 96].copy_from_slice(&SPENDING_KEY_GENERATOR.to_bytes()),
                _ => unreachable!(),
            }
            assert_ne!(changed, raw);
            assert_eq!(
                check(&outputs_only(&parse(&changed, BranchId::Sapling))),
                Err(SaplingCryptoError::InvalidOutputProof { index }), "output {index}, field {field}",
            );
        }
    }
}

#[test]
fn finite_subgroup_replacements_fail_each_actual_proof_component() {
    let (raw, _) = recorded();
    let g1 = G1Affine::generator().to_compressed();
    let g2 = G2Affine::generator().to_compressed();
    for (proof_start, output) in [(SPEND + 128, None), (OUTPUTS[0] + 756, Some(0)), (OUTPUTS[1] + 756, Some(1))] {
        for (start, end) in [(0, 48), (48, 144), (144, 192)] {
            let replacement: &[u8] = if start == 48 { &g2 } else { &g1 };
            let mut changed = raw.clone();
            assert_ne!(&changed[proof_start + start..proof_start + end], replacement);
            changed[proof_start + start..proof_start + end].copy_from_slice(replacement);
            bellman::groth16::Proof::<Bls12>::read(&changed[proof_start..proof_start + 192]).unwrap();
            let transaction = parse(&changed, BranchId::Sapling);
            let (result, expected) = match output {
                None => (check(&transaction), SaplingCryptoError::InvalidSpendProof { index: 0 }),
                Some(index) => (check(&outputs_only(&transaction)), SaplingCryptoError::InvalidOutputProof { index }),
            };
            assert_eq!(result, Err(expected), "proof {proof_start}, component {start}");
        }
    }
}

#[test]
fn malformed_infinite_and_noncanonical_proof_points_are_not_accepted() {
    let (raw, _) = recorded();
    let modulus = bytes(concat!(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf",
        "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    ));
    for (proof_start, output) in [(SPEND + 128, None), (OUTPUTS[0] + 756, Some(0)), (OUTPUTS[1] + 756, Some(1))] {
        for (start, end) in [(0, 48), (48, 144), (144, 192)] {
            for malformed in 0..4 {
                let mut changed = raw.clone();
                match malformed {
                    0 => changed[proof_start + start] &= 0x7f,
                    1 | 2 => {
                        changed[proof_start + start..proof_start + end].fill(0);
                        changed[proof_start + start] = if malformed == 1 { 0xc0 } else { 0xe0 };
                    }
                    3 => {
                        changed[proof_start + start..proof_start + start + 48].copy_from_slice(&modulus);
                        changed[proof_start + start] |= 0x80;
                    }
                    _ => unreachable!(),
                }
                let transaction = parse(&changed, BranchId::Sapling);
                let (result, expected) = match output {
                    None => (check(&transaction), SaplingCryptoError::InvalidSpendProofEncoding { index: 0 }),
                    Some(index) => (check(&outputs_only(&transaction)), SaplingCryptoError::InvalidOutputProofEncoding { index }),
                };
                assert_eq!(result, Err(expected), "proof {proof_start}, component {start}, malformed {malformed}");
            }
        }
    }
}

#[test]
fn spend_authorization_binding_branch_and_all_ciphertexts_commit_to_this_transaction() {
    let (raw, _) = recorded();
    let mut changed = raw.clone();
    changed[SPEND + 320] ^= 1;
    assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
    let mut changed = raw.clone();
    changed[BINDING] ^= 1;
    assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidBindingSignature));
    let mut changed = raw.clone();
    changed[18] ^= 1; // Actual signed valueBalance.
    assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
    for branch in [BranchId::Blossom, BranchId::Canopy, BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        assert_eq!(check(&parse(&raw, branch)), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
    }
    for offset in OUTPUTS {
        for ciphertext_byte in [96, 675, 676, 755] {
            let mut changed = raw.clone();
            changed[offset + ciphertext_byte] ^= 1;
            assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
        }
    }
}

#[test]
fn small_order_spend_keys_and_ephemeral_keys_are_rejected_separately_from_signatures() {
    let (raw, _) = recorded();
    let identity = jubjub::AffinePoint::identity().to_bytes();
    let mut changed = raw.clone();
    changed[SPEND + 96..SPEND + 128].copy_from_slice(&identity);
    assert_eq!(check(&parse(&changed, BranchId::Sapling)), Err(SaplingCryptoError::InvalidSpendKey { index: 0 }));
    let order_two = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one()).to_bytes();
    for (index, offset) in OUTPUTS.into_iter().enumerate() {
        for point in [identity, order_two] {
            for noncanonical in [false, true] {
                let mut changed = raw.clone();
                changed[offset + 64..offset + 96].copy_from_slice(&point);
                if noncanonical { changed[offset + 95] |= 0x80; }
                assert_eq!(
                    check(&outputs_only(&parse(&changed, BranchId::Sapling))),
                    Err(SaplingCryptoError::InvalidEphemeralKey { index }),
                );
            }
        }
    }
}

#[test]
fn directly_constructed_small_order_value_commitments_do_not_bypass_network_guards() {
    let (_, original) = recorded();
    let bundle = original.sapling_bundle().unwrap();
    let zero_cv = || ValueCommitment::derive(NoteValue::from_raw(0), ValueCommitTrapdoor::from_bytes([0; 32]).unwrap());
    let spend = &bundle.shielded_spends()[0];
    let changed_spend = SpendDescription::from_parts(
        zero_cv(), *spend.anchor(), *spend.nullifier(), *spend.rk(), *spend.zkproof(), *spend.spend_auth_sig(),
    );
    let changed = with_bundle(&original, Bundle::from_parts(
        vec![changed_spend], bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization(),
    ));
    assert_eq!(check(&changed), Err(SaplingCryptoError::InvalidSpendValueCommitment { index: 0 }));
    for index in 0..2 {
        let mut outputs = bundle.shielded_outputs().to_vec();
        let output = &outputs[index];
        outputs[index] = OutputDescription::from_parts(
            zero_cv(), *output.cmu(), output.ephemeral_key().clone(), *output.enc_ciphertext(), *output.out_ciphertext(), *output.zkproof(),
        );
        let changed = with_bundle(&original, Bundle::from_parts(
            vec![], outputs, *bundle.value_balance(), *bundle.authorization(),
        ));
        assert_eq!(check(&changed), Err(SaplingCryptoError::InvalidOutputValueCommitment { index }));
    }
}

#[test]
fn absence_succeeds_only_inside_the_typed_v4_shape_boundary_not_as_ledger_truth() {
    for branch in [BranchId::Sapling, BranchId::Canopy, BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        // No inputs/outputs: intentionally not a ledger-valid transaction.
        let transaction = TransactionData::<Authorized>::from_parts(
            TxVersion::V4, branch, 0, 0_u32.into(), None, None, None, None,
        ).freeze().unwrap();
        assert_eq!(check(&transaction), Ok(()));
    }
    let unsupported = TransactionData::<Authorized>::from_parts(
        TxVersion::V3, BranchId::Overwinter, 0, 0_u32.into(), None, None, None, None,
    ).freeze().unwrap();
    assert!(matches!(SaplingSignatureHash::new(&unsupported), Err(SaplingSighashError::UnsupportedVersion)));
    let wrong_branch = TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Overwinter, 0, 0_u32.into(), None, None, None, None,
    ).freeze().unwrap();
    assert!(matches!(SaplingSignatureHash::new(&wrong_branch), Err(SaplingSighashError::UnsupportedBranch)));
}

#[test]
fn nu61_and_nu62_every_actual_output_proof_and_old_spend_authorization_stay_required() {
    let (raw, _) = recorded();
    for branch in [BranchId::Nu6_1, BranchId::Nu6_2] {
        let source = parse(&raw, branch);
        assert_eq!(check(&source), Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
        for (index, offset) in OUTPUTS.into_iter().enumerate() {
            let mut changed = raw.clone();
            changed[offset + 756] ^= 0x20;
            assert_eq!(check(&outputs_only(&parse(&changed, branch))), Err(SaplingCryptoError::InvalidOutputProof { index }));
        }
        assert_eq!(check(&outputs_only(&source)), Err(SaplingCryptoError::InvalidBindingSignature));
    }
}

#[test]
fn nu61_and_nu62_real_output_proofs_binding_value_and_ephemeral_keys_are_checked_independently() {
    let (raw, _) = recorded();
    for branch in [BranchId::Nu6_1, BranchId::Nu6_2] {
        let source = parse(&raw, branch);
        let bundle = source.sapling_bundle().unwrap();
        for index in 0..2 {
            let original = &bundle.shielded_outputs()[index];
            for mutation in 0..3 {
                let mut outputs = bundle.shielded_outputs().to_vec();
                let zero_cv = ValueCommitment::derive(NoteValue::from_raw(0), ValueCommitTrapdoor::from_bytes([0; 32]).unwrap());
                let mut proof = *original.zkproof();
                if mutation == 2 { proof[0] ^= 0x20; }
                outputs[index] = OutputDescription::from_parts(
                    if mutation == 0 { zero_cv } else { original.cv().clone() },
                    *original.cmu(),
                    if mutation == 1 { zcash_note_encryption::EphemeralKeyBytes(jubjub::AffinePoint::identity().to_bytes()) } else { original.ephemeral_key().clone() },
                    *original.enc_ciphertext(), *original.out_ciphertext(), proof,
                );
                let changed = with_bundle(&source, Bundle::from_parts(vec![], outputs, *bundle.value_balance(), *bundle.authorization()));
                assert_eq!(check(&changed), Err(match mutation {
                    0 => SaplingCryptoError::InvalidOutputValueCommitment { index },
                    1 => SaplingCryptoError::InvalidEphemeralKey { index },
                    _ => SaplingCryptoError::InvalidOutputProof { index },
                }));
            }
        }
        let mut signature = <[u8; 64]>::from(bundle.authorization().binding_sig);
        signature[..32].copy_from_slice(&jubjub::AffinePoint::identity().to_bytes());
        signature[31] |= 0x80;
        let changed = with_bundle(&source, Bundle::from_parts(vec![], bundle.shielded_outputs().to_vec(), *bundle.value_balance(), SaplingAuthorized { binding_sig: signature.into() }));
        assert_eq!(check(&changed), Err(SaplingCryptoError::InvalidBindingSignature));
    }
}
