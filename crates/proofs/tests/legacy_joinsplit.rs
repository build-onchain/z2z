//! Actual pre-Overwinter JoinSplit proof plus historical signature acceptance;
//! this does not establish transparent authorization, UTXOs, history, or finality.

use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion, components::sprout::{Bundle, JsDescription}};
use zcash_protocol::{consensus::BranchId, value::MAX_MONEY};
use zcash_transparent::bundle::TxOut;
use ziquid_proofs::legacy_joinsplit::{LegacyJoinSplitError, verify_legacy_joinsplit_crypto};

#[path = "fixtures/legacy-joinsplit-mainnet-396.rs"]
mod primary;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |value| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

fn parse(raw: &[u8]) -> Transaction {
    let mut reader = raw;
    let transaction = Transaction::read(&mut reader, BranchId::Sprout).expect("source transaction parses");
    assert!(reader.is_empty(), "complete transaction consumed");
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).expect("source transaction serializes");
    assert_eq!(canonical, raw, "canonical transaction bytes");
    transaction
}

#[test]
fn recorded_mined_v2_accepts_original_proof_and_actual_joinsplit_signature() {
    let raw = bytes(primary::TRANSACTION_HEX);
    assert_eq!(raw.len(), 2022);
    assert_eq!(verify_legacy_joinsplit_crypto(&parse(&raw)), Ok(()));
}

#[test]
fn signature_scalar_malleation_and_every_signed_transaction_field_reject() {
    let original = bytes(primary::TRANSACTION_HEX);
    // Field offsets are in the authentic full transaction, not reconstructed
    // witness data. They include both inputs/outputs of the PHGR statement,
    // every proof component, ephemeral key, and both ciphertexts.
    for offset in [
        0, 5, 37, 114, 119, 124, 140, 172, 204, 236, 268, 300, 332, 364, 396,
        428, 461, 494, 559, 592, 625, 658, 691, 724, 1325, 1926, 1958, 1990,
    ] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        assert_eq!(
            verify_legacy_joinsplit_crypto(&parse(&changed)),
            Err(LegacyJoinSplitError::InvalidSignature),
            "accepted signed-field mutation at {offset}",
        );
    }

    // Original Zcash test_checktransaction.cpp adds the group order to a valid
    // signature scalar. Normal libsodium 1.0.15 must reject even with the same R.
    let order = bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut changed = original;
    let mut carry = 0_u16;
    for (scalar_byte, order_byte) in changed[1990..2022].iter_mut().zip(order) {
        let sum = u16::from(*scalar_byte) + u16::from(order_byte) + carry;
        *scalar_byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(verify_legacy_joinsplit_crypto(&parse(&changed)), Err(LegacyJoinSplitError::InvalidSignature));

    // An added actual output, including its value and script, is committed.
    let source = parse(&bytes(primary::TRANSACTION_HEX));
    let mut transparent = source.transparent_bundle().unwrap().clone();
    transparent.vout.push(output(1));
    let added_output = TransactionData::<Authorized>::from_parts(
        TxVersion::Sprout(2), BranchId::Sprout, 0, 0.into(),
        Some(transparent), source.sprout_bundle().cloned(), None, None,
    ).freeze().unwrap();
    assert_eq!(verify_legacy_joinsplit_crypto(&added_output), Err(LegacyJoinSplitError::InvalidSignature));
}

#[test]
fn transparent_script_sig_is_intentionally_not_joinsplit_authorization() {
    let mut changed = bytes(primary::TRANSACTION_HEX);
    changed[42] ^= 1;
    assert_eq!(verify_legacy_joinsplit_crypto(&parse(&changed)), Ok(()));
    // This success does not claim that the transparent input is authorized.
}

fn output(value: u64) -> TxOut {
    let mut raw = value.to_le_bytes().to_vec();
    raw.extend_from_slice(&[1, 0x51]);
    TxOut::read(&mut raw.as_slice()).unwrap()
}

fn description(old: u64, new: u64, first_nullifier: u8, second_nullifier: u8) -> JsDescription {
    let source = bytes(primary::TRANSACTION_HEX);
    let mut raw = source[124..1926].to_vec();
    raw[..8].copy_from_slice(&old.to_le_bytes());
    raw[8..16].copy_from_slice(&new.to_le_bytes());
    raw[48..80].fill(first_nullifier);
    raw[80..112].fill(second_nullifier);
    JsDescription::read(&raw[..], false).unwrap()
}

fn bundle(descriptions: Vec<JsDescription>) -> Bundle {
    // Existing signature/proofs are deliberately invalid after changing these
    // statements. Categorical errors prove cheap guards are not masked by them.
    let source = parse(&bytes(primary::TRANSACTION_HEX));
    let mut bundle = source.sprout_bundle().unwrap().clone();
    bundle.joinsplits = descriptions;
    bundle
}

fn with_bundle(sprout: Option<Bundle>, outputs: &[u64]) -> Transaction {
    let source = parse(&bytes(primary::TRANSACTION_HEX));
    let mut transparent = source.transparent_bundle().unwrap().clone();
    transparent.vout = outputs.iter().copied().map(output).collect();
    TransactionData::<Authorized>::from_parts(
        TxVersion::Sprout(2), BranchId::Sprout, 0, 0.into(),
        Some(transparent), sprout, None, None,
    ).freeze().unwrap()
}

#[test]
fn one_zero_rule_and_separate_debit_credit_totals_precede_cryptography() {
    let both_nonzero = with_bundle(Some(bundle(vec![description(1, 1, 1, 2)])), &[]);
    assert_eq!(verify_legacy_joinsplit_crypto(&both_nonzero), Err(LegacyJoinSplitError::InvalidPublicValues));

    // Both zero and exact individual/aggregate MAX_MONEY are permitted by the
    // cheap relation, and therefore reach the (deliberately invalid) signature.
    for (old, new, outputs) in [(0, 0, vec![]), (MAX_MONEY, 0, vec![]), (0, MAX_MONEY, vec![MAX_MONEY])] {
        let transaction = with_bundle(Some(bundle(vec![description(old, new, 1, 2)])), &outputs);
        assert_eq!(verify_legacy_joinsplit_crypto(&transaction), Err(LegacyJoinSplitError::InvalidSignature));
    }

    let debit = with_bundle(Some(bundle(vec![description(MAX_MONEY, 0, 1, 2)])), &[1]);
    assert_eq!(verify_legacy_joinsplit_crypto(&debit), Err(LegacyJoinSplitError::DebitOutOfRange));
    let old_total = with_bundle(Some(bundle(vec![description(MAX_MONEY, 0, 1, 2), description(1, 0, 3, 4)])), &[]);
    assert_eq!(verify_legacy_joinsplit_crypto(&old_total), Err(LegacyJoinSplitError::DebitOutOfRange));
    let credit = with_bundle(Some(bundle(vec![description(0, MAX_MONEY, 1, 2), description(0, 1, 3, 4)])), &[]);
    assert_eq!(verify_legacy_joinsplit_crypto(&credit), Err(LegacyJoinSplitError::CreditOutOfRange));

    // The positive/negative flows cancel net balance, but both totals still
    // exceed MAX_MONEY. A net-only guard would incorrectly reach the signature.
    let offsetting = with_bundle(Some(bundle(vec![
        description(MAX_MONEY, 0, 1, 2), description(1, 0, 3, 4),
        description(0, MAX_MONEY, 5, 6), description(0, 1, 7, 8),
    ])), &[]);
    assert_eq!(verify_legacy_joinsplit_crypto(&offsetting), Err(LegacyJoinSplitError::DebitOutOfRange));

    let output_total = with_bundle(None, &[MAX_MONEY, 1]);
    assert_eq!(verify_legacy_joinsplit_crypto(&output_total), Err(LegacyJoinSplitError::DebitOutOfRange));
}

#[test]
fn canonical_transaction_boundary_rejects_negative_and_excessive_public_amounts() {
    // JsDescription's public typed construction already requires these ranges;
    // hostile wire values must be rejected before reaching the crypto helper.
    for start in [124, 132] {
        for invalid in [u64::MAX, MAX_MONEY + 1] {
            let mut changed = bytes(primary::TRANSACTION_HEX);
            changed[start..start + 8].copy_from_slice(&invalid.to_le_bytes());
            assert!(Transaction::read(&changed[..], BranchId::Sprout).is_err());
        }
    }
}

#[test]
fn duplicate_nullifiers_inside_and_across_actual_descriptions_precede_signature() {
    for descriptions in [
        vec![description(0, 0, 1, 1)],
        vec![description(0, 0, 1, 2), description(0, 0, 3, 1)],
        vec![description(0, 0, 0, 0)],
    ] {
        let transaction = with_bundle(Some(bundle(descriptions)), &[]);
        assert_eq!(verify_legacy_joinsplit_crypto(&transaction), Err(LegacyJoinSplitError::DuplicateNullifier));
    }
}

#[test]
fn canonical_no_joinsplits_needs_no_joinsplit_signature_but_shape_is_guarded() {
    let source = parse(&bytes(primary::TRANSACTION_HEX));
    let make = |version, expiry, sprout| TransactionData::<Authorized>::from_parts(
        version, BranchId::Sprout, 0, expiry,
        source.transparent_bundle().cloned(), sprout, None, None,
    ).freeze().unwrap();
    for version in [1, 2, 3, 0x7fff_ffff] {
        assert_eq!(verify_legacy_joinsplit_crypto(&make(TxVersion::Sprout(version), 0.into(), None)), Ok(()));
    }
    for version in [TxVersion::Sprout(0), TxVersion::Sprout(0x8000_0000), TxVersion::V3, TxVersion::V4] {
        assert_eq!(verify_legacy_joinsplit_crypto(&make(version, 0.into(), None)), Err(LegacyJoinSplitError::UnsupportedVersion));
    }
    let mut groth_bundle = source.sprout_bundle().unwrap().clone();
    groth_bundle.joinsplits[0] = JsDescription::read(&bytes(primary::TRANSACTION_HEX)[124..1926], true).unwrap();
    for transaction in [
        make(TxVersion::Sprout(2), 1.into(), None),
        make(TxVersion::Sprout(1), 0.into(), source.sprout_bundle().cloned()),
        make(TxVersion::Sprout(2), 0.into(), Some(bundle(vec![]))),
        make(TxVersion::Sprout(2), 0.into(), Some(groth_bundle)),
    ] {
        assert_eq!(verify_legacy_joinsplit_crypto(&transaction), Err(LegacyJoinSplitError::IncompatibleTransaction));
    }
}
