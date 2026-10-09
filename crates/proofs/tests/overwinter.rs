//! ZIP143 and actual original V3 authorization. Isolated public vectors are
//! not connected history, transparent authorization, or settlement facts.

use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TxVersion,
    components::sprout::{Bundle, JsDescription},
};
use zcash_protocol::{consensus::BranchId, value::{MAX_MONEY, Zatoshis}};
use zcash_transparent::{address::Script, bundle::{self, OutPoint, TxIn, TxOut}};
use ziquid_proofs::{
    legacy_joinsplit::{LegacyJoinSplitError, verify_overwinter_joinsplit_crypto},
    overwinter::{OverwinterSignatureHash, OverwinterSighashError},
};

#[path = "fixtures/overwinter-primary.rs"]
mod digests;
#[path = "fixtures/overwinter-mined.rs"]
mod primary;
#[path = "fixtures/overwinter-offsets.rs"]
mod offsets;

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
    let mut remaining = raw;
    let transaction = Transaction::read(&mut remaining, BranchId::Overwinter).unwrap();
    assert!(remaining.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn script(code: &[u8]) -> Script {
    let mut script = Script::default();
    script.0.0 = code.to_vec();
    script
}

fn transparent() -> bundle::Bundle<bundle::Authorized> {
    bundle::Bundle {
        vin: vec![
            TxIn::from_parts(OutPoint::new([0x41; 32], 7), script(&[]), 123),
            TxIn::from_parts(OutPoint::new([0x42; 32], 9), script(&[]), 456),
        ],
        vout: vec![
            TxOut::new(Zatoshis::from_u64(12).unwrap(), script(&[0x51])),
            TxOut::new(Zatoshis::from_u64(34).unwrap(), script(&[0x52])),
        ],
        authorization: bundle::Authorized,
    }
}

fn transaction(bundle: bundle::Bundle<bundle::Authorized>, expiry: u32) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V3, BranchId::Overwinter, 17, expiry.into(), Some(bundle), None, None, None,
    ).freeze().unwrap()
}

#[test]
fn matches_every_independent_maintained_zip143_and_signed_i32_c_tuple() {
    for vector in digests::ZIP143_VECTORS {
        let tx = parse(&bytes(vector.tx_hex));
        let hashes = OverwinterSignatureHash::new(&tx).unwrap();
        let digest = match vector.input_index {
            Some(index) => hashes.transparent(index, &bytes(vector.script_hex), Zatoshis::from_u64(vector.amount).unwrap(), vector.raw_hash_type).unwrap(),
            None => hashes.joinsplit(),
        };
        assert_eq!(digest, vector.expected);
    }
}

#[test]
fn all_none_single_and_anyonecanpay_bind_exact_selected_fields_and_full_raw_type() {
    let original = transaction(transparent(), 250_000);
    let amount = Zatoshis::from_u64(100).unwrap();
    for raw_type in [0, 1, 2, 3, 0x81, 0x82, 0x83, 0x41, -865_463_971] {
        let hashes = OverwinterSignatureHash::new(&original).unwrap();
        let digest = hashes.transparent(0, &[0x51, 0xab, 0], amount, raw_type).unwrap();
        for other in [raw_type ^ 0x100, raw_type ^ i32::MIN] {
            assert_ne!(hashes.transparent(0, &[0x51, 0xab, 0], amount, other), Ok(digest));
        }
        for script_code in [&[0x51, 0][..], &[0x51, 0xab, 1][..]] {
            assert_ne!(hashes.transparent(0, script_code, amount, raw_type), Ok(digest));
        }
        for value in [99, 101] {
            assert_ne!(hashes.transparent(0, &[0x51, 0xab, 0], Zatoshis::from_u64(value).unwrap(), raw_type), Ok(digest));
        }
        // Removing/replacing these fields must preserve a digest ONLY when its
        // original selector excludes them; selected input always stays bound.
        for field in 0..9 {
            let mut bundle = transparent();
            let expiry = if field == 5 { 250_001 } else { 250_000 };
            match field {
                0 | 1 => {
                    let index = field;
                    bundle.vin[index] = TxIn::from_parts(OutPoint::new([0x55; 32], 1), script(&[]), bundle.vin[index].sequence());
                }
                2 => bundle.vin[1] = TxIn::from_parts(bundle.vin[1].prevout().clone(), script(&[]), 457),
                3 => bundle.vout[0] = TxOut::new(Zatoshis::from_u64(13).unwrap(), script(&[0x51])),
                4 => bundle.vout[1] = TxOut::new(Zatoshis::from_u64(35).unwrap(), script(&[0x52])),
                6 => bundle.vin[0] = TxIn::from_parts(bundle.vin[0].prevout().clone(), script(&[]), 124),
                7 => bundle.vin[0] = TxIn::from_parts(bundle.vin[0].prevout().clone(), script(&[0x51, 0]), 123),
                _ => {}
            }
            let changed = if field == 8 {
                TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 18, expiry.into(), Some(bundle), None, None, None).freeze().unwrap()
            } else {
                transaction(bundle, expiry)
            };
            let changed_digest = OverwinterSignatureHash::new(&changed).unwrap().transparent(0, &[0x51, 0xab, 0], amount, raw_type).unwrap();
            let base = raw_type & 0x1f;
            let excluded = match field {
                1 => raw_type & 0x80 != 0,
                2 => raw_type & 0x80 != 0 || matches!(base, 2 | 3),
                3 => base == 2,
                4 => matches!(base, 2 | 3),
                7 => true, // scriptSig is replaced by caller's whole scriptCode.
                _ => false,
            };
            assert_eq!(changed_digest == digest, excluded, "field={field}, type={raw_type}");
        }
    }
}

#[test]
fn single_without_output_is_defined_but_out_of_range_input_and_sentinel_are_errors() {
    let mut bundle = transparent();
    bundle.vout.clear();
    let tx = transaction(bundle, 0);
    let hashes = OverwinterSignatureHash::new(&tx).unwrap();
    for raw_type in [3_u8, 0x83] {
        use zcash_primitives::transaction::{sighash::SignableInput, sighash_v4::v4_signature_hash};
        use zcash_transparent::sighash::{SignableInput as TransparentInput, SighashType};
        let code = script(&[0x51]);
        let input = TransparentInput::from_parts(tx.transparent_bundle().unwrap(), SighashType::from_raw(raw_type), 1, &code, &code, Zatoshis::ZERO).unwrap();
        let expected = v4_signature_hash(&tx, &SignableInput::Transparent(input));
        let digest = hashes.transparent(1, &[0x51], Zatoshis::ZERO, i32::from(raw_type)).unwrap();
        assert_eq!(digest.as_slice(), expected.as_bytes());
    }
    for index in [2, usize::MAX] {
        assert_eq!(hashes.transparent(index, &[], Zatoshis::ZERO, 1), Err(OverwinterSighashError::InputIndexOutOfRange));
    }
    let empty = parse(&bytes("030000807082c4030000000000000000000000"));
    assert_eq!(OverwinterSignatureHash::new(&empty).unwrap().transparent(0, &[], Zatoshis::ZERO, 1), Err(OverwinterSighashError::InputIndexOutOfRange));
}

#[test]
fn only_exact_v3_overwinter_phgr_shape_is_hashable_but_expiry_is_contextual() {
    let source = parse(&bytes(primary::MINED_V3_TX_HEX));
    let make = |version, branch, expiry: u32, sprout| TransactionData::<Authorized>::from_parts(
        version, branch, 0, expiry.into(), source.transparent_bundle().cloned(), sprout, None, None,
    ).freeze().unwrap();
    for (version, branch) in [(TxVersion::Sprout(3), BranchId::Sprout), (TxVersion::V4, BranchId::Sapling), (TxVersion::V5, BranchId::Nu5), (TxVersion::V6, BranchId::Nu6_3)] {
        let tx = make(version, branch, 0_u32, None);
        assert!(matches!(OverwinterSignatureHash::new(&tx), Err(OverwinterSighashError::UnsupportedVersion)));
    }
    for branch in [BranchId::Sprout, BranchId::Sapling, BranchId::Nu5] {
        let tx = make(TxVersion::V3, branch, 0_u32, None);
        assert!(matches!(OverwinterSignatureHash::new(&tx), Err(OverwinterSighashError::UnsupportedBranch)));
    }
    let mut empty = source.sprout_bundle().unwrap().clone();
    empty.joinsplits.clear();
    let mut groth = source.sprout_bundle().unwrap().clone();
    let mut encoded = Vec::new();
    groth.joinsplits[0].write(&mut encoded).unwrap();
    groth.joinsplits[0] = JsDescription::read(encoded.as_slice(), true).unwrap();
    for bundle in [empty, groth] {
        let tx = make(TxVersion::V3, BranchId::Overwinter, 0_u32, Some(bundle));
        assert!(matches!(OverwinterSignatureHash::new(&tx), Err(OverwinterSighashError::IncompatibleTransaction)));
    }
    for expiry in [0, 499_999_999, 500_000_000, u32::MAX] {
        let tx = make(TxVersion::V3, BranchId::Overwinter, expiry, None);
        assert!(OverwinterSignatureHash::new(&tx).is_ok());
    }
    let mut malformed = bytes(primary::MINED_V3_TX_HEX);
    malformed[4] ^= 1;
    assert!(Transaction::read(malformed.as_slice(), BranchId::Overwinter).is_err());
    malformed = bytes(primary::MINED_V3_TX_HEX);
    malformed[0] = 4;
    assert!(Transaction::read(malformed.as_slice(), BranchId::Overwinter).is_err());
}

#[test]
fn recorded_zero_vin_v3_passes_original_ed25519_and_every_phgr_equation() {
    let tx = parse(&bytes(primary::MINED_V3_TX_HEX));
    assert!(tx.transparent_bundle().is_none());
    let hashes = OverwinterSignatureHash::new(&tx).unwrap();
    assert_eq!(verify_overwinter_joinsplit_crypto(&hashes), Ok(()));
    for offset in [
        offsets::MINED_V3_LOCK_TIME_OFFSET, offsets::MINED_V3_EXPIRY_HEIGHT_OFFSET,
        offsets::MINED_V3_ANCHOR_OFFSET, offsets::MINED_V3_NULLIFIER_OFFSET,
        offsets::MINED_V3_PROOF_OFFSET + 1, offsets::MINED_V3_CIPHERTEXT_OFFSET,
        offsets::MINED_V3_CIPHERTEXT_OFFSET + 601, offsets::MINED_V3_PUBKEY_OFFSET,
        offsets::MINED_V3_SIGNATURE_OFFSET,
    ] {
        let mut changed = bytes(primary::MINED_V3_TX_HEX);
        changed[offset] ^= 1;
        let changed = parse(&changed);
        assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&changed).unwrap()), Err(LegacyJoinSplitError::InvalidSignature), "unbound original byte {offset}");
    }
}

#[test]
fn complete_joinsplits_and_key_are_bound_by_every_transparent_mode_but_signature_is_omitted() {
    let source = parse(&bytes(primary::MINED_V3_TX_HEX));
    let make = |sprout| TransactionData::<Authorized>::from_parts(
        TxVersion::V3, BranchId::Overwinter, 0, 207_521_u32.into(), Some(transparent()), Some(sprout), None, None,
    ).freeze().unwrap();
    let tx = make(source.sprout_bundle().unwrap().clone());
    let original = OverwinterSignatureHash::new(&tx).unwrap();
    for raw_type in [1, 2, 3, 0x81, 0x82, 0x83] {
        let digest = original.transparent(0, &[0x51], Zatoshis::ZERO, raw_type).unwrap();
        let mut changed = source.sprout_bundle().unwrap().clone();
        changed.joinsplit_sig[0] ^= 1;
        let changed = make(changed);
        let hashes = OverwinterSignatureHash::new(&changed).unwrap();
        assert_eq!(hashes.transparent(0, &[0x51], Zatoshis::ZERO, raw_type), Ok(digest));
        assert_eq!(hashes.joinsplit(), original.joinsplit());
        for offset in [0, 8, 16, 48, 80, 112, 144, 176, 208, 240, 272, 305, 599, 600, 1201, 1801, 1802] {
            let mut changed = source.sprout_bundle().unwrap().clone();
            if offset == 1802 {
                changed.joinsplit_pubkey[0] ^= 1;
            } else {
                let mut raw = Vec::new();
                changed.joinsplits[0].write(&mut raw).unwrap();
                raw[offset] ^= 1;
                changed.joinsplits[0] = JsDescription::read(raw.as_slice(), false).unwrap();
            }
            let changed = make(changed);
            let hashes = OverwinterSignatureHash::new(&changed).unwrap();
            assert_ne!(hashes.transparent(0, &[0x51], Zatoshis::ZERO, raw_type), Ok(digest));
            assert_ne!(hashes.joinsplit(), original.joinsplit());
        }
    }
}

#[test]
fn public_value_and_nullifier_guards_precede_original_v3_signature_verification() {
    let source = parse(&bytes(primary::MINED_V3_TX_HEX));
    let make = |bundle: Option<Bundle>, outputs: &[u64]| {
        let mut transparent = transparent();
        transparent.vout = outputs.iter().map(|value| TxOut::new(Zatoshis::from_u64(*value).unwrap(), script(&[]))).collect();
        TransactionData::<Authorized>::from_parts(
            TxVersion::V3, BranchId::Overwinter, 0, 0.into(), Some(transparent), bundle, None, None,
        ).freeze().unwrap()
    };
    for (old, new, outputs, expected) in [
        (1_u64, 1_u64, vec![], LegacyJoinSplitError::InvalidPublicValues),
        (MAX_MONEY, 0_u64, vec![1], LegacyJoinSplitError::DebitOutOfRange),
    ] {
        let mut bundle = source.sprout_bundle().unwrap().clone();
        let mut raw = Vec::new();
        bundle.joinsplits[0].write(&mut raw).unwrap();
        raw[..8].copy_from_slice(&old.to_le_bytes());
        raw[8..16].copy_from_slice(&new.to_le_bytes());
        bundle.joinsplits[0] = JsDescription::read(raw.as_slice(), false).unwrap();
        let tx = make(Some(bundle), &outputs);
        assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Err(expected));
    }
    for across_descriptions in [false, true] {
        let mut bundle = source.sprout_bundle().unwrap().clone();
        if across_descriptions {
            bundle.joinsplits.push(bundle.joinsplits[0].clone());
        } else {
            let mut raw = Vec::new();
            bundle.joinsplits[0].write(&mut raw).unwrap();
            let first = raw[48..80].to_vec();
            raw[80..112].copy_from_slice(&first);
            bundle.joinsplits[0] = JsDescription::read(raw.as_slice(), false).unwrap();
        }
        let tx = make(Some(bundle), &[]);
        assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Err(LegacyJoinSplitError::DuplicateNullifier));
    }
    let mut bundle = source.sprout_bundle().unwrap().clone();
    let mut raw = Vec::new();
    bundle.joinsplits[0].write(&mut raw).unwrap();
    raw[8..16].copy_from_slice(&MAX_MONEY.to_le_bytes());
    bundle.joinsplits[0] = JsDescription::read(raw.as_slice(), false).unwrap();
    // Aggregate credit bound must precede even the duplicated-nullifier guard.
    bundle.joinsplits.push(bundle.joinsplits[0].clone());
    let tx = make(Some(bundle), &[]);
    assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Err(LegacyJoinSplitError::CreditOutOfRange));
    let tx = make(None, &[MAX_MONEY, 1]);
    assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Err(LegacyJoinSplitError::DebitOutOfRange));
    let tx = make(None, &[]);
    assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Ok(()));
}

#[test]
fn historical_identity_key_acceptance_cannot_bypass_the_actual_v3_phgr_key_binding() {
    let source = parse(&bytes(primary::MINED_V3_TX_HEX));
    let mut bundle = source.sprout_bundle().unwrap().clone();
    bundle.joinsplit_pubkey = [0; 32];
    bundle.joinsplit_pubkey[0] = 1;
    // Literal pinned original-C accepted identity-A tuple: R=B,S=1, valid for
    // every message under original libsodium. Not a modern strict signature.
    bundle.joinsplit_sig = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
    let tx = TransactionData::<Authorized>::from_parts(TxVersion::V3, BranchId::Overwinter, 0, 207_521_u32.into(), None, Some(bundle), None, None).freeze().unwrap();
    assert_eq!(verify_overwinter_joinsplit_crypto(&OverwinterSignatureHash::new(&tx).unwrap()), Err(LegacyJoinSplitError::SproutProof { index: 0, error: ziquid_proofs::sprout::LegacyError::InvalidProof }));
}
