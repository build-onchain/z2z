//! Original Zcash legacy hash relation and real historical signatures; not UTXO,
//! source-chain, JoinSplit-proof, or complete script-consensus validation.

use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion, components::sprout::JsDescription};
use zcash_protocol::consensus::BranchId;
use zcash_script::{
    interpreter::{CallbackTransactionSignatureChecker, Flags},
    script::{self, Raw},
    signature,
};
use ziquid_proofs::legacy_sighash::{LegacySighashError, legacy_signature_hash};

#[path = "fixtures/legacy-sighash.rs"]
mod primary;
#[path = "fixtures/legacy-signed.rs"]
mod signed;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn parse(raw: &[u8]) -> Transaction {
    let mut reader = raw;
    let transaction = Transaction::read(&mut reader, BranchId::Sprout).expect("primary transaction parses");
    assert!(reader.is_empty(), "complete fixture consumed");
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).expect("fixture serializes");
    assert_eq!(canonical, raw, "canonical fixture bytes");
    transaction
}

fn eval(transaction: &Transaction, input_index: usize, previous_script: &[u8]) -> Result<bool, (script::ComponentType, script::Error)> {
    let input = &transaction.transparent_bundle().expect("fixture has transparent inputs").vin[input_index];
    let sighash = |code: &script::Code, hash_type: &signature::HashType| {
        legacy_signature_hash(transaction, input_index, &code.0, hash_type.raw_bits()).ok()
    };
    let checker = CallbackTransactionSignatureChecker {
        sighash: &sighash,
        lock_time: i64::from(transaction.lock_time()),
        is_final: input.sequence() == u32::MAX,
    };
    Raw::from_raw_parts(input.script_sig().0.0.clone(), previous_script.to_vec()).eval(Flags::P2SH, &checker)
}

#[test]
fn matches_independent_original_legacy_digests_in_raw_hash_order() {
    for (raw, script, input_index, raw_hash_type, _source_branch, display_hash) in primary::DIGEST_VECTORS {
        let mut expected: [u8; 32] = bytes(display_hash).try_into().expect("primary digest size");
        expected.reverse(); // Only reverses primary GetHex display order; no local hash oracle.
        assert_eq!(legacy_signature_hash(&parse(&bytes(raw)), input_index, &bytes(script), raw_hash_type), Ok(expected));
    }
}

#[test]
fn actual_published_v1_signature_passes_upstream_ecdsa_verification() {
    assert_eq!(eval(&parse(&bytes(signed::V1_SIGNED)), 0, &bytes(signed::V1_SCRIPT)), Ok(true));
}

#[test]
fn duplicated_signature_is_not_deleted_from_zcash_script_code() {
    let transaction = parse(&bytes(signed::V1_SIGNED));
    let result = eval(&transaction, 0, &bytes(primary::V1_NO_FIND_AND_DELETE_SCRIPT));
    assert!(matches!(result, Err((script::ComponentType::PubKey, script::Error::Interpreter(_, zcash_script::interpreter::Error::Verify)))));
}

#[test]
fn published_bitcoin_one_signature_fails_closed_for_missing_single_output() {
    let transaction = parse(&bytes(primary::V1_BITCOIN_ONE_SIGNED));
    let script = bytes(primary::V1_BITCOIN_ONE_SCRIPT);
    for hash_type in [3, 0x83, -125] {
        assert_eq!(legacy_signature_hash(&transaction, 1, &script, hash_type), Err(LegacySighashError::MissingSingleOutput));
    }
    assert_eq!(eval(&transaction, 1, &script), Ok(false));
}

#[test]
fn nonexistent_transparent_input_is_an_error_including_the_joinsplit_sentinel() {
    let transaction = parse(&bytes(signed::V1_SIGNED));
    for input_index in [1, usize::MAX] {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            assert_eq!(legacy_signature_hash(&transaction, input_index, &[], hash_type), Err(LegacySighashError::InputIndexOutOfRange));
        }
    }
    let empty = parse(&bytes("01000000000000000000"));
    assert_eq!(legacy_signature_hash(&empty, 0, &[], 1), Err(LegacySighashError::InputIndexOutOfRange));
}

#[test]
fn published_all_and_anyonecanpay_signatures_use_unsigned_suffixes() {
    let transaction = parse(&bytes(signed::V1_ALL_ACP_SIGNED));
    let script = bytes(signed::V1_ALL_ACP_SCRIPT);
    assert_eq!(eval(&transaction, 0, &script), Ok(true));
    assert_eq!(eval(&transaction, 1, &script), Ok(true));
}

#[test]
fn legal_sprout_version_range_is_preserved_and_new_formats_are_rejected() {
    let template = parse(&bytes(signed::V1_SIGNED));
    for version in [TxVersion::Sprout(1), TxVersion::Sprout(2), TxVersion::Sprout(0x7fff_ffff)] {
        let transaction = TransactionData::<Authorized>::from_parts(
            version, BranchId::Sprout, template.lock_time(), 0.into(),
            template.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        let mut raw = Vec::new();
        transaction.write(&mut raw).unwrap();
        let reparsed = parse(&raw);
        let script = bytes(signed::V1_SCRIPT);
        let digest = legacy_signature_hash(&reparsed, 0, &script, 1).unwrap();
        if version != TxVersion::Sprout(1) {
            assert_ne!(digest, legacy_signature_hash(&template, 0, &script, 1).unwrap());
        }
    }
    for version in [TxVersion::Sprout(0), TxVersion::Sprout(0x8000_0000), TxVersion::Sprout(u32::MAX), TxVersion::V3, TxVersion::V4] {
        let transaction = TransactionData::<Authorized>::from_parts(
            version, BranchId::Sprout, 0, 0.into(),
            template.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        assert_eq!(legacy_signature_hash(&transaction, 0, &[], 1), Err(LegacySighashError::UnsupportedVersion));
    }
    for (version, branch) in [(TxVersion::V5, BranchId::Nu5), (TxVersion::V6, BranchId::Nu6_3)] {
        let transaction = TransactionData::<Authorized>::from_parts(
            version, branch, 0, 0.into(), template.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        assert_eq!(legacy_signature_hash(&transaction, 0, &[], 1), Err(LegacySighashError::UnsupportedVersion));
    }
}

#[test]
fn rejects_incoherent_typed_legacy_shapes_before_hashing() {
    let template = parse(&bytes(primary::DIGEST_VECTORS[2].0));
    let make = |version, expiry, sprout| TransactionData::<Authorized>::from_parts(
        version, BranchId::Sprout, 0, expiry,
        template.transparent_bundle().cloned(), sprout, None, None,
    ).freeze().unwrap();
    let nonzero_expiry = make(TxVersion::Sprout(2), 1.into(), None);
    let v1_with_joinsplit = make(TxVersion::Sprout(1), 0.into(), template.sprout_bundle().cloned());
    let mut empty_bundle = template.sprout_bundle().unwrap().clone();
    empty_bundle.joinsplits.clear();
    let empty_joinsplit_authorization = make(TxVersion::Sprout(2), 0.into(), Some(empty_bundle));
    let mut groth_bundle = template.sprout_bundle().unwrap().clone();
    let mut groth_encoding = Vec::new();
    groth_bundle.joinsplits[0].write(&mut groth_encoding).unwrap();
    // A public upstream reader can artificially pair a Groth description with a
    // Sprout header. It is not an actual parsed legacy transaction.
    groth_bundle.joinsplits[0] = JsDescription::read(&groth_encoding[..], true).unwrap();
    let wrong_joinsplit_proof_format = make(TxVersion::Sprout(2), 0.into(), Some(groth_bundle));
    for transaction in [nonzero_expiry, v1_with_joinsplit, empty_joinsplit_authorization, wrong_joinsplit_proof_format] {
        assert_eq!(legacy_signature_hash(&transaction, 0, &[], 1), Err(LegacySighashError::IncompatibleTransaction));
    }
}

#[test]
fn joinsplit_authorization_is_masked_but_full_descriptions_are_bound_for_every_hash_type() {
    let (raw_hex, script_hex, input_index, _, _, _) = primary::DIGEST_VECTORS[2];
    let raw = bytes(raw_hex);
    let transaction = parse(&raw);
    let script = bytes(script_hex);
    let bundle = transaction.sprout_bundle().unwrap();
    assert_eq!(bundle.joinsplits.len(), 1);
    let mut description = Vec::new();
    bundle.joinsplits[0].write(&mut description).unwrap();
    assert_eq!(description.len(), 1802);
    let description_start = raw.len() - 1802 - 32 - 64;
    assert_eq!(&raw[description_start..description_start + 1802], description);
    let mut changed_auth = raw.clone();
    for byte in &mut changed_auth[raw.len() - 64..] {
        *byte ^= 0xff;
    }
    let changed_auth = parse(&changed_auth);
    for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
        let digest = legacy_signature_hash(&transaction, input_index, &script, hash_type).unwrap();
        assert_eq!(legacy_signature_hash(&changed_auth, input_index, &script, hash_type), Ok(digest));
        // Pubkey, private description fields, proof and both ciphertexts must
        // enter every transparent hash type. Byte changes assert commitments,
        // not that modified statements/proofs would be accepted by consensus.
        for offset in [
            0, 8, 16, 48, 80, 112, 144, 176, 208, 240, 272,
            304, 599, 600, 1200, 1201, 1801, 1802,
        ] {
            let mut changed = raw.clone();
            changed[description_start + offset] ^= 1;
            assert_ne!(legacy_signature_hash(&parse(&changed), input_index, &script, hash_type), Ok(digest), "unbound JoinSplit byte {offset}, hash type {hash_type}");
        }
    }
}

#[test]
fn transaction_scripts_are_not_hashed_but_the_actual_script_code_and_sequence_are() {
    let (raw_hex, script_hex, input_index, raw_hash_type, _, _) = primary::DIGEST_VECTORS[1];
    let raw = bytes(raw_hex);
    let transaction = parse(&raw);
    let script = bytes(script_hex);
    let digest = legacy_signature_hash(&transaction, input_index, &script, raw_hash_type).unwrap();
    let bundle = transaction.transparent_bundle().unwrap();
    let mut offset = 5; // This pinned row has a one-byte input count.
    let mut changed_scripts = raw.clone();
    for input in &bundle.vin {
        offset += 36;
        let script_len = input.script_sig().0.0.len();
        assert!(script_len < 253);
        offset += 1;
        for byte in &mut changed_scripts[offset..offset + script_len] {
            *byte ^= 1;
        }
        offset += script_len + 4;
    }
    assert_eq!(legacy_signature_hash(&parse(&changed_scripts), input_index, &script, raw_hash_type), Ok(digest));
    let mut changed_code = script;
    changed_code[0] ^= 1;
    assert_ne!(legacy_signature_hash(&transaction, input_index, &changed_code, raw_hash_type), Ok(digest));
    let mut selected_sequence = raw;
    let selected_sequence_start = 5 + bundle.vin[..input_index].iter().map(|input| 41 + input.script_sig().0.0.len()).sum::<usize>() + 37 + bundle.vin[input_index].script_sig().0.0.len();
    selected_sequence[selected_sequence_start] ^= 1;
    assert_ne!(legacy_signature_hash(&parse(&selected_sequence), input_index, &changed_code, raw_hash_type), legacy_signature_hash(&transaction, input_index, &changed_code, raw_hash_type));
}

// Hand-inspected V1 transaction: two distinct outpoints/sequences, three
// distinct outputs, and nonzero lock_time. These are encoding cases, not
// invented signatures or asserted-valid spends. Expected preimages are literal
// independent encodings, never produced by the native implementation.
const BRANCH_TRANSACTION: &str = concat!(
    "0100000002",
    "111111111111111111111111111111111111111111111111111111111111111144332211015188776655",
    "2222222222222222222222222222222222222222222222222222222222222222665544330152aa998877",
    "03010000000000000001510200000000000000015203000000000000000153ccbbaa99",
);

#[test]
fn all_none_single_and_anyonecanpay_match_independently_encoded_preimages() {
    use sha2::{Digest, Sha256};
    let transaction = parse(&bytes(BRANCH_TRANSACTION));
    let all = concat!(
        "0100000002",
        "1111111111111111111111111111111111111111111111111111111111111111443322110088776655",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "03010000000000000001510200000000000000015203000000000000000153ccbbaa99",
    );
    let none = concat!(
        "0100000002",
        "1111111111111111111111111111111111111111111111111111111111111111443322110000000000",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "00ccbbaa99",
    );
    let single = concat!(
        "0100000002",
        "1111111111111111111111111111111111111111111111111111111111111111443322110000000000",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "02ffffffffffffffff0002000000000000000152ccbbaa99",
    );
    let acp_all = concat!(
        "0100000001",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "03010000000000000001510200000000000000015203000000000000000153ccbbaa99",
    );
    let acp_none = concat!(
        "0100000001",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "00ccbbaa99",
    );
    let acp_single = concat!(
        "0100000001",
        "2222222222222222222222222222222222222222222222222222222222222222665544330201abaa998877",
        "02ffffffffffffffff0002000000000000000152ccbbaa99",
    );
    for (hash_type, preimage, suffix) in [
        (1, all, "01000000"), (2, none, "02000000"), (3, single, "03000000"),
        (0x81, acp_all, "81000000"), (0x82, acp_none, "82000000"), (0x83, acp_single, "83000000"),
        (0, all, "00000000"), (4, all, "04000000"), (0x1234_561f, all, "1f563412"),
        (-1, acp_all, "ffffffff"), (-126, acp_none, "82ffffff"), (-125, acp_single, "83ffffff"),
    ] {
        let mut first_hash = Sha256::new();
        first_hash.update(bytes(preimage));
        first_hash.update(bytes(suffix));
        let expected: [u8; 32] = Sha256::digest(first_hash.finalize()).into();
        assert_eq!(legacy_signature_hash(&transaction, 1, &[1, 0xab], hash_type), Ok(expected), "raw type {hash_type}");
    }
}

#[test]
fn output_and_nonselected_sequence_commitments_follow_hash_type_selection() {
    let raw = bytes(BRANCH_TRANSACTION);
    let transaction = parse(&raw);
    let selected_script = [1, 0xab];
    // First sequence, preceding output, selected output, trailing output.
    for (offset, all_bound, none_bound, single_bound, acp_bound) in [
        (43, true, false, false, false),
        (90, true, false, false, true),
        (100, true, false, true, true),
        (110, true, false, false, true),
    ] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        let changed = parse(&changed);
        for (hash_type, bound) in [
            (1, all_bound), (2, none_bound), (3, single_bound),
            (0x81, all_bound && acp_bound), (0x82, none_bound && acp_bound), (0x83, single_bound && acp_bound),
        ] {
            let original = legacy_signature_hash(&transaction, 1, &selected_script, hash_type).unwrap();
            let altered = legacy_signature_hash(&changed, 1, &selected_script, hash_type).unwrap();
            assert_eq!(altered != original, bound, "byte {offset}, raw type {hash_type}");
        }
    }
}

#[test]
fn compact_script_boundaries_and_literal_separator_bytes_are_committed_exactly() {
    use sha2::{Digest, Sha256};
    let transaction = parse(&bytes(BRANCH_TRANSACTION));
    for (script_len, compact_size) in [(0, "00"), (252, "fc"), (253, "fdfd00"), (65535, "fdffff"), (65536, "fe00000100")] {
        // Both a pushed 0xab and an actual 0xab are raw bytes at this primitive
        // boundary. Disabled-opcode rejection belongs to the upstream evaluator.
        let script = vec![0xab; script_len];
        let mut first_hash = Sha256::new();
        first_hash.update(bytes(concat!(
            "0100000001",
            "222222222222222222222222222222222222222222222222222222222222222266554433",
        )));
        first_hash.update(bytes(compact_size));
        first_hash.update(&script);
        first_hash.update(bytes("aa99887700ccbbaa9982000000"));
        let expected: [u8; 32] = Sha256::digest(first_hash.finalize()).into();
        assert_eq!(legacy_signature_hash(&transaction, 1, &script, 0x82), Ok(expected), "script length {script_len}");
    }
}

#[test]
fn actual_parsed_overwinter_headers_never_enter_legacy_hashing() {
    let template = parse(&bytes(signed::V1_SIGNED));
    for (version, branch) in [
        (TxVersion::V3, BranchId::Overwinter), (TxVersion::V4, BranchId::Sapling),
        (TxVersion::V5, BranchId::Nu5), (TxVersion::V6, BranchId::Nu6_3),
    ] {
        let transaction = TransactionData::<Authorized>::from_parts(
            version, branch, template.lock_time(), 0.into(), template.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        let mut raw = Vec::new();
        transaction.write(&mut raw).unwrap();
        let parsed = parse(&raw);
        assert_eq!(legacy_signature_hash(&parsed, 0, &[], 1), Err(LegacySighashError::UnsupportedVersion));
    }
}

