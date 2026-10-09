//! Original ZIP243 literal digests only; no ledger admission or chain-validity claim.
use sapling_crypto::bundle::{Authorized as SaplingAuthorized, Bundle as SaplingBundle, OutputDescription, SpendDescription};
use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TxVersion,
    components::sprout::JsDescription,
    sighash::SignableInput, sighash_v4::v4_signature_hash,
};
use zcash_protocol::{consensus::BranchId, value::{MAX_MONEY, ZatBalance, Zatoshis}};
use zcash_transparent::{
    address::Script,
    bundle::{self, OutPoint, TxIn, TxOut},
    sighash::{SignableInput as TransparentInput, SighashType},
};
use ziquid_proofs::sapling_sighash::{SaplingSignatureHash, SaplingSighashError};

#[path = "fixtures/sapling-sighash-primary.rs"]
mod primary;
#[path = "fixtures/overwinter-mined.rs"]
mod overwinter;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |value| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid primary hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

#[test]
fn matches_all_ten_original_zip243_source_literal_tuples() {
    for vector in primary::ZIP243_VECTORS {
        let raw = bytes(vector.tx_hex);
        let mut remaining = raw.as_slice();
        let transaction = Transaction::read(&mut remaining, BranchId::Sapling).unwrap();
        assert!(remaining.is_empty());
        let mut canonical = Vec::new();
        transaction.write(&mut canonical).unwrap();
        assert_eq!(canonical, raw);
        let hashes = SaplingSignatureHash::new(&transaction).unwrap();
        let digest = match vector.input_index {
            Some(index) => hashes.transparent(index, &bytes(vector.script_hex), Zatoshis::from_u64(vector.amount).unwrap(), vector.hash_type).unwrap(),
            None => hashes.shielded(),
        };
        assert_eq!(digest, vector.expected);
    }
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

fn transaction(bundle: Option<bundle::Bundle<bundle::Authorized>>, branch: BranchId) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V4, branch, 17, 250_000_u32.into(), bundle, None, None, None,
    ).freeze().unwrap()
}

fn oracle(transaction: &Transaction, index: usize, code: &[u8], amount: Zatoshis, hash_type: u8) -> [u8; 32] {
    let code = script(code);
    let input = TransparentInput::from_parts(
        transaction.transparent_bundle().unwrap(), SighashType::from_raw(hash_type),
        index, &code, &code, amount,
    ).unwrap();
    v4_signature_hash(transaction, &SignableInput::Transparent(input)).as_bytes().try_into().unwrap()
}

fn with_sapling(source: &Transaction, sapling: Option<SaplingBundle<SaplingAuthorized, ZatBalance>>) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V4, source.consensus_branch_id(), source.lock_time(), source.expiry_height(),
        source.transparent_bundle().cloned(), source.sprout_bundle().cloned(), sapling, None,
    ).freeze().unwrap()
}

#[test]
fn all_none_single_and_anyonecanpay_keep_original_selected_index_and_exact_script() {
    let original = transaction(Some(transparent()), BranchId::Sapling);
    let amount = Zatoshis::from_u64(100).unwrap();
    let code = [0x51, 0xab, 0];
    for raw_type in [0_u8, 1, 2, 3, 0x81, 0x82, 0x83, 0x41, 0xff] {
        let hashes = SaplingSignatureHash::new(&original).unwrap();
        let digest = hashes.transparent(1, &code, amount, i32::from(raw_type)).unwrap();
        assert_eq!(digest, oracle(&original, 1, &code, amount, raw_type));
        for high_bits in [0x100, i32::MIN] {
            assert_ne!(hashes.transparent(1, &code, amount, i32::from(raw_type) ^ high_bits), Ok(digest));
        }
        for changed_code in [&[0x51, 0][..], &[0x51, 0xab, 1][..]] {
            assert_ne!(hashes.transparent(1, changed_code, amount, i32::from(raw_type)), Ok(digest));
        }
        for value in [99, 101] {
            assert_ne!(hashes.transparent(1, &code, Zatoshis::from_u64(value).unwrap(), i32::from(raw_type)), Ok(digest));
        }
        for field in 0..7 {
            let mut bundle = transparent();
            match field {
                0 | 1 => {
                    bundle.vin[field] = TxIn::from_parts(OutPoint::new([0x55; 32], 1), script(&[]), bundle.vin[field].sequence());
                }
                2 | 3 => {
                    let index = field - 2;
                    bundle.vin[index] = TxIn::from_parts(bundle.vin[index].prevout().clone(), script(&[]), bundle.vin[index].sequence() + 1);
                }
                4 | 5 => {
                    let index = field - 4;
                    bundle.vout[index] = TxOut::new(Zatoshis::from_u64(99).unwrap(), bundle.vout[index].script_pubkey().clone());
                }
                6 => bundle.vin[1] = TxIn::from_parts(bundle.vin[1].prevout().clone(), script(&[0x51, 0]), 456),
                _ => unreachable!(),
            }
            let changed = transaction(Some(bundle), BranchId::Sapling);
            let changed_digest = SaplingSignatureHash::new(&changed).unwrap().transparent(1, &code, amount, i32::from(raw_type)).unwrap();
            let base = raw_type & 0x1f;
            let excluded = match field {
                0 => raw_type & 0x80 != 0,
                2 => raw_type & 0x80 != 0 || matches!(base, 2 | 3),
                4 => matches!(base, 2 | 3),
                5 => base == 2,
                6 => true,
                _ => false,
            };
            assert_eq!(changed_digest == digest, excluded, "field={field}, type={raw_type}");
            assert_eq!(changed_digest, oracle(&changed, 1, &code, amount, raw_type));
        }
    }
}

#[test]
fn single_without_selected_output_uses_zero_hash_but_invalid_inputs_reject() {
    for outputs in [0, 1] {
        let mut bundle = transparent();
        bundle.vout.truncate(outputs);
        let tx = transaction(Some(bundle), BranchId::Sapling);
        let hashes = SaplingSignatureHash::new(&tx).unwrap();
        for raw_type in [3_u8, 0x83] {
            let digest = hashes.transparent(1, &[0x51], Zatoshis::ZERO, i32::from(raw_type)).unwrap();
            assert_eq!(digest, oracle(&tx, 1, &[0x51], Zatoshis::ZERO, raw_type));
        }
        for index in [2, usize::MAX] {
            assert_eq!(hashes.transparent(index, &[], Zatoshis::ZERO, 1), Err(SaplingSighashError::InputIndexOutOfRange));
        }
    }
    let tx = transaction(None, BranchId::Sapling);
    assert_eq!(SaplingSignatureHash::new(&tx).unwrap().transparent(0, &[], Zatoshis::ZERO, 1), Err(SaplingSighashError::InputIndexOutOfRange));
}

#[test]
fn exact_v4_and_all_locked_legal_branches_bind_the_actual_branch_with_contextual_expiry() {
    let mut digests = Vec::new();
    for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood, BranchId::Canopy, BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        assert!(TxVersion::V4.valid_in_branch(branch));
        let tx = transaction(Some(transparent()), branch);
        let hashes = SaplingSignatureHash::new(&tx).unwrap();
        let expected = v4_signature_hash(&tx, &SignableInput::Shielded);
        assert_eq!(hashes.shielded().as_slice(), expected.as_bytes());
        assert!(!digests.contains(&hashes.shielded()));
        digests.push(hashes.shielded());
        assert_eq!(hashes.transparent(1, &[], Zatoshis::ZERO, 1).unwrap(), oracle(&tx, 1, &[], Zatoshis::ZERO, 1));
    }
    for branch in [BranchId::Sprout, BranchId::Overwinter] {
        let tx = transaction(Some(transparent()), branch);
        assert!(matches!(SaplingSignatureHash::new(&tx), Err(SaplingSighashError::UnsupportedBranch)));
    }
    for (version, branch) in [(TxVersion::Sprout(3), BranchId::Sprout), (TxVersion::V3, BranchId::Overwinter), (TxVersion::V5, BranchId::Nu5), (TxVersion::V6, BranchId::Nu6_3)] {
        let tx = TransactionData::<Authorized>::from_parts(version, branch, 0, 0_u32.into(), Some(transparent()), None, None, None).freeze().unwrap();
        assert!(matches!(SaplingSignatureHash::new(&tx), Err(SaplingSighashError::UnsupportedVersion)));
    }
    let mut digests = Vec::new();
    for expiry in [0_u32, 499_999_999, 500_000_000, u32::MAX] {
        let tx = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 17, expiry.into(), Some(transparent()), None, None, None).freeze().unwrap();
        let hashes = SaplingSignatureHash::new(&tx).unwrap();
        assert!(!digests.contains(&hashes.shielded()));
        digests.push(hashes.shielded());
    }
    let tx = transaction(Some(transparent()), BranchId::Sapling);
    let hashes = SaplingSignatureHash::new(&tx).unwrap();
    let changed = TransactionData::<Authorized>::from_parts(TxVersion::V4, BranchId::Sapling, 18, tx.expiry_height(), Some(transparent()), None, None, None).freeze().unwrap();
    assert_ne!(SaplingSignatureHash::new(&changed).unwrap().shielded(), hashes.shielded());
}

fn assert_sapling_change(source: &Transaction, changed: &Transaction, excluded: bool) {
    let original = SaplingSignatureHash::new(source).unwrap();
    let hashes = SaplingSignatureHash::new(changed).unwrap();
    assert_eq!(hashes.shielded() == original.shielded(), excluded);
    assert_eq!(hashes.shielded().as_slice(), v4_signature_hash(changed, &SignableInput::Shielded).as_bytes());
    for raw_type in [1_u8, 2, 3, 0x81, 0x82, 0x83] {
        let digest = original.transparent(1, &[0x51], Zatoshis::ZERO, i32::from(raw_type)).unwrap();
        let changed_digest = hashes.transparent(1, &[0x51], Zatoshis::ZERO, i32::from(raw_type)).unwrap();
        assert_eq!(changed_digest == digest, excluded, "type={raw_type}");
        assert_eq!(changed_digest, oracle(changed, 1, &[0x51], Zatoshis::ZERO, raw_type));
    }
}

#[test]
fn sapling_spends_bind_cv_anchor_nullifier_rk_and_every_proof_byte_but_not_spend_auth_sig() {
    let fixture = parse(&bytes(primary::ZIP243_VECTORS[0].tx_hex), BranchId::Sapling);
    let source = TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Sapling, fixture.lock_time(), fixture.expiry_height(),
        Some(transparent()), fixture.sprout_bundle().cloned(), fixture.sapling_bundle().cloned(), None,
    ).freeze().unwrap();
    let bundle = source.sapling_bundle().unwrap();
    assert!(bundle.shielded_spends().len() >= 2);
    let spend = &bundle.shielded_spends()[0];
    let other = &bundle.shielded_spends()[1];
    for field in 0..197 {
        let mut nullifier = *spend.nullifier();
        let mut proof = *spend.zkproof();
        let mut signature: [u8; 64] = (*spend.spend_auth_sig()).into();
        if field == 2 { nullifier.0[0] ^= 1; }
        if field >= 5 { proof[field - 5] ^= 1; }
        if field == 4 { signature[0] ^= 1; }
        let changed_spend = SpendDescription::from_parts(
            if field == 0 { other.cv().clone() } else { spend.cv().clone() },
            if field == 1 { *other.anchor() } else { *spend.anchor() },
            nullifier,
            if field == 3 { *other.rk() } else { *spend.rk() },
            proof, signature.into(),
        );
        let mut spends = bundle.shielded_spends().to_vec();
        spends[0] = changed_spend;
        let changed = with_sapling(&source, SaplingBundle::from_parts(
            spends, bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization(),
        ));
        assert_sapling_change(&source, &changed, field == 4);
    }
    let mut reversed = bundle.shielded_spends().to_vec();
    reversed.swap(0, 1);
    let changed = with_sapling(&source, SaplingBundle::from_parts(
        reversed, bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization(),
    ));
    assert_sapling_change(&source, &changed, false);
}

#[test]
fn sapling_outputs_bind_cv_cmu_ephemeral_key_both_ciphertexts_and_all_192_proof_bytes() {
    let fixture = parse(&bytes(primary::ZIP243_VECTORS[0].tx_hex), BranchId::Sapling);
    let source = TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Sapling, fixture.lock_time(), fixture.expiry_height(),
        Some(transparent()), fixture.sprout_bundle().cloned(), fixture.sapling_bundle().cloned(), None,
    ).freeze().unwrap();
    let bundle = source.sapling_bundle().unwrap();
    assert!(bundle.shielded_outputs().len() >= 2);
    let output = &bundle.shielded_outputs()[0];
    let other = &bundle.shielded_outputs()[1];
    for field in 0..199 {
        let mut ephemeral = output.ephemeral_key().clone();
        let mut enc_ciphertext = *output.enc_ciphertext();
        let mut out_ciphertext = *output.out_ciphertext();
        let mut proof = *output.zkproof();
        match field {
            2 => ephemeral.0[0] ^= 1,
            3 => enc_ciphertext[0] ^= 1,
            4 => enc_ciphertext[579] ^= 1,
            5 => out_ciphertext[0] ^= 1,
            6 => out_ciphertext[79] ^= 1,
            7..=198 => proof[field - 7] ^= 1,
            _ => {}
        }
        let changed_output = OutputDescription::from_parts(
            if field == 0 { other.cv().clone() } else { output.cv().clone() },
            if field == 1 { *other.cmu() } else { *output.cmu() },
            ephemeral, enc_ciphertext, out_ciphertext, proof,
        );
        let mut outputs = bundle.shielded_outputs().to_vec();
        outputs[0] = changed_output;
        let changed = with_sapling(&source, SaplingBundle::from_parts(
            bundle.shielded_spends().to_vec(), outputs, *bundle.value_balance(), *bundle.authorization(),
        ));
        assert_sapling_change(&source, &changed, false);
    }
    let mut reversed = bundle.shielded_outputs().to_vec();
    reversed.swap(0, 1);
    let changed = with_sapling(&source, SaplingBundle::from_parts(
        bundle.shielded_spends().to_vec(), reversed, *bundle.value_balance(), *bundle.authorization(),
    ));
    assert_sapling_change(&source, &changed, false);
}

#[test]
fn signed_value_balance_is_bound_and_binding_signature_is_excluded() {
    let fixture = parse(&bytes(primary::ZIP243_VECTORS[0].tx_hex), BranchId::Sapling);
    let source = TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Sapling, fixture.lock_time(), fixture.expiry_height(),
        Some(transparent()), fixture.sprout_bundle().cloned(), fixture.sapling_bundle().cloned(), None,
    ).freeze().unwrap();
    let bundle = source.sapling_bundle().unwrap();
    for value in [-(MAX_MONEY as i64), -1, 0, 1, MAX_MONEY as i64] {
        let changed = with_sapling(&source, SaplingBundle::from_parts(
            bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(),
            ZatBalance::from_i64(value).unwrap(), *bundle.authorization(),
        ));
        assert_sapling_change(&source, &changed, false);
    }
    let mut signature: [u8; 64] = bundle.authorization().binding_sig.into();
    signature[0] ^= 1;
    let changed = with_sapling(&source, SaplingBundle::from_parts(
        bundle.shielded_spends().to_vec(), bundle.shielded_outputs().to_vec(), *bundle.value_balance(),
        SaplingAuthorized { binding_sig: signature.into() },
    ));
    assert_sapling_change(&source, &changed, true);
}

#[test]
fn absent_components_and_personalized_empty_transparent_hashes_follow_zip243() {
    let fixture = parse(&bytes(primary::ZIP243_VECTORS[0].tx_hex), BranchId::Sapling);
    let bundle = fixture.sapling_bundle().unwrap();
    for sapling in [
        None,
        SaplingBundle::from_parts(bundle.shielded_spends().to_vec(), vec![], *bundle.value_balance(), *bundle.authorization()),
        SaplingBundle::from_parts(vec![], bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization()),
    ] {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V4, BranchId::Sapling, 0, 0_u32.into(), None, None, sapling, None,
        ).freeze().unwrap();
        let hashes = SaplingSignatureHash::new(&tx).unwrap();
        assert_eq!(hashes.shielded().as_slice(), v4_signature_hash(&tx, &SignableInput::Shielded).as_bytes());
        assert_eq!(hashes.transparent(0, &[], Zatoshis::ZERO, 1), Err(SaplingSighashError::InputIndexOutOfRange));
    }
    let tx = transaction(None, BranchId::Sapling);
    let hashes = SaplingSignatureHash::new(&tx).unwrap();
    let mut preimage = bytes("0400008085202f89");
    for personalization in [b"ZcashPrevoutHash", b"ZcashSequencHash", b"ZcashOutputsHash"] {
        let digest = blake2b_simd::Params::new().hash_length(32).personal(personalization).hash(&[]);
        assert_ne!(digest.as_bytes(), &[0; 32]);
        preimage.extend_from_slice(digest.as_bytes());
    }
    preimage.extend_from_slice(&[0; 96]); // absent JS, Sapling spend and output hashes
    preimage.extend_from_slice(&bytes("1100000090d00300000000000000000001000000"));
    let expected = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashSigHash\xbb\x09\xb8\x76").hash(&preimage);
    assert_eq!(hashes.shielded().as_slice(), expected.as_bytes());
    preimage[8..104].fill(0); // empty ordinary components MUST NOT become zero hashes
    let wrong = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashSigHash\xbb\x09\xb8\x76").hash(&preimage);
    assert_ne!(hashes.shielded().as_slice(), wrong.as_bytes());
}

#[test]
fn signed_i32_high_bits_use_original_literal_preimage_not_an_unsigned_byte_oracle() {
    let tx = transaction(Some(transparent()), BranchId::Sapling);
    let hashes = SaplingSignatureHash::new(&tx).unwrap();
    // Literal ZIP243 preimage for original input1, ANYONECANPAY|ALL, script51ab00,
    // value100. Raw type0x80000181 retains both high bits: LE81010080, not81000000.
    let mut preimage = bytes("0400008085202f89");
    preimage.extend_from_slice(&[0; 64]);
    let output_bytes = bytes("0c00000000000000015122000000000000000152");
    let outputs = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashOutputsHash").hash(&output_bytes);
    preimage.extend_from_slice(outputs.as_bytes());
    preimage.extend_from_slice(&[0; 96]);
    preimage.extend_from_slice(&bytes("1100000090d00300000000000000000081010080"));
    preimage.extend_from_slice(&[0x42; 32]);
    preimage.extend_from_slice(&bytes("090000000351ab006400000000000000c8010000"));
    let expected = blake2b_simd::Params::new().hash_length(32).personal(b"ZcashSigHash\xbb\x09\xb8\x76").hash(&preimage);
    let digest = hashes.transparent(1, &[0x51, 0xab, 0], Zatoshis::from_u64(100).unwrap(), i32::MIN | 0x181).unwrap();
    assert_eq!(digest.as_slice(), expected.as_bytes());
    for truncated in [0x181, 0x81, -127] {
        assert_ne!(hashes.transparent(1, &[0x51, 0xab, 0], Zatoshis::from_u64(100).unwrap(), truncated), Ok(digest));
    }
}

#[test]
fn empty_and_phgr_joinsplits_cannot_be_typed_as_hashable_v4() {
    let source = parse(&bytes(overwinter::MINED_V3_TX_HEX), BranchId::Overwinter);
    let mut empty = source.sprout_bundle().unwrap().clone();
    empty.joinsplits.clear();
    for sprout in [empty, source.sprout_bundle().unwrap().clone()] {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V4, BranchId::Sapling, 0, 0_u32.into(), Some(transparent()), Some(sprout), None, None,
        ).freeze().unwrap();
        assert!(matches!(SaplingSignatureHash::new(&tx), Err(SaplingSighashError::IncompatibleTransaction)));
    }
}

fn canonical_read(raw: &[u8]) -> Option<Transaction> {
    let mut remaining = raw;
    let tx = Transaction::read(&mut remaining, BranchId::Sapling).ok()?;
    let mut canonical = Vec::new();
    tx.write(&mut canonical).ok()?;
    (remaining.is_empty() && canonical == raw).then_some(tx)
}

#[test]
fn canonical_exhausted_byte_boundary_rejects_trailing_truncated_and_normalized_sapling_shapes() {
    let raw = bytes(primary::ZIP243_VECTORS[0].tx_hex);
    assert!(canonical_read(&raw).is_some());
    assert!(canonical_read(&raw[..raw.len() - 1]).is_none());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(canonical_read(&trailing).is_none());
    let mut bad_group = raw;
    bad_group[4] ^= 1;
    assert!(canonical_read(&bad_group).is_none());
    // Pinned typed reader drops a nonzero raw valueBalance when both vectors are
    // empty. It cannot be recovered from &Transaction; byte consumers MUST
    // reject the noncanonical round-trip, not pretend the digest validates it.
    let mut malformed = bytes("0400008085202f89");
    malformed.extend_from_slice(&[0; 10]); // vin/vout counts, locktime and expiry
    malformed.extend_from_slice(&1_i64.to_le_bytes());
    malformed.extend_from_slice(&[0; 3]); // Sapling spend/output and JS counts
    let normalized = Transaction::read(malformed.as_slice(), BranchId::Sapling).unwrap();
    assert!(normalized.sapling_bundle().is_none());
    assert!(canonical_read(&malformed).is_none());
    malformed[18] = 0;
    assert!(canonical_read(&malformed).is_some());
}

#[test]
fn complete_groth_joinsplits_and_key_are_bound_by_every_mode_but_signature_is_excluded() {
    let fixture = primary::ZIP243_VECTORS.iter().map(|vector| {
        parse(&bytes(vector.tx_hex), BranchId::Sapling)
    }).find(|tx| tx.sprout_bundle().is_some()).unwrap();
    let make = |sprout| TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Sapling, fixture.lock_time(), fixture.expiry_height(),
        Some(transparent()), Some(sprout), fixture.sapling_bundle().cloned(), None,
    ).freeze().unwrap();
    let source = make(fixture.sprout_bundle().unwrap().clone());
    let mut changed = fixture.sprout_bundle().unwrap().clone();
    changed.joinsplit_sig[0] ^= 1;
    assert_sapling_change(&source, &make(changed), true);
    for offset in [0, 8, 16, 47, 48, 79, 80, 111, 112, 143, 144, 175, 176, 207, 208, 239, 240, 271, 272, 303, 304, 495, 496, 1096, 1097, 1697, 1698] {
        let mut changed = fixture.sprout_bundle().unwrap().clone();
        if offset == 1698 {
            changed.joinsplit_pubkey[0] ^= 1;
        } else {
            let mut encoded = Vec::new();
            changed.joinsplits[0].write(&mut encoded).unwrap();
            assert_eq!(encoded.len(), 1698);
            encoded[offset] ^= 1;
            changed.joinsplits[0] = JsDescription::read(encoded.as_slice(), true).unwrap();
        }
        assert_sapling_change(&source, &make(changed), false);
    }
}

#[test]
fn maintained_independently_signed_v4_uses_local_digest_with_actual_script_and_prevout_value() {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use zcash_script::{
        interpreter::{CallbackTransactionSignatureChecker, Flags},
        script::{Code, Raw}, signature::HashType,
    };
    // Public scalar1 is synthetic test data, never a wallet credential.
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SecretKey::from_slice(&scalar).unwrap();
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &key).serialize();
    let mut code = vec![33];
    code.extend_from_slice(&pubkey);
    code.push(0xac);
    let amount = Zatoshis::from_u64(100).unwrap();
    for raw_type in [0_u8, 1, 2, 3, 0x81, 0x82, 0x83, 0x41] {
        let unsigned = transaction(Some(transparent()), BranchId::Sapling);
        let expected = oracle(&unsigned, 1, &code, amount, raw_type);
        let signature = secp.sign_ecdsa(&Message::from_digest(expected), &key).serialize_der();
        let mut pushed = vec![(signature.len() + 1) as u8];
        pushed.extend_from_slice(&signature);
        pushed.push(raw_type);
        let mut signed = transparent();
        signed.vin[1] = TxIn::from_parts(signed.vin[1].prevout().clone(), script(&pushed), signed.vin[1].sequence());
        let signed = transaction(Some(signed), BranchId::Sapling);
        let evaluate = |tx: &Transaction, value: Zatoshis| {
            let hashes = SaplingSignatureHash::new(tx).unwrap();
            let sighash = |code: &Code, hash_type: &HashType| {
                hashes.transparent(1, &code.0, value, hash_type.raw_bits()).ok()
            };
            let checker = CallbackTransactionSignatureChecker {
                sighash: &sighash, lock_time: i64::from(tx.lock_time()), is_final: false,
            };
            Raw::from_raw_parts(pushed.clone(), code.clone()).eval(Flags::P2SH, &checker).unwrap_or(false)
        };
        assert!(evaluate(&signed, amount), "type={raw_type}");
        for value in [99, 101] {
            assert!(!evaluate(&signed, Zatoshis::from_u64(value).unwrap()));
        }
        let changed = TransactionData::<Authorized>::from_parts(
            TxVersion::V4, BranchId::Sapling, signed.lock_time(), 250_001_u32.into(),
            signed.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        assert!(!evaluate(&changed, amount));
    }
}

#[test]
fn native_orchard_and_ironwood_bundles_cannot_enter_a_v4_digest() {
    use zcash_encoding::CompactSize;
    use zcash_primitives::transaction::components::orchard::{read_v5_bundle, read_v6_bundle};
    // Reuse the existing early-ledger foreign-pool fixture construction. Public
    // scalar1 identifies synthetic points, not a wallet or proof-valid witness.
    let mut scalar_one = [0; 32];
    scalar_one[0] = 1;
    let key = orchard::primitives::redpallas::SigningKey::<orchard::primitives::redpallas::SpendAuth>::try_from(scalar_one).unwrap();
    let point: [u8; 32] = orchard::primitives::redpallas::VerificationKey::from(&key).into();
    let encoded_bundle = |proof_size: usize| {
        let mut raw = vec![1];
        raw.extend_from_slice(&[0; 64]);
        raw.extend_from_slice(&point);
        raw.extend_from_slice(&[0; 32]);
        raw.extend_from_slice(&point);
        raw.extend_from_slice(&[0; 660]);
        raw.push(2);
        raw.extend_from_slice(&[0; 40]);
        CompactSize::write(&mut raw, proof_size).unwrap();
        raw.resize(raw.len() + proof_size + 128, 0);
        raw
    };
    let orchard = read_v5_bundle(encoded_bundle(0).as_slice(), BranchId::Nu5).unwrap();
    assert!(orchard.is_some());
    // The upstream owned V4 constructor itself refuses Orchard; the digest
    // still defensively checks the pool rather than relying on its serializer.
    assert!(TransactionData::<Authorized>::from_parts(
        TxVersion::V4, BranchId::Nu5, 0, 0_u32.into(), Some(transparent()), None, None, orchard.clone(),
    ).freeze().is_err());
    let orchard = TransactionData::<Authorized>::from_parts(
        TxVersion::V5, BranchId::Nu5, 0, 0_u32.into(), Some(transparent()), None, None, orchard,
    ).freeze().unwrap();
    assert!(matches!(SaplingSignatureHash::new(&orchard), Err(SaplingSighashError::UnsupportedVersion)));
    let ironwood = read_v6_bundle(
        encoded_bundle(orchard::Proof::expected_proof_size(1)).as_slice(),
        BranchId::Nu6_3, orchard::ValuePool::Ironwood,
    ).unwrap();
    assert!(ironwood.is_some());
    let ironwood = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3, 0, 0_u32.into(), Some(transparent()), None, None, ironwood,
    ).freeze().unwrap();
    assert!(matches!(SaplingSignatureHash::new(&ironwood), Err(SaplingSighashError::UnsupportedVersion)));
}

#[test]
fn whole_script_code_uses_compact_size_at_both_width_transitions() {
    let tx = transaction(Some(transparent()), BranchId::Sapling);
    let hashes = SaplingSignatureHash::new(&tx).unwrap();
    for length in [0, 252, 253, 65_535, 65_536] {
        let mut code = vec![0xab; length];
        let digest = hashes.transparent(1, &code, Zatoshis::ZERO, 1).unwrap();
        assert_eq!(digest, oracle(&tx, 1, &code, Zatoshis::ZERO, 1));
        if let Some(last) = code.last_mut() {
            *last ^= 1;
            assert_ne!(hashes.transparent(1, &code, Zatoshis::ZERO, 1), Ok(digest));
        }
    }
}
