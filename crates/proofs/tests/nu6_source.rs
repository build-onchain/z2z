//! Synthetic original-byte NU6 digest boundary, not a mined transaction or history.
extern crate alloc;

use zcash_primitives::transaction::{Transaction, TxVersion, sighash::SignableInput, sighash_v4::v4_signature_hash};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{address::Script, bundle::TxOut, sighash::{SignableInput as TransparentInput, SighashType}};
use ziquid_proofs::{raw_v5::{RawV5, RawV5Error}, sapling_sighash::SaplingSignatureHash,
    zip244::{PostNu5SignatureHash, PostNu5SighashError}};

#[path = "fixtures/zip244-primary.rs"]
mod primary;

#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod original_v4;

fn digest(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

fn prevouts(vector: &primary::zip_0244::TestVector) -> Vec<TxOut> {
    vector.amounts.iter().zip(&vector.script_pubkeys).map(|(amount, code)| {
        let mut script = Script::default();
        script.0.0 = code.clone();
        TxOut::new(Zatoshis::from_nonnegative_i64(*amount).unwrap(), script)
    }).collect()
}
#[test]
fn nu6_original_byte_effect_auth_and_no_input_signature_context_are_branch_bound() {
    let original = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
    let mut raw = original.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let parsed = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(parsed.version(), TxVersion::V5);
    assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6);
    assert_eq!(parsed.original_bytes().as_ptr(), raw.as_ptr());
    // Independent Python hashlib BLAKE2b ZIP244 equations on these exact bytes,
    // separately cross-checked below with the maintained original-byte reader.
    assert_eq!(parsed.effect_id(), digest("2db313a54ad1bac2a16db3024242ab95d4940bb80a20c70c9f12eb78aeeee052"));
    assert_eq!(parsed.auth_digest(), digest("374ec110632adde9c86a9c6e652026b94db5e409ee4b67f599c64d661d0548f7"));
    let mut remaining = raw.as_slice();
    let maintained = Transaction::read(&mut remaining, BranchId::Nu6).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(parsed.effect_id(), <[u8;32]>::from(maintained.txid()));
    assert_eq!(parsed.auth_digest().as_slice(), maintained.auth_commitment().as_bytes());
    let context = parsed.into_signature_context(vec![]).unwrap();
    let typed = PostNu5SignatureHash::new(maintained, vec![]).unwrap();
    assert_eq!(context.shielded(), typed.shielded());
    assert_ne!(context.effect_id(), RawV5::parse_exact(original).unwrap().effect_id());
    raw[8..12].copy_from_slice(&u32::from(BranchId::Canopy).to_le_bytes());
    assert_eq!(RawV5::parse_exact(&raw).unwrap_err(), RawV5Error::UnsupportedBranch);
}

#[test]
fn nu6_empty_bundle_header_and_auth_roots_match_independent_numeric_literals() {
    // Empty bundles are a digest vector, not a CheckTransaction-valid spend.
    for (branch, effect, auth) in [
        (BranchId::Nu5, "66f7789d8392944539e07ddfe52488729f9c6163428ce4353e85cafaf01c864b",
            "0a5a5c39c72f6cdab17c5a43f2e5b0ee82d9e0fbc0294f30868e55a1dfc0330f"),
        (BranchId::Nu6, "514d14f9697a499614b8b8b880c0a453ef95ec07b1fd06f0cd347b646ffa5606",
            "9db85688a39dcff6d5eda7665ebabb24b701407ae360ca9ebe14ac02de3ca7b6"),
    ] {
        let mut raw = TxVersion::V5.header().to_le_bytes().to_vec();
        raw.extend_from_slice(&TxVersion::V5.version_group_id().to_le_bytes());
        raw.extend_from_slice(&u32::from(branch).to_le_bytes());
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.extend_from_slice(&2_976_000_u32.to_le_bytes());
        raw.extend_from_slice(&[0; 5]);
        let parsed = RawV5::parse_exact(&raw).unwrap();
        assert_eq!(parsed.effect_id(), digest(effect));
        assert_eq!(parsed.auth_digest(), digest(auth));
        let context = parsed.into_signature_context(vec![]).unwrap();
        assert_eq!(context.shielded(), digest(effect));
        let typed = Transaction::read(raw.as_slice(), BranchId::Nu5).unwrap();
        let typed = PostNu5SignatureHash::new(typed, vec![]).unwrap();
        assert_eq!(typed.effect_id(), digest(effect));
        assert_eq!(typed.auth_digest(), digest(auth));
    }
}

#[test]
fn all_ten_source_vectors_keep_nu5_literals_and_bind_synthetic_nu6_and_actual_prevouts() {
    let vectors = primary::zip_0244::make_test_vectors();
    assert_eq!(vectors.len(), 10);
    for (number, vector) in vectors.iter().enumerate() {
        let nu5 = RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(prevouts(vector)).unwrap();
        assert_eq!(nu5.effect_id(), vector.txid);
        assert_eq!(nu5.auth_digest(), vector.auth_digest);
        assert_eq!(nu5.shielded(), vector.sighash_shielded);
        let mut raw = vector.tx.clone();
        raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
        let parsed = RawV5::parse_exact(&raw).unwrap();
        assert_eq!(parsed.original_bytes(), raw);
        assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6);
        let context = parsed.into_signature_context(prevouts(vector)).unwrap();
        assert_eq!(context.transaction().consensus_branch_id(), BranchId::Nu6);
        assert_ne!(context.effect_id(), vector.txid, "effect {number}");
        assert_ne!(context.auth_digest(), vector.auth_digest, "auth {number}");
        assert_ne!(context.shielded(), vector.sighash_shielded, "shielded {number}");
        // These six source tuples are inside the maintained Action constructor's
        // narrower encoding domain. Others retain their original opaque EPKs.
        if matches!(number, 1 | 2 | 3 | 4 | 5 | 8) {
            let mut reader = raw.as_slice();
            let maintained = Transaction::read(&mut reader, BranchId::Nu5).unwrap();
            assert!(reader.is_empty());
            let mut canonical = Vec::new();
            maintained.write(&mut canonical).unwrap();
            assert_eq!(canonical, raw);
            let typed = PostNu5SignatureHash::new(maintained, prevouts(vector)).unwrap();
            assert_eq!(context.effect_id(), typed.effect_id());
            assert_eq!(context.auth_digest(), typed.auth_digest());
            assert_eq!(context.shielded(), typed.shielded());
            if let Some(index) = vector.transparent_input {
                for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                    assert_eq!(context.transparent(index as usize, kind), typed.transparent(index as usize, kind));
                }
            }
        }
        if let Some(index) = vector.transparent_input {
            for (kind, expected) in [
                (1, vector.sighash_all), (2, vector.sighash_none),
                (3, vector.sighash_single), (0x81, vector.sighash_all_anyone),
                (0x82, vector.sighash_none_anyone), (0x83, vector.sighash_single_anyone),
            ] {
                let nu5_digest = nu5.transparent(index as usize, kind);
                assert_eq!(nu5_digest, expected.ok_or(PostNu5SighashError::SingleOutputMissing),
                    "NU5 source literal {number}, hash type {kind}");
                match nu5_digest {
                    Ok(old) => assert_ne!(context.transparent(index as usize, kind).unwrap(), old),
                    Err(error) => assert_eq!(context.transparent(index as usize, kind), Err(error)),
                }
            }
        }
        let mut extra = prevouts(vector);
        extra.push(TxOut::new(Zatoshis::ZERO, Script::default()));
        assert!(matches!(RawV5::parse_exact(&raw).unwrap().into_signature_context(extra),
            Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual })
            if expected == vector.amounts.len() && actual == expected + 1));
        for index in 0..vector.amounts.len() {
            for change_script in [false, true] {
                let mut changed = prevouts(vector);
                let mut code = vector.script_pubkeys[index].clone();
                if change_script { code.push(0x51); }
                let mut script = Script::default();
                script.0.0 = code;
                changed[index] = TxOut::new(
                    Zatoshis::from_nonnegative_i64(vector.amounts[index] + i64::from(!change_script)).unwrap(), script,
                );
                let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(changed).unwrap();
                assert_eq!(changed.effect_id(), context.effect_id());
                assert_eq!(changed.auth_digest(), context.auth_digest());
                assert_ne!(changed.shielded(), context.shielded(), "prevout {number}/{index}");
                if let Some(selected) = vector.transparent_input {
                    for kind in [1, 2, 0x81, 0x82] {
                        assert_eq!(changed.transparent(selected as usize, kind).unwrap() == context.transparent(selected as usize, kind).unwrap(),
                            kind & 0x80 != 0 && index != selected as usize);
                    }
                }
            }
        }
    }
}

#[test]
fn v4_original_wire_uses_candidate_nu6_branch_and_supplied_prevout_in_zip243() {
    let raw: Vec<u8> = original_v4::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect();
    // Historical signatures are not claimed valid in either new branch. These
    // explicit prevout contexts isolate exact branch/script/value commitment.
    let mut code = Script::default();
    code.0.0 = vec![0x51, 0xab, 0];
    let amount = Zatoshis::from_u64(125_000_000).unwrap();
    let mut digests = Vec::new();
    for branch in [BranchId::Nu5, BranchId::Nu6] {
        let mut reader = raw.as_slice();
        let transaction = Transaction::read(&mut reader, branch).unwrap();
        assert!(reader.is_empty());
        let mut canonical = Vec::new();
        transaction.write(&mut canonical).unwrap();
        assert_eq!(canonical, raw);
        assert_eq!(transaction.consensus_branch_id(), branch);
        let hashes = SaplingSignatureHash::new(&transaction).unwrap();
        assert_eq!(hashes.shielded().as_slice(), v4_signature_hash(&transaction, &SignableInput::Shielded).as_bytes());
        let mut messages = vec![hashes.shielded()];
        for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
            let input = TransparentInput::from_parts(transaction.transparent_bundle().unwrap(),
                SighashType::from_raw(kind), 0, &code, &code, amount).unwrap();
            let digest = hashes.transparent(0, &code.0.0, amount, i32::from(kind)).unwrap();
            assert_eq!(digest.as_slice(), v4_signature_hash(&transaction, &SignableInput::Transparent(input)).as_bytes());
            assert_ne!(hashes.transparent(0, &code.0.0, Zatoshis::from_u64(125_000_001).unwrap(), i32::from(kind)).unwrap(), digest);
            assert_ne!(hashes.transparent(0, &[0x51, 0xab, 1], amount, i32::from(kind)).unwrap(), digest);
            messages.push(digest);
        }
        digests.push(messages);
    }
    for (nu5, nu6) in digests[0].iter().zip(&digests[1]) { assert_ne!(nu5, nu6); }
}
