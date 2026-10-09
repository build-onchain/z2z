//! Original ZIP244 literals and digest boundaries, not mined-proof or ledger-validity evidence.
extern crate alloc;

use std::io::ErrorKind;

use sapling_crypto::bundle::{Authorized as SaplingAuthorized, Bundle as SaplingBundle};
use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TxVersion,
    components::sprout,
};
use zcash_protocol::{consensus::BranchId, value::{ZatBalance, Zatoshis}};
use zcash_transparent::{
    address::Script,
    bundle::{self, TxIn, TxOut},
    sighash::TransparentAuthorizingContext,
};
use ziquid_proofs::{raw_v5::RawV5, zip244::{PostNu5Authorization, PostNu5SignatureHash, PostNu5SighashError}};

#[path = "fixtures/zip244-primary.rs"]
mod primary;

fn parse_exact(raw: &[u8]) -> Result<Transaction, ErrorKind> {
    let mut remaining = raw;
    let transaction = Transaction::read(&mut remaining, BranchId::Nu5)
        .map_err(|error| error.kind())?;
    if !remaining.is_empty() {
        return Err(ErrorKind::InvalidData);
    }
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).map_err(|error| error.kind())?;
    if canonical != raw {
        return Err(ErrorKind::InvalidData);
    }
    Ok(transaction)
}

fn script(bytes: &[u8]) -> Script {
    let mut script = Script::default();
    script.0.0 = bytes.to_vec();
    script
}

fn prevouts(vector: &primary::zip_0244::TestVector) -> Vec<TxOut> {
    assert_eq!(vector.amounts.len(), vector.script_pubkeys.len());
    vector.amounts.iter().zip(&vector.script_pubkeys).map(|(amount, code)| {
        TxOut::new(Zatoshis::from_nonnegative_i64(*amount).unwrap(), script(code))
    }).collect()
}

fn hashes(vector: &primary::zip_0244::TestVector) -> PostNu5SignatureHash {
    RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(prevouts(vector)).unwrap()
}

// Only a round-trip test helper: no alternate digest algorithm or fake authorization data.
fn restore_authorized(data: &TransactionData<PostNu5Authorization>) -> Transaction {
    let transparent = data.transparent_bundle().map(|bundle| bundle::Bundle {
        vin: bundle.vin.iter().map(|input| TxIn::from_parts(
            input.prevout().clone(), input.script_sig().clone(), input.sequence(),
        )).collect(),
        vout: bundle.vout.clone(),
        authorization: bundle::Authorized,
    });
    TransactionData::<Authorized>::from_parts(
        data.version(), data.consensus_branch_id(), data.lock_time(), data.expiry_height(),
        transparent, data.sprout_bundle().cloned(), data.sapling_bundle().cloned(),
        data.orchard_bundle().cloned(),
    ).freeze().unwrap()
}

#[test]
fn original_zip244_literals_bind_actual_prevouts_effects_and_authorizations() {
    let vectors = primary::zip_0244::make_test_vectors();
    assert_eq!(vectors.len(), 10);
    for (number, vector) in vectors.iter().enumerate() {
        let hashes = hashes(vector);
        assert_eq!(hashes.effect_id(), vector.txid, "effect vector {number}");
        assert_eq!(hashes.auth_digest(), vector.auth_digest, "auth vector {number}");
        assert_eq!(hashes.shielded(), vector.sighash_shielded, "shielded vector {number}");
        if let Some(index) = vector.transparent_input {
            for (kind, expected) in [
                (1, vector.sighash_all), (2, vector.sighash_none),
                (3, vector.sighash_single), (0x81, vector.sighash_all_anyone),
                (0x82, vector.sighash_none_anyone), (0x83, vector.sighash_single_anyone),
            ] {
                let actual = hashes.transparent(index as usize, kind);
                match expected {
                    Some(expected) => assert_eq!(actual, Ok(expected), "vector {number}, type {kind}"),
                    None => assert_eq!(actual, Err(PostNu5SighashError::SingleOutputMissing)),
                }
            }
        }
        if let Some(bundle) = hashes.transaction().transparent_bundle() {
            assert_eq!(bundle.authorization.input_amounts(), prevouts(vector).iter().map(TxOut::value).collect::<Vec<_>>());
            assert_eq!(bundle.authorization.input_scriptpubkeys(), prevouts(vector).iter().map(|output| output.script_pubkey().clone()).collect::<Vec<_>>());
        }
    }
}

#[test]
fn every_actual_prevout_amount_and_locking_script_commits_to_mixed_shielded_all() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[7];
    let original = hashes(vector);
    assert!(RawV5::parse_exact(&vector.tx).unwrap().orchard().is_some());
    assert_ne!(original.shielded(), original.effect_id());
    let selected = vector.transparent_input.unwrap() as usize;
    assert!(selected > 0);
    for index in 0..vector.amounts.len() {
        for change_script in [false, true] {
            let mut changed = prevouts(vector);
            let amount = Zatoshis::from_nonnegative_i64(vector.amounts[index] + i64::from(!change_script)).unwrap();
            let mut code = vector.script_pubkeys[index].clone();
            if change_script { code.push(0x51); }
            changed[index] = TxOut::new(amount, script(&code));
            let changed = RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(changed).unwrap();
            assert_ne!(changed.shielded(), vector.sighash_shielded);
            assert_eq!(changed.effect_id(), vector.txid);
            assert_eq!(changed.auth_digest(), vector.auth_digest);
            for (kind, expected) in [
                (1, vector.sighash_all.unwrap()), (2, vector.sighash_none.unwrap()),
                (0x81, vector.sighash_all_anyone.unwrap()), (0x82, vector.sighash_none_anyone.unwrap()),
            ] {
                assert_eq!(changed.transparent(selected, kind).unwrap() == expected,
                    kind & 0x80 != 0 && index != selected, "prevout {index}, script {change_script}, type {kind}");
            }
        }
    }
    let mut reversed = prevouts(vector);
    reversed.swap(0, selected);
    let changed = RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(reversed).unwrap();
    assert_ne!(changed.shielded(), vector.sighash_shielded);
    assert_ne!(changed.transparent(selected, 1).unwrap(), vector.sighash_all.unwrap());
    assert_ne!(changed.transparent(selected, 0x81).unwrap(), vector.sighash_all_anyone.unwrap());
}

#[test]
fn transparent_hash_types_indices_and_single_output_bounds_fail_closed() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[5];
    let hashes = PostNu5SignatureHash::new(parse_exact(&vector.tx).unwrap(), prevouts(vector)).unwrap();
    let index = vector.transparent_input.unwrap() as usize;
    for raw in 0..=u8::MAX {
        if matches!(raw, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
            assert!(hashes.transparent(index, raw).is_ok());
        } else {
            assert_eq!(hashes.transparent(index, raw), Err(PostNu5SighashError::InvalidHashType));
        }
    }
    for index in [vector.amounts.len(), usize::MAX] {
        for raw in [1, 2, 3, 0x81, 0x82, 0x83] {
            assert_eq!(hashes.transparent(index, raw), Err(PostNu5SighashError::InputIndexOutOfRange));
        }
    }
    assert_ne!(hashes.transparent(0, 1), hashes.transparent(1, 1));
    for outputs in [0, 1] {
        let tx = parse_exact(&vector.tx).unwrap().into_data().map_bundles::<Authorized>(
            |bundle| bundle.map(|mut bundle| { bundle.vout.truncate(outputs); bundle }),
            |bundle| bundle, |bundle| bundle,
        ).freeze().unwrap();
        let hashes = PostNu5SignatureHash::new(tx, prevouts(vector)).unwrap();
        for raw in [3, 0x83] {
            assert_eq!(hashes.transparent(1, raw), Err(PostNu5SighashError::SingleOutputMissing));
        }
        assert!(hashes.transparent(1, 1).is_ok());
        assert!(hashes.transparent(1, 2).is_ok());
    }
}

#[test]
fn context_requires_exact_input_count_and_coinbase_has_no_spend_prevout() {
    let mut saw_coinbase = false;
    let mut saw_no_input = false;
    for vector in primary::zip_0244::make_test_vectors() {
        let original = hashes(&vector);
        let coinbase = original.transaction().transparent_bundle().is_some_and(|bundle| bundle.is_coinbase());
        saw_coinbase |= coinbase;
        saw_no_input |= original.transaction().transparent_bundle().is_none_or(|bundle| bundle.vin.is_empty());
        if vector.amounts.is_empty() {
            assert_eq!(original.shielded(), vector.txid);
            assert_eq!(original.transparent(0, 1), Err(PostNu5SighashError::InputIndexOutOfRange));
        }
        if coinbase { assert!(vector.amounts.is_empty()); }
        let count = vector.amounts.len();
        let mut extra = prevouts(&vector);
        extra.push(TxOut::new(Zatoshis::ZERO, Script::default()));
        assert!(matches!(RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(extra),
            Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual }) if expected == count && actual == count + 1));
        if count > 0 {
            let mut missing = prevouts(&vector);
            missing.pop();
            assert!(matches!(RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(missing),
                Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual }) if expected == count && actual == count - 1));
        }
    }
    assert!(saw_coinbase && saw_no_input);
}

#[test]
fn exact_v5_through_nu63_and_v6_nu63_without_sprout_are_admitted_to_this_primitive() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[5];
    let source = parse_exact(&vector.tx).unwrap();
    for version in [TxVersion::Sprout(1), TxVersion::V3, TxVersion::V4] {
        let tx = TransactionData::<Authorized>::from_parts(
            version, BranchId::Nu5, source.lock_time(), source.expiry_height(),
            source.transparent_bundle().cloned(), None, None, None,
        ).freeze().unwrap();
        assert!(matches!(PostNu5SignatureHash::new(tx, prevouts(vector)), Err(PostNu5SighashError::UnsupportedVersion)));
    }
    for branch in [BranchId::Sprout, BranchId::Overwinter, BranchId::Sapling, BranchId::Blossom,
        BranchId::Heartwood, BranchId::Canopy] {
        let tx = TransactionData::<Authorized>::from_parts(
            source.version(), branch, source.lock_time(), source.expiry_height(),
            source.transparent_bundle().cloned(), source.sprout_bundle().cloned(),
            source.sapling_bundle().cloned(), source.orchard_bundle().cloned(),
        ).freeze().unwrap();
        assert!(matches!(PostNu5SignatureHash::new(tx, prevouts(vector)), Err(PostNu5SighashError::UnsupportedBranch)));
    }
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2] {
        let tx = TransactionData::<Authorized>::from_parts_v6(
            branch, source.lock_time(), source.expiry_height(), source.transparent_bundle().cloned(),
            None, None, None,
        ).freeze().unwrap();
        assert!(matches!(PostNu5SignatureHash::new(tx, prevouts(vector)), Err(PostNu5SighashError::UnsupportedBranch)));
    }
    let tx = TransactionData::<Authorized>::from_parts(
        TxVersion::V5, BranchId::Nu5, source.lock_time(), source.expiry_height(),
        source.transparent_bundle().cloned(),
        Some(sprout::Bundle { joinsplits: Vec::new(), joinsplit_pubkey: [0; 32], joinsplit_sig: [0; 64] }),
        None, None,
    ).freeze().unwrap();
    assert!(matches!(PostNu5SignatureHash::new(tx, prevouts(vector)), Err(PostNu5SighashError::IncompatibleTransaction)));
    let orchard = parse_exact(include_bytes!("fixtures/orchard-pure-testnet-1842467.bin")).unwrap();
    let tx = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3, source.lock_time(), source.expiry_height(), source.transparent_bundle().cloned(),
        None, None, orchard.orchard_bundle().cloned(),
    ).freeze().unwrap();
    assert!(tx.ironwood_bundle().is_some());
    let hashes = PostNu5SignatureHash::new(tx, prevouts(vector)).unwrap();
    assert!(hashes.transaction().ironwood_bundle().is_some());
    // Constructed typed data can have a wrong pool version. Hashing alone is
    // not pool admission; the dedicated crypto route must reject before keys.
    assert_eq!(ziquid_proofs::zip244::verify_post_nu63_crypto(&hashes),
        Err(ziquid_proofs::zip244::PostNu63CryptoError::InvalidBundleVersion { pool: orchard::ValuePool::Ironwood }));
}

#[test]
fn effect_mutations_change_effect_and_signature_digests_not_authorizations() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[5];
    let source = parse_exact(&vector.tx).unwrap();
    for field in 0..6 {
        let mut bundle = source.transparent_bundle().unwrap().clone();
        match field {
            0 => bundle.vin[0] = TxIn::from_parts(bundle.vin[1].prevout().clone(), bundle.vin[0].script_sig().clone(), bundle.vin[0].sequence()),
            1 => bundle.vin[0] = TxIn::from_parts(bundle.vin[0].prevout().clone(), bundle.vin[0].script_sig().clone(), bundle.vin[0].sequence() ^ 1),
            2 => bundle.vout[1] = TxOut::new(Zatoshis::from_u64(1).unwrap(), bundle.vout[1].script_pubkey().clone()),
            3 => bundle.vout[1] = TxOut::new(bundle.vout[1].value(), script(&[0x51])),
            _ => {}
        }
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5, BranchId::Nu5, source.lock_time() ^ u32::from(field == 4),
            (u32::from(source.expiry_height()) ^ u32::from(field == 5)).into(),
            Some(bundle), None, None, None,
        ).freeze().unwrap();
        let changed = PostNu5SignatureHash::new(tx, prevouts(vector)).unwrap();
        assert_ne!(changed.effect_id(), vector.txid, "field {field}");
        assert_ne!(changed.shielded(), vector.sighash_shielded, "field {field}");
        for (kind, expected) in [
            (0x81, vector.sighash_all_anyone.unwrap()),
            (0x82, vector.sighash_none_anyone.unwrap()),
            (0x83, vector.sighash_single_anyone.unwrap()),
        ] {
            let excluded = matches!(field, 0 | 1) || matches!(field, 2 | 3) && kind == 0x82;
            assert_eq!(changed.transparent(1, kind).unwrap() == expected, excluded,
                "effect field {field}, type {kind}");
        }
        assert_ne!(changed.transparent(1, 1).unwrap(), vector.sighash_all.unwrap(), "field {field}");
        assert_eq!(changed.auth_digest(), vector.auth_digest);
        if matches!(field, 2 | 3) {
            assert_eq!(changed.transparent(1, 2).unwrap(), vector.sighash_none.unwrap());
            assert_ne!(changed.transparent(1, 3).unwrap(), vector.sighash_single.unwrap());
        }
    }
}

#[test]
fn transparent_script_sig_changes_only_auth_digest_and_remains_in_consumer_data() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[5];
    let source = parse_exact(&vector.tx).unwrap();
    let tx = source.into_data().map_bundles::<Authorized>(|bundle| bundle.map(|mut bundle| {
        let input = &bundle.vin[1];
        bundle.vin[1] = TxIn::from_parts(input.prevout().clone(), script(&[0x51, 0x00, 0x51]), input.sequence());
        bundle
    }), |bundle| bundle, |bundle| bundle).freeze().unwrap();
    let changed = PostNu5SignatureHash::new(tx, prevouts(vector)).unwrap();
    assert_eq!(changed.effect_id(), vector.txid);
    assert_eq!(changed.shielded(), vector.sighash_shielded);
    assert_ne!(changed.auth_digest(), vector.auth_digest);
    assert_eq!(changed.transaction().transparent_bundle().unwrap().vin[1].script_sig(), &script(&[0x51, 0x00, 0x51]));
    for (kind, expected) in [(1, vector.sighash_all), (2, vector.sighash_none), (3, vector.sighash_single),
        (0x81, vector.sighash_all_anyone), (0x82, vector.sighash_none_anyone), (0x83, vector.sighash_single_anyone)] {
        assert_eq!(changed.transparent(1, kind).unwrap(), expected.unwrap());
    }
}

fn sapling_bytes(bundle: &SaplingBundle<SaplingAuthorized, ZatBalance>) -> Vec<u8> {
    let mut bytes = Vec::new();
    Transaction::temporary_zcashd_write_v5_sapling(Some(bundle), &mut bytes).unwrap();
    bytes
}

#[test]
fn sapling_authorization_mutations_preserve_effects_and_actual_consumer_bytes() {
    let mut covered = [false; 4];
    for vector in primary::zip_0244::make_test_vectors() {
        let source = RawV5::parse_exact(&vector.tx).unwrap();
        let Some(bundle) = source.sapling_bundle() else { continue; };
        let original_bytes = sapling_bytes(bundle);
        let start = vector.tx.windows(original_bytes.len()).position(|bytes| bytes == original_bytes).unwrap();
        assert_eq!(vector.tx.windows(original_bytes.len()).filter(|bytes| *bytes == original_bytes).count(), 1);
        for (field, was_covered) in covered.iter_mut().enumerate() {
            if matches!(field, 0 | 2) && bundle.shielded_spends().is_empty()
                || field == 1 && bundle.shielded_outputs().is_empty()
            {
                continue;
            }
            *was_covered = true;
            let changed: SaplingBundle<SaplingAuthorized, ZatBalance> = bundle.clone().map_authorization(
                (), |_, mut proof| {
                    if field == 0 { proof[0] ^= 1; } proof
                }, |_, mut proof| {
                    if field == 1 { proof[0] ^= 1; } proof
                }, |_, signature| {
                    let mut bytes: [u8; 64] = signature.into();
                    if field == 2 { bytes[0] ^= 1; } bytes.into()
                }, |_, mut authorization| {
                    let mut bytes: [u8; 64] = authorization.binding_sig.into();
                    if field == 3 { bytes[0] ^= 1; }
                    authorization.binding_sig = bytes.into(); authorization
                },
            );
            let changed_bytes = sapling_bytes(&changed);
            assert_eq!(changed_bytes.len(), original_bytes.len());
            let mut raw = vector.tx.clone();
            raw[start..start + changed_bytes.len()].copy_from_slice(&changed_bytes);
            let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(prevouts(&vector)).unwrap();
            assert_eq!(changed.effect_id(), vector.txid);
            assert_eq!(changed.shielded(), vector.sighash_shielded);
            assert_ne!(changed.auth_digest(), vector.auth_digest);
            assert_eq!(sapling_bytes(changed.transaction().sapling_bundle().unwrap()), changed_bytes);
            if let Some(index) = vector.transparent_input {
                assert_eq!(changed.transparent(index as usize, 1), Ok(vector.sighash_all.unwrap()));
            }
        }
    }
    assert_eq!(covered, [true; 4]);
}

#[test]
fn typed_orchard_auth_mutations_preserve_effects_and_all_other_auth_bytes() {
    let raw = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
    let source = parse_exact(raw).unwrap();
    let original = PostNu5SignatureHash::new(source.clone(), Vec::new()).unwrap();
    for field in 0..3 {
        let tx = source.clone().into_data().map_bundles::<Authorized>(|bundle| bundle, |bundle| bundle,
            |bundle| bundle.map(|bundle| bundle.map_authorization(&mut (), |_, _, signature| {
                let mut bytes: [u8; 64] = (&signature).into();
                if field == 0 { bytes[0] ^= 1; } bytes.into()
            }, |_, authorization| {
                let mut proof = authorization.proof().as_ref().to_vec();
                if field == 1 { proof[0] ^= 1; }
                let mut signature: [u8; 64] = authorization.binding_signature().into();
                if field == 2 { signature[0] ^= 1; }
                orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof), signature.into())
            })),
        ).freeze().unwrap();
        let mut expected_bytes = Vec::new();
        tx.write(&mut expected_bytes).unwrap();
        let changed = PostNu5SignatureHash::new(tx, Vec::new()).unwrap();
        assert_eq!(changed.effect_id(), original.effect_id());
        assert_eq!(changed.shielded(), original.shielded());
        assert_ne!(changed.auth_digest(), original.auth_digest());
        let mut restored = Vec::new();
        restore_authorized(changed.transaction()).write(&mut restored).unwrap();
        assert_eq!(restored, expected_bytes);
    }
}

#[test]
fn typed_constructor_preserves_actual_transaction_effects_and_authorizing_bytes() {
    let vectors = primary::zip_0244::make_test_vectors();
    for index in [1, 2, 3, 4, 5, 8] {
        let vector = &vectors[index];
        let typed = PostNu5SignatureHash::new(parse_exact(&vector.tx).unwrap(), prevouts(vector)).unwrap();
        assert_eq!(typed.effect_id(), vector.txid);
        assert_eq!(typed.auth_digest(), vector.auth_digest);
        assert_eq!(typed.shielded(), vector.sighash_shielded);
        let mut restored = Vec::new();
        restore_authorized(typed.transaction()).write(&mut restored).unwrap();
        assert_eq!(restored, vector.tx);
        let mut extra = prevouts(vector);
        extra.push(TxOut::new(Zatoshis::ZERO, Script::default()));
        assert!(matches!(PostNu5SignatureHash::new(parse_exact(&vector.tx).unwrap(), extra),
            Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual })
                if expected == vector.amounts.len() && actual == expected + 1));
        if !vector.amounts.is_empty() {
            let mut missing = prevouts(vector);
            missing.pop();
            assert!(matches!(PostNu5SignatureHash::new(parse_exact(&vector.tx).unwrap(), missing),
                Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual })
                    if expected == vector.amounts.len() && actual + 1 == expected));
        }
    }
    let raw = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
    let source = parse_exact(raw).unwrap();
    let hashes = PostNu5SignatureHash::new(source, Vec::new()).unwrap();
    let mut restored = Vec::new();
    restore_authorized(hashes.transaction()).write(&mut restored).unwrap();
    assert_eq!(restored, raw);
}

#[test]
fn exact_byte_boundary_rejects_tails_and_preserves_actual_later_embedded_branch() {
    let vectors = primary::zip_0244::make_test_vectors();
    let vector = &vectors[5];
    let mut trailing = vector.tx.clone();
    trailing.push(0);
    let mut remaining = trailing.as_slice();
    let transaction = Transaction::read(&mut remaining, BranchId::Nu5).unwrap();
    assert_eq!(remaining, &[0]);
    assert!(PostNu5SignatureHash::new(transaction, prevouts(vector)).is_ok());
    assert!(matches!(parse_exact(&trailing), Err(ErrorKind::InvalidData)));
    for cut in [0, 8, 20, vector.tx.len() - 1] {
        assert!(parse_exact(&vector.tx[..cut]).is_err());
    }
    let mut noncanonical = vector.tx.clone();
    assert_eq!(noncanonical[20], 2);
    noncanonical.splice(20..21, [0xfd, 2, 0]);
    assert!(parse_exact(&noncanonical).is_err());
    // Standalone digest construction uses the encoded branch, not the supplied
    // V4 reader context. Further NU6.3 crypto and ledger policy remain separate.
    let mut later_branch = vector.tx.clone();
    later_branch[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    let tx = Transaction::read(later_branch.as_slice(), BranchId::Nu5).unwrap();
    assert_eq!(tx.consensus_branch_id(), BranchId::Nu6_3);
    let typed = PostNu5SignatureHash::new(tx, prevouts(vector)).unwrap();
    let raw = RawV5::parse_exact(&later_branch).unwrap().into_signature_context(prevouts(vector)).unwrap();
    assert_eq!((raw.effect_id(), raw.auth_digest(), raw.shielded()),
        (typed.effect_id(), typed.auth_digest(), typed.shielded()));
    let mut invalid_branch = vector.tx.clone();
    invalid_branch[8..12].copy_from_slice(&[0xff; 4]);
    assert!(parse_exact(&invalid_branch).is_err());
}
