//! Synthetic NU6.2 digest/framing boundaries, not mined or connected history.
//! Branch-mutated historical proofs/signatures below are never fixed positives.
extern crate alloc;

use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion, sighash::SignableInput, sighash_v4::v4_signature_hash};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{address::Script, bundle::TxOut, sighash::{SignableInput as TransparentInput, SighashType}};
use ziquid_proofs::{history::BodyError, post_nu5_body::{PostNu5Block, PostNu5Transaction},
    raw_v5::{RawV5, RawV5Error}, sapling_sighash::SaplingSignatureHash,
    zip244::{PostNu5SignatureHash, PostNu5SighashError}};

#[path = "fixtures/zip244-primary.rs"]
mod primary;
#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod original_v4;

const HEADER_BYTES: usize = 1487;
const PURE: &[u8] = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
const ORIGINAL_BODY: &[u8] = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");

fn digest(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

fn script(code: &[u8]) -> Script {
    let mut script = Script::default();
    script.0.0 = code.to_vec();
    script
}

fn prevouts(vector: &primary::zip_0244::TestVector) -> Vec<TxOut> {
    vector.amounts.iter().zip(&vector.script_pubkeys).map(|(amount, code)| {
        TxOut::new(Zatoshis::from_nonnegative_i64(*amount).unwrap(), script(code))
    }).collect()
}

fn parse_typed(raw: &[u8], branch: BranchId) -> Transaction {
    let mut remaining = raw;
    let transaction = Transaction::read(&mut remaining, branch).unwrap();
    assert!(remaining.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn new_branch(raw: &[u8]) -> Vec<u8> {
    let mut changed = raw.to_vec();
    changed[8..12].copy_from_slice(&0x5437_f330_u32.to_le_bytes());
    changed
}

fn v4_wire() -> Vec<u8> {
    original_v4::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

#[test]
fn nu62_empty_context_preserves_actual_embedded_branch_and_digest() {
    let mut raw = TxVersion::V5.header().to_le_bytes().to_vec();
    raw.extend_from_slice(&TxVersion::V5.version_group_id().to_le_bytes());
    raw.extend_from_slice(&u32::from(BranchId::Nu6_2).to_le_bytes());
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&4_052_000u32.to_le_bytes());
    raw.extend_from_slice(&[0; 5]);
    let actual = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(actual.consensus_branch_id(), BranchId::Nu6_2);
    let typed = Transaction::read(raw.as_slice(), BranchId::Nu6_2).unwrap();
    assert_eq!(actual.effect_id(), <[u8; 32]>::from(typed.txid()));
    assert_eq!(actual.auth_digest().as_slice(), typed.auth_commitment().as_bytes());
    let expected = PostNu5SignatureHash::new(typed, vec![]).unwrap();
    assert_eq!(actual.into_signature_context(vec![]).unwrap().shielded(), expected.shielded());
}

#[test]
fn nu62_original_effect_auth_and_empty_context_match_independent_numeric_literals() {
    // Independently derived with Python hashlib ZIP244 equations over exact
    // bytes, then cross-checked against the maintained reader and digest path.
    let mut empty = vec![5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0x30, 0xf3, 0x37, 0x54];
    empty.extend_from_slice(&0_u32.to_le_bytes());
    empty.extend_from_slice(&4_052_000_u32.to_le_bytes());
    empty.extend_from_slice(&[0; 5]);
    for (raw, effect, auth) in [
        (empty, "b12067f4c7d1354c757084f33cee954d86139202ca7001120e08a7270fb455c3",
            "86c75c8ac79352591e16a4997c4d3739fb190a9ec64aeaa75bca202dc00a0fd5"),
        (new_branch(PURE), "6cb585f6cfd3dcf88fc61c36d2323a4c71c8e854ffc7826856ad1dd066e49b27",
            "9fc000810f19156eead39302f83b3f5b4564c3658528ec273b2642d380415562"),
    ] {
        let parsed = RawV5::parse_exact(&raw).unwrap();
        assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6_2);
        assert_eq!(parsed.original_bytes().as_ptr(), raw.as_ptr());
        assert_eq!(parsed.effect_id(), digest(effect));
        assert_eq!(parsed.auth_digest(), digest(auth));
        let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), vec![]).unwrap();
        let actual = parsed.into_signature_context(vec![]).unwrap();
        assert_eq!(actual.shielded(), digest(effect));
        assert_eq!(typed.shielded(), actual.shielded());
        assert_eq!(typed.auth_digest(), actual.auth_digest());
    }
}

#[test]
fn nu62_two_actual_prevouts_and_all_hash_types_match_independent_numeric_literals() {
    // Arbitrary input scripts, no signing. Prevout data is supplied separately,
    // never inferred from this wire or replaced by the selected input alone.
    let mut raw = vec![5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0x30, 0xf3, 0x37, 0x54];
    raw.extend_from_slice(&17_u32.to_le_bytes());
    raw.extend_from_slice(&4_052_000_u32.to_le_bytes());
    raw.push(2);
    for (id, index, code, sequence) in [(0x41, 7_u32, &[][..], 123_u32), (0x42, 9, &[0x51][..], 456)] {
        raw.extend_from_slice(&[id; 32]);
        raw.extend_from_slice(&index.to_le_bytes());
        raw.push(code.len() as u8);
        raw.extend_from_slice(code);
        raw.extend_from_slice(&sequence.to_le_bytes());
    }
    raw.push(2);
    for (amount, code) in [(12_i64, 0x51), (34, 0x52)] {
        raw.extend_from_slice(&amount.to_le_bytes());
        raw.extend_from_slice(&[1, code]);
    }
    raw.extend_from_slice(&[0; 3]);
    let outputs = || vec![TxOut::new(Zatoshis::from_u64(100).unwrap(), script(&[0x53])),
        TxOut::new(Zatoshis::from_u64(200).unwrap(), script(&[0x54, 0x55]))];
    let actual = RawV5::parse_exact(&raw).unwrap().into_signature_context(outputs()).unwrap();
    assert_eq!(actual.effect_id(), digest("67bb7fb5e51f5cd19c3bc36f19e5ecafd80cab9d902b8dff669e9c5ef185147c"));
    assert_eq!(actual.auth_digest(), digest("9f4cbcc387483499eea1fd9691429b1b8e12aa76da9d1dbc4e449e6511cea3cd"));
    assert_eq!(actual.shielded(), digest("4809003641b839c9e06aa61acddb4ed77467125cb76910f20b7de871673caf75"));
    let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), outputs()).unwrap();
    assert_eq!(typed.shielded(), actual.shielded());
    for (kind, literal) in [
        (1, "70224a7d0dc710b863b2ef91ac8e58504f7725ea31cb44328ef54b12e900ed1a"),
        (2, "79b7b7c192ebf6743cc3a4d0f8d40eebec0f3e877c70fb050e13d47c900f2b2a"),
        (3, "62ea79613af60a192d5d39b9b538476ef96c2aa24cd0520c818c2fd295b8e1f5"),
        (0x81, "2574e6fefa5827b562d5210179acf407884b2f7d236a72bed1fdf67d529469df"),
        (0x82, "0a9e86d5d2b02a1c394f7cc0b28b3c1f26537078fb63f5dedc08e0f77c70bbdd"),
        (0x83, "778cb89c3bb1d9e85b7a3ce2f1d6db8088c468b52066ca202406575f4b2d0c85"),
    ] {
        assert_eq!(actual.transparent(1, kind), Ok(digest(literal)));
        assert_eq!(typed.transparent(1, kind), Ok(digest(literal)));
    }
    for index in 0..2 {
        for change_script in [false, true] {
            let mut previous = outputs();
            let code = if index == 0 { &[0x53][..] } else { &[0x54, 0x55][..] };
            let mut changed_code = code.to_vec();
            if change_script { changed_code.push(0x51); }
            previous[index] = TxOut::new(Zatoshis::from_u64(
                (if index == 0 { 100 } else { 200 }) + u64::from(!change_script)).unwrap(), script(&changed_code));
            let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(previous).unwrap();
            assert_eq!(changed.effect_id(), actual.effect_id());
            assert_eq!(changed.auth_digest(), actual.auth_digest());
            assert_ne!(changed.shielded(), actual.shielded());
            for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                assert_eq!(changed.transparent(1, kind) == actual.transparent(1, kind), kind & 0x80 != 0 && index == 0);
            }
        }
    }
    for count in [0, 1, 3] {
        let mut previous = outputs();
        previous.resize(count, TxOut::new(Zatoshis::ZERO, Script::default()));
        assert!(matches!(RawV5::parse_exact(&raw).unwrap().into_signature_context(previous),
            Err(PostNu5SighashError::PrevoutCountMismatch { expected: 2, actual }) if actual == count));
    }
    let mut reversed = outputs();
    reversed.swap(0, 1);
    let reversed = RawV5::parse_exact(&raw).unwrap().into_signature_context(reversed).unwrap();
    assert_ne!(reversed.shielded(), actual.shielded());
    assert_ne!(reversed.transparent(1, 0x81), actual.transparent(1, 0x81));
    for kind in [0, 4, 0x80, 0x84, 0xff] {
        assert_eq!(actual.transparent(0, kind), Err(PostNu5SighashError::InvalidHashType));
    }
    assert_eq!(actual.transparent(2, 1), Err(PostNu5SighashError::InputIndexOutOfRange));
    for output_count in [0, 1] {
        let transaction = parse_typed(&raw, BranchId::Nu5).into_data().map_bundles::<zcash_primitives::transaction::Authorized>(
            |bundle| bundle.map(|mut bundle| { bundle.vout.truncate(output_count); bundle }),
            |bundle| bundle, |bundle| bundle,
        ).freeze().unwrap();
        let typed = PostNu5SignatureHash::new(transaction.clone(), outputs()).unwrap();
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).unwrap();
        let raw_context = RawV5::parse_exact(&bytes).unwrap().into_signature_context(outputs()).unwrap();
        for kind in [3, 0x83] {
            assert_eq!(typed.transparent(1, kind), Err(PostNu5SighashError::SingleOutputMissing));
            assert_eq!(raw_context.transparent(1, kind), Err(PostNu5SighashError::SingleOutputMissing));
        }
        for kind in [1, 2, 0x81, 0x82] {
            assert_eq!(raw_context.transparent(1, kind), typed.transparent(1, kind));
        }
    }
}

#[test]
fn all_ten_original_oracles_remain_and_fixed_framing_rejects_short_random_proofs() {
    let vectors = primary::zip_0244::make_test_vectors();
    assert_eq!(vectors.len(), 10);
    for (number, vector) in vectors.iter().enumerate() {
        let old = RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(prevouts(vector)).unwrap();
        assert_eq!(old.effect_id(), vector.txid);
        assert_eq!(old.auth_digest(), vector.auth_digest);
        assert_eq!(old.shielded(), vector.sighash_shielded);
        if let Some(selected) = vector.transparent_input {
            for (kind, literal) in [(1, vector.sighash_all), (2, vector.sighash_none),
                (3, vector.sighash_single), (0x81, vector.sighash_all_anyone),
                (0x82, vector.sighash_none_anyone), (0x83, vector.sighash_single_anyone)] {
                assert_eq!(old.transparent(selected as usize, kind), literal.ok_or(PostNu5SighashError::SingleOutputMissing));
            }
        }
        let raw = new_branch(&vector.tx);
        if matches!(number, 0 | 6 | 7 | 9) {
            // Literal random proof lengths 135/239/97/199 are not fixed proofs.
            assert_eq!(RawV5::parse_exact(&raw).unwrap_err(), RawV5Error::InvalidOrchardProofLength);
            continue;
        }
        let actual = RawV5::parse_exact(&raw).unwrap().into_signature_context(prevouts(vector)).unwrap();
        let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), prevouts(vector)).unwrap();
        assert_eq!(actual.transaction().consensus_branch_id(), BranchId::Nu6_2);
        assert_eq!(actual.effect_id(), typed.effect_id());
        assert_eq!(actual.auth_digest(), typed.auth_digest());
        assert_eq!(actual.shielded(), typed.shielded());
        assert_ne!(actual.effect_id(), vector.txid);
        assert_ne!(actual.auth_digest(), vector.auth_digest);
        assert_ne!(actual.shielded(), vector.sighash_shielded);
        if let Some(selected) = vector.transparent_input {
            for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                assert_eq!(actual.transparent(selected as usize, kind), typed.transparent(selected as usize, kind));
            }
        }
        for count in [vector.amounts.len().checked_sub(1), Some(vector.amounts.len() + 1)].into_iter().flatten() {
            let mut previous = prevouts(vector);
            previous.resize(count, TxOut::new(Zatoshis::ZERO, Script::default()));
            assert!(matches!(RawV5::parse_exact(&raw).unwrap().into_signature_context(previous),
                Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual })
                if expected == vector.amounts.len() && actual == count));
        }
        for index in 0..vector.amounts.len() {
            for change_script in [false, true] {
                let mut previous = prevouts(vector);
                let mut code = vector.script_pubkeys[index].clone();
                if change_script { code.push(0x51); }
                previous[index] = TxOut::new(Zatoshis::from_nonnegative_i64(
                    vector.amounts[index] + i64::from(!change_script)).unwrap(), script(&code));
                let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(previous).unwrap();
                assert_eq!(changed.effect_id(), actual.effect_id());
                assert_eq!(changed.auth_digest(), actual.auth_digest());
                assert_ne!(changed.shielded(), actual.shielded());
                if let Some(selected) = vector.transparent_input {
                    for kind in [1, 2, 0x81, 0x82] {
                        assert_eq!(changed.transparent(selected as usize, kind) == actual.transparent(selected as usize, kind),
                            kind & 0x80 != 0 && index != selected as usize);
                    }
                }
            }
        }
    }
}

#[test]
fn v4_exact_nu62_zip243_context_binds_original_script_and_actual_amount() {
    let raw = v4_wire();
    let amount = Zatoshis::from_u64(125_000_000).unwrap();
    let code = script(&[0x51, 0xab, 0]);
    let previous = parse_typed(&raw, BranchId::Nu6_1);
    let transaction = parse_typed(&raw, BranchId::Nu6_2);
    let hashes = SaplingSignatureHash::new(&transaction).unwrap();
    let old = SaplingSignatureHash::new(&previous).unwrap();
    assert_ne!(hashes.shielded(), old.shielded());
    assert_eq!(hashes.shielded().as_slice(), v4_signature_hash(&transaction, &SignableInput::Shielded).as_bytes());
    // Python hashlib ZIP243 over exact original JoinSplit bytes; these new
    // branch messages do not imply the old signatures are valid at NU6.2.
    assert_eq!(hashes.shielded(), digest("0e153834eaaf90a531f362554409c6b444daa1666cd2255cf2cd647050988d79"));
    for (kind, literal) in [
        (1, "0556da2c5ec2f55879852e0a4a347094e6ae9d3d7d8a37988925c977cc51b659"),
        (2, "5b46b784e0f450506fa973258e156a1f04093ff65448c5d1e1e754f4556ac942"),
        (3, "3329b10fce6fe4d2ac367549e2d4a2663505516dfaaa8d3d4c5223b39c2b4245"),
        (0x81, "54e4d8b113e9a88be80666743a276c35af0328a1a63778fa6ef84b9482bae36e"),
        (0x82, "a343e35926cd220affc34b27eca7b430d70632b49f15755420b49c77c6cb2ced"),
        (0x83, "ad37ca480d2cb9934ebd672c0138e95b98fb635d11b7b7b62853f96927c9840c"),
    ] {
        let input = TransparentInput::from_parts(transaction.transparent_bundle().unwrap(),
            SighashType::from_raw(kind), 0, &code, &code, amount).unwrap();
        let actual = hashes.transparent(0, &code.0.0, amount, i32::from(kind)).unwrap();
        assert_eq!(actual, digest(literal));
        assert_eq!(actual.as_slice(), v4_signature_hash(&transaction, &SignableInput::Transparent(input)).as_bytes());
        assert_ne!(actual, old.transparent(0, &code.0.0, amount, i32::from(kind)).unwrap());
        assert_ne!(actual, hashes.transparent(0, &[0x51, 0xab, 1], amount, i32::from(kind)).unwrap());
        assert_ne!(actual, hashes.transparent(0, &code.0.0, Zatoshis::from_u64(125_000_001).unwrap(), i32::from(kind)).unwrap());
    }
}

fn coinbase(height: u32, version: TxVersion, branch: BranchId) -> Vec<u8> {
    let mut raw = if version == TxVersion::V4 {
        include_bytes!("fixtures/testnet-canopy-block-1115999.bin")[HEADER_BYTES + 1..].to_vec()
    } else { ORIGINAL_BODY[HEADER_BYTES + 1..1690].to_vec() };
    let prefix = [3, height as u8, (height >> 8) as u8, (height >> 16) as u8];
    if version == TxVersion::V4 {
        raw[46..50].copy_from_slice(&prefix);
        raw[242..246].copy_from_slice(&height.to_le_bytes());
    } else {
        raw[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
        raw[58..62].copy_from_slice(&prefix);
        raw[16..20].copy_from_slice(&height.to_le_bytes());
    }
    raw
}

// Maintained full-wire leaves plus independent SHA256d/BLAKE2b tree equations;
// no production body/helper digest is reused, and mutated headers have no PoW.
fn structural_body(transactions: &[&[u8]], branch: BranchId) -> (Vec<u8>, [u8; 32]) {
    let typed: Vec<_> = transactions.iter().map(|raw| parse_typed(raw, branch)).collect();
    let mut effects: Vec<[u8; 32]> = typed.iter().map(|tx| tx.txid().into()).collect();
    let mut auth: Vec<[u8; 32]> = typed.iter().map(|tx| {
        if tx.version() == TxVersion::V4 { [0xff; 32] }
        else { *tx.auth_commitment().as_bytes().first_chunk::<32>().unwrap() }
    }).collect();
    while effects.len() > 1 {
        if !effects.len().is_multiple_of(2) { effects.push(*effects.last().unwrap()); }
        effects = effects.as_chunks::<2>().0.iter().map(|pair| {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            Sha256::digest(hasher.finalize()).into()
        }).collect();
    }
    auth.resize(auth.len().next_power_of_two(), [0; 32]);
    while auth.len() > 1 {
        auth = auth.as_chunks::<2>().0.iter().map(|pair| {
            *blake2b_simd::Params::new().hash_length(32).personal(b"ZcashAuthDatHash")
                .to_state().update(&pair[0]).update(&pair[1]).finalize().as_bytes().first_chunk::<32>().unwrap()
        }).collect();
    }
    let mut raw = ORIGINAL_BODY[..HEADER_BYTES].to_vec();
    raw[36..68].copy_from_slice(&effects[0]);
    CompactSize::write(&mut raw, transactions.len()).unwrap();
    for transaction in transactions { raw.extend_from_slice(transaction); }
    (raw, auth[0])
}

#[test]
fn both_formats_reenable_orchard_at_nu62_and_preserve_valid_nu63_candidates() {
    let v4 = v4_wire();
    for (height, branch, orchard_allowed) in [
        (4_048_499_u32, BranchId::Nu6_1, true),
        (4_048_500, BranchId::Nu6_1, false),
        (4_051_999, BranchId::Nu6_1, false),
        (4_052_000, BranchId::Nu6_2, true),
        (4_052_001, BranchId::Nu6_2, true),
        (4_133_999, BranchId::Nu6_2, true),
    ] {
        let mut orchard = PURE.to_vec();
        orchard[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
        let mut absent = orchard[..24].to_vec();
        absent.push(0);
        for version in [TxVersion::V4, TxVersion::V5] {
            let cb = coinbase(height, version, branch);
            let (without, auth) = structural_body(&[&cb, &v4, &absent], branch);
            let parsed = PostNu5Block::parse(&without, height).unwrap();
            assert_eq!(parsed.transactions().len(), 3);
            assert_eq!(parsed.transactions()[0].version(), version);
            assert_eq!(parsed.transactions()[1].version(), TxVersion::V4);
            assert_eq!(parsed.transactions()[2].version(), TxVersion::V5);
            assert!(parsed.transactions().iter().all(|tx| tx.consensus_branch_id() == branch));
            assert_eq!(parsed.auth_data_root(), auth);
            let (with, auth) = structural_body(&[&cb, &v4, &orchard], branch);
            if orchard_allowed {
                let parsed = PostNu5Block::parse(&with, height).unwrap();
                assert_eq!(parsed.auth_data_root(), auth);
                let PostNu5Transaction::V5(raw) = &parsed.transactions()[2] else { panic!("raw V5 lost"); };
                assert_eq!(raw.original_bytes(), orchard);
            } else {
                assert_eq!(PostNu5Block::parse(&with, height).unwrap_err(), BodyError::MalformedBlock);
            }
        }
        for flags in [1, 2, 3] {
            let mut cb = coinbase(height, TxVersion::V5, branch);
            assert_eq!(cb.pop(), Some(0));
            let mut shielded = orchard.clone();
            shielded[1665] = flags;
            cb.extend_from_slice(&shielded[24..]);
            let (body, auth) = structural_body(&[&cb], branch);
            if orchard_allowed {
                assert_eq!(PostNu5Block::parse(&body, height).unwrap().auth_data_root(), auth);
            } else {
                assert_eq!(PostNu5Block::parse(&body, height).unwrap_err(), BodyError::MalformedBlock);
            }
        }
    }
    for version in [TxVersion::V4, TxVersion::V5] {
        let cb = coinbase(4_134_000, version, BranchId::Nu6_3);
        let (raw, auth) = structural_body(&[&cb, &v4], BranchId::Nu6_3);
        let parsed = PostNu5Block::parse(&raw, 4_134_000).unwrap();
        assert_eq!(parsed.auth_data_root(), auth);
        assert_eq!(parsed.transactions()[0].consensus_branch_id(), BranchId::Nu6_3);
        assert_eq!(PostNu5Block::parse(&raw, u32::MAX).unwrap_err(), BodyError::WrongConsensusBranch);
    }
}

#[test]
fn fixed_candidate_checks_branch_coinbase_flags_and_complete_original_auth_tree() {
    let height = 4_052_000;
    let ordinary = new_branch(PURE);
    let cb = coinbase(height, TxVersion::V5, BranchId::Nu6_2);
    let (baseline, _) = structural_body(&[&cb, &ordinary], BranchId::Nu6_2);
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_3] {
        for start in [HEADER_BYTES + 1, HEADER_BYTES + 1 + cb.len()] {
            let mut bad = baseline.clone();
            bad[start + 8..start + 12].copy_from_slice(&u32::from(branch).to_le_bytes());
            assert_eq!(PostNu5Block::parse(&bad, height).unwrap_err(), BodyError::WrongConsensusBranch);
        }
    }
    let parsed = PostNu5Block::parse(&baseline, height).unwrap();
    for offset in [1709, 8973, 9037, 9101, ordinary.len() - 1] {
        let mut changed = ordinary.clone();
        changed[offset] ^= 1;
        let (body, auth) = structural_body(&[&cb, &changed], BranchId::Nu6_2);
        let changed = PostNu5Block::parse(&body, height).unwrap();
        assert_eq!(changed.header().merkle_root, parsed.header().merkle_root);
        assert_ne!(changed.auth_data_root(), parsed.auth_data_root());
        assert_eq!(changed.auth_data_root(), auth);
    }
    for flags in [1, 2, 3] {
        for is_coinbase in [false, true] {
            let mut orchard = ordinary.clone();
            orchard[1665] = flags;
            let transactions = if is_coinbase {
                let mut shielded = cb.clone();
                assert_eq!(shielded.pop(), Some(0));
                shielded.extend_from_slice(&orchard[24..]);
                vec![shielded]
            } else { vec![cb.clone(), orchard] };
            let borrowed: Vec<_> = transactions.iter().map(Vec::as_slice).collect();
            let (body, auth) = structural_body(&borrowed, BranchId::Nu6_2);
            let parsed = PostNu5Block::parse(&body, height).unwrap();
            assert_eq!(parsed.auth_data_root(), auth);
            // Eligibility only: coinbase spends-enabled/proofs/reward/signature
            // validity belong to the real ledger relation, not this parser.
        }
    }
    for version in [TxVersion::V4, TxVersion::V5] {
        let mut bad_cb = coinbase(height, version, BranchId::Nu6_2);
        let expiry = if version == TxVersion::V4 { 242 } else { 16 };
        bad_cb[expiry..expiry + 4].copy_from_slice(&(height + 1).to_le_bytes());
        let (body, _) = structural_body(&[&bad_cb, &ordinary], BranchId::Nu6_2);
        // Framing does not admit the ledger: retain exact wrong expiry for its
        // contextual rejection instead of normalizing it or choosing the era.
        let parsed = PostNu5Block::parse(&body, height).unwrap();
        assert_eq!(u32::from(parsed.transactions()[0].expiry_height()), height + 1);
        let mut bad_cb = coinbase(height, version, BranchId::Nu6_2);
        let prefix = if version == TxVersion::V4 { 46 } else { 58 };
        bad_cb[prefix + 1] ^= 1;
        let (body, _) = structural_body(&[&bad_cb, &ordinary], BranchId::Nu6_2);
        assert_eq!(PostNu5Block::parse(&body, height).unwrap_err(), BodyError::MalformedBlock);
    }
    let (duplicate, _) = structural_body(&[&cb, &ordinary, &ordinary], BranchId::Nu6_2);
    assert_eq!(PostNu5Block::parse(&duplicate, height).unwrap_err(), BodyError::DuplicateTransaction);
    let (two_coinbase, _) = structural_body(&[&cb, &cb], BranchId::Nu6_2);
    assert_eq!(PostNu5Block::parse(&two_coinbase, height).unwrap_err(), BodyError::MalformedBlock);
    for delta in [-1_i16, 1] {
        let mut bad = baseline.clone();
        let start = HEADER_BYTES + 1 + cb.len();
        bad[start + 1707..start + 1709].copy_from_slice(&(7264_u16.wrapping_add_signed(delta)).to_le_bytes());
        assert_eq!(PostNu5Block::parse(&bad, height).unwrap_err(), BodyError::MalformedBlock);
    }
    for index in 0..2 {
        for field in [64, 128] {
            let mut bad = baseline.clone();
            let start = HEADER_BYTES + 1 + cb.len() + 25 + index * 820 + field;
            bad[start..start + 32].fill(0);
            assert_eq!(PostNu5Block::parse(&bad, height).unwrap_err(), BodyError::MalformedBlock);
        }
    }
    let mut truncated = baseline.clone();
    truncated.pop();
    assert_eq!(PostNu5Block::parse(&truncated, height).unwrap_err(), BodyError::MalformedBlock);
    let mut trailing = baseline.clone();
    trailing.push(0);
    assert_eq!(PostNu5Block::parse(&trailing, height).unwrap_err(), BodyError::TrailingBytes);
    let mut wrong_root = baseline;
    wrong_root[36] ^= 1;
    assert_eq!(PostNu5Block::parse(&wrong_root, height).unwrap_err(), BodyError::MerkleRootMismatch);
}

#[test]
fn nu62_both_wire_formats_keep_header_counts_and_nested_preflight_bounded() {
    let height = 4_052_000;
    let ordinary = new_branch(PURE);
    let v4 = v4_wire();
    for version in [TxVersion::V4, TxVersion::V5] {
        let cb = coinbase(height, version, BranchId::Nu6_2);
        let (raw, _) = structural_body(&[&cb, &v4, &ordinary], BranchId::Nu6_2);
        for length in [0, 3, 139, 142, HEADER_BYTES - 1, HEADER_BYTES, raw.len() - 1] {
            assert_eq!(PostNu5Block::parse(&raw[..length], height).unwrap_err(), BodyError::MalformedBlock);
        }
        let mut oversized = raw.clone();
        oversized.resize(2_000_001, 0);
        assert_eq!(PostNu5Block::parse(&oversized, height).unwrap_err(), BodyError::BlockTooLarge);
        for offset in [0, 140] {
            let mut bad = raw.clone();
            if offset == 0 { bad[..4].copy_from_slice(&3_i32.to_le_bytes()); }
            else { bad[offset] ^= 1; }
            assert_eq!(PostNu5Block::parse(&bad, height).unwrap_err(), BodyError::InvalidHeader);
        }
        for offset in [0, 4] {
            for start in [HEADER_BYTES + 1, HEADER_BYTES + 1 + cb.len(), HEADER_BYTES + 1 + cb.len() + v4.len()] {
                let mut bad = raw.clone();
                bad[start + offset] ^= 1;
                assert_eq!(PostNu5Block::parse(&bad, height).unwrap_err(), BodyError::WrongConsensusBranch);
            }
        }
        let mut noncanonical = raw.clone();
        noncanonical.splice(HEADER_BYTES..HEADER_BYTES + 1, [0xfd, 3, 0]);
        assert_eq!(PostNu5Block::parse(&noncanonical, height).unwrap_err(), BodyError::NoncanonicalEncoding);
        let mut empty = raw.clone();
        empty[HEADER_BYTES] = 0;
        assert_eq!(PostNu5Block::parse(&empty, height).unwrap_err(), BodyError::MalformedBlock);
        let mut huge = raw[..HEADER_BYTES].to_vec();
        huge.extend_from_slice(&[0xfe, 0, 0, 0, 2]);
        assert_eq!(PostNu5Block::parse(&huge, height).unwrap_err(), BodyError::MalformedBlock);
    }
    let cb = coinbase(height, TxVersion::V4, BranchId::Nu6_2);
    let (baseline, _) = structural_body(&[&cb, &ordinary], BranchId::Nu6_2);
    // Every existing empty-V4 count/script position is preflighted before its
    // maintained reader can reserve based on an attacker-controlled count.
    for offset in [8, 45, 107, 116, 254, 255, 256] {
        let mut huge = cb.clone();
        huge.splice(offset..offset + 1, [0xfe, 0, 0, 0, 2]);
        let mut body = baseline[..HEADER_BYTES + 1].to_vec();
        body.extend_from_slice(&huge);
        body.extend_from_slice(&ordinary);
        assert_eq!(PostNu5Block::parse(&body, height).unwrap_err(), BodyError::MalformedBlock);
    }
}
