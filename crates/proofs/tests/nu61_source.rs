//! Synthetic NU6.1 branch/body mutations are subrelations, not mined or connected history.
extern crate alloc;

use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion, sighash::SignableInput, sighash_v4::v4_signature_hash};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{address::Script, bundle::TxOut, sighash::{SignableInput as TransparentInput, SighashType}};
use ziquid_proofs::{history::BodyError, orchard_original::OriginalOrchardVerifier,
    post_nu5_body::{PostNu5Block, PostNu5Transaction}, raw_v5::{RawV5, RawV5Error},
    sapling_sighash::SaplingSignatureHash, zip244::{PostNu5SignatureHash, PostNu5SighashError}};

#[path = "fixtures/zip244-primary.rs"]
mod primary;
#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod original_v4;

const HEADER_BYTES: usize = 1487;
const PURE: &[u8] = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
const ORIGINAL_BODY: &[u8] = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");
static VERIFIER: LazyLock<OriginalOrchardVerifier> = LazyLock::new(OriginalOrchardVerifier::new);

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
    changed[8..12].copy_from_slice(&0x4dec4df0_u32.to_le_bytes());
    changed
}
#[test]
fn nu61_original_byte_digests_and_actual_context_preserve_encoded_branch() {
    let mut raw = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin").to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_1).to_le_bytes());
    let parsed = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6_1);
    let mut remaining = raw.as_slice();
    let transaction = Transaction::read(&mut remaining, BranchId::Nu6_1).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(parsed.effect_id(), <[u8; 32]>::from(transaction.txid()));
    assert_eq!(parsed.auth_digest().as_slice(), transaction.auth_commitment().as_bytes());
    let expected = PostNu5SignatureHash::new(transaction, vec![]).unwrap();
    let actual = parsed.into_signature_context(vec![]).unwrap();
    assert_eq!(actual.shielded(), expected.shielded());
}

#[test]
fn nu61_empty_and_original_orchard_roots_match_independent_numeric_literals() {
    // Independently derived with Python hashlib ZIP244 equations, not the
    // production or maintained Rust digest helpers; no consensus validity claim.
    let mut empty = vec![5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0xf0, 0x4d, 0xec, 0x4d];
    empty.extend_from_slice(&17_u32.to_le_bytes());
    empty.extend_from_slice(&3_536_500_u32.to_le_bytes());
    empty.extend_from_slice(&[0; 5]);
    for (raw, effect, auth) in [
        (empty, "8101411e71f7d09a735621d97d2e29a04bf3338769ae554bd71a78d3e6bcb963",
            "a052a7aac3a7b7e231045f9ef283bde1f129298d078768cd6572a3bc53545c7e"),
        (new_branch(PURE), "496939814c3dd97369e1b71506131a286b848a943b94b31efab4eb769815400f",
            "f4414f101eaa1bd795cdd23903ff623c054d38c7b855c6e8a0809f8c0a71c25c"),
    ] {
        let parsed = RawV5::parse_exact(&raw).unwrap();
        assert_eq!(parsed.consensus_branch_id(), BranchId::Nu6_1);
        assert_eq!(parsed.effect_id(), digest(effect));
        assert_eq!(parsed.auth_digest(), digest(auth));
        let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), vec![]).unwrap();
        let actual = parsed.into_signature_context(vec![]).unwrap();
        assert_eq!(actual.shielded(), digest(effect));
        assert_eq!(typed.shielded(), actual.shielded());
    }
}

#[test]
fn nu61_actual_two_prevout_hashes_match_independent_numeric_literals() {
    // Synthetic two-input wire: arbitrary authorizing scripts, no signatures.
    let mut raw = vec![5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0xf0, 0x4d, 0xec, 0x4d];
    raw.extend_from_slice(&17_u32.to_le_bytes());
    raw.extend_from_slice(&3_536_500_u32.to_le_bytes());
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
    assert_eq!(actual.effect_id(), digest("d5df4984295b68a60624302851dc9ad7a99d26501f270edba5bc4902da119d7a"));
    assert_eq!(actual.auth_digest(), digest("ad7415da44be50336b5f5838a0c7d9a205d723ef2cf1c13f980884900c439e83"));
    assert_eq!(actual.shielded(), digest("6cf60a3b5c128e5e6b77c167464d637efb1edf0d46196d745de817b73dcf3499"));
    let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), outputs()).unwrap();
    for (kind, literal) in [
        (1, "1102e1ed6ba3e5b4f6b78305d3947c380418264bcf451c09269b3ce6db86b0e5"),
        (2, "cad212e0bf8cbab88ce0d39899113f762bbcfc18b94eca9325567289365c023e"),
        (3, "cc5cd895a2c7f3a0c0fca1b86ef7499f03b6c688870829a34a0dbf6023c9e0fa"),
        (0x81, "76efa9285400b5d5b03ddf032353dc41826e9d2baedff9313bafbed41f734f15"),
        (0x82, "c4d2fa4cbcd6544a6e12ade325a3eb7b5fb6cbc12051901b801a05e3382f4b01"),
        (0x83, "eea60a1ee072da78cf68c1d7f91c5c89d4daf67a4d3be5aa472f2e32243f605f"),
    ] {
        assert_eq!(actual.transparent(1, kind), Ok(digest(literal)));
        assert_eq!(typed.transparent(1, kind), Ok(digest(literal)));
    }
    let mut reversed = outputs();
    reversed.swap(0, 1);
    let reversed = RawV5::parse_exact(&raw).unwrap().into_signature_context(reversed).unwrap();
    assert_ne!(reversed.shielded(), actual.shielded());
    assert_ne!(reversed.transparent(1, 0x81), actual.transparent(1, 0x81));
}

#[test]
fn all_ten_primary_vectors_bind_nu61_branch_and_every_actual_prevout() {
    let vectors = primary::zip_0244::make_test_vectors();
    assert_eq!(vectors.len(), 10);
    for (number, vector) in vectors.iter().enumerate() {
        let nu5 = RawV5::parse_exact(&vector.tx).unwrap().into_signature_context(prevouts(vector)).unwrap();
        assert_eq!(nu5.effect_id(), vector.txid);
        assert_eq!(nu5.auth_digest(), vector.auth_digest);
        assert_eq!(nu5.shielded(), vector.sighash_shielded);
        let raw = new_branch(&vector.tx);
        let context = RawV5::parse_exact(&raw).unwrap().into_signature_context(prevouts(vector)).unwrap();
        assert_eq!(context.transaction().consensus_branch_id(), BranchId::Nu6_1);
        assert_ne!(context.effect_id(), vector.txid);
        assert_ne!(context.auth_digest(), vector.auth_digest);
        assert_ne!(context.shielded(), vector.sighash_shielded);
        // These exact tuples lie inside the maintained parser's narrower EPK
        // acceptance domain. The remaining four still use original opaque EPKs.
        if matches!(number, 1 | 2 | 3 | 4 | 5 | 8) {
            let typed = PostNu5SignatureHash::new(parse_typed(&raw, BranchId::Nu5), prevouts(vector)).unwrap();
            assert_eq!(context.effect_id(), typed.effect_id());
            assert_eq!(context.auth_digest(), typed.auth_digest());
            assert_eq!(context.shielded(), typed.shielded());
            if let Some(index) = vector.transparent_input {
                for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                    assert_eq!(context.transparent(index as usize, kind), typed.transparent(index as usize, kind));
                }
            }
        }
        if let Some(selected) = vector.transparent_input {
            for (kind, literal) in [(1, vector.sighash_all), (2, vector.sighash_none),
                (3, vector.sighash_single), (0x81, vector.sighash_all_anyone),
                (0x82, vector.sighash_none_anyone), (0x83, vector.sighash_single_anyone)] {
                assert_eq!(nu5.transparent(selected as usize, kind), literal.ok_or(PostNu5SighashError::SingleOutputMissing));
                if let Some(old) = literal {
                    assert_ne!(context.transparent(selected as usize, kind).unwrap(), old);
                } else {
                    assert_eq!(context.transparent(selected as usize, kind), Err(PostNu5SighashError::SingleOutputMissing));
                }
            }
        }
        for count in [vector.amounts.len().checked_sub(1), Some(vector.amounts.len() + 1)].into_iter().flatten() {
            let mut outputs = prevouts(vector);
            outputs.resize(count, TxOut::new(Zatoshis::ZERO, script(&[])));
            assert!(matches!(RawV5::parse_exact(&raw).unwrap().into_signature_context(outputs),
                Err(PostNu5SighashError::PrevoutCountMismatch { expected, actual })
                if expected == vector.amounts.len() && actual == count));
        }
        for index in 0..vector.amounts.len() {
            for change_script in [false, true] {
                let mut outputs = prevouts(vector);
                let mut code = vector.script_pubkeys[index].clone();
                if change_script { code.push(0x51); }
                outputs[index] = TxOut::new(Zatoshis::from_nonnegative_i64(
                    vector.amounts[index] + i64::from(!change_script)).unwrap(), script(&code));
                let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(outputs).unwrap();
                assert_eq!(changed.effect_id(), context.effect_id());
                assert_eq!(changed.auth_digest(), context.auth_digest());
                assert_ne!(changed.shielded(), context.shielded());
                if let Some(selected) = vector.transparent_input {
                    for kind in [1, 2, 0x81, 0x82] {
                        assert_eq!(changed.transparent(selected as usize, kind) == context.transparent(selected as usize, kind),
                            kind & 0x80 != 0 && index != selected as usize);
                    }
                }
            }
        }
    }
}

#[test]
fn v4_original_wire_uses_exact_nu61_zip243_branch_script_and_amount() {
    let raw: Vec<u8> = original_v4::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect();
    let amount = Zatoshis::from_u64(125_000_000).unwrap();
    let code = script(&[0x51, 0xab, 0]);
    let previous = parse_typed(&raw, BranchId::Nu6);
    let transaction = parse_typed(&raw, BranchId::Nu6_1);
    let hashes = SaplingSignatureHash::new(&transaction).unwrap();
    let old = SaplingSignatureHash::new(&previous).unwrap();
    assert_ne!(hashes.shielded(), old.shielded());
    assert_eq!(hashes.shielded().as_slice(), v4_signature_hash(&transaction, &SignableInput::Shielded).as_bytes());
    // Python hashlib ZIP243 over the exact original wire/JoinSplit bytes;
    // these are new-branch messages, not valid historical authorizations.
    assert_eq!(hashes.shielded(), digest("99227a8bf8f6d296aae4f86d340f50db2495c9b717817b494f70b8e68c1292fd"));
    for (kind, literal) in [
        (1, "0298f86ba9bd195ebed0d1ae5e6f3d03fc6fd30a93dfd62439047fbc40b4d50a"),
        (2, "75a3769e9eb1beb0a2457905bce4beb8a864e627600271cee8919ea3961d58c9"),
        (3, "df224e0cddbda95cedde546b73105d8aa61f96e40d7d9e904dc1bb535fe6e3f5"),
        (0x81, "c7135228a8183490044dba32164f0ca6e98c69b95faab88f327394b0d8411456"),
        (0x82, "af080c140efc5cc9149bb711077c85ebab8c57b8ed02d7eac79e425ccd17e6ad"),
        (0x83, "48e1433f4a6653bab684c87447b1562e515b900e1ff045f6d38bb876eefaa56d"),
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

#[test]
fn nu61_branch_mutation_preserves_original_proofs_but_not_old_authorization() {
    let original = RawV5::parse_exact(PURE).unwrap();
    let raw = new_branch(PURE);
    let changed = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(changed.original_bytes(), raw);
    let orchard = *changed.orchard().unwrap();
    assert_eq!(orchard.proof(), original.orchard().unwrap().proof());
    assert_eq!(orchard.spend_auth_signatures(), original.orchard().unwrap().spend_auth_signatures());
    assert_eq!(orchard.binding_signature(), original.orchard().unwrap().binding_signature());
    let hashes = changed.into_signature_context(vec![]).unwrap();
    assert_eq!(orchard.verify_orchard(&VERIFIER, &hashes.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    // Only isolates unchanged original cryptography; not NU6.1 admission.
    orchard.verify_orchard(&VERIFIER, &original.effect_id()).unwrap();
    let mixed = new_branch(include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin"));
    let mixed = RawV5::parse_exact(&mixed).unwrap().into_signature_context(vec![]).unwrap();
    assert!(matches!(ziquid_proofs::zip244::verify_sapling_post_nu5_crypto(&mixed),
        Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidSpendAuthSignature { .. })
        | Err(ziquid_proofs::sapling_crypto::SaplingCryptoError::InvalidBindingSignature)));
}

fn coinbase(height: u32, version: TxVersion) -> Vec<u8> {
    let mut raw = if version == TxVersion::V4 {
        include_bytes!("fixtures/testnet-canopy-block-1115999.bin")[HEADER_BYTES + 1..].to_vec()
    } else {
        new_branch(&ORIGINAL_BODY[HEADER_BYTES + 1..1690])
    };
    let prefix = [3, height as u8, (height >> 8) as u8, (height >> 16) as u8];
    if version == TxVersion::V4 {
        raw[46..50].copy_from_slice(&prefix);
        raw[242..246].copy_from_slice(&height.to_le_bytes());
    } else {
        raw[58..62].copy_from_slice(&prefix);
        raw[16..20].copy_from_slice(&height.to_le_bytes());
    }
    raw
}

// Independent effect/auth tree equations on maintained full-wire transactions,
// not production body helpers. These mutations do not retain valid header PoW.
fn structural_body(transactions: &[&[u8]]) -> (Vec<u8>, [u8; 32]) {
    let typed: Vec<_> = transactions.iter().map(|raw| parse_typed(raw, BranchId::Nu6_1)).collect();
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

fn body_error(raw: &[u8], height: u32) -> BodyError {
    PostNu5Block::parse(raw, height).unwrap_err()
}

#[test]
fn nu61_v4_and_v5_bodies_remain_live_through_disable_and_finite_cutoff() {
    let v4: Vec<u8> = original_v4::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect();
    let mut absent = new_branch(&PURE[..24]);
    absent.push(0); // nActions=0, not a present zero-valued Orchard bundle.
    assert!(RawV5::parse_exact(&absent).unwrap().orchard().is_none());
    for height in [3_536_500_u32, 3_536_501, 4_048_499, 4_048_500, 4_048_501, 4_051_999] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let cb = coinbase(height, version);
            let (raw, auth) = structural_body(&[&cb, &v4, &absent]);
            let parsed = PostNu5Block::parse(&raw, height).unwrap();
            assert_eq!(parsed.transactions().len(), 3);
            assert_eq!(parsed.transactions()[0].version(), version);
            assert_eq!(parsed.transactions()[1].version(), TxVersion::V4);
            assert_eq!(parsed.transactions()[2].version(), TxVersion::V5);
            assert!(parsed.transactions().iter().all(|tx| tx.consensus_branch_id() == BranchId::Nu6_1));
            assert_eq!(parsed.auth_data_root(), auth);
            let PostNu5Transaction::V5(borrowed) = &parsed.transactions()[2] else { panic!("raw V5 lost"); };
            assert_eq!(borrowed.original_bytes(), absent);
            assert_eq!(body_error(&raw, 4_134_000), if version == TxVersion::V4 {
                BodyError::MalformedBlock // V4 inherits the live candidate branch, not its old height
            } else { BodyError::WrongConsensusBranch });
            assert_eq!(body_error(&raw, u32::MAX), BodyError::WrongConsensusBranch);
        }
    }
    for height in [3_536_500_u32, 4_051_999] {
        let cb = coinbase(height, TxVersion::V5);
        let (baseline, _) = structural_body(&[&cb, &absent]);
        for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_2] {
            for index in [0, 1] {
                let mut bad = baseline.clone();
                let start = HEADER_BYTES + 1 + if index == 0 { 0 } else { cb.len() };
                bad[start + 8..start + 12].copy_from_slice(&u32::from(branch).to_le_bytes());
                assert_eq!(body_error(&bad, height), BodyError::WrongConsensusBranch);
            }
        }
        let mut truncated = baseline.clone();
        truncated.pop();
        assert_eq!(body_error(&truncated, height), BodyError::MalformedBlock);
        let mut trailing = baseline.clone();
        trailing.push(0);
        assert_eq!(body_error(&trailing, height), BodyError::TrailingBytes);
        let mut wrong_root = baseline.clone();
        wrong_root[36] ^= 1;
        assert_eq!(body_error(&wrong_root, height), BodyError::MerkleRootMismatch);
    }
}

#[test]
fn contextual_disable_rejects_all_present_orchard_for_coinbase_and_ordinary() {
    for flags in [1, 2, 3] {
        for value in [-1000_i64, 0, 1000] {
            let mut orchard = new_branch(PURE);
            orchard[1665] = flags;
            orchard[1666..1674].copy_from_slice(&value.to_le_bytes());
            // This standalone parser knows no candidate height. Nonzero actions
            // remain present even with zero value or spends/outputs disabled.
            assert!(RawV5::parse_exact(&orchard).unwrap().orchard().is_some());
            for is_coinbase in [false, true] {
                for height in [4_048_499_u32, 4_048_500, 4_048_501, 4_051_999] {
                    let mut cb = coinbase(height, TxVersion::V5);
                    let (raw, _) = if is_coinbase {
                        assert_eq!(cb.pop(), Some(0));
                        cb.extend_from_slice(&orchard[24..]);
                        structural_body(&[&cb])
                    } else { structural_body(&[&cb, &orchard]) };
                    if height == 4_048_499 {
                        // Structural pre-disable eligibility only: changed flags,
                        // value and coinbase context do not preserve signatures.
                        PostNu5Block::parse(&raw, height).unwrap();
                    } else {
                        assert_eq!(body_error(&raw, height), BodyError::MalformedBlock);
                    }
                }
            }
        }
    }
}

#[test]
fn nu61_preserves_full_proof_suffix_auth_and_original_opaque_epk_domain() {
    let height = 4_048_499;
    let cb = coinbase(height, TxVersion::V5);
    let pure = new_branch(PURE);
    let (raw, _) = structural_body(&[&cb, &pure]);
    let baseline = PostNu5Block::parse(&raw, height).unwrap();
    let mut padded = pure.clone();
    padded[1707..1709].copy_from_slice(&7265_u16.to_le_bytes());
    padded.insert(1709 + 7264, 0x42);
    let (padded_body, expected_auth) = structural_body(&[&cb, &padded]);
    let parsed = PostNu5Block::parse(&padded_body, height).unwrap();
    assert_eq!(parsed.header().merkle_root, baseline.header().merkle_root);
    assert_ne!(parsed.auth_data_root(), baseline.auth_data_root());
    assert_eq!(parsed.auth_data_root(), expected_auth);
    let PostNu5Transaction::V5(transaction) = &parsed.transactions()[1] else { panic!("raw V5 lost"); };
    assert_eq!(transaction.original_bytes(), padded);
    assert_eq!(transaction.orchard().unwrap().proof().last(), Some(&0x42));
    let original = RawV5::parse_exact(PURE).unwrap();
    transaction.verify_orchard(&VERIFIER, &original.effect_id()).unwrap();
    let cb_disabled = coinbase(4_048_500, TxVersion::V5);
    let (disabled, _) = structural_body(&[&cb_disabled, &padded]);
    assert_eq!(body_error(&disabled, 4_048_500), BodyError::MalformedBlock);
    let mut opaque = pure.clone();
    opaque[25 + 128..25 + 160].fill(0xff);
    let changed = RawV5::parse_exact(&opaque).unwrap();
    let baseline = RawV5::parse_exact(&pure).unwrap();
    assert_ne!(changed.effect_id(), baseline.effect_id());
    assert_eq!(changed.auth_digest(), baseline.auth_digest());
    let mut unsupported = pure.clone();
    unsupported[8..12].copy_from_slice(&u32::from(BranchId::Canopy).to_le_bytes());
    assert_eq!(RawV5::parse_exact(&unsupported).unwrap_err(), RawV5Error::UnsupportedBranch);
    let mut strict = opaque;
    strict[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    assert_eq!(RawV5::parse_exact(&strict).unwrap_err(), RawV5Error::InvalidOrchardEphemeralKey { index: 0 });
}
