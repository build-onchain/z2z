//! Synthetic NU6.3 framing/digest/signature checks, not mined or connected history.
//! Historical bytes retain old proofs/signatures; only the explicit signature
//! helpers re-authorize a deliberately invalid proof statement for rejection tests.
// Original bytes: Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291,
// block-test-1-842-467.txt and block-test-1-842-421.txt; extracted fixtures are
// shared with raw_v5/sapling_v5 tests. Original-author license retained below.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use ziquid_proofs::zip244::PostNu5SignatureHash;
#[test]
fn actual_v6_hash_context_preserves_embedded_branch_and_full_authorization() {
    let mut raw = TxVersion::V6.header().to_le_bytes().to_vec();
    raw.extend_from_slice(&TxVersion::V6.version_group_id().to_le_bytes());
    raw.extend_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&4_134_000u32.to_le_bytes());
    raw.extend_from_slice(&[0; 6]);
    let mut input = raw.as_slice();
    let tx = Transaction::read(&mut input, BranchId::Nu6_3).unwrap();
    assert!(input.is_empty());
    let effect: [u8;32] = tx.txid().into();
    let auth: [u8; 32] = tx.auth_commitment().as_bytes().try_into().unwrap();
    let actual = PostNu5SignatureHash::new(tx, vec![]).unwrap();
    assert_eq!(actual.effect_id(), effect);
    assert_eq!(actual.auth_digest(), auth);
    assert_eq!(actual.transaction().version(), TxVersion::V6);
    assert_eq!(actual.transaction().consensus_branch_id(), BranchId::Nu6_3);
}

const HEIGHT: u32 = 4_134_000;
const HEADER_BYTES: usize = 1487;
const PURE: &[u8] = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
const BODY: &[u8] = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");

#[path = "fixtures/sapling-mainnet-419202.rs"]
mod sapling_outputs;

fn parse(raw: &[u8]) -> Transaction {
    let mut input = raw;
    let transaction = Transaction::read(&mut input, BranchId::Nu6_3).unwrap();
    assert!(input.is_empty());
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, raw);
    transaction
}

fn v6_header(height: u32) -> Vec<u8> {
    let mut raw = TxVersion::V6.header().to_le_bytes().to_vec();
    raw.extend_from_slice(&TxVersion::V6.version_group_id().to_le_bytes());
    raw.extend_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    raw.extend_from_slice(&17u32.to_le_bytes());
    raw.extend_from_slice(&height.to_le_bytes());
    raw
}

// Exact historical fields are only framing/hash material after branch/format
// mutation. Their old proofs and signatures are NOT NU6.3 crypto positives.
fn mixed_wire() -> Vec<u8> {
    let source = parse(include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin"));
    let output_wire: Vec<u8> = sapling_outputs::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect();
    let output_source = parse(&output_wire);
    let original = source.sapling_bundle().unwrap();
    // Four real historical spends plus two real historical output encodings.
    // This assembled bundle's old signatures are intentionally NOT valid.
    let sapling = sapling_crypto::Bundle::from_parts(
        original.shielded_spends().to_vec(), output_source.sapling_bundle().unwrap().shielded_outputs().to_vec(),
        *original.value_balance(), *original.authorization(),
    ).unwrap();
    let mut raw = v6_header(HEIGHT);
    raw.push(2);
    for (id, index, code, sequence) in [(0x41, 7u32, &[][..], 123u32), (0x42, 9, &[0x51][..], 456)] {
        raw.extend_from_slice(&[id; 32]);
        raw.extend_from_slice(&index.to_le_bytes());
        raw.push(code.len() as u8);
        raw.extend_from_slice(code);
        raw.extend_from_slice(&sequence.to_le_bytes());
    }
    raw.push(2);
    for (amount, code) in [(12i64, 0x51), (34, 0x52)] {
        raw.extend_from_slice(&amount.to_le_bytes());
        raw.extend_from_slice(&[1, code]);
    }
    Transaction::temporary_zcashd_write_v5_sapling(Some(&sapling), &mut raw).unwrap();
    raw.extend_from_slice(&PURE[24..]);
    raw.extend_from_slice(&PURE[24..]);
    // Two Actions: count1 + actions1640; Ironwood may enable cross-address.
    let ironwood_flags = raw.len() - (PURE.len() - 24) + 1641;
    raw[ironwood_flags] |= 4;
    raw
}

fn script(code: &[u8]) -> zcash_transparent::address::Script {
    let mut script = zcash_transparent::address::Script::default();
    script.0.0 = code.to_vec();
    script
}

fn prevouts() -> Vec<zcash_transparent::bundle::TxOut> {
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::bundle::TxOut;
    vec![TxOut::new(Zatoshis::from_u64(100).unwrap(), script(&[0x53])),
        TxOut::new(Zatoshis::from_u64(200).unwrap(), script(&[0x54, 0x55]))]
}

// Independent maintained authorizing context, not the production adapter.
#[derive(Debug)]
struct OraclePrevouts(Vec<zcash_transparent::bundle::TxOut>);
impl zcash_transparent::bundle::Authorization for OraclePrevouts {
    type ScriptSig = zcash_transparent::address::Script;
}
impl zcash_transparent::sighash::TransparentAuthorizingContext for OraclePrevouts {
    fn input_amounts(&self) -> Vec<zcash_protocol::value::Zatoshis> {
        self.0.iter().map(zcash_transparent::bundle::TxOut::value).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<zcash_transparent::address::Script> {
        self.0.iter().map(|output| output.script_pubkey().clone()).collect()
    }
}
#[derive(Debug)]
struct OracleAuthorization;
impl zcash_primitives::transaction::Authorization for OracleAuthorization {
    type TransparentAuth = OraclePrevouts;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

fn oracle(raw: &[u8], previous: Vec<zcash_transparent::bundle::TxOut>)
    -> zcash_primitives::transaction::TransactionData<OracleAuthorization>
{
    parse(raw).into_data().map_bundles::<OracleAuthorization>(
        |bundle| bundle.map(|bundle| zcash_transparent::bundle::Bundle {
            vin: bundle.vin.into_iter().map(|input| zcash_transparent::bundle::TxIn::from_parts(
                input.prevout().clone(), input.script_sig().clone(), input.sequence(),
            )).collect(),
            vout: bundle.vout, authorization: OraclePrevouts(previous),
        }), |bundle| bundle, |bundle| bundle,
    )
}

#[test]
fn actual_mixed_v6_dispatch_binds_both_pools_and_all_ordered_prevouts() {
    use zcash_primitives::transaction::{sighash::{SignableInput, signature_hash}, txid::TxIdDigester};
    use zcash_transparent::sighash::{SighashType, SignableInput as TransparentInput};
    let raw = mixed_wire();
    let maintained = oracle(&raw, prevouts());
    let parts = maintained.digest(TxIdDigester);
    let actual = PostNu5SignatureHash::new(parse(&raw), prevouts()).unwrap();
    assert_eq!(actual.shielded(), *signature_hash(&maintained, &SignableInput::Shielded, &parts).as_ref());
    assert_ne!(actual.shielded(), actual.effect_id());
    let retained = actual.transaction();
    assert!(retained.sapling_bundle().is_some());
    assert_eq!(retained.orchard_bundle().unwrap().bundle_version(), orchard::bundle::BundleVersion::orchard_v3());
    assert_eq!(retained.ironwood_bundle().unwrap().bundle_version(), orchard::bundle::BundleVersion::ironwood_v3());
    assert!(!retained.orchard_bundle().unwrap().flags().cross_address_enabled());
    assert!(retained.ironwood_bundle().unwrap().flags().cross_address_enabled());
    for index in 0..2 {
        for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
            let previous = &maintained.transparent_bundle().unwrap().authorization.0[index];
            let input = TransparentInput::from_parts(maintained.transparent_bundle().unwrap(),
                SighashType::parse(kind).unwrap(), index, previous.script_pubkey(), previous.script_pubkey(), previous.value()).unwrap();
            assert_eq!(actual.transparent(index, kind).unwrap(),
                *signature_hash(&maintained, &SignableInput::Transparent(input), &parts).as_ref());
        }
        for change_script in [false, true] {
            let mut previous = prevouts();
            let old = &previous[index];
            let mut code = old.script_pubkey().0.0.clone();
            if change_script { code.push(0x51); }
            previous[index] = zcash_transparent::bundle::TxOut::new(
                zcash_protocol::value::Zatoshis::from_u64(u64::from(old.value()) + u64::from(!change_script)).unwrap(), script(&code));
            let changed = PostNu5SignatureHash::new(parse(&raw), previous).unwrap();
            assert_eq!((changed.effect_id(), changed.auth_digest()), (actual.effect_id(), actual.auth_digest()));
            assert_ne!(changed.shielded(), actual.shielded());
            for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                assert_eq!(changed.transparent(1, kind) == actual.transparent(1, kind), kind & 0x80 != 0 && index == 0);
            }
        }
    }
    let mut reversed = prevouts();
    reversed.swap(0, 1);
    assert_ne!(PostNu5SignatureHash::new(parse(&raw), reversed).unwrap().shielded(), actual.shielded());
    for count in [0, 1, 3] {
        let mut previous = prevouts();
        previous.resize(count, zcash_transparent::bundle::TxOut::new(zcash_protocol::value::Zatoshis::ZERO, script(&[])));
        assert!(matches!(PostNu5SignatureHash::new(parse(&raw), previous),
            Err(ziquid_proofs::zip244::PostNu5SighashError::PrevoutCountMismatch { expected: 2, actual }) if actual == count));
    }
}

fn coinbase(height: u32, version: TxVersion) -> Vec<u8> {
    let mut raw = if version == TxVersion::V4 {
        include_bytes!("fixtures/testnet-canopy-block-1115999.bin")[HEADER_BYTES + 1..].to_vec()
    } else { BODY[HEADER_BYTES + 1..1690].to_vec() };
    let prefix = [3, height as u8, (height >> 8) as u8, (height >> 16) as u8];
    if version == TxVersion::V4 {
        raw[46..50].copy_from_slice(&prefix);
        raw[242..246].copy_from_slice(&height.to_le_bytes());
    } else {
        raw[..4].copy_from_slice(&version.header().to_le_bytes());
        raw[4..8].copy_from_slice(&version.version_group_id().to_le_bytes());
        raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
        raw[16..20].copy_from_slice(&height.to_le_bytes());
        raw[58..62].copy_from_slice(&prefix);
        if version == TxVersion::V6 { raw.push(0); }
    }
    raw
}

// Independent trees over actual upstream leaves; these headers have no valid PoW.
fn body(transactions: &[&[u8]]) -> (Vec<u8>, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let typed: Vec<_> = transactions.iter().map(|raw| parse(raw)).collect();
    let mut effects: Vec<[u8; 32]> = typed.iter().map(|tx| tx.txid().into()).collect();
    let mut auth: Vec<[u8; 32]> = typed.iter().map(|tx| if tx.version() == TxVersion::V4 {
        [0xff; 32]
    } else { tx.auth_commitment().as_bytes().try_into().unwrap() }).collect();
    while effects.len() > 1 {
        if !effects.len().is_multiple_of(2) { effects.push(*effects.last().unwrap()); }
        effects = effects.as_chunks::<2>().0.iter().map(|pair| {
            let mut hash = Sha256::new();
            hash.update(pair[0]); hash.update(pair[1]);
            Sha256::digest(hash.finalize()).into()
        }).collect();
    }
    auth.resize(auth.len().next_power_of_two(), [0; 32]);
    while auth.len() > 1 {
        auth = auth.as_chunks::<2>().0.iter().map(|pair| {
            *blake2b_simd::Params::new().hash_length(32).personal(b"ZcashAuthDatHash")
                .to_state().update(&pair[0]).update(&pair[1]).finalize().as_bytes().first_chunk::<32>().unwrap()
        }).collect();
    }
    let mut raw = BODY[..HEADER_BYTES].to_vec();
    raw[36..68].copy_from_slice(&effects[0]);
    zcash_encoding::CompactSize::write(&mut raw, transactions.len()).unwrap();
    for transaction in transactions { raw.extend_from_slice(transaction); }
    (raw, auth[0])
}

#[test]
fn complete_v6_body_keeps_full_actual_payload_and_finite_height_policy() {
    use ziquid_proofs::post_nu5_body::{PostNu5Block, PostNu5Transaction};
    let mixed = mixed_wire();
    let mut absent_v5 = PURE[..24].to_vec();
    absent_v5[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    absent_v5.push(0);
    for height in [HEIGHT, HEIGHT + 1, 4_465_025] {
        for version in [TxVersion::V4, TxVersion::V5, TxVersion::V6] {
            let cb = coinbase(height, version);
            let (raw, auth) = body(&[&cb, &absent_v5, &mixed]);
            let parsed = PostNu5Block::parse(&raw, height).unwrap();
            assert_eq!(parsed.auth_data_root(), auth);
            assert_eq!(parsed.transactions()[0].version(), version);
            let PostNu5Transaction::V6(actual) = &parsed.transactions()[2] else { panic!("actual V6 missing"); };
            let mut canonical = Vec::new(); actual.write(&mut canonical).unwrap();
            assert_eq!(canonical, mixed);
            assert!(actual.sapling_bundle().is_some() && actual.orchard_bundle().is_some() && actual.ironwood_bundle().is_some());
            let PostNu5Transaction::V6(owned) = parsed.into_transactions().pop().unwrap() else { panic!("owned V6 missing"); };
            assert!(PostNu5SignatureHash::new(*owned, prevouts()).unwrap().transaction().ironwood_bundle().is_some());
        }
    }
    let cb = coinbase(4_465_026, TxVersion::V6);
    let (raw, _) = body(&[&cb]);
    for height in [4_465_026, u32::MAX] {
        assert_eq!(PostNu5Block::parse(&raw, height).unwrap_err(), ziquid_proofs::history::BodyError::WrongConsensusBranch);
    }
}

fn slots(raw: &[u8]) -> [usize; 2] {
    let tx = parse(raw);
    let mut prefix = Vec::new();
    tx.write_v6_header(&mut prefix).unwrap();
    tx.write_transparent(&mut prefix).unwrap();
    tx.write_v5_sapling(&mut prefix).unwrap();
    [prefix.len(), prefix.len() + PURE.len() - 24]
}

#[test]
fn v6_reanchoring_changes_only_full_auth_not_effects_or_signature_messages() {
    let raw = mixed_wire();
    let original = PostNu5SignatureHash::new(parse(&raw), prevouts()).unwrap();
    let slot = slots(&raw);
    for start in slot {
        let mut changed = raw.clone();
        let anchor = start + 1 + 2 * 820 + 1 + 8;
        changed[anchor..anchor + 32].copy_from_slice(&orchard::Anchor::empty_tree().to_bytes());
        let changed = PostNu5SignatureHash::new(parse(&changed), prevouts()).unwrap();
        assert_eq!(changed.effect_id(), original.effect_id());
        assert_eq!(changed.shielded(), original.shielded());
        assert_ne!(changed.auth_digest(), original.auth_digest());
        for index in 0..2 {
            for kind in [1, 2, 3, 0x81, 0x82, 0x83] {
                assert_eq!(changed.transparent(index, kind), original.transparent(index, kind));
            }
        }
    }
    // Sapling V6 spends carry their anchor only in the authorizing digest too.
    let tx = parse(&raw);
    assert!(!tx.sapling_bundle().unwrap().shielded_spends().is_empty());
    let changed = tx.into_data().map_bundles::<zcash_primitives::transaction::Authorized>(
        |bundle| bundle, |bundle| bundle.map(|bundle| {
            let spends = bundle.shielded_spends().iter().map(|spend| sapling_crypto::bundle::SpendDescription::from_parts(
                spend.cv().clone(), bls12_381::Scalar::from(7u64), *spend.nullifier(), *spend.rk(), *spend.zkproof(), *spend.spend_auth_sig(),
            )).collect();
            sapling_crypto::Bundle::from_parts(spends, bundle.shielded_outputs().to_vec(), *bundle.value_balance(), *bundle.authorization()).unwrap()
        }), |bundle| bundle,
    ).freeze().unwrap();
    let changed = PostNu5SignatureHash::new(changed, prevouts()).unwrap();
    assert_eq!((changed.effect_id(), changed.shielded()), (original.effect_id(), original.shielded()));
    assert_ne!(changed.auth_digest(), original.auth_digest());
}

#[test]
fn v6_both_complete_slots_reject_noncanonical_counts_proof_sizes_and_every_tail() {
    use ziquid_proofs::{history::BodyError, post_nu5_body::PostNu5Block};
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let raw = mixed_wire();
    let (complete, _) = body(&[&cb, &raw]);
    let start = HEADER_BYTES + 1 + cb.len();
    for slot in slots(&raw) {
        for length in [slot, slot + 1, slot + 1 + 31, slot + 1 + 2 * 820,
            slot + 1 + 2 * 820 + 1, slot + 1 + 2 * 820 + 8,
            slot + 1 + 2 * 820 + 41, slot + 1 + 2 * 820 + 44,
            slot + 1 + 2 * 820 + 44 + 7263,
            slot + 1 + 2 * 820 + 44 + 7264 + 63,
            slot + 1 + 2 * 820 + 44 + 7264 + 127,
            slot + 1 + 2 * 820 + 44 + 7264 + 128 + 63]
        {
            assert_eq!(PostNu5Block::parse(&complete[..start + length], HEIGHT).unwrap_err(), BodyError::MalformedBlock, "cut {length}");
        }
        for encoded in [vec![0xfd, 2, 0], vec![0xfe, 2, 0, 0, 0], vec![0xff, 2, 0, 0, 0, 0, 0, 0, 0]] {
            let mut bad = complete.clone();
            bad.splice(start + slot..start + slot + 1, encoded);
            assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::NoncanonicalEncoding);
        }
        let mut too_many = complete.clone();
        too_many.splice(start + slot..start + slot + 1, [0xfe, 0, 0, 1, 0]);
        assert_eq!(PostNu5Block::parse(&too_many, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
        let proof_length = start + slot + 1 + 2 * 820 + 41;
        for length in [0u16, 1, 4992, 7263, 7265] {
            let mut bad = complete.clone();
            if length < 253 { bad.splice(proof_length..proof_length + 3, [length as u8]); }
            else { bad[proof_length + 1..proof_length + 3].copy_from_slice(&length.to_le_bytes()); }
            assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
        }
        for key in [64, 128] {
            for bytes in [[0; 32], [0xff; 32]] {
                let mut bad = complete.clone();
                bad[start + slot + 1 + key..start + slot + 1 + key + 32].copy_from_slice(&bytes);
                assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
            }
        }
    }
    for offset in [20, 20 + 1 + 41 + 42] {
        let mut bad = complete.clone();
        let count = bad[start + offset];
        bad.splice(start + offset..start + offset + 1, [0xfd, count, 0]);
        assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::NoncanonicalEncoding);
    }
    for position in [HEADER_BYTES, start + 20] {
        let mut bad = complete.clone();
        bad.splice(position..position + 1, [0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert!(PostNu5Block::parse(&bad, HEIGHT).is_err());
    }
    let mut trailing = complete.clone(); trailing.push(0);
    assert_eq!(PostNu5Block::parse(&trailing, HEIGHT).unwrap_err(), BodyError::TrailingBytes);
    let mut too_large = complete.clone(); too_large.resize(2_000_001, 0);
    assert_eq!(PostNu5Block::parse(&too_large, HEIGHT).unwrap_err(), BodyError::BlockTooLarge);
    let (duplicates, _) = body(&[&cb, &raw, &raw]);
    assert_eq!(PostNu5Block::parse(&duplicates, HEIGHT).unwrap_err(), BodyError::DuplicateTransaction);
    for offset in [0, 4, 8] {
        let mut bad = complete.clone(); bad[start + offset] ^= 1;
        assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::WrongConsensusBranch);
    }
    let (not_first, _) = body(&[&raw, &cb]);
    assert_eq!(PostNu5Block::parse(&not_first, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
    let (second_cb, _) = body(&[&coinbase(HEIGHT, TxVersion::V4), &cb]);
    assert_eq!(PostNu5Block::parse(&second_cb, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
}

#[test]
fn nu63_pool_specific_flag_grammar_and_raw_modes_do_not_fall_back() {
    use ziquid_proofs::{history::BodyError, post_nu5_body::PostNu5Block, raw_v5::{RawV5, RawV5Error},
        orchard_original::{OriginalOrchardVerifier, FixedOrchardVerifier, PostNu63OrchardVerifier}};
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let raw = mixed_wire();
    let (complete, _) = body(&[&cb, &raw]);
    let start = HEADER_BYTES + 1 + cb.len();
    for (index, slot) in slots(&raw).into_iter().enumerate() {
        for flag in 0..=u8::MAX {
            let allowed = if index == 0 { matches!(flag, 1..=3) } else { matches!(flag, 1..=3 | 5..=7) };
            if allowed { continue; }
            let mut bad = complete.clone(); bad[start + slot + 1641] = flag;
            assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
        }
        for flag in if index == 0 { &[1, 2, 3][..] } else { &[1, 2, 3, 5, 6, 7][..] } {
            let mut changed = raw.clone(); changed[slot + 1641] = *flag;
            let (changed, _) = body(&[&cb, &changed]);
            assert!(PostNu5Block::parse(&changed, HEIGHT).is_ok());
        }
    }
    let mut raw = PURE.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    let original = RawV5::parse_exact(&raw).unwrap();
    let typed = PostNu5SignatureHash::new(parse(&raw), vec![]).unwrap();
    assert_eq!(original.effect_id(), typed.effect_id());
    assert_eq!(original.auth_digest(), typed.auth_digest());
    let descriptor = *original.orchard().unwrap();
    assert!(!descriptor.flags().cross_address_enabled());
    let hashes = original.into_signature_context(vec![]).unwrap();
    assert_eq!(hashes.shielded(), typed.shielded());
    assert_eq!(descriptor.verify_orchard(&OriginalOrchardVerifier::new(), &hashes.shielded()), Err(RawV5Error::OrchardVerifierModeMismatch));
    assert_eq!(descriptor.verify_orchard_fixed(&FixedOrchardVerifier::new(), &hashes.shielded()), Err(RawV5Error::OrchardVerifierModeMismatch));
    // This historical authorization is intentionally NOT re-signed.
    assert_eq!(descriptor.verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &hashes.shielded()), Err(RawV5Error::InvalidOrchardSpendAuth { index: 0 }));
    for branch in [BranchId::Nu5, BranchId::Nu6_2] {
        raw[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
        let original = RawV5::parse_exact(&raw).unwrap();
        assert_eq!(original.orchard().unwrap().verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &[0; 32]), Err(RawV5Error::OrchardVerifierModeMismatch));
    }
}

// Real deterministic RedPallas signatures over an independently dispatched V6
// message. The changed zero-cv statement deliberately has NO valid Halo2 proof;
// these are signature/rejection checks, not complete cryptographic positives.
fn signature_wire(pool: orchard::ValuePool, flags: u8) -> (Vec<u8>, usize) {
    use orchard::primitives::redpallas::{SigningKey, SpendAuth, VerificationKey};
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::{sighash::{SignableInput, signature_hash}, txid::TxIdDigester};
    let mut scalar = [0; 32]; scalar[0] = 1;
    let key = SigningKey::<SpendAuth>::try_from(scalar).unwrap();
    let point: [u8; 32] = VerificationKey::from(&key).into();
    let mut bundle = PURE[24..].to_vec();
    for index in 0..2 {
        let action = 1 + index * 820;
        bundle[action..action + 32].fill(0); // identity cv is consensus-encodable
        bundle[action + 64..action + 96].copy_from_slice(&point);
    }
    bundle[1641] = flags;
    bundle[1642..1650].fill(0); // vb=0 makes the binding verification key identity
    let binding_start = bundle.len() - 64;
    bundle[binding_start..].fill(0); // actual allowed identity binding equation
    let mut raw = v6_header(HEIGHT);
    raw.extend_from_slice(&[0; 4]);
    if pool == orchard::ValuePool::Ironwood { raw.push(0); }
    let start = raw.len();
    raw.extend_from_slice(&bundle);
    if pool == orchard::ValuePool::Orchard { raw.push(0); }
    let tx = oracle(&raw, vec![]);
    let message = *signature_hash(&tx, &SignableInput::Shielded, &tx.digest(TxIdDigester)).as_ref();
    let spend_sigs = start + 1641 + 41 + 3 + 7264;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x63; 32]);
    for index in 0..2 {
        let signature: [u8; 64] = (&key.sign(&mut rng, &message)).into();
        raw[spend_sigs + index * 64..spend_sigs + (index + 1) * 64].copy_from_slice(&signature);
    }
    (raw, start)
}

#[test]
fn typed_both_pool_routes_check_every_disabled_spend_and_binding_before_halo2() {
    use orchard::ValuePool;
    use ziquid_proofs::{orchard_original::PostNu63OrchardError,
        zip244::{PostNu63CryptoError, verify_post_nu63_crypto}};
    for pool in [ValuePool::Orchard, ValuePool::Ironwood] {
        let flags = if pool == ValuePool::Orchard { &[1, 2, 3][..] } else { &[1, 2, 3, 5, 6, 7][..] };
        for flags in flags {
            let (raw, start) = signature_wire(pool, *flags);
            let hashes = PostNu5SignatureHash::new(parse(&raw), vec![]).unwrap();
            assert_eq!(verify_post_nu63_crypto(&hashes),
                Err(PostNu63CryptoError::Proof { pool, error: PostNu63OrchardError::InvalidProof }));
            let sigs = start + 1641 + 41 + 3 + 7264;
            for index in 0..2 {
                let mut changed = raw.clone(); changed[sigs + index * 64 + 63] ^= 1;
                let hashes = PostNu5SignatureHash::new(parse(&changed), vec![]).unwrap();
                assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidSpendAuth { pool, index }));
            }
            let mut changed = raw.clone(); changed[sigs + 128 + 63] ^= 1;
            let hashes = PostNu5SignatureHash::new(parse(&changed), vec![]).unwrap();
            assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidBindingSignature { pool }));
        }
    }
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let hashes = PostNu5SignatureHash::new(parse(&cb), vec![]).unwrap();
    assert_eq!(verify_post_nu63_crypto(&hashes), Ok(()));
    assert!(matches!(PostNu5SignatureHash::new(parse(&cb), prevouts()),
        Err(ziquid_proofs::zip244::PostNu5SighashError::PrevoutCountMismatch { expected: 0, actual: 2 })));
}

#[test]
fn raw_nu63_uses_shared_actual_signature_builder_and_rejects_typed_projection_success() {
    use ziquid_proofs::{raw_v5::{RawV5, RawV5Error}, orchard_original::PostNu63OrchardVerifier,
        zip244::{PostNu63CryptoError, verify_post_nu63_crypto}};
    for flag in [1, 2, 3] {
        let (mut raw, _) = signature_wire(orchard::ValuePool::Orchard, flag);
        raw[..4].copy_from_slice(&TxVersion::V5.header().to_le_bytes());
        raw[4..8].copy_from_slice(&TxVersion::V5.version_group_id().to_le_bytes());
        assert_eq!(raw.pop(), Some(0)); // V5 has no Ironwood slot
        use orchard::primitives::redpallas::{SigningKey, SpendAuth};
        use rand_core::SeedableRng;
        use zcash_primitives::transaction::{sighash::{SignableInput, signature_hash}, txid::TxIdDigester};
        let tx = oracle(&raw, vec![]);
        let message = *signature_hash(&tx, &SignableInput::Shielded, &tx.digest(TxIdDigester)).as_ref();
        let mut scalar = [0; 32]; scalar[0] = 1;
        let key = SigningKey::<SpendAuth>::try_from(scalar).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x64; 32]);
        let sigs = 24 + 1641 + 41 + 3 + 7264;
        for index in 0..2 {
            let signature: [u8; 64] = (&key.sign(&mut rng, &message)).into();
            raw[sigs + index * 64..sigs + (index + 1) * 64].copy_from_slice(&signature);
        }
        let original = RawV5::parse_exact(&raw).unwrap();
        let orchard = *original.orchard().unwrap();
        let hashes = original.into_signature_context(vec![]).unwrap();
        assert_eq!(hashes.shielded(), message);
        assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::IncompleteTransaction));
        assert_eq!(orchard.verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &message), Err(RawV5Error::InvalidOrchardProof));
        for index in 0..2 {
            let mut changed = raw.clone(); changed[sigs + index * 64 + 63] ^= 1;
            let parsed = RawV5::parse_exact(&changed).unwrap();
            assert_eq!(parsed.orchard().unwrap().verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &message),
                Err(RawV5Error::InvalidOrchardSpendAuth { index }));
        }
        let mut changed = raw.clone(); changed[sigs + 128 + 63] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(parsed.orchard().unwrap().verify_orchard_post_nu63(&PostNu63OrchardVerifier::new(), &message),
            Err(RawV5Error::InvalidOrchardBindingSignature));
    }
}

fn blake(personal: &[u8; 16], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = blake2b_simd::Params::new().hash_length(32).personal(personal).to_state();
    for field in fields { hash.update(field); }
    *hash.finalize().as_bytes().first_chunk::<32>().unwrap()
}

// Independent byte-slice ZIP229 equations; never a production digest helper.
fn pool_digests(raw: &[u8], ironwood: bool) -> ([u8; 32], [u8; 32]) {
    let domains: [&[u8; 16]; 5] = if ironwood {
        [b"ZTxIdIrnActCH_v6", b"ZTxIdIrnActMH_v6", b"ZTxIdIrnActNH_v6", b"ZTxIdIronwd_H_v6", b"ZTxAuthIrnwdH_v6"]
    } else {
        [b"ZTxIdOrcActCHash", b"ZTxIdOrcActMHash", b"ZTxIdOrcActNHash", b"ZTxIdOrchardH_v6", b"ZTxAuthOrchaH_v6"]
    };
    assert_eq!(raw[0], 2);
    let mut compact = Vec::new();
    let mut memo = Vec::new();
    let mut noncompact = Vec::new();
    for action in raw[1..1641].as_chunks::<820>().0 {
        compact.extend_from_slice(&action[32..64]);
        compact.extend_from_slice(&action[96..212]);
        memo.extend_from_slice(&action[212..724]);
        noncompact.extend_from_slice(&action[..32]);
        noncompact.extend_from_slice(&action[64..96]);
        noncompact.extend_from_slice(&action[724..820]);
    }
    let compact = blake(domains[0], &[&compact]);
    let memo = blake(domains[1], &[&memo]);
    let noncompact = blake(domains[2], &[&noncompact]);
    let effect = blake(domains[3], &[&compact, &memo, &noncompact, &raw[1641..1650]]);
    assert_eq!(&raw[1682..1685], &[0xfd, 0x60, 0x1c]); // canonical 7264
    let auth = blake(domains[4], &[&raw[1685..], &raw[1650..1682]]);
    (effect, auth)
}

#[test]
fn exact_v6_roots_match_independent_domains_and_original_complete_auth_bytes() {
    let mut raw = v6_header(HEIGHT);
    raw.extend_from_slice(&[0; 4]);
    raw.extend_from_slice(&PURE[24..]);
    let ironwood_start = raw.len();
    raw.extend_from_slice(&PURE[24..]);
    raw[ironwood_start + 1641] |= 4;
    for present in [false, true] {
        let wire = if present { raw.clone() } else {
            let mut empty = v6_header(HEIGHT); empty.extend_from_slice(&[0; 6]); empty
        };
        let header = blake(b"ZTxIdHeadersHash", &[&wire[..20]]);
        let transparent = blake(b"ZTxIdTranspaHash", &[]);
        let sapling = blake(b"ZTxIdSaplingHash", &[]);
        let (orchard, orchard_auth, ironwood, ironwood_auth) = if present {
            let (orchard, orchard_auth) = pool_digests(&wire[24..ironwood_start], false);
            let (ironwood, ironwood_auth) = pool_digests(&wire[ironwood_start..], true);
            (orchard, orchard_auth, ironwood, ironwood_auth)
        } else {
            (blake(b"ZTxIdOrchardH_v6", &[]), blake(b"ZTxAuthOrchaH_v6", &[]),
                blake(b"ZTxIdIronwd_H_v6", &[]), blake(b"ZTxAuthIrnwdH_v6", &[]))
        };
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(b"ZcashTxHash_");
        personal[12..].copy_from_slice(&0x37a5_165bu32.to_le_bytes());
        let effect = blake(&personal, &[&header, &transparent, &sapling, &orchard, &ironwood]);
        personal[..12].copy_from_slice(b"ZTxAuthHash_");
        let transparent_auth = blake(b"ZTxAuthTransHash", &[]);
        let sapling_auth = blake(b"ZTxAuthSapliH_v6", &[]);
        let auth = blake(&personal, &[&transparent_auth, &sapling_auth, &orchard_auth, &ironwood_auth]);
        let actual = PostNu5SignatureHash::new(parse(&wire), vec![]).unwrap();
        assert_eq!((actual.effect_id(), actual.auth_digest(), actual.shielded()), (effect, auth, effect));
        let typed = parse(&wire);
        assert_eq!(effect, <[u8; 32]>::from(typed.txid()));
        assert_eq!(auth.as_slice(), typed.auth_commitment().as_bytes());
    }
}

#[test]
fn raw_nu63_restricted_framing_is_strict_without_rewriting_historical_bytes() {
    use ziquid_proofs::raw_v5::{RawV5, RawV5Error};
    let mut raw = PURE.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    for flag in 0..=u8::MAX {
        let mut changed = raw.clone(); changed[1665] = flag;
        if matches!(flag, 1..=3) {
            assert!(!RawV5::parse_exact(&changed).unwrap().orchard().unwrap().flags().cross_address_enabled());
        } else {
            assert_eq!(RawV5::parse_exact(&changed).unwrap_err(), RawV5Error::InvalidOrchardFlags);
        }
    }
    for index in 0..2 {
        for field in [64, 128] {
            let mut off_curve = [0; 32]; off_curve[0] = 2;
            for encoding in [[0; 32], off_curve, [0xff; 32]] {
                let mut changed = raw.clone();
                let offset = 25 + index * 820 + field;
                changed[offset..offset + 32].copy_from_slice(&encoding);
                let error = if field == 64 { RawV5Error::InvalidOrchardRandomizedKey { index } }
                    else { RawV5Error::InvalidOrchardEphemeralKey { index } };
                assert_eq!(RawV5::parse_exact(&changed).unwrap_err(), error);
            }
        }
    }
    for proof_length in [7263u16, 7265] {
        let mut changed = raw.clone();
        changed[1707..1709].copy_from_slice(&proof_length.to_le_bytes());
        if proof_length < 7264 { changed.remove(1709 + 7263); }
        else { changed.insert(1709 + 7264, 0x42); }
        changed[89..121].fill(0xff); // bad rk must not precede proof-size gate
        let mut input = changed.as_slice();
        assert_eq!(RawV5::parse(&mut input).unwrap_err(), RawV5Error::InvalidOrchardProofLength);
        assert_eq!(input, changed);
    }
    let actual = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(actual.original_bytes().as_ptr(), raw.as_ptr());
    let raw_orchard = actual.orchard().unwrap();
    assert_eq!(raw_orchard.actions().as_ptr(), raw[25..].as_ptr());
    assert_eq!(raw_orchard.proof().as_ptr(), raw[1709..].as_ptr());
    for offset in [1709, 1709 + 7263, 1709 + 7264, raw.len() - 1] {
        let mut changed = raw.clone(); changed[offset] ^= 1;
        let parsed = RawV5::parse_exact(&changed).unwrap();
        assert_eq!(parsed.effect_id(), actual.effect_id());
        assert_ne!(parsed.auth_digest(), actual.auth_digest());
        assert_eq!(parsed.original_bytes(), changed);
    }
    let mut joined = raw.clone(); joined.extend_from_slice(PURE);
    let mut input = joined.as_slice();
    assert_eq!(RawV5::parse(&mut input).unwrap().consensus_branch_id(), BranchId::Nu6_3);
    assert_eq!(input, PURE);
    assert_eq!(RawV5::parse(&mut input).unwrap().consensus_branch_id(), BranchId::Nu5);
    assert!(input.is_empty());
    assert_eq!(RawV5::parse_exact(&joined).unwrap_err(), RawV5Error::TrailingBytes);
}

#[test]
fn v6_transparent_hash_kind_single_and_script_framing_are_checked_before_hashing() {
    use ziquid_proofs::{history::BodyError, post_nu5_body::PostNu5Block, zip244::PostNu5SighashError};
    let raw = mixed_wire();
    let actual = PostNu5SignatureHash::new(parse(&raw), prevouts()).unwrap();
    for kind in 0..=u8::MAX {
        if matches!(kind, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
            assert!(actual.transparent(1, kind).is_ok());
        } else { assert_eq!(actual.transparent(1, kind), Err(PostNu5SighashError::InvalidHashType)); }
    }
    assert_eq!(actual.transparent(2, 1), Err(PostNu5SighashError::InputIndexOutOfRange));
    for output_count in [0, 1] {
        let changed = parse(&raw).into_data().map_bundles::<zcash_primitives::transaction::Authorized>(
            |bundle| bundle.map(|mut bundle| { bundle.vout.truncate(output_count); bundle }),
            |bundle| bundle, |bundle| bundle,
        ).freeze().unwrap();
        let changed = PostNu5SignatureHash::new(changed, prevouts()).unwrap();
        assert_eq!(changed.transparent(1, 3), Err(PostNu5SighashError::SingleOutputMissing));
        assert_eq!(changed.transparent(1, 0x83), Err(PostNu5SighashError::SingleOutputMissing));
        assert!(changed.transparent(1, 1).is_ok() && changed.transparent(1, 2).is_ok());
    }
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let (complete, _) = body(&[&cb, &raw]);
    let start = HEADER_BYTES + 1 + cb.len();
    for offset in [57, 98, 113, 123] { // both input and both output script lengths
        let mut bad = complete.clone();
        let length = bad[start + offset];
        bad.splice(start + offset..start + offset + 1, [0xfd, length, 0]);
        assert_eq!(PostNu5Block::parse(&bad, HEIGHT).unwrap_err(), BodyError::NoncanonicalEncoding);
        let mut truncated = complete.clone();
        truncated.splice(start + offset..start + offset + 1, [0xfe, 0x80, 0x84, 0x1e, 0]); // 2,000,000
        assert_eq!(PostNu5Block::parse(&truncated, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
    }
    let mut missing_empty_slot = coinbase(HEIGHT, TxVersion::V6);
    assert_eq!(missing_empty_slot.pop(), Some(0));
    let mut raw = BODY[..HEADER_BYTES].to_vec();
    raw.push(1); raw.extend_from_slice(&missing_empty_slot);
    assert_eq!(PostNu5Block::parse(&raw, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
}

#[test]
fn v6_sapling_counts_complete_tails_and_coinbase_height_remain_bounded() {
    use ziquid_proofs::{history::BodyError, post_nu5_body::PostNu5Block};
    let raw = mixed_wire();
    let tx = parse(&raw);
    let mut prefix = Vec::new(); tx.write_v6_header(&mut prefix).unwrap(); tx.write_transparent(&mut prefix).unwrap();
    let sapling_start = prefix.len();
    let bundle = tx.sapling_bundle().unwrap();
    let spends = bundle.shielded_spends().len();
    let outputs = bundle.shielded_outputs().len();
    assert!(spends > 0 && spends < 253 && outputs > 0 && outputs < 253);
    let output_count = sapling_start + 1 + spends * 96;
    let descriptions_end = output_count + 1 + outputs * 756;
    let proofs = descriptions_end + 8 + 32;
    let spend_sigs = proofs + spends * 192;
    let output_proofs = spend_sigs + spends * 64;
    let binding = output_proofs + outputs * 192;
    assert_eq!(binding + 64, slots(&raw)[0]);
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let (complete, _) = body(&[&cb, &raw]);
    let start = HEADER_BYTES + 1 + cb.len();
    for count in [sapling_start, output_count] {
        let mut noncanonical = complete.clone();
        let value = noncanonical[start + count];
        noncanonical.splice(start + count..start + count + 1, [0xfd, value, 0]);
        assert_eq!(PostNu5Block::parse(&noncanonical, HEIGHT).unwrap_err(), BodyError::NoncanonicalEncoding);
        let mut too_many = complete.clone();
        too_many.splice(start + count..start + count + 1, [0xfe, 0, 0, 1, 0]);
        assert_eq!(PostNu5Block::parse(&too_many, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
    }
    for cut in [sapling_start, output_count, descriptions_end + 7, proofs - 1,
        spend_sigs - 1, output_proofs - 1, binding - 1, binding + 63]
    {
        assert_eq!(PostNu5Block::parse(&complete[..start + cut], HEIGHT).unwrap_err(), BodyError::MalformedBlock);
    }
    for offset in [58, 16] {
        let mut changed_cb = cb.clone(); changed_cb[offset] ^= 1;
        let (changed, _) = body(&[&changed_cb, &raw]);
        if offset == 58 {
            assert_eq!(PostNu5Block::parse(&changed, HEIGHT).unwrap_err(), BodyError::MalformedBlock);
        } else {
            // Expiry is a contextual ledger rule, not asserted by body framing.
            assert!(PostNu5Block::parse(&changed, HEIGHT).is_ok());
        }
    }
}

#[test]
fn v5_nu63_keeps_original_zip244_anchor_effects_and_old_typed_eras_cannot_route_new_crypto() {
    use ziquid_proofs::{raw_v5::RawV5, zip244::{PostNu63CryptoError, verify_post_nu63_crypto}};
    let mut raw = PURE.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    let original = RawV5::parse_exact(&raw).unwrap().into_signature_context(vec![]).unwrap();
    raw[1665 + 9..1665 + 41].copy_from_slice(&orchard::Anchor::empty_tree().to_bytes());
    let changed = RawV5::parse_exact(&raw).unwrap().into_signature_context(vec![]).unwrap();
    assert_ne!(changed.effect_id(), original.effect_id());
    assert_ne!(changed.shielded(), original.shielded());
    assert_eq!(changed.auth_digest(), original.auth_digest());
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2] {
        raw[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
        let hashes = PostNu5SignatureHash::new(parse(&raw), vec![]).unwrap();
        assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::UnsupportedBranch));
    }
    // Complete typed V5 Nu6.3 is accepted as a route, unlike raw projection;
    // its unchanged historical signatures must fail, never fake success.
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    let hashes = PostNu5SignatureHash::new(parse(&raw), vec![]).unwrap();
    assert_eq!(verify_post_nu63_crypto(&hashes),
        Err(PostNu63CryptoError::InvalidSpendAuth { pool: orchard::ValuePool::Orchard, index: 0 }));
    assert!(!format!("{:?}", verify_post_nu63_crypto(&hashes).unwrap_err()).contains("255"));
}

#[test]
fn v6_complete_original_auth_root_includes_both_pools_every_signature_and_proof() {
    use ziquid_proofs::post_nu5_body::PostNu5Block;
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let raw = mixed_wire();
    let actual = PostNu5SignatureHash::new(parse(&raw), prevouts()).unwrap();
    let (baseline_body, baseline_auth) = body(&[&cb, &raw]);
    let baseline = PostNu5Block::parse(&baseline_body, HEIGHT).unwrap();
    assert_eq!(baseline.auth_data_root(), baseline_auth);
    for slot in slots(&raw) {
        let proof = slot + 1685;
        let spend_sigs = proof + 7264;
        for offset in [proof, proof + 7263, spend_sigs, spend_sigs + 64, spend_sigs + 128, spend_sigs + 191] {
            let mut changed = raw.clone(); changed[offset] ^= 1;
            let hashes = PostNu5SignatureHash::new(parse(&changed), prevouts()).unwrap();
            assert_eq!((hashes.effect_id(), hashes.shielded()), (actual.effect_id(), actual.shielded()));
            assert_ne!(hashes.auth_digest(), actual.auth_digest());
            let (changed_body, auth) = body(&[&cb, &changed]);
            let parsed = PostNu5Block::parse(&changed_body, HEIGHT).unwrap();
            assert_eq!(parsed.header().merkle_root, baseline.header().merkle_root);
            assert_eq!(parsed.auth_data_root(), auth);
            assert_ne!(parsed.auth_data_root(), baseline_auth);
        }
        for action in 0..2 {
            for field in [0, 32, 64, 96, 128] {
                let mut changed = raw.clone();
                let offset = slot + 1 + action * 820 + field;
                let other = slot + 1 + (1 - action) * 820 + field;
                changed[offset..offset + 32].copy_from_slice(&raw[other..other + 32]);
                let hashes = PostNu5SignatureHash::new(parse(&changed), prevouts()).unwrap();
                assert_ne!(hashes.effect_id(), actual.effect_id());
                assert_ne!(hashes.shielded(), actual.shielded());
                assert_eq!(hashes.auth_digest(), actual.auth_digest());
            }
        }
    }
}

#[test]
fn typed_nu63_rejects_all_disabled_flags_before_keys_and_checks_both_bundle_routes() {
    use orchard::ValuePool;
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use ziquid_proofs::zip244::{PostNu63CryptoError, verify_post_nu63_crypto};
    for pool in [ValuePool::Orchard, ValuePool::Ironwood] {
        let (raw, _) = signature_wire(pool, 0);
        let hashes = PostNu5SignatureHash::new(parse(&raw), vec![]).unwrap();
        assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidFlags { pool }));
        let old = parse(PURE).orchard_bundle().unwrap().clone();
        let transaction = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3, 0, HEIGHT.into(), None, None,
            (pool == ValuePool::Orchard).then(|| old.clone()),
            (pool == ValuePool::Ironwood).then_some(old),
        ).freeze().unwrap();
        let hashes = PostNu5SignatureHash::new(transaction, vec![]).unwrap();
        assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidBundleVersion { pool }));
    }
}

#[test]
fn nu63_v4_still_compares_original_wire_and_v6_cannot_backdate_its_branch() {
    use ziquid_proofs::{history::BodyError, post_nu5_body::PostNu5Block};
    let cb = coinbase(HEIGHT, TxVersion::V4);
    let (baseline, _) = body(&[&cb]);
    assert!(PostNu5Block::parse(&baseline, HEIGHT).is_ok());
    let mut normalized = baseline.clone();
    normalized[HEADER_BYTES + 1 + 246..HEADER_BYTES + 1 + 254].copy_from_slice(&1i64.to_le_bytes());
    assert_eq!(PostNu5Block::parse(&normalized, HEIGHT).unwrap_err(), BodyError::NoncanonicalEncoding);
    let cb = coinbase(HEIGHT, TxVersion::V6);
    let (raw, _) = body(&[&cb]);
    for height in [1_842_420, 2_976_000, 3_536_500, 4_052_000, HEIGHT - 1] {
        assert_eq!(PostNu5Block::parse(&raw, height).unwrap_err(), BodyError::WrongConsensusBranch);
    }
    let mixed = mixed_wire();
    let (raw, _) = body(&[&cb, &mixed]);
    let mut wrong_merkle = raw.clone(); wrong_merkle[36] ^= 1;
    assert_eq!(PostNu5Block::parse(&wrong_merkle, HEIGHT).unwrap_err(), BodyError::MerkleRootMismatch);
    let mut wrong_header = raw; wrong_header[140] ^= 1;
    assert_eq!(PostNu5Block::parse(&wrong_header, HEIGHT).unwrap_err(), BodyError::InvalidHeader);
}

#[test]
fn typed_v3_pool_tag_substitution_cannot_turn_a_shared_key_into_pool_authority() {
    use orchard::ValuePool;
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use ziquid_proofs::zip244::{PostNu63CryptoError, verify_post_nu63_crypto};
    // Restricted Ironwood and Orchard have identical cross-address constraints
    // and circuit generation, but different typed tags and commitment domains.
    for (source_pool, target_pool) in [(ValuePool::Orchard, ValuePool::Ironwood), (ValuePool::Ironwood, ValuePool::Orchard)] {
        let (raw, _) = signature_wire(source_pool, 3);
        let source = parse(&raw);
        let bundle = if source_pool == ValuePool::Orchard { source.orchard_bundle().unwrap() }
            else { source.ironwood_bundle().unwrap() }.clone();
        let tx = TransactionData::<Authorized>::from_parts_v6(BranchId::Nu6_3, 17, HEIGHT.into(), None, None,
            (target_pool == ValuePool::Orchard).then(|| bundle.clone()),
            (target_pool == ValuePool::Ironwood).then_some(bundle),
        ).freeze().unwrap();
        let hashes = PostNu5SignatureHash::new(tx, vec![]).unwrap();
        assert_eq!(verify_post_nu63_crypto(&hashes), Err(PostNu63CryptoError::InvalidBundleVersion { pool: target_pool }));
    }
}

#[test]
fn post_nu5_sapling_crypto_uses_actual_v6_message_without_discarding_original_proofs() {
    use ziquid_proofs::{sapling_crypto::SaplingCryptoError, zip244::verify_sapling_post_nu5_crypto};
    let raw = mixed_wire();
    let hashes = PostNu5SignatureHash::new(parse(&raw), prevouts()).unwrap();
    let retained = hashes.transaction().sapling_bundle().unwrap();
    assert_eq!(retained.shielded_spends().len(), 4);
    assert_eq!(verify_sapling_post_nu5_crypto(&hashes),
        Err(SaplingCryptoError::InvalidSpendAuthSignature { index: 0 }));
    let source = parse(include_bytes!("fixtures/nu5-mixed-testnet-1842421.bin"));
    let source = source.sapling_bundle().unwrap();
    for (actual, old) in retained.shielded_spends().iter().zip(source.shielded_spends()) {
        assert_eq!(actual.zkproof(), old.zkproof());
        assert_eq!(<[u8; 64]>::from(*actual.spend_auth_sig()), <[u8; 64]>::from(*old.spend_auth_sig()));
    }
    let output_wire: Vec<u8> = sapling_outputs::TRANSACTION_HEX.as_bytes().as_chunks::<2>().0.iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect();
    let output_source = parse(&output_wire);
    let old_outputs = output_source.sapling_bundle().unwrap().shielded_outputs();
    assert_eq!(retained.shielded_outputs().len(), old_outputs.len());
    for (actual, old) in retained.shielded_outputs().iter().zip(old_outputs) {
        assert_eq!(actual.zkproof(), old.zkproof());
    }
}

#[test]
fn raw_nu63_retains_negative_balance_for_ledger_policy_and_never_serializes_ironwood() {
    use ziquid_proofs::raw_v5::RawV5;
    let mut raw = PURE.to_vec();
    raw[8..12].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
    raw[1666..1674].copy_from_slice(&(-7i64).to_le_bytes());
    let parsed = RawV5::parse_exact(&raw).unwrap();
    assert_eq!(i64::from(parsed.orchard().unwrap().value_balance()), -7);
    assert_eq!(parsed.original_bytes(), raw);
    let hashes = parsed.into_signature_context(vec![]).unwrap();
    assert!(hashes.transaction().ironwood_bundle().is_none());
    assert_eq!(hashes.effect_id(), <[u8; 32]>::from(parse(&raw).txid()));
    let cb = coinbase(HEIGHT, TxVersion::V5);
    let mut cb_orchard = cb[..cb.len() - 1].to_vec();
    cb_orchard.extend_from_slice(&raw[24..]);
    // Orchard coinbase admission is ledger-owned, never smuggled into parsing.
    let parsed = RawV5::parse_exact(&cb_orchard).unwrap();
    assert!(parsed.transparent_bundle().unwrap().is_coinbase() && parsed.orchard().is_some());
}
