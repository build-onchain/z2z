//! Original testnet bodies from Zebra commit
//! e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291, `zebra-test/src/vectors/`.
//! Mutations below are structural counterexamples, never PoW, signature,
//! accepted-history, state-transition or settlement-validity evidence.
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

use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BranchId, TEST_NETWORK};
use ziquid_proofs::{
    history::{BodyError, ParsedBlockBody},
    post_nu5_body::{PostNu5Block, PostNu5Transaction},
    raw_v5::RawV5,
};

#[path = "fixtures/sprout-groth16-testnet-280003.rs"]
mod original_v4;

#[path = "fixtures/sapling-mainnet-419202.rs"]
mod original_sapling_v4;

const HEADER_BYTES: usize = 1487;
const HEIGHT: u32 = 1_842_467;
const ORIGINAL: &[u8; 10855] = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");
const PURE: &[u8; 9165] = include_bytes!("fixtures/orchard-pure-testnet-1842467.bin");
const SECOND_TRANSACTION: usize = 1690;

// SHA256 of the complete, unchanged upstream bodies, not just their headers.
const ORIGINALS: [(u32, &[u8], &str); 5] = [
    (1_842_421, include_bytes!("fixtures/testnet-nu5-block-1842421.bin"),
        "d0a3527c87773aaaa061320e5eb9ced29966cd1649e0eb0dce0b5365c41c70d1"),
    (1_842_432, include_bytes!("fixtures/testnet-nu5-block-1842432.bin"),
        "8439fb0635a6f2f438ecc090d60ed4740389018ab267818716012195bd82eb20"),
    (1_842_462, include_bytes!("fixtures/testnet-nu5-block-1842462.bin"),
        "e88fe4f157d343ae19960fb839ada42784ffb72a17c3ba7f84366b59019c7c03"),
    (HEIGHT, ORIGINAL,
        "1be0777aeea102d3ba65c1871b4f254e2b8fb0f7477658e0d3819323d8593a83"),
    (1_842_468, include_bytes!("fixtures/testnet-nu5-block-1842468.bin"),
        "78544791980941e172d0dd807b21f8fbe3c763ecd85bfa9d47d21a363400693e"),
];

fn digest(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

fn original_v4_bytes() -> Vec<u8> {
    hex_bytes(original_v4::TRANSACTION_HEX)
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn error(raw: &[u8], height: u32) -> BodyError {
    match PostNu5Block::parse(raw, height) {
        Ok(_) => panic!("malformed or out-of-profile full body accepted"),
        Err(error) => error,
    }
}

// Independent test oracle: literal SHA256d effect-tree equation; never the
// production history helper. Odd levels duplicate their final real effect.
fn effect_root(mut effects: Vec<[u8; 32]>) -> [u8; 32] {
    assert!(!effects.is_empty());
    while effects.len() > 1 {
        if !effects.len().is_multiple_of(2) {
            effects.push(*effects.last().unwrap());
        }
        effects = effects.as_chunks::<2>().0.iter().map(|pair| {
            let mut hash = Sha256::new();
            hash.update(pair[0]);
            hash.update(pair[1]);
            Sha256::digest(hash.finalize()).into()
        }).collect();
    }
    effects[0]
}

// Independent ZIP244 auth-tree equation, including pre-V5 FF leaves and
// absent zero leaves. Expected leaves always come from maintained parsing.
fn auth_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    assert!(!leaves.is_empty());
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    while leaves.len() > 1 {
        leaves = leaves.as_chunks::<2>().0.iter().map(|pair| {
            *blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"ZcashAuthDatHash")
                .to_state()
                .update(&pair[0])
                .update(&pair[1])
                .finalize()
                .as_bytes()
                .first_chunk::<32>()
                .unwrap()
        }).collect();
    }
    leaves[0]
}

fn maintained(raw: &[u8]) -> Transaction {
    let mut reader = raw;
    let transaction = Transaction::read(&mut reader, BranchId::Nu5).unwrap();
    assert!(reader.is_empty());
    transaction
}

fn effect(raw: &[u8]) -> [u8; 32] {
    if raw.starts_with(&TxVersion::V5.header().to_le_bytes()) {
        RawV5::parse_exact(raw).unwrap().effect_id()
    } else {
        maintained(raw).txid().into()
    }
}

fn coinbase() -> &'static [u8] {
    &ORIGINAL[HEADER_BYTES + 1..SECOND_TRANSACTION]
}

// Retain the genuine header fields and only replace its Merkle root/count
// when assembling mutation cases. Such headers are not claimed to satisfy PoW.
fn structural_body(transactions: &[&[u8]]) -> Vec<u8> {
    let mut raw = ORIGINAL[..HEADER_BYTES].to_vec();
    let root = effect_root(transactions.iter().map(|tx| effect(tx)).collect());
    raw[36..68].copy_from_slice(&root);
    CompactSize::write(&mut raw, transactions.len()).unwrap();
    for transaction in transactions {
        raw.extend_from_slice(transaction);
    }
    raw
}

#[test]
fn original_complete_nu5_body_derives_the_same_actual_effects_and_auth_tree() {
    for (height, raw, sha256) in ORIGINALS {
        assert_eq!(<[u8; 32]>::from(Sha256::digest(raw)), digest(sha256));
        let upstream = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
        let parsed = PostNu5Block::parse(raw, height).unwrap();
        assert_eq!(parsed.header().hash(), upstream.block().header().hash());
        assert_eq!(parsed.transactions().len(), upstream.transaction_count());
        assert_eq!(parsed.auth_data_root(), upstream.auth_data_root());
        let mut effects = Vec::new();
        let mut auth = Vec::new();
        let mut next_original_byte = HEADER_BYTES + 1;
        for (index, tx) in parsed.transactions().iter().enumerate() {
            let expected = upstream.transaction(index).unwrap();
            let context = &upstream.block().vtx()[index];
            assert_eq!(tx.effect_id(), expected.effect_id());
            assert_eq!(tx.auth_digest(), expected.auth_digest());
            assert_eq!(tx.version(), context.version());
            assert_eq!(tx.consensus_branch_id(), BranchId::Nu5);
            assert_eq!(tx.lock_time(), context.lock_time());
            assert_eq!(tx.expiry_height(), context.expiry_height());
            assert_eq!(tx.transparent_bundle().map(|b| (b.vin.len(), b.vout.len())),
                context.transparent_bundle().map(|b| (b.vin.len(), b.vout.len())));
            assert_eq!(tx.sapling_bundle().map(|b| (b.shielded_spends().len(), b.shielded_outputs().len())),
                context.sapling_bundle().map(|b| (b.shielded_spends().len(), b.shielded_outputs().len())));
            let PostNu5Transaction::V5(original) = tx else { panic!("genuine NU5 fixture unexpectedly changed format"); };
            assert_eq!(original.original_bytes().as_ptr(), raw[next_original_byte..].as_ptr());
            next_original_byte += original.consumed_bytes();
            effects.push(expected.effect_id());
            auth.push(expected.auth_digest().unwrap_or([0xff; 32]));
        }
        assert_eq!(next_original_byte, raw.len());
        assert_eq!(effect_root(effects), parsed.header().merkle_root);
        assert_eq!(auth_root(auth), parsed.auth_data_root());
        assert_eq!(parsed.into_transactions().len(), upstream.transaction_count());
    }
}

#[test]
fn finite_height_requires_exact_canonical_coinbase_prefix_but_keeps_original_tail() {
    for height in [0, 1_842_419, 3_536_500, u32::MAX] {
        assert_eq!(error(ORIGINAL, height), BodyError::WrongConsensusBranch);
    }
    for height in [HEIGHT - 1, HEIGHT + 1] {
        assert_eq!(error(ORIGINAL, height), BodyError::MalformedBlock);
    }
    // An unmodified NU5 body cannot choose NU6 rules by supplying a new height.
    assert_eq!(error(ORIGINAL, 2_976_000), BodyError::WrongConsensusBranch);
    // Original script starts [3, 0x23, 0x1d, 0x1c]; its arbitrary tail is legal.
    assert_eq!(&coinbase()[58..64], &[3, 0x23, 0x1d, 0x1c, 1, 1]);
    for tail in [&[][..], &[0x4c, 0xff, 0, 0x6a, 0x80][..]] {
        let mut changed = coinbase().to_vec();
        changed[57] = u8::try_from(4 + tail.len()).unwrap();
        changed.splice(62..64, tail.iter().copied());
        let raw = structural_body(&[&changed, PURE]);
        assert_eq!(PostNu5Block::parse(&raw, HEIGHT).unwrap().transactions().len(), 2);
    }
    for prefix in [vec![0x4c, 3, 0x23, 0x1d, 0x1c], vec![4, 0x23, 0x1d, 0x1c, 0], vec![3, 0x23, 0x1d, 0x9c], vec![3, 0x24, 0x1d, 0x1c]] {
        let mut changed = coinbase().to_vec();
        changed[57] = u8::try_from(prefix.len() + 2).unwrap();
        changed.splice(58..62, prefix);
        assert_eq!(error(&structural_body(&[&changed, PURE]), HEIGHT), BodyError::MalformedBlock);
    }
    // Both finite-era endpoints are selected by candidate height, not expiry.
    for (height, prefix) in [(1_842_420, [3, 0xf4, 0x1c, 0x1c]), (2_975_999, [3, 0xff, 0x68, 0x2d])] {
        let mut changed = coinbase().to_vec();
        changed[58..62].copy_from_slice(&prefix);
        let raw = structural_body(&[&changed, PURE]);
        PostNu5Block::parse(&raw, height).unwrap();
    }
}

#[test]
fn coinbase_must_be_first_and_only_and_every_later_null_input_is_rejected() {
    assert_eq!(error(&structural_body(&[PURE, coinbase()]), HEIGHT), BodyError::MalformedBlock);
    assert_eq!(error(&structural_body(&[coinbase(), coinbase()]), HEIGHT), BodyError::MalformedBlock);
    let mut missing = coinbase().to_vec();
    missing[21] = 1; // no longer the all-zero null outpoint
    assert_eq!(error(&structural_body(&[&missing, PURE]), HEIGHT), BodyError::MalformedBlock);

    // Genuine 50-input transparent/Sapling transaction, with only its second
    // outpoint replaced by NULL. It is not coinbase but must still be rejected.
    let original = ORIGINALS[1].1;
    let mut non_coinbase = original[SECOND_TRANSACTION..].to_vec();
    non_coinbase[169..201].fill(0);
    non_coinbase[201..205].fill(0xff);
    assert!(!RawV5::parse_exact(&non_coinbase).unwrap().transparent_bundle().unwrap().is_coinbase());
    assert_eq!(error(&structural_body(&[coinbase(), &non_coinbase]), HEIGHT), BodyError::MalformedBlock);
}

#[test]
fn header_count_and_transaction_framing_are_bounded_before_allocation() {
    for length in [0, 3, 139, 140, 142, HEADER_BYTES - 1, HEADER_BYTES, ORIGINAL.len() - 1] {
        assert_eq!(error(&ORIGINAL[..length], HEIGHT), BodyError::MalformedBlock, "length {length}");
    }
    let mut oversized = ORIGINAL.to_vec();
    oversized.resize(2_000_001, 0);
    assert_eq!(error(&oversized, HEIGHT), BodyError::BlockTooLarge);
    for encoded in [vec![0], vec![0xfd, 0x3f, 0x05], vec![0xfe, 0x40, 0x05, 0, 0], vec![0xfe, 0, 0, 0, 2], vec![0xff; 9]] {
        let mut raw = ORIGINAL.to_vec();
        raw.splice(140..143, encoded);
        assert_eq!(error(&raw, HEIGHT), BodyError::InvalidHeader);
    }
    for version in [0_i32, 3, -1, i32::MIN] {
        let mut raw = ORIGINAL.to_vec();
        raw[..4].copy_from_slice(&version.to_le_bytes());
        assert_eq!(error(&raw, HEIGHT), BodyError::InvalidHeader);
    }
    for count in [vec![0], vec![253, 253, 0], vec![0xfe, 0, 0, 0, 2]] {
        let mut raw = ORIGINAL[..HEADER_BYTES].to_vec();
        raw.extend_from_slice(&count);
        assert_eq!(error(&raw, HEIGHT), BodyError::MalformedBlock);
    }
    for count in [vec![0xfd, 2, 0], vec![0xfe, 2, 0, 0, 0], vec![0xff, 2, 0, 0, 0, 0, 0, 0, 0]] {
        let mut raw = ORIGINAL.to_vec();
        raw.splice(HEADER_BYTES..HEADER_BYTES + 1, count);
        assert_eq!(error(&raw, HEIGHT), BodyError::NoncanonicalEncoding);
    }
    let mut missing = ORIGINAL.to_vec();
    missing[HEADER_BYTES] = 3;
    assert_eq!(error(&missing, HEIGHT), BodyError::MalformedBlock);
    let mut omitted = ORIGINAL.to_vec();
    omitted[HEADER_BYTES] = 1;
    assert_eq!(error(&omitted, HEIGHT), BodyError::TrailingBytes);
    let mut trailing = ORIGINAL.to_vec();
    trailing.push(0);
    assert_eq!(error(&trailing, HEIGHT), BodyError::TrailingBytes);
    let mut bad_transaction_count = ORIGINAL.to_vec();
    bad_transaction_count.splice(SECOND_TRANSACTION + 20..SECOND_TRANSACTION + 21, [0xfd, 0, 0]);
    assert_eq!(error(&bad_transaction_count, HEIGHT), BodyError::NoncanonicalEncoding);
    let mut bad_transaction_resource = ORIGINAL.to_vec();
    bad_transaction_resource.splice(SECOND_TRANSACTION + 24..SECOND_TRANSACTION + 25, [0xfe, 0, 0, 1, 0]);
    assert_eq!(error(&bad_transaction_resource, HEIGHT), BodyError::MalformedBlock);
}

#[test]
fn every_transaction_version_group_and_embedded_branch_is_checked() {
    for start in [HEADER_BYTES + 1, SECOND_TRANSACTION] {
        for branch in [BranchId::Canopy, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_3] {
            let mut raw = ORIGINAL.to_vec();
            raw[start + 8..start + 12].copy_from_slice(&u32::from(branch).to_le_bytes());
            assert_eq!(error(&raw, HEIGHT), BodyError::WrongConsensusBranch);
        }
        for version in [TxVersion::Sprout(2), TxVersion::V3, TxVersion::V6] {
            let mut raw = ORIGINAL.to_vec();
            raw[start..start + 4].copy_from_slice(&version.header().to_le_bytes());
            raw[start + 4..start + 8].copy_from_slice(&version.version_group_id().to_le_bytes());
            assert_eq!(error(&raw, HEIGHT), BodyError::WrongConsensusBranch);
        }
        let mut wrong_group = ORIGINAL.to_vec();
        wrong_group[start + 4] ^= 1;
        assert_eq!(error(&wrong_group, HEIGHT), BodyError::WrongConsensusBranch);
        let mut missing_overwinter = ORIGINAL.to_vec();
        missing_overwinter[start + 3] &= 0x7f;
        assert_eq!(error(&missing_overwinter, HEIGHT), BodyError::WrongConsensusBranch);
    }
}

#[test]
fn ordered_real_effects_reject_duplicates_mutated_shape_and_header_mismatch() {
    for transactions in [vec![coinbase(), PURE, PURE], vec![coinbase(), PURE, PURE, PURE]] {
        let raw = structural_body(&transactions);
        assert_eq!(error(&raw, HEIGHT), BodyError::DuplicateTransaction);
    }
    let mut wrong_root = ORIGINAL.to_vec();
    wrong_root[36] ^= 1;
    assert_eq!(error(&wrong_root, HEIGHT), BodyError::MerkleRootMismatch);
    let truncated = &ORIGINAL[..SECOND_TRANSACTION];
    let mut incomplete = truncated.to_vec();
    incomplete[HEADER_BYTES] = 1;
    assert_eq!(error(&incomplete, HEIGHT), BodyError::MerkleRootMismatch);
    // An extra terminal duplicate can preserve a Bitcoin-style odd tree root;
    // the complete transaction list, not only its equation, must reject it.
    let mixed = &ORIGINALS[0].1[SECOND_TRANSACTION..];
    let odd = structural_body(&[coinbase(), PURE, mixed]);
    let ambiguous = structural_body(&[coinbase(), PURE, mixed, mixed]);
    assert_eq!(&odd[36..68], &ambiguous[36..68]);
    PostNu5Block::parse(&odd, HEIGHT).unwrap();
    assert_eq!(error(&ambiguous, HEIGHT), BodyError::DuplicateTransaction);
}

#[test]
fn opaque_identity_epk_is_preserved_while_maintained_action_parser_rejects_it() {
    let original = PostNu5Block::parse(ORIGINAL, HEIGHT).unwrap();
    let mut changed_transaction = PURE.to_vec();
    changed_transaction[25 + 128..25 + 160].fill(0);
    let mut upstream_reader = changed_transaction.as_slice();
    assert!(Transaction::read(&mut upstream_reader, BranchId::Nu5).is_err());
    let changed = structural_body(&[coinbase(), &changed_transaction]);
    assert!(ParsedBlockBody::parse(&changed, &TEST_NETWORK).is_err());
    let parsed = PostNu5Block::parse(&changed, HEIGHT).unwrap();
    assert_ne!(parsed.header().merkle_root, original.header().merkle_root);
    assert_ne!(parsed.transactions()[1].effect_id(), original.transactions()[1].effect_id());
    assert_eq!(parsed.transactions()[1].auth_digest(), original.transactions()[1].auth_digest());
    assert_eq!(parsed.auth_data_root(), original.auth_data_root());
    let PostNu5Transaction::V5(raw) = &parsed.transactions()[1] else { panic!("expected raw V5"); };
    assert_eq!(raw.original_bytes(), changed_transaction);
    assert_eq!(&raw.orchard().unwrap().actions()[128..160], &[0; 32]);
    assert_eq!(raw.original_bytes().as_ptr(), changed[SECOND_TRANSACTION..].as_ptr());
    // Only the structural parser ran: the synthetic Merkle root does not make
    // the changed effects' original signatures or the header's PoW valid.
}

#[test]
fn proof_suffix_keeps_effects_but_authenticates_every_original_authorizing_byte() {
    const PROOF_LENGTH: usize = 1706;
    const PROOF: usize = 1709;
    const SPEND_SIGS: usize = PROOF + 7264;
    let mut padded_transaction = PURE.to_vec();
    padded_transaction[PROOF_LENGTH + 1..PROOF].copy_from_slice(&7265_u16.to_le_bytes());
    padded_transaction.insert(SPEND_SIGS, 0x42);
    let mut padded = ORIGINAL[..SECOND_TRANSACTION].to_vec();
    padded.extend_from_slice(&padded_transaction);
    let original = PostNu5Block::parse(ORIGINAL, HEIGHT).unwrap();
    let parsed = PostNu5Block::parse(&padded, HEIGHT).unwrap();
    assert_eq!(parsed.header().hash(), original.header().hash());
    assert_eq!(parsed.transactions()[1].effect_id(), original.transactions()[1].effect_id());
    assert_ne!(parsed.transactions()[1].auth_digest(), original.transactions()[1].auth_digest());
    assert_ne!(parsed.auth_data_root(), original.auth_data_root());
    let maintained_padded = ParsedBlockBody::parse(&padded, &TEST_NETWORK).unwrap();
    assert_eq!(parsed.auth_data_root(), maintained_padded.auth_data_root());
    let PostNu5Transaction::V5(raw) = &parsed.transactions()[1] else { panic!("expected raw V5"); };
    assert_eq!(raw.original_bytes(), padded_transaction);
    assert_eq!(raw.orchard().unwrap().proof().last(), Some(&0x42));
    let transactions = parsed.into_transactions();
    let PostNu5Transaction::V5(raw) = transactions.into_iter().nth(1).unwrap() else { panic!("expected raw V5"); };
    let context = (*raw).into_signature_context(vec![]).unwrap();
    assert_eq!(context.effect_id(), original.transactions()[1].effect_id());
    assert_eq!(Some(context.auth_digest()), maintained_padded.transaction(1).unwrap().auth_digest());
    // No parent-history root was supplied: structural admission alone must not
    // silently assert that this changed auth root matches header commitments.
}

#[test]
fn maintained_v4_uses_candidate_nu5_context_and_ff_auth_leaves_with_zero_padding() {
    // Genuine pre-NU5 V4 coinbase bytes, mutated ONLY to exercise supported V4
    // structure in a synthetic NU5 body; not a valid cross-era block/signature.
    let source = include_bytes!("fixtures/testnet-canopy-block-1115999.bin");
    let mut v4 = source[HEADER_BYTES + 1..].to_vec();
    v4[46..50].copy_from_slice(&[3, 0x23, 0x1d, 0x1c]);
    let expected = maintained(&v4);
    let raw = structural_body(&[&v4, PURE]);
    let parsed = PostNu5Block::parse(&raw, HEIGHT).unwrap();
    let PostNu5Transaction::V4(actual) = &parsed.transactions()[0] else { panic!("expected actual owned V4"); };
    assert_eq!(actual.consensus_branch_id(), BranchId::Nu5);
    assert_eq!(actual.txid(), expected.txid());
    assert_eq!(parsed.transactions()[0].auth_digest(), None);
    let mut serialized = Vec::new();
    actual.write(&mut serialized).unwrap();
    assert_eq!(serialized, v4);
    let second_auth = *maintained(PURE).auth_commitment().as_bytes().first_chunk::<32>().unwrap();
    assert_eq!(parsed.auth_data_root(), auth_root(vec![[0xff; 32], second_auth]));

    let mixed_bytes = &ORIGINALS[0].1[SECOND_TRANSACTION..];
    let odd = structural_body(&[&v4, PURE, mixed_bytes]);
    let parsed_odd = PostNu5Block::parse(&odd, HEIGHT).unwrap();
    let third_auth = *maintained(mixed_bytes).auth_commitment().as_bytes().first_chunk::<32>().unwrap();
    let expected_root = auth_root(vec![[0xff; 32], second_auth, third_auth]);
    assert_eq!(parsed_odd.auth_data_root(), expected_root);
    assert_ne!(expected_root, auth_root(vec![[0xff; 32], second_auth, third_auth, [0xff; 32]]));

    let only_v4 = structural_body(&[&v4]);
    let single = PostNu5Block::parse(&only_v4, HEIGHT).unwrap();
    assert_eq!(single.auth_data_root(), [0xff; 32]);
    let PostNu5Transaction::V4(owned) = single.into_transactions().pop().unwrap() else { panic!("expected owned V4"); };
    assert_eq!((*owned).into_data().consensus_branch_id(), BranchId::Nu5);

    for offset in [8, 45] {
        let mut bad = v4.clone();
        let count = bad[offset];
        bad.splice(offset..offset + 1, [0xfd, count, 0]);
        let mut block = raw[..HEADER_BYTES + 1].to_vec();
        block.extend_from_slice(&bad);
        block.extend_from_slice(PURE);
        assert_eq!(error(&block, HEIGHT), BodyError::NoncanonicalEncoding);
    }

    // An empty Sapling bundle's nonzero wire value balance is discarded by
    // the maintained reader. Exact original roundtrip must catch that loss.
    let mut normalized = v4.clone();
    normalized[246..254].copy_from_slice(&1_i64.to_le_bytes());
    assert_eq!(error(&structural_body(&[&normalized, PURE]), HEIGHT), BodyError::NoncanonicalEncoding);

    for offset in [0, 4] {
        let mut wrong_format = raw.clone();
        wrong_format[HEADER_BYTES + 1 + offset] ^= 1;
        assert_eq!(error(&wrong_format, HEIGHT), BodyError::WrongConsensusBranch);
    }
}

#[test]
fn genuine_noncoinbase_v4_keeps_original_bytes_and_requires_no_branch_repair() {
    let original = original_v4_bytes();
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&original)),
        digest("5768fee2dff7c221e53d1fade8bc4a982de536df299a13fd4d62ed930d59321c"));
    let raw = structural_body(&[coinbase(), &original, PURE]);
    let parsed = PostNu5Block::parse(&raw, HEIGHT).unwrap();
    let PostNu5Transaction::V4(actual) = &parsed.transactions()[1] else { panic!("expected actual V4"); };
    assert_eq!(actual.consensus_branch_id(), BranchId::Nu5);
    assert!(actual.sprout_bundle().is_some());
    let mut serialized = Vec::new();
    actual.write(&mut serialized).unwrap();
    assert_eq!(serialized, original);
    assert_eq!(parsed.transactions()[1].auth_digest(), None);
    assert_eq!(parsed.transactions()[1].effect_id(), <[u8; 32]>::from(maintained(&original).txid()));
    let independent = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
    assert_eq!(parsed.auth_data_root(), independent.auth_data_root());

    let mut null = original.clone();
    null[9..41].fill(0);
    null[41..45].fill(0xff);
    assert_eq!(error(&structural_body(&[coinbase(), &null, PURE]), HEIGHT), BodyError::MalformedBlock);
    let mut null_coinbase_with_sprout = null;
    null_coinbase_with_sprout[46..50].copy_from_slice(&[3, 0x23, 0x1d, 0x1c]);
    assert_eq!(error(&structural_body(&[&null_coinbase_with_sprout, PURE]), HEIGHT), BodyError::MalformedBlock);

    // Same maintained V4 header with impossible input count remains bounded by
    // the supplied bytes; it cannot fabricate owned inputs or fill the block.
    let mut huge_count = original[..8].to_vec();
    huge_count.extend_from_slice(&[0xfe, 0, 0, 0, 2]);
    let mut raw = ORIGINAL[..SECOND_TRANSACTION].to_vec();
    raw.extend_from_slice(&huge_count);
    raw.extend_from_slice(PURE);
    assert_eq!(error(&raw, HEIGHT), BodyError::MalformedBlock);
}

#[test]
fn exact_maximum_body_keeps_full_proof_suffix_and_next_byte_is_rejected() {
    const PROOF_LENGTH: usize = 1706;
    const PROOF: usize = 1709;
    const SPEND_SIGS: usize = PROOF + 7264;
    // Extend only the genuine proof's suffix. Structural admission does not
    // run Halo2/signatures or claim this mutated block is accepted history.
    let suffix_length = 2_000_000 - SECOND_TRANSACTION - PROOF_LENGTH - 5 - 192;
    let mut raw = ORIGINAL[..SECOND_TRANSACTION + PROOF_LENGTH].to_vec();
    CompactSize::write(&mut raw, suffix_length).unwrap();
    raw.extend_from_slice(&PURE[PROOF..SPEND_SIGS]);
    raw.resize(SECOND_TRANSACTION + PROOF_LENGTH + 5 + suffix_length, 0x42);
    raw.extend_from_slice(&PURE[SPEND_SIGS..]);
    assert_eq!(raw.len(), 2_000_000);
    let parsed = PostNu5Block::parse(&raw, HEIGHT).unwrap();
    let PostNu5Transaction::V5(transaction) = &parsed.transactions()[1] else { panic!("expected raw V5"); };
    assert_eq!(transaction.consumed_bytes(), raw.len() - SECOND_TRANSACTION);
    assert_eq!(transaction.orchard().unwrap().proof().len(), suffix_length);
    assert_eq!(parsed.header().merkle_root, PostNu5Block::parse(ORIGINAL, HEIGHT).unwrap().header().merkle_root);
    raw.push(0);
    assert_eq!(error(&raw, HEIGHT), BodyError::BlockTooLarge);
}

#[test]
fn every_v4_nested_count_and_script_is_preflighted_before_maintained_allocation() {
    let source = include_bytes!("fixtures/testnet-canopy-block-1115999.bin");
    let mut v4 = source[HEADER_BYTES + 1..].to_vec();
    v4[46..50].copy_from_slice(&[3, 0x23, 0x1d, 0x1c]);
    // Offsets are decoded from this genuine unchanged V4 layout: vin count,
    // input script length, vout count, first output script length, Sapling
    // spend/output counts, then Groth JoinSplit count.
    for offset in [8, 45, 107, 116, 254, 255, 256] {
        let mut malformed = v4.clone();
        malformed.splice(offset..offset + 1, [0xfe, 0, 0, 0, 2]);
        let mut raw = ORIGINAL[..HEADER_BYTES].to_vec();
        raw.push(2);
        raw.extend_from_slice(&malformed);
        raw.extend_from_slice(PURE);
        assert_eq!(error(&raw, HEIGHT), BodyError::MalformedBlock, "oversized count at {offset}");

        let mut noncanonical = v4.clone();
        let count = noncanonical[offset];
        noncanonical.splice(offset..offset + 1, [0xfd, count, 0]);
        let mut raw = ORIGINAL[..HEADER_BYTES].to_vec();
        raw.push(2);
        raw.extend_from_slice(&noncanonical);
        raw.extend_from_slice(PURE);
        assert_eq!(error(&raw, HEIGHT), BodyError::NoncanonicalEncoding, "noncanonical count at {offset}");
    }
    // Genuine Groth JoinSplit with its final public key/signature truncated;
    // the framing pass must include authorization tails, not just descriptions.
    let joinsplit = original_v4_bytes();
    for removed in [1, 32, 64, 96, 1698] {
        let mut raw = ORIGINAL[..SECOND_TRANSACTION].to_vec();
        raw.extend_from_slice(&joinsplit[..joinsplit.len() - removed]);
        assert_eq!(error(&raw, HEIGHT), BodyError::MalformedBlock, "removed {removed}");
    }
}

#[test]
fn genuine_sapling_v4_frames_spends_outputs_and_final_binding_without_projection() {
    // Offline original fixture only, not a network operation or a claim that
    // this historical transaction's signatures authorize the NU5 context.
    let original = hex_bytes(original_sapling_v4::TRANSACTION_HEX);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&original)),
        digest("d081c5cf8f0d8db14f56adc1e8a259ed54f59353909c8b64402432fccaf1d59d"));
    let raw = structural_body(&[coinbase(), &original, PURE]);
    let parsed = PostNu5Block::parse(&raw, HEIGHT).unwrap();
    let PostNu5Transaction::V4(transaction) = &parsed.transactions()[1] else { panic!("expected actual V4"); };
    let sapling = transaction.sapling_bundle().unwrap();
    assert_eq!((sapling.shielded_spends().len(), sapling.shielded_outputs().len()), (1, 2));
    assert_eq!(transaction.consensus_branch_id(), BranchId::Nu5);
    let mut canonical = Vec::new();
    transaction.write(&mut canonical).unwrap();
    assert_eq!(canonical, original);
    assert_eq!(parsed.auth_data_root(), ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap().auth_data_root());

    for removed in [1, 64, 948, 384] {
        let mut raw = ORIGINAL[..SECOND_TRANSACTION].to_vec();
        raw.extend_from_slice(&original[..original.len() - removed]);
        assert_eq!(error(&raw, HEIGHT), BodyError::MalformedBlock, "removed {removed}");
    }
}

#[test]
fn both_formats_use_exact_candidate_branch_at_nu5_and_nu6_finite_boundaries() {
    // Synthetic bodies use genuine older bytes, not mined NU6 evidence or valid
    // cross-era authorizations. No proof or signature bytes are regenerated.
    let v4_source = include_bytes!("fixtures/testnet-canopy-block-1115999.bin");
    let joinsplit = original_v4_bytes();
    let sapling = hex_bytes(original_sapling_v4::TRANSACTION_HEX);
    for (height, branch) in [(1_842_420_u32, BranchId::Nu5), (2_975_999, BranchId::Nu5),
        (2_976_000, BranchId::Nu6), (3_395_999, BranchId::Nu6),
        (3_396_000, BranchId::Nu6), (3_536_499, BranchId::Nu6)] {
        for version in [TxVersion::V4, TxVersion::V5] {
            let mut cb = if version == TxVersion::V4 {
                v4_source[HEADER_BYTES + 1..].to_vec()
            } else { coinbase().to_vec() };
            let prefix = [3, height as u8, (height >> 8) as u8, (height >> 16) as u8];
            if version == TxVersion::V4 {
                cb[46..50].copy_from_slice(&prefix);
                cb[242..246].copy_from_slice(&height.to_le_bytes());
            } else {
                cb[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
                cb[16..20].copy_from_slice(&height.to_le_bytes());
                cb[58..62].copy_from_slice(&prefix);
            }
            let mut pure = PURE.to_vec();
            pure[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
            let transactions = [&cb[..], &joinsplit[..], &pure[..], &sapling[..]];
            let raw = structural_body(&transactions);
            let parsed = PostNu5Block::parse(&raw, height).unwrap();
            assert_eq!(parsed.transactions().len(), 4);
            assert_eq!(parsed.transactions()[0].version(), version);
            let mut effects = Vec::new();
            let mut auth = Vec::new();
            let mut offset = HEADER_BYTES + 1;
            for (actual, wire) in parsed.transactions().iter().zip(transactions) {
                let mut reader = wire;
                let expected = Transaction::read(&mut reader, branch).unwrap();
                assert!(reader.is_empty());
                assert_eq!(actual.consensus_branch_id(), branch);
                assert_eq!(actual.effect_id(), <[u8; 32]>::from(expected.txid()));
                let mut canonical = Vec::new();
                expected.write(&mut canonical).unwrap();
                assert_eq!(canonical, wire);
                effects.push(expected.txid().into());
                if actual.version() == TxVersion::V4 {
                    assert_eq!(actual.auth_digest(), None);
                    auth.push([0xff; 32]);
                    let PostNu5Transaction::V4(owned) = actual else { panic!("expected actual V4"); };
                    canonical.clear();
                    owned.write(&mut canonical).unwrap();
                    assert_eq!(canonical, wire);
                } else {
                    let expected_auth = *expected.auth_commitment().as_bytes().first_chunk::<32>().unwrap();
                    assert_eq!(actual.auth_digest(), Some(expected_auth));
                    auth.push(expected_auth);
                    let PostNu5Transaction::V5(borrowed) = actual else { panic!("expected original V5"); };
                    assert_eq!(borrowed.original_bytes().as_ptr(), raw[offset..].as_ptr());
                    assert_eq!(borrowed.original_bytes(), wire);
                }
                offset += wire.len();
            }
            assert_eq!(offset, raw.len());
            assert_eq!(parsed.header().merkle_root, effect_root(effects));
            assert_eq!(parsed.auth_data_root(), auth_root(auth));
            let owned = parsed.into_transactions();
            assert_eq!(owned.len(), 4);
            assert!(owned.iter().all(|tx| tx.consensus_branch_id() == branch));
            assert_eq!(error(&raw, 4_134_000), if version == TxVersion::V4 {
                BodyError::MalformedBlock // candidate branch is now live; old coinbase height is not
            } else { BodyError::WrongConsensusBranch });
        }
    }
}

#[test]
fn nu6_body_preserves_full_auth_suffix_opaque_epk_and_all_structural_rejections() {
    let height = 2_976_000_u32;
    let mut cb = coinbase().to_vec();
    cb[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    cb[16..20].copy_from_slice(&height.to_le_bytes());
    cb[58..62].copy_from_slice(&[3, 0, 0x69, 0x2d]);
    let mut pure = PURE.to_vec();
    pure[8..12].copy_from_slice(&u32::from(BranchId::Nu6).to_le_bytes());
    let v4 = original_v4_bytes();
    let raw = structural_body(&[&cb, &v4, &pure]);
    let baseline = PostNu5Block::parse(&raw, height).unwrap();
    for branch in [BranchId::Nu5, BranchId::Nu6_1, BranchId::Canopy] {
        for index in [0, 2] {
            let mut changed = if index == 0 { cb.clone() } else { pure.clone() };
            changed[8..12].copy_from_slice(&u32::from(branch).to_le_bytes());
            // Construct directly: unsupported branches must reject before a
            // test helper computes any production effect root from them.
            let mut bad = raw[..HEADER_BYTES + 1].to_vec();
            bad.extend_from_slice(if index == 0 { &changed } else { &cb });
            bad.extend_from_slice(&v4);
            bad.extend_from_slice(if index == 2 { &changed } else { &pure });
            assert_eq!(error(&bad, height), BodyError::WrongConsensusBranch);
        }
    }
    for offset in [0, 4] {
        let mut bad = raw.clone();
        bad[HEADER_BYTES + 1 + cb.len() + offset] ^= 1;
        assert_eq!(error(&bad, height), BodyError::WrongConsensusBranch);
    }
    let mut padded = pure.clone();
    padded[1707..1709].copy_from_slice(&7265_u16.to_le_bytes());
    padded.insert(1709 + 7264, 0x42);
    let padded_body = structural_body(&[&cb, &v4, &padded]);
    let parsed = PostNu5Block::parse(&padded_body, height).unwrap();
    assert_eq!(parsed.header().merkle_root, baseline.header().merkle_root);
    assert_eq!(parsed.header().hash(), baseline.header().hash());
    assert_ne!(parsed.auth_data_root(), baseline.auth_data_root());
    let PostNu5Transaction::V5(borrowed) = &parsed.transactions()[2] else { panic!("expected raw V5"); };
    assert_eq!(borrowed.original_bytes(), padded);
    assert_eq!(borrowed.orchard().unwrap().proof().last(), Some(&0x42));
    let effect = borrowed.effect_id();
    let auth = borrowed.auth_digest();
    let PostNu5Transaction::V5(owned) = parsed.into_transactions().pop().unwrap() else { panic!("expected owned V5"); };
    let hashes = (*owned).into_signature_context(vec![]).unwrap();
    assert_eq!(hashes.effect_id(), effect);
    assert_eq!(hashes.auth_digest(), auth);
    let mut opaque = pure.clone();
    opaque[25 + 128..25 + 160].fill(0xff);
    let opaque_body = structural_body(&[&cb, &v4, &opaque]);
    let parsed = PostNu5Block::parse(&opaque_body, height).unwrap();
    assert_ne!(parsed.header().merkle_root, baseline.header().merkle_root);
    assert_eq!(parsed.auth_data_root(), baseline.auth_data_root());
    for (offset, expected) in [(0, BodyError::InvalidHeader), (140, BodyError::InvalidHeader),
        (36, BodyError::MerkleRootMismatch)] {
        let mut bad = raw.clone();
        if offset == 0 { bad[..4].copy_from_slice(&3_i32.to_le_bytes()); } else { bad[offset] ^= 1; }
        assert_eq!(error(&bad, height), expected);
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(error(&trailing, height), BodyError::TrailingBytes);
    assert_eq!(error(&raw[..raw.len() - 1], height), BodyError::MalformedBlock);
    let mut noncanonical = raw.clone();
    noncanonical.splice(HEADER_BYTES..HEADER_BYTES + 1, [0xfd, 3, 0]);
    assert_eq!(error(&noncanonical, height), BodyError::NoncanonicalEncoding);
    assert_eq!(error(&structural_body(&[&cb, &v4, &pure, &pure]), height), BodyError::DuplicateTransaction);
    assert_eq!(error(&structural_body(&[&cb, &cb, &pure]), height), BodyError::MalformedBlock);
    // V4 empty-bundle normalization remains rejected under NU6 as under NU5.
    let source = include_bytes!("fixtures/testnet-canopy-block-1115999.bin");
    let mut normalized = source[HEADER_BYTES + 1..].to_vec();
    normalized[46..50].copy_from_slice(&[3, 0, 0x69, 0x2d]);
    normalized[246..254].copy_from_slice(&1_i64.to_le_bytes());
    assert_eq!(error(&structural_body(&[&normalized, &pure]), height), BodyError::NoncanonicalEncoding);
    for offset in [8, 45, 107, 116, 254, 255, 256] {
        let mut huge = source[HEADER_BYTES + 1..].to_vec();
        huge[46..50].copy_from_slice(&[3, 0, 0x69, 0x2d]);
        huge.splice(offset..offset + 1, [0xfe, 0, 0, 0, 2]);
        let mut bad = raw[..HEADER_BYTES].to_vec();
        bad.push(2);
        bad.extend_from_slice(&huge);
        bad.extend_from_slice(&pure);
        assert_eq!(error(&bad, height), BodyError::MalformedBlock, "V4 preflight {offset}");
    }
}
