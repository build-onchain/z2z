//! Generated structural fixtures, not mined blocks or source-validity evidence.
//! Literal digests were derived independently using Python hashlib and ZIP-244/229.

use zcash_primitives::{block::Block, transaction::Transaction};
use zcash_protocol::consensus::{BranchId, TEST_NETWORK};
use ziquid_proofs::history::{BodyError, ParsedBlockBody};

const HEIGHT: u32 = 4_134_000;
const HISTORY_ROOT: [u8; 32] = [0x42; 32];
const HEADER_LENGTH: usize = 1487;

fn digest(hex: &str) -> [u8; 32] {
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let value = |v: u8| match v {
            b'0'..=b'9' => v - b'0',
            b'a'..=b'f' => v - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        };
        *byte = value(pair[0]) * 16 + value(pair[1]);
    }
    assert_eq!(hex.len(), 64);
    result
}

fn transaction(tag: u8, coinbase: bool) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&0x8000_0006_u32.to_le_bytes());
    raw.extend_from_slice(&0xd884_b698_u32.to_le_bytes());
    raw.extend_from_slice(&0x37a5_165b_u32.to_le_bytes());
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.extend_from_slice(&HEIGHT.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(&[tag; 32]);
    raw.extend_from_slice(&(if coinbase { u32::MAX } else { 0 }).to_le_bytes());
    if coinbase {
        raw.push(4);
        raw.push(3);
        raw.extend_from_slice(&HEIGHT.to_le_bytes()[..3]);
    } else {
        raw.extend_from_slice(&[1, 0x51]);
    }
    raw.extend_from_slice(&u32::MAX.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(&1_u64.to_le_bytes());
    raw.extend_from_slice(&[1, 0x51]);
    raw.extend_from_slice(&[0; 4]); // empty Sapling spends/outputs, Orchard and Ironwood
    raw
}

fn roots(count: usize) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (effects, auth, commitment) = match count {
        1 => (
            "f37c8d165a7e9685c997c8ecb03560c1949f02d7178bffc99bdcea38ab522474",
            "266f841e532d586ef58af8e33ddccd9c37f084956c63722f918dbcb271842929",
            "a05ff730e4314c1f06125bfadc04bbadceca8682e7f549f7e247e8195f18cbcb",
        ),
        2 => (
            "2007877238552d3cb9d8a728620180ec765459064a32497c503d9c3cbbd8def4",
            "84efa0ea4b599df177f9f024c87e2744fbdd7ea8efb0fad744b17373ef9c8cea",
            "eb3dea83425b213ed1a334477258a4d805dc0e3b734356ac70cb416119ef29b0",
        ),
        3 => (
            "9a89d692822b0ffb17e665b52cfed94c9d0635be22ff401870c8296d4c391152",
            "d24b6062e31144c4208451681bdb3b08206a83e91ae2e68c3166357a90553572",
            "b4231a75b0103a30bf2a7b07a6762614029f3d7ded5406f804614e2088e2549d",
        ),
        4 => (
            "53ad14b941a0dace1e018d9488517dc05c176ce161e0f07d6d0b38381739b656",
            "8b39813e6abfbe2908f8fc39993f21e226c63ca815e35836893f92809271985d",
            "3a966064aa3abc7a30a9ffe3cdb66779a365ef7d28c931eabf47a097e749a51c",
        ),
        _ => panic!("no independent vector for count"),
    };
    (digest(effects), digest(auth), digest(commitment))
}

fn block_with(transactions: &[Vec<u8>], effects: [u8; 32], commitment: [u8; 32]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&4_u32.to_le_bytes());
    raw.extend_from_slice(&[0x11; 32]);
    raw.extend_from_slice(&effects);
    raw.extend_from_slice(&commitment);
    raw.extend_from_slice(&1_800_000_000_u32.to_le_bytes());
    raw.extend_from_slice(&0x1f07_ffff_u32.to_le_bytes());
    raw.extend_from_slice(&[0; 32]);
    raw.extend_from_slice(&[0xfd, 0x40, 0x05]);
    raw.extend_from_slice(&[0; 1344]); // deliberately not a valid PoW solution
    assert_eq!(raw.len(), HEADER_LENGTH);
    raw.push(transactions.len().try_into().unwrap());
    for tx in transactions {
        raw.extend_from_slice(tx);
    }
    raw
}

fn fixture(count: usize) -> Vec<u8> {
    let transactions = (0..count)
        .map(|index| transaction(index as u8, index == 0))
        .collect::<Vec<_>>();
    let (effects, _, commitment) = roots(count);
    block_with(&transactions, effects, commitment)
}

fn error(bytes: &[u8]) -> BodyError {
    match ParsedBlockBody::parse(bytes, &TEST_NETWORK) {
        Ok(_) => panic!("hostile structural body accepted"),
        Err(error) => error,
    }
}

#[test]
fn complete_parsed_body_derives_leaf_count_effect_auth_pairs_and_both_tree_shapes() {
    for count in 1..=4 {
        let raw = fixture(count);
        let body = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
        let (_, expected_auth, _) = roots(count);
        assert_eq!(body.transaction_count(), count);
        assert_eq!(body.auth_data_root(), expected_auth);
        assert_eq!(body.transaction(0).unwrap().effect_id(), roots(1).0);
        assert_eq!(
            body.transaction(0).unwrap().auth_digest(),
            Some(digest(
                "266f841e532d586ef58af8e33ddccd9c37f084956c63722f918dbcb271842929"
            )),
        );
        assert!(body.transaction(count).is_none());
        body.check_post_nu5_commitment_equation(&HISTORY_ROOT)
            .unwrap();
    }
}

#[test]
fn same_effect_substituted_authorization_cannot_match_header_commitment() {
    let mut raw = fixture(3);
    // Change only the second transaction's transparent scriptSig, excluded from v6 txid.
    raw[HEADER_LENGTH + 1 + transaction(0, true).len() + 58] = 0x52;
    let body = ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
    assert_eq!(
        body.transaction(1).unwrap().effect_id(),
        digest("4c32bdfd5b805ff19ed0ccf40e1db57694b1660b03ba59397e94765cb375e168"),
    );
    assert_ne!(body.auth_data_root(), roots(3).1);
    assert_eq!(
        body.check_post_nu5_commitment_equation(&HISTORY_ROOT),
        Err(BodyError::BlockCommitmentMismatch),
    );
}

#[test]
fn selected_transaction_body_is_compared_by_effect_and_authorization_not_tx_equality() {
    let body = ParsedBlockBody::parse(&fixture(3), &TEST_NETWORK).unwrap();
    let exact = transaction(1, false);
    body.check_selected_transaction(1, &exact).unwrap();
    let mut substituted_auth = exact.clone();
    substituted_auth[58] = 0x52;
    // Upstream Transaction::PartialEq compares txid only, so it cannot guard this boundary.
    let lhs = Transaction::read(exact.as_slice(), BranchId::Nu6_3).unwrap();
    let rhs = Transaction::read(substituted_auth.as_slice(), BranchId::Nu6_3).unwrap();
    assert_eq!(lhs.txid(), rhs.txid());
    assert_eq!(
        body.check_selected_transaction(1, &substituted_auth),
        Err(BodyError::SelectedTransactionMismatch),
    );
    assert_eq!(
        body.check_selected_transaction(2, &exact),
        Err(BodyError::SelectedTransactionMismatch),
    );
    assert_eq!(
        body.check_selected_transaction(3, &exact),
        Err(BodyError::TransactionIndexOutOfBounds),
    );
    let mut suffix = exact;
    suffix.push(0);
    assert_eq!(
        body.check_selected_transaction(1, &suffix),
        Err(BodyError::TrailingBytes),
    );
}

#[test]
fn header_root_or_internal_node_cannot_be_reinterpreted_as_transaction_body() {
    let mut raw = fixture(3);
    raw.truncate(HEADER_LENGTH);
    raw.push(1);
    raw.extend_from_slice(&roots(3).0);
    assert_eq!(error(&raw), BodyError::MalformedBlock);
    let mut internal_node = fixture(3);
    internal_node.truncate(HEADER_LENGTH);
    internal_node.push(1);
    internal_node.extend_from_slice(&roots(2).0);
    assert_eq!(error(&internal_node), BodyError::MalformedBlock);
}

#[test]
fn omitted_complete_transaction_or_invented_count_cannot_match_full_body() {
    let mut raw = fixture(3);
    raw[HEADER_LENGTH] = 2;
    assert_eq!(error(&raw), BodyError::TrailingBytes);
    raw.truncate(raw.len() - transaction(2, false).len());
    assert_eq!(error(&raw), BodyError::MerkleRootMismatch);
    let mut inflated = fixture(3);
    inflated[HEADER_LENGTH] = 4;
    assert_eq!(error(&inflated), BodyError::MalformedBlock);
    let mut truncated_auth = fixture(3);
    truncated_auth.pop();
    assert_eq!(error(&truncated_auth), BodyError::MalformedBlock);
}

#[test]
fn duplicate_last_leaf_is_rejected_even_when_it_preserves_the_effect_root() {
    let mut transactions = (0..3)
        .map(|index| transaction(index, index == 0))
        .collect::<Vec<_>>();
    transactions.push(transactions[2].clone());
    let raw = block_with(&transactions, roots(3).0, roots(3).2);
    assert_eq!(error(&raw), BodyError::DuplicateTransaction);
}

#[test]
fn canonical_encoding_and_complete_header_structure_are_required() {
    let mut noncanonical_count = fixture(3);
    noncanonical_count.splice(HEADER_LENGTH..HEADER_LENGTH + 1, [0xfd, 3, 0]);
    assert_eq!(error(&noncanonical_count), BodyError::MalformedBlock);
    let mut appended = fixture(3);
    appended.extend_from_slice(&[0; 32]);
    assert_eq!(error(&appended), BodyError::TrailingBytes);
    let mut invalid_version = fixture(3);
    invalid_version[..4].copy_from_slice(&3_u32.to_le_bytes());
    assert_eq!(error(&invalid_version), BodyError::InvalidHeader);
    let mut short_solution = fixture(3);
    short_solution.splice(140..HEADER_LENGTH, [1, 0]);
    assert_eq!(error(&short_solution), BodyError::InvalidHeader);
    let oversized = vec![0; 2_000_001];
    assert_eq!(error(&oversized), BodyError::BlockTooLarge);
}

#[test]
fn noncoinbase_wrong_branch_is_rejected_even_with_correct_framing() {
    let mut raw = fixture(3);
    let offset = HEADER_LENGTH + 1 + transaction(0, true).len() + 8;
    raw[offset..offset + 4].copy_from_slice(&0x5437_f330_u32.to_le_bytes());
    assert_eq!(error(&raw), BodyError::WrongConsensusBranch);
}

#[test]
fn caller_checkpoint_state_is_not_accepted_as_block_body_or_history_proof() {
    let snapshot = [0x42; 32];
    assert_eq!(error(&snapshot), BodyError::MalformedBlock);
    let body = ParsedBlockBody::parse(&fixture(3), &TEST_NETWORK).unwrap();
    assert_eq!(
        body.check_post_nu5_commitment_equation(&[0x43; 32]),
        Err(BodyError::BlockCommitmentMismatch),
    );
    // The matching equation uses a generated, unauthenticated history root. It does NOT
    // establish bootstrap validity: this type has no history/finality/settlement conversion.
    body.check_post_nu5_commitment_equation(&HISTORY_ROOT)
        .unwrap();
}

#[test]
fn invalid_pow_is_explicitly_outside_body_structure_relation() {
    let raw = fixture(3);
    let upstream = Block::read(raw.as_slice(), &TEST_NETWORK).unwrap();
    assert!(
        zcash_primitives::block::equihash::is_valid_solution(
            200,
            9,
            &raw[..108],
            &upstream.header().nonce,
            &upstream.header().solution,
        )
        .is_err()
    );
    // Deliberately proves the limit: a structural body is NOT a fully-valid block.
    ParsedBlockBody::parse(&raw, &TEST_NETWORK).unwrap();
}
