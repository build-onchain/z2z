//! Public generated tree/log fixtures only, not admitted rights or deployed state.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use primitive_types::U256;
use serde_json::{Value, json};
use ziquid_protocol::samechain::{Role, tree::{NoteInsertion, NoteTree}};
use super::support::{self, HistoryBlockFixture, hex, uint_word};

pub struct ExpectedNote {
    pub commitment: [u8; 32],
    pub insertion: NoteInsertion,
    pub ciphertext: Vec<u8>,
    pub block_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub transaction_index: u64,
    pub log_index: u64,
    pub manifest_index: u32,
    pub role: Role,
}

pub struct Scenario {
    pub blocks: Vec<HistoryBlockFixture>,
    pub notes: Vec<ExpectedNote>,
}

pub fn block_hash(number: u64) -> [u8; 32] {
    let mut hash = [0x60; 32];
    hash[24..].copy_from_slice(&number.to_be_bytes());
    hash
}

pub fn empty_block(number: u64, tree: &NoteTree) -> HistoryBlockFixture {
    let mut scope = support::scope();
    scope.block_hash = block_hash(number);
    HistoryBlockFixture {
        scope, number: U256::from(number), parent_hash: block_hash(number - 1),
        tree_id: tree.tree_id(), tree_count: tree.count(), tree_root: tree.root(),
        appended_logs: Vec::new(), nullifier_logs: Vec::new(),
        root_counts: BTreeMap::new(), spent: BTreeSet::new(),
    }
}

pub fn event_log(block: &HistoryBlockFixture, transaction_hash: [u8; 32],
    transaction_index: u64, log_index: u64, topic: &str, data: String) -> Value
{
    json!({
        "address":hex(&block.scope.expected.authority), "blockHash":hex(&block.scope.block_hash),
        "blockNumber":format!("0x{:x}", block.number), "removed":false,
        "transactionHash":hex(&transaction_hash), "transactionIndex":format!("0x{transaction_index:x}"),
        "logIndex":format!("0x{log_index:x}"), "topics":[topic], "data":data,
    })
}

pub fn append(block: &mut HistoryBlockFixture, tree: &mut NoteTree,
    commitment: [u8; 32], transaction_hash: [u8; 32],
    positions: (u64, u64, u32), role: Role, ciphertext: Vec<u8>) -> ExpectedNote
{
    let (transaction_index, log_index, manifest_index) = positions;
    let insertion = tree.append(commitment).unwrap();
    // Encode Solidity's words and dynamic tail here, not through the acquisition decoder.
    let mut data = [
        [0x11; 32], uint_word(u64::from(manifest_index)), uint_word(role as u64),
        uint_word(u64::from(insertion.tree_id)), uint_word(u64::from(insertion.index)),
        uint_word(insertion.count), insertion.root, commitment, [0xc7; 32],
        uint_word(1), uint_word(352), uint_word(ciphertext.len() as u64),
    ].concat();
    data.extend_from_slice(&ciphertext);
    data.resize(data.len() + (32 - ciphertext.len() % 32) % 32, 0);
    block.appended_logs.push(event_log(block, transaction_hash, transaction_index,
        log_index, support::note_appended_topic(), hex(&data)));
    block.tree_id = tree.tree_id();
    block.tree_count = tree.count();
    block.tree_root = tree.root();
    block.root_counts.insert((insertion.tree_id, insertion.root), insertion.count);
    ExpectedNote {
        commitment, insertion, ciphertext, block_hash: block.scope.block_hash,
        transaction_hash, transaction_index, log_index, manifest_index, role,
    }
}

pub fn consume(block: &mut HistoryBlockFixture, nullifier: [u8; 32],
    transaction_hash: [u8; 32], transaction_index: u64, log_index: u64)
{
    block.nullifier_logs.push(event_log(block, transaction_hash, transaction_index,
        log_index, support::nullifier_consumed_topic(), hex(&[[0x11; 32], nullifier].concat())));
    block.spent.insert(nullifier);
}

pub fn hash_label(number: u64) -> [u8; 32] {
    let mut label = [0x91; 32];
    label[24..].copy_from_slice(&number.to_be_bytes());
    label
}

impl Scenario {
    pub fn new() -> Self {
        let scope = support::scope();
        let mut tree = NoteTree::new(scope.expected.digest().unwrap(), 0).unwrap();
        let origin = empty_block(42, &tree);
        let mut first = empty_block(43, &tree);
        consume(&mut first, [0x55; 32], [0x22; 32], 0, 0);
        let a = append(&mut first, &mut tree, [0xb1; 32], [0x22; 32],
            (0, 1, 0), Role::A, vec![0xd1, 0xd2, 0xd3]);
        // The skipped manifest/log positions can be an intervening Fee/Exit event.
        let b = append(&mut first, &mut tree, [0xb2; 32], [0x22; 32],
            (0, 3, 2), Role::B, vec![0xe1; 65]);
        let mut empty = empty_block(44, &tree);
        empty.root_counts = first.root_counts.clone();
        empty.spent = first.spent.clone();
        let mut last = empty_block(45, &tree);
        last.root_counts = empty.root_counts.clone();
        last.spent = empty.spent.clone();
        consume(&mut last, [0x56; 32], [0x23; 32], 0, 0);
        let c = append(&mut last, &mut tree, [0xb3; 32], [0x23; 32],
            (0, 1, 5), Role::A, vec![0xf1; 32]);
        Self { blocks: vec![origin, first, empty, last], notes: vec![a, b, c] }
    }
}
