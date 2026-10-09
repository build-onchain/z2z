//! Parser-derived public observation coherence, never proof/finality/funded recovery.
use primitive_types::U256;
use serde_json::json;
use ziquid_chains::samechain::{
    history::{HistoryError, PublicHistory},
    inspection::{AuthorityObservation, InputState, InspectionPacket, SamechainInspectionClient},
};
use ziquid_protocol::samechain::{Role, tree::{NoteTree, root_from_path}};

#[path = "support/samechain_inspection.rs"]
mod support;
#[path = "support/samechain_history.rs"]
mod history_support;
use history_support::{Scenario, append, block_hash, consume, empty_block, hash_label};
use support::{Fixture, HistoryBlockFixture, hex};

async fn acquire(fixture: &Fixture, block: &HistoryBlockFixture) -> AuthorityObservation {
    SamechainInspectionClient::new(fixture.endpoint(), true).unwrap()
        .inspect(&block.scope, None).await.unwrap()
}

async fn initial(scenario: &Scenario) -> PublicHistory {
    let origin = &scenario.blocks[0];
    let fixture = Fixture::with_history(vec![origin.clone()]);
    let mut history = PublicHistory::new(origin.scope, origin.number).unwrap();
    history.ingest(origin.scope.block_hash, acquire(&fixture, origin).await).unwrap();
    history
}

fn snapshot(history: &PublicHistory) -> String {
    // Explicit caller retrieval clones are permitted; ingestion must never clone growing history.
    format!("{:?}|{:?}|{:?}|{:?}|{:?}|{:?}", history.latest_block(), history.tree_state(),
        history.block_count(), history.ciphertext_bytes(),
        history.notes().collect::<Vec<_>>(), history.nullifiers().collect::<Vec<_>>())
}

#[tokio::test]
async fn replays_adjacent_blocks_including_empty_with_exact_paths_ciphertexts_and_observed_nullifiers() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks.clone());
    let mut history = PublicHistory::new(scenario.blocks[0].scope, U256::from(42)).unwrap();
    assert_eq!(history.latest_block(), None);
    for block in &scenario.blocks {
        let observation = acquire(&fixture, block).await;
        assert_eq!(observation.parent_hash(), block.parent_hash);
        history.ingest(block.scope.block_hash, observation).unwrap();
    }
    assert_eq!(history.block_count(), 4);
    let latest = history.latest_block().unwrap();
    assert_eq!((latest.number, latest.hash, latest.parent_hash),
        (U256::from(45), block_hash(45), block_hash(44)));
    assert_eq!(history.tree_state(), (0, 3, scenario.notes[2].insertion.root));
    assert_eq!(history.note_count(), 3);
    assert_eq!(history.nullifier_count(), 2);
    assert_eq!(history.ciphertext_bytes(), 100);
    for expected in &scenario.notes {
        let retained = history.note(&expected.commitment).unwrap();
        assert_eq!(retained.block.hash, expected.block_hash);
        assert_eq!(retained.note.commitment, expected.commitment);
        assert_eq!(retained.note.ciphertext, expected.ciphertext);
        assert_eq!(retained.note.recovery_key_commitment, [0xc7; 32]);
        assert_eq!(retained.note.ciphertext_version, 1);
        assert_eq!(retained.note.manifest_index, expected.manifest_index);
        assert_eq!(retained.note.role, expected.role);
        assert_eq!(retained.note.occurrence.transaction_hash, expected.transaction_hash);
        assert_eq!(retained.note.occurrence.transaction_index, expected.transaction_index);
        assert_eq!(retained.note.occurrence.log_index, expected.log_index);
        assert_eq!(retained.insertion, expected.insertion);
        assert_eq!(root_from_path(&scenario.blocks[0].scope.expected.digest().unwrap(),
            0, expected.insertion.index, &expected.commitment, &retained.insertion.siblings),
            expected.insertion.root);
        assert_eq!(history.root_count(0, expected.insertion.root), expected.insertion.count);
    }
    assert_eq!(history.root_count(0, scenario.blocks[0].tree_root), 0); // Empty root is not admitted.
    assert_eq!(history.root_count(7, [1; 32]), 0);
    assert!(history.observed_spent(&[0x55; 32]));
    assert!(history.observed_spent(&[0x56; 32]));
    assert!(!history.observed_spent(&[0x57; 32]));
    let consumed = history.observed_nullifier(&[0x55; 32]).unwrap();
    assert_eq!(consumed.block.hash, block_hash(43));
    assert_eq!(consumed.event.packet_digest, [0x11; 32]);
    assert_eq!(consumed.event.occurrence.transaction_hash, [0x22; 32]);
    assert_eq!((consumed.event.occurrence.transaction_index, consumed.event.occurrence.log_index), (0, 0));
    assert_eq!(history.source_scope(), "TRUSTED_NODE_AT_SELECTED_BLOCK");
    assert_eq!(history.initial_boundary_trust(), "TRUSTED_PROVIDER_INITIAL_EMPTY_BOUNDARY");
    assert_eq!(history.log_completeness_trust(), "TRUSTED_PROVIDER_LOG_COMPLETENESS");
    let mut input = InputState { tree_id:0, index:0, root:scenario.notes[0].insertion.root,
        nullifier:[0x55; 32], reported_root_count:1, reported_spent:true };
    history.check_input_state(&input).unwrap();
    input.reported_spent = false;
    assert_eq!(history.check_input_state(&input), Err(HistoryError::InputMismatch));
    input.reported_spent = true;
    input.reported_root_count = 2;
    assert_eq!(history.check_input_state(&input), Err(HistoryError::InputMismatch));
    input.root = [0x88; 32];
    input.reported_root_count = 0;
    history.check_input_state(&input).unwrap();
}

#[tokio::test]
async fn successful_ingestion_moves_ciphertext_and_rejected_block_can_be_reacquired_correctly() {
    let scenario = Scenario::new();
    let mut history = initial(&scenario).await;
    let mut bad_block = scenario.blocks[1].clone();
    bad_block.tree_root[0] ^= 1;
    let bad = Fixture::with_history(vec![bad_block.clone()]);
    assert_eq!(history.ingest(block_hash(43), acquire(&bad, &bad_block).await), Err(HistoryError::TreeMismatch));
    let fixture = Fixture::with_history(vec![scenario.blocks[1].clone()]);
    let observation = acquire(&fixture, &scenario.blocks[1]).await;
    let original_payload = observation.appended_notes()[0].ciphertext.as_ptr();
    history.ingest(block_hash(43), observation).unwrap();
    assert_eq!(history.note(&[0xb1; 32]).unwrap().note.ciphertext.as_ptr(), original_payload);
    assert_eq!(history.block_count(), 2);
    assert!(history.observed_spent(&[0x55; 32]));
}

#[tokio::test]
async fn reordered_same_block_append_stream_is_rejected_by_actual_acquisition() {
    let scenario = Scenario::new();
    let mut block = scenario.blocks[1].clone();
    block.appended_logs.reverse();
    let fixture = Fixture::with_history(vec![block.clone()]);
    let mut history = initial(&scenario).await;
    let before = snapshot(&history);
    let error = SamechainInspectionClient::new(fixture.endpoint(), true).unwrap()
        .inspect(&block.scope, None).await.unwrap_err();
    assert_eq!(error, ziquid_chains::samechain::inspection::InspectionError::MalformedResponse);
    assert_eq!(snapshot(&history), before);
    let fixture = Fixture::with_history(vec![scenario.blocks[1].clone()]);
    history.ingest(block_hash(43), acquire(&fixture, &scenario.blocks[1]).await).unwrap();
}

#[tokio::test]
async fn only_exact_selected_initial_empty_tree_zero_without_notes_or_nullifiers_can_start_history() {
    let scenario = Scenario::new();
    for fault in 0..7 {
        let mut origin = scenario.blocks[0].clone();
        match fault {
            0 => origin.number += U256::one(),
            1 => origin.tree_id = 1,
            2 => origin.tree_count = 1,
            3 => origin.tree_root = [0x88; 32],
            4 => origin.appended_logs = scenario.blocks[1].appended_logs.clone(),
            5 => consume(&mut origin, [0x55; 32], [0x22; 32], 0, 0),
            6 => origin.scope.policy_id[0] ^= 1,
            _ => unreachable!(),
        }
        if fault == 4 {
            for log in &mut origin.appended_logs {
                log["blockHash"] = json!(hex(&origin.scope.block_hash));
                log["blockNumber"] = json!("0x2a");
            }
        }
        let fixture = Fixture::with_history(vec![origin.clone()]);
        let mut history = PublicHistory::new(scenario.blocks[0].scope, U256::from(42)).unwrap();
        let before = snapshot(&history);
        assert!(history.ingest(scenario.blocks[0].scope.block_hash,
            acquire(&fixture, &origin).await).is_err(), "origin fault {fault}");
        assert_eq!(snapshot(&history), before);
    }
    let fixture = Fixture::with_history(vec![scenario.blocks[0].clone()]);
    let mut history = PublicHistory::new(scenario.blocks[0].scope, U256::from(42)).unwrap();
    assert_eq!(history.ingest([0x77; 32], acquire(&fixture, &scenario.blocks[0]).await),
        Err(HistoryError::WrongBlock));
    let mut bad_scope = scenario.blocks[0].scope;
    bad_scope.block_hash = [0; 32];
    assert_eq!(PublicHistory::new(bad_scope, U256::from(42)).unwrap_err(), HistoryError::InvalidOrigin);
}

#[tokio::test]
async fn independently_pinned_block_hash_parent_number_and_deployment_must_stay_adjacent() {
    let scenario = Scenario::new();
    for fault in 0..8 {
        let mut history = initial(&scenario).await;
        let mut block = scenario.blocks[1].clone();
        match fault {
            0 => block.number += U256::one(),
            1 => block.parent_hash[0] ^= 1,
            2 => block.scope.policy_id[0] ^= 1,
            3 => block.scope.expected.owner_program[0] ^= 1,
            4 => block.scope.token[0] ^= 1,
            5 => block.scope.block_hash = scenario.blocks[0].scope.block_hash,
            6 => block.number = scenario.blocks[0].number,
            7 => {},
            _ => unreachable!(),
        }
        for log in block.appended_logs.iter_mut().chain(&mut block.nullifier_logs) {
            log["blockHash"] = json!(hex(&block.scope.block_hash));
            log["blockNumber"] = json!(format!("0x{:x}", block.number));
        }
        let fixture = Fixture::with_history(vec![block.clone()]);
        let expected_hash = if fault == 7 { [0x77; 32] } else { block.scope.block_hash };
        let before = snapshot(&history);
        assert!(history.ingest(expected_hash, acquire(&fixture, &block).await).is_err(), "fault {fault}");
        assert_eq!(snapshot(&history), before);
    }
    let mut history = initial(&scenario).await;
    let fixture = Fixture::with_history(scenario.blocks.clone());
    assert!(history.ingest(block_hash(44), acquire(&fixture, &scenario.blocks[2]).await).is_err());
    history.ingest(block_hash(43), acquire(&fixture, &scenario.blocks[1]).await).unwrap();
    let before = snapshot(&history);
    assert!(history.ingest(block_hash(43), acquire(&fixture, &scenario.blocks[1]).await).is_err());
    assert_eq!(snapshot(&history), before);
}

#[tokio::test]
async fn block_number_overflow_rejects_without_wrapping_history_cursor() {
    let scenario = Scenario::new();
    let mut origin = scenario.blocks[0].clone();
    origin.number = U256::MAX;
    let mut next = scenario.blocks[2].clone();
    next.number = U256::zero();
    next.parent_hash = origin.scope.block_hash;
    let fixture = Fixture::with_history(vec![origin.clone(), next.clone()]);
    let mut history = PublicHistory::new(origin.scope, U256::MAX).unwrap();
    history.ingest(origin.scope.block_hash, acquire(&fixture, &origin).await).unwrap();
    let before = snapshot(&history);
    assert_eq!(history.ingest(next.scope.block_hash, acquire(&fixture, &next).await),
        Err(HistoryError::WrongBlock));
    assert_eq!(snapshot(&history), before);
}

#[tokio::test]
async fn corrupt_missing_repeated_or_misindexed_appends_reject_the_whole_block_atomically() {
    let scenario = Scenario::new();
    for fault in 0..8 {
        let mut history = initial(&scenario).await;
        let mut block = scenario.blocks[1].clone();
        match fault {
            0 => mutate_append_word(&mut block, 1, 6, [0x88; 32]),
            1 => { block.appended_logs.remove(0); },
            2 => mutate_append_word(&mut block, 1, 7, [0xb1; 32]),
            3 => mutate_append_word(&mut block, 0, 5, support::uint_word(2)),
            4 => { // Decoder-valid index<count and count=index+1, but wrong next insertion.
                mutate_append_word(&mut block, 0, 4, support::uint_word(1));
                mutate_append_word(&mut block, 0, 5, support::uint_word(2));
            },
            5 => mutate_append_word(&mut block, 0, 3, support::uint_word(1)),
            6 => mutate_append_word(&mut block, 0, 3, support::uint_word(2)),
            7 => block.tree_root = [0x88; 32],
            _ => unreachable!(),
        }
        let fixture = Fixture::with_history(vec![block.clone()]);
        let before = snapshot(&history);
        let expected = if fault == 2 { HistoryError::DuplicateCommitment } else { HistoryError::TreeMismatch };
        assert_eq!(history.ingest(block.scope.block_hash, acquire(&fixture, &block).await), Err(expected), "fault {fault}");
        assert_eq!(snapshot(&history), before);
        assert_eq!(history.root_count(0, scenario.notes[0].insertion.root), 0);
        assert!(!history.observed_spent(&[0x55; 32]));
    }
}

fn mutate_append_word(block: &mut HistoryBlockFixture, note: usize, word: usize, replacement: [u8; 32]) {
    let data = block.appended_logs[note]["data"].as_str().unwrap();
    let mut data = data.to_owned();
    data.replace_range(2 + word * 64..2 + (word + 1) * 64, &hex(&replacement)[2..]);
    block.appended_logs[note]["data"] = json!(data);
}

#[tokio::test]
async fn empty_block_tree_state_is_checked_and_commitment_uniqueness_survives_other_blocks() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks[..2].to_vec());
    let mut history = initial(&scenario).await;
    history.ingest(block_hash(43), acquire(&fixture, &scenario.blocks[1]).await).unwrap();
    for fault in 0..3 {
        let mut block = scenario.blocks[2].clone();
        match fault {
            0 => block.tree_count += 1,
            1 => block.tree_root[0] ^= 1,
            2 => {
                let mut tree = NoteTree::new(block.scope.expected.digest().unwrap(), 0).unwrap();
                tree.append([0xb1; 32]).unwrap();
                tree.append([0xb2; 32]).unwrap();
                append(&mut block, &mut tree, [0xb1; 32], [0x24; 32], (0, 0, 4), Role::A, vec![1]);
            }
            _ => unreachable!(),
        }
        let bad = Fixture::with_history(vec![block.clone()]);
        let before = snapshot(&history);
        assert!(history.ingest(block.scope.block_hash, acquire(&bad, &block).await).is_err());
        assert_eq!(snapshot(&history), before);
    }
}

#[tokio::test]
async fn nullifiers_and_combined_event_occurrences_cannot_repeat_or_conflict() {
    let scenario = Scenario::new();
    for fault in 0..8 {
        let mut history = initial(&scenario).await;
        let fixture = Fixture::with_history(vec![scenario.blocks[1].clone()]);
        history.ingest(block_hash(43), acquire(&fixture, &scenario.blocks[1]).await).unwrap();
        let mut block = scenario.blocks[2].clone();
        match fault {
            0 => consume(&mut block, [0x55; 32], [0x24; 32], 0, 0),
            1 => { consume(&mut block, [0x57; 32], [0x24; 32], 0, 0);
                consume(&mut block, [0x57; 32], [0x24; 32], 0, 1); },
            2 => consume(&mut block, [0x57; 32], [0x22; 32], 0, 0), // Same tx hash in another block.
            3..=7 => {
                block = scenario.blocks[3].clone();
                block.number = U256::from(44);
                block.scope.block_hash = block_hash(44);
                block.parent_hash = block_hash(43);
                for log in block.appended_logs.iter_mut().chain(&mut block.nullifier_logs) {
                    log["blockHash"] = json!(hex(&block.scope.block_hash));
                    log["blockNumber"] = json!("0x2c");
                }
                match fault {
                    3 => block.nullifier_logs[0]["logIndex"] = json!("0x1"),
                    4 => block.nullifier_logs[0]["transactionHash"] = json!(hex(&[0x24; 32])),
                    5 => { // Distinct transactions still cannot reuse a global logIndex.
                        block.nullifier_logs[0]["transactionHash"] = json!(hex(&[0x24; 32]));
                        block.nullifier_logs[0]["transactionIndex"] = json!("0x1");
                        block.nullifier_logs[0]["logIndex"] = json!("0x1");
                    }
                    6 => { // Transaction hash cannot identify two indices across filtered streams.
                        block.nullifier_logs[0]["transactionIndex"] = json!("0x1");
                        block.nullifier_logs[0]["logIndex"] = json!("0x2");
                    }
                    7 => { // Increasing txIndex must also advance the global logIndex.
                        block.nullifier_logs[0]["transactionHash"] = json!(hex(&[0x24; 32]));
                        block.nullifier_logs[0]["transactionIndex"] = json!("0x1");
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
        let bad = Fixture::with_history(vec![block.clone()]);
        let before = snapshot(&history);
        assert!(history.ingest(block.scope.block_hash, acquire(&bad, &block).await).is_err(), "fault {fault}");
        assert_eq!(snapshot(&history), before);
        assert!(!history.observed_spent(&[0x57; 32]));
    }
}

#[tokio::test]
async fn packet_selected_root_counts_and_spent_answers_are_cross_checked_before_commit() {
    let scenario = Scenario::new();
    for fault in 0..3 {
        let mut history = initial(&scenario).await;
        let mut block = scenario.blocks[1].clone();
        if fault == 1 { block.root_counts.insert((0, scenario.notes[0].insertion.root), 2); }
        if fault == 2 { block.spent.remove(&[0x55; 32]); }
        let fixture = Fixture::with_history(vec![block.clone()]);
        let mut packet = fixture.single_packet();
        packet.input.tree_id = 0;
        packet.input.index = 0;
        packet.input.root = scenario.notes[0].insertion.root;
        packet.input.nullifier = [0x55; 32];
        let observation = SamechainInspectionClient::new(fixture.endpoint(), true).unwrap()
            .inspect(&block.scope, Some(InspectionPacket::Single(&packet))).await.unwrap();
        let before = snapshot(&history);
        if fault == 0 {
            history.ingest(block.scope.block_hash, observation).unwrap();
            assert!(history.observed_spent(&packet.input.nullifier));
        } else {
            assert_eq!(history.ingest(block.scope.block_hash, observation), Err(HistoryError::InputMismatch));
            assert_eq!(snapshot(&history), before);
        }
    }
}

#[tokio::test]
async fn absent_unqueried_nf_only_transactions_remain_an_explicit_provider_completeness_assumption() {
    let scenario = Scenario::new();
    let mut block = scenario.blocks[2].clone();
    // A provider can omit a complete NF-only transaction without changing treeState.
    // Coherent replay cannot detect that omission and must not certify an unspent set.
    block.number = U256::from(43);
    block.scope.block_hash = block_hash(43);
    block.parent_hash = block_hash(42);
    block.tree_count = 0;
    block.tree_root = scenario.blocks[0].tree_root;
    let fixture = Fixture::with_history(vec![block.clone()]);
    let mut history = initial(&scenario).await;
    history.ingest(block.scope.block_hash, acquire(&fixture, &block).await).unwrap();
    assert!(!history.observed_spent(&[0x55; 32]));
    assert_eq!(history.log_completeness_trust(), "TRUSTED_PROVIDER_LOG_COMPLETENESS");
}

#[tokio::test]
async fn lifetime_block_bound_includes_origin_and_keeps_the_previous_accepted_state() {
    let tree = NoteTree::new(support::scope().expected.digest().unwrap(), 0).unwrap();
    let blocks: Vec<_> = (42..42 + 2049).map(|number| empty_block(number, &tree)).collect();
    let fixture = Fixture::with_history(blocks.clone());
    let mut history = PublicHistory::new(blocks[0].scope, blocks[0].number).unwrap();
    for block in &blocks[..2048] {
        history.ingest(block.scope.block_hash, acquire(&fixture, block).await).unwrap();
    }
    let before = snapshot(&history);
    assert_eq!(history.ingest(blocks[2048].scope.block_hash, acquire(&fixture, &blocks[2048]).await),
        Err(HistoryError::LimitExceeded));
    assert_eq!(snapshot(&history), before);
}

#[tokio::test]
async fn lifetime_nullifier_bound_never_evicts_old_spent_observations() {
    let tree = NoteTree::new(support::scope().expected.digest().unwrap(), 0).unwrap();
    let mut blocks = vec![empty_block(42, &tree)];
    for batch in 0..33u64 {
        let mut block = empty_block(43 + batch, &tree);
        for index in 0..if batch == 32 { 1 } else { 256 } {
            consume(&mut block, hash_label(batch * 256 + index), hash_label(100_000 + batch), 0, index);
        }
        blocks.push(block);
    }
    let fixture = Fixture::with_history(blocks.clone());
    let mut history = PublicHistory::new(blocks[0].scope, blocks[0].number).unwrap();
    for block in &blocks[..33] {
        history.ingest(block.scope.block_hash, acquire(&fixture, block).await).unwrap();
    }
    assert_eq!(history.nullifier_count(), 8192);
    assert!(history.observed_spent(&hash_label(0)));
    let before = snapshot(&history);
    assert_eq!(history.ingest(blocks[33].scope.block_hash, acquire(&fixture, &blocks[33]).await),
        Err(HistoryError::LimitExceeded));
    assert_eq!(snapshot(&history), before);
}

#[tokio::test]
async fn lifetime_note_and_ciphertext_bounds_keep_all_accepted_recovery_bytes() {
    for ciphertext_len in [1, 4096] {
        let mut tree = NoteTree::new(support::scope().expected.digest().unwrap(), 0).unwrap();
        let mut blocks = vec![empty_block(42, &tree)];
        for batch in 0..65u64 {
            let mut block = empty_block(43 + batch, &tree);
            for index in 0..if batch == 64 { 1 } else { 64 } {
                append(&mut block, &mut tree, hash_label(batch * 64 + index),
                    hash_label(100_000 + batch), (0, index, index as u32), Role::A,
                    vec![0xd8; ciphertext_len]);
            }
            blocks.push(block);
        }
        let fixture = Fixture::with_history(blocks.clone());
        let mut history = PublicHistory::new(blocks[0].scope, blocks[0].number).unwrap();
        for block in &blocks[..65] {
            history.ingest(block.scope.block_hash, acquire(&fixture, block).await).unwrap();
        }
        assert_eq!(history.note_count(), 4096);
        assert_eq!(history.ciphertext_bytes(), 4096 * ciphertext_len);
        assert_eq!(history.note(&hash_label(0)).unwrap().note.ciphertext, vec![0xd8; ciphertext_len]);
        let before = (history.latest_block(), history.tree_state(), history.note_count(),
            history.ciphertext_bytes(), history.root_count(0, blocks[64].tree_root));
        assert_eq!(history.ingest(blocks[65].scope.block_hash, acquire(&fixture, &blocks[65]).await),
            Err(HistoryError::LimitExceeded));
        assert_eq!((history.latest_block(), history.tree_state(), history.note_count(),
            history.ciphertext_bytes(), history.root_count(0, blocks[64].tree_root)), before);
        assert!(history.note(&hash_label(4096)).is_none());
        assert_eq!(history.root_count(0, blocks[65].tree_root), 0);
    }
}
