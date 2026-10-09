use super::*;

#[path = "../../tests/native_trade_support/mod.rs"]
mod fixtures;

#[test]
fn quote_transition_requires_unchanged_terms_and_each_predecessor() {
    let proposal = fixtures::quote(QuotePhase::Proposal, 8, 1);
    let accepted = fixtures::quote(QuotePhase::UserAcceptance, 8, 1);
    let agreed = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let snapshot = QuoteSnapshot::from_quote(&proposal, [51; 32], TradeCursor { version: 1, generation: 1 });
    assert!(!snapshot.accept_quote(&proposal).unwrap());
    assert!(snapshot.accept_quote(&accepted).unwrap());
    assert_eq!(snapshot.accept_quote(&agreed), Err(NativeTradeError::State));
    assert_eq!(snapshot.accept_quote(&fixtures::quote(QuotePhase::Proposal, 8, 2)), Err(NativeTradeError::Conflict));
    let accepted_snapshot = QuoteSnapshot::from_quote(&accepted, [52; 32], TradeCursor { version: 2, generation: 1 });
    assert!(accepted_snapshot.accept_quote(&agreed).unwrap());
    assert_eq!(accepted_snapshot.accept_quote(&proposal), Err(NativeTradeError::State));
    let mut stopped = accepted_snapshot;
    stopped.stopped = true;
    assert_eq!(stopped.accept_quote(&accepted), Err(NativeTradeError::Stopped));
}

#[test]
fn cursors_reject_zero_overflow_and_stale_generation_before_version() {
    let actual = TradeCursor { version: 8, generation: 3 };
    assert_eq!(check_cursor(actual, TradeCursor { version: 7, generation: 2 }), Err(NativeTradeError::StaleGeneration));
    assert_eq!(check_cursor(actual, TradeCursor { version: 7, generation: 3 }), Err(NativeTradeError::StaleVersion));
    assert_eq!(actual.advance(false).unwrap(), TradeCursor { version: 9, generation: 3 });
    assert_eq!(actual.advance(true).unwrap(), TradeCursor { version: 9, generation: 4 });
    for cursor in [TradeCursor { version: 0, generation: 1 }, TradeCursor { version: 1, generation: 0 },
        TradeCursor { version: i64::MAX as u64 + 1, generation: 1 }] {
        assert!(cursor.validate().is_err());
    }
    assert!(TradeCursor { version: i64::MAX as u64, generation: 1 }.advance(false).is_err());
    assert!(TradeCursor { version: 1, generation: i64::MAX as u64 }.advance(true).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn capsule_quote_restoration_authenticates_digest_role_and_complete_transcript() {
    let directory = fixtures::private_directory();
    let path = directory.path().join("quote");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let quote = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let (digest, restored) = capsule::save_quote(location, &quote).unwrap();
    assert_eq!(restored.encode(), quote.encode());
    assert_eq!(capsule::save_quote(location, &quote).unwrap().0, digest);
    assert!(capsule::load_quote(location, quote.selection(), QuotePhase::Agreed, [73; 32]).is_err());
    for index in 0..6 {
        let mut selection = *quote.selection();
        match index {
            0 => selection.local_role = NativeRole::Solver,
            1 => selection.challenge_i = [74; 32],
            2 => selection.challenge_r = [75; 32],
            3 => selection.proposal_seq += 1,
            4 => selection.user_acceptance_seq += 1,
            _ => selection.solver_acceptance_seq += 1,
        }
        assert!(capsule::load_quote(location, &selection, QuotePhase::Agreed, digest).is_err());
    }
    assert!(capsule::load_quote(location, quote.selection(), QuotePhase::Proposal, digest).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn operation_capsule_loads_exact_bytes_and_rejects_each_altered_binding() {
    let directory = fixtures::private_directory();
    let path = directory.path().join("operation");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let quote = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let payload = b"exact retained execution";
    let binding = fixtures::binding(31, payload);
    let digest = capsule::save_operation_capsule(location, quote.selection(), &binding, payload).unwrap();
    assert_eq!(capsule::load_operation(location, quote.selection(), &binding, digest).unwrap().as_slice(), payload);
    for index in 0..6 {
        let mut changed = binding;
        match index {
            0 => changed.op_id = [74; 32],
            1 => changed.context_digest = [75; 32],
            2 => changed.deployment_digest = [76; 32],
            3 => changed.stable_j_tag = [77; 32],
            4 => changed.payload_digest = [78; 32],
            _ => changed.action = 2,
        }
        assert_eq!(capsule::load_operation(location, quote.selection(), &changed, digest).unwrap_err(), NativeTradeError::Binding);
    }
    let wrong_key = [79; 32];
    assert!(capsule::load_operation(CapsuleLocation { key: &wrong_key, ..location }, quote.selection(), &binding, digest).is_err());
    assert!(capsule::load_operation(location, quote.selection(), &binding, [80; 32]).is_err());
    assert!(capsule::load_operation(CapsuleLocation { namespace: [81; 32], ..location }, quote.selection(), &binding, digest).is_err());
}

#[test]
fn operation_decoder_rejects_unknown_without_capsule_and_never_drops_known_hash() {
    assert_eq!(journal::decode_operation_state(3, None, None), Err(invalid_record()));
    assert_eq!(journal::decode_operation_state(2, Some([51; 32]), None), Err(invalid_record()));
    assert_eq!(journal::decode_operation_state(0, Some([51; 32]), None), Err(invalid_record()));
    assert_eq!(journal::decode_operation_state(3, Some([51; 32]), Some([52; 32])).unwrap(), OperationState::Unknown);
    assert_eq!(journal::decode_operation_state(3, Some([51; 32]), None).unwrap(), OperationState::Unknown);
    for state in [-1, 4, i16::MAX] {
        assert_eq!(journal::decode_operation_state(state, Some([51; 32]), Some([52; 32])), Err(invalid_record()));
    }
}

#[cfg(target_os = "linux")]
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn actual_process_restart_authenticates_quote_and_operation_without_sql() {
    let directory = fixtures::private_directory();
    let quote_path = directory.path().join("quote");
    let operation_path = directory.path().join("operation");
    let mut key = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *key).unwrap();
    let quote = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let quote_location = CapsuleLocation { path: &quote_path, key: &key, namespace: [72; 32] };
    let quote_digest = capsule::save_quote(quote_location, &quote).unwrap().0;
    let payload = b"exact retained execution";
    let binding = fixtures::binding(31, payload);
    let operation_digest = save_operation_capsule(CapsuleLocation { path: &operation_path, ..quote_location }, quote.selection(), &binding, payload).unwrap();
    write_private(&directory.path().join("generated-capability"), &*key);
    let mut digests = [0; 64];
    digests[..32].copy_from_slice(&quote_digest);
    digests[32..].copy_from_slice(&operation_digest);
    write_private(&directory.path().join("independent-digests"), &digests);
    let quote_ciphertext = std::fs::read(&quote_path).unwrap();
    let operation_ciphertext = std::fs::read(&operation_path).unwrap();
    drop(quote);
    let key_probe = zeroize::Zeroizing::new(*key);
    drop(key);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_trade::tests::native_trade_capsule_restart_child", "--nocapture"])
        .env("ZIQUID_NATIVE_TRADE_RESTART_DIRECTORY", directory.path()).output().unwrap();
    assert!(child.status.success(), "generated native trade capsule restart failed");
    let output = [child.stdout, child.stderr].concat();
    assert!(!output.windows(payload.len()).any(|bytes| bytes == payload));
    assert!(!output.windows(key_probe.len()).any(|bytes| bytes == key_probe.as_slice()));
    assert_eq!(std::fs::read(quote_path).unwrap(), quote_ciphertext);
    assert_eq!(std::fs::read(operation_path).unwrap(), operation_ciphertext);
}

#[cfg(target_os = "linux")]
#[test]
fn native_trade_capsule_restart_child() {
    use zeroize::Zeroizing;
    let Some(directory) = std::env::var_os("ZIQUID_NATIVE_TRADE_RESTART_DIRECTORY") else { return; };
    let directory = std::path::Path::new(&directory);
    let quote_path = directory.join("quote");
    let operation_path = directory.join("operation");
    let key_bytes = Zeroizing::new(std::fs::read(directory.join("generated-capability")).unwrap());
    let key = Zeroizing::new(<[u8; 32]>::try_from(key_bytes.as_slice()).unwrap());
    let digests = std::fs::read(directory.join("independent-digests")).unwrap();
    assert_eq!(digests.len(), 64);
    let quote_digest = <[u8; 32]>::try_from(&digests[..32]).unwrap();
    let operation_digest = <[u8; 32]>::try_from(&digests[32..]).unwrap();
    // Independent generated fixture pins are recomputed, never inferred from custody.
    let expected = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let location = CapsuleLocation { path: &quote_path, key: &key, namespace: [72; 32] };
    let quote = capsule::load_quote(location, expected.selection(), QuotePhase::Agreed, quote_digest).unwrap();
    assert!(quote.encode() == expected.encode());
    let payload = b"exact retained execution";
    let binding = fixtures::binding(31, payload);
    let restored = capsule::load_operation(CapsuleLocation { path: &operation_path, ..location }, expected.selection(), &binding, operation_digest).unwrap();
    assert!(restored.as_slice() == payload);
}

#[test]
fn missing_response_transition_retains_hash_and_same_operation_only_reconciliation() {
    let hash = [52; 32];
    let (state, retained, changed) = journal::operation_transition(OperationState::Submitted, Some(hash), None).unwrap();
    assert_eq!(state, OperationState::Unknown);
    assert_eq!(retained, Some(hash));
    assert!(changed);
    assert_eq!(journal::operation_transition(OperationState::Unknown, Some(hash), None).unwrap(),
        (OperationState::Unknown, Some(hash), false));
    assert_eq!(journal::operation_transition(OperationState::Unknown, Some(hash), Some([53; 32])), Err(NativeTradeError::Conflict));
    assert_eq!(journal::operation_transition(OperationState::Unknown, Some(hash), Some(hash)).unwrap(),
        (OperationState::Submitted, Some(hash), true));
    assert_eq!(journal::operation_transition(OperationState::Released, None, None).unwrap(),
        (OperationState::Unknown, None, true));
    assert_eq!(journal::operation_transition(OperationState::Prepared, None, None), Err(NativeTradeError::State));
    assert_eq!(journal::operation_transition(OperationState::Prepared, None, Some(hash)), Err(NativeTradeError::State));
    assert_eq!(journal::operation_transition(OperationState::Submitted, Some(hash), Some(hash)).unwrap(),
        (OperationState::Submitted, Some(hash), false));
}

#[cfg(target_os = "linux")]
#[test]
fn authenticated_operation_frame_rejects_trailing_truncated_and_wrong_payload_bytes() {
    let directory = fixtures::private_directory();
    let key = [71; 32];
    let quote = fixtures::quote(QuotePhase::Agreed, 8, 1);
    let payload = b"exact retained execution";
    let binding = fixtures::binding(31, payload);
    // Independent test frame, not a second production encoder or financial proof.
    let mut frame = b"ZIQUID_NATIVE_OPERATION_CAPSULE\0".to_vec();
    frame.extend_from_slice(&1_u16.to_be_bytes());
    for field in [binding.op_id, binding.context_digest, binding.deployment_digest, binding.stable_j_tag, binding.payload_digest] {
        frame.extend_from_slice(&field);
    }
    frame.extend_from_slice(&binding.action.to_be_bytes());
    let length_offset = frame.len();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let mut trailing = frame.clone();
    trailing.push(0);
    let mut truncated = frame.clone();
    truncated.pop();
    let mut altered = frame.clone();
    *altered.last_mut().unwrap() ^= 1;
    let mut oversized = frame;
    oversized[length_offset..length_offset + 4].copy_from_slice(&(96_u32 * 1024 * 1024).to_be_bytes());
    for (index, (bytes, error)) in [(trailing, NativeTradeError::Encoding), (truncated, NativeTradeError::Encoding),
        (altered, NativeTradeError::Binding), (oversized, NativeTradeError::ResourceLimit)].into_iter().enumerate() {
        let path = directory.path().join(format!("malformed-{index}"));
        let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
        let digest = capsule::save_bytes(location, capsule::quote_selection_digest(quote.selection()), 3, &bytes).unwrap();
        assert_eq!(capsule::load_operation(location, quote.selection(), &binding, digest).unwrap_err(), error);
    }
}
