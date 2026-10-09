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
