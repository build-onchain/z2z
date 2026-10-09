mod native_trade_support;

use sha2::{Digest, Sha256};
use ziquid_runtime::{native_quote::QuotePhase, native_trade::{NativeTradeError, OperationState}};

#[test]
fn unknown_preserves_submission_reconciliation_but_never_releases_again() {
    assert!(OperationState::Prepared.can_release());
    assert!(!OperationState::Prepared.can_mark_unknown());
    assert!(!OperationState::Prepared.can_submit());
    assert!(OperationState::Released.can_submit());
    assert!(OperationState::Released.can_mark_unknown());
    assert!(OperationState::Submitted.can_mark_unknown());
    assert!(OperationState::Unknown.can_submit());
    assert!(!OperationState::Unknown.can_release());
}

#[test]
fn operation_binding_rejects_missing_pins_and_unsupported_sql_action() {
    let original = native_trade_support::binding(31, b"retained executable bytes");
    original.validate().unwrap();
    for index in 0..5 {
        let mut binding = original;
        match index {
            0 => binding.op_id = [0; 32],
            1 => binding.context_digest = [0; 32],
            2 => binding.deployment_digest = [0; 32],
            3 => binding.stable_j_tag = [0; 32],
            _ => binding.payload_digest = [0; 32],
        }
        assert_eq!(binding.validate(), Err(NativeTradeError::Binding));
    }
    for action in [0, 32768, u16::MAX] {
        let mut binding = original;
        binding.action = action;
        assert_eq!(binding.validate(), Err(NativeTradeError::Binding));
    }
}

#[test]
fn signed_coordination_fixture_covers_all_three_existing_decoder_phases() {
    for phase in [QuotePhase::Proposal, QuotePhase::UserAcceptance, QuotePhase::Agreed] {
        let quote = native_trade_support::quote(phase, 8, 1);
        assert_eq!(quote.phase(), phase);
        assert_eq!(quote.user_acceptance_hash().is_some(), phase != QuotePhase::Proposal);
        assert_eq!(quote.solver_acceptance_hash().is_some(), phase == QuotePhase::Agreed);
        assert_eq!(quote.agreement_digest().is_some(), phase == QuotePhase::Agreed);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn immutable_operation_capsule_retries_exact_bytes_and_rejects_changed_payload_or_selection() {
    use ziquid_runtime::native_trade::{CapsuleLocation, save_operation_capsule};
    let directory = native_trade_support::private_directory();
    let path = directory.path().join("operation");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let quote = native_trade_support::quote(QuotePhase::Agreed, 8, 1);
    let payload = b"retained executable bytes";
    let binding = native_trade_support::binding(31, payload);
    let digest = save_operation_capsule(location, quote.selection(), &binding, payload).unwrap();
    assert_eq!(digest, save_operation_capsule(location, quote.selection(), &binding, payload).unwrap());
    assert_eq!(save_operation_capsule(location, quote.selection(), &binding, b"replacement"), Err(NativeTradeError::Binding));
    let mut changed = binding;
    changed.payload_digest = Sha256::digest(b"replacement").into();
    assert!(save_operation_capsule(location, quote.selection(), &changed, b"replacement").is_err());
    let mut selection = *quote.selection();
    selection.owner_scope = [73; 32];
    assert!(save_operation_capsule(location, &selection, &binding, payload).is_err());
    let disk = std::fs::read(path).unwrap();
    assert!(!disk.windows(payload.len()).any(|bytes| bytes == payload));
}
