//! Real subprocess checks with deterministic synthetic keys and supplied paths;
//! no SQL, network, accepted-root admission, backing or financial execution.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{MAX_PRIVATE_INPUT_BYTES, decrypt_output};
use ziquid_proofs::samechain::withdrawal::NoteWithdrawalWitness;
use ziquid_protocol::samechain::{
    Action, Asset, MAX_PACKET_BYTES, OutputDescriptor, PublicPacket, Role, SingleOwnerPacket,
};
use ziquid_protocol::samechain::withdrawal::{
    NoteWithdrawalJournal, NoteWithdrawalPacket, validate_note_withdrawal,
};

#[allow(dead_code)]
#[path = "../../proofs/tests/support/ordinary_withdrawal.rs"]
mod support;
#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod fill_support;

fn not_disclosed(output: &[u8], private: &[u8]) {
    if private.is_empty() { return; }
    assert!(!output.windows(private.len()).any(|window| window == private), "private bytes disclosed");
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).unwrap();
    assert!(!output.windows(json.len()).any(|window| window == &json[..]), "private serialized bytes disclosed");
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut hex = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *hex, "{byte:02x}").unwrap(); }
        assert!(!output.windows(64).any(|window| window.eq_ignore_ascii_case(hex.as_bytes())), "private hex bytes disclosed");
    }
}

fn run(arguments: &[&str], bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .arg("samechain").args(arguments)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    not_disclosed(&output.stderr, bytes);
    for argument in arguments {
        if argument.starts_with('/') || argument.contains("sentinel") {
            not_disclosed(&output.stderr, argument.as_bytes());
        }
    }
    if let Ok(witness) = NoteWithdrawalWitness::decode(bytes) {
        for stream in [&output.stdout, &output.stderr] {
            not_disclosed(stream, &witness.owner_seed);
            not_disclosed(stream, &witness.blind);
            not_disclosed(stream, &witness.input.encode().unwrap());
            for opening in &witness.owned_outputs {
                not_disclosed(stream, &opening.recovery_key);
                not_disclosed(stream, &opening.note.encode().unwrap());
            }
        }
    }
    output
}

fn check(bytes: &[u8]) -> Output {
    run(&["check-note-withdrawal", "--witness-stdin"], bytes)
}

fn review(packet: &[u8], bytes: &[u8]) -> Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(packet).unwrap();
    run(&["review-note-withdrawal", "--packet", file.path().to_str().unwrap(), "--witness-stdin"], bytes)
}

fn rejected(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn public_bytes(json: &serde_json::Value, field: &str) -> Vec<u8> {
    serde_json::from_value(json[field].clone()).unwrap()
}

fn export(output: &Output, reviewing: bool) -> serde_json::Value {
    assert!(output.status.success(), "ordinary withdrawal command rejected");
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], if reviewing { "review_note_withdrawal" } else { "check_note_withdrawal" });
    assert_eq!(json["role"], Role::A as u8);
    assert_eq!(json["action"], Action::Exit as u8);
    assert_eq!(json["evidence"], if reviewing { "native_owner_preconsent_review" } else { "native_owner_relation" });
    for field in ["root_eligibility", "global_unspentness", "asset_backing"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["proof_certificate", "financial_execution", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    assert_eq!(json.get("journal").is_none(), reviewing);
    assert_eq!(json.get("consent_message").is_some(), reviewing);
    let packet = NoteWithdrawalPacket::decode(&public_bytes(&json, "packet")).unwrap();
    assert_eq!(public_bytes(&json, "packet_digest"), packet.digest().unwrap());
    if !reviewing {
        let journal = NoteWithdrawalJournal::decode(&public_bytes(&json, "journal")).unwrap();
        validate_note_withdrawal(&packet, &journal).unwrap();
    }
    json
}

fn reviewed_and_signed(mut witness: NoteWithdrawalWitness) -> (NoteWithdrawalWitness, serde_json::Value) {
    witness.consent = [0; 64];
    let packet = witness.packet.encode().unwrap();
    let json = export(&review(&packet, &witness.encode().unwrap()), true);
    assert_eq!(public_bytes(&json, "packet"), packet);
    rejected(check(&witness.encode().unwrap()));
    // Signing exists only in this deterministic synthetic fixture, never CLI.
    witness.consent = SigningKey::from_bytes(&witness.owner_seed)
        .sign(&public_bytes(&json, "consent_message")).to_bytes();
    let checked = export(&check(&witness.encode().unwrap()), false);
    (witness, checked)
}

#[test]
fn receipt_review_signed_check_recovers_change_for_a_second_withdrawal() {
    let fill = fill_support::known_fill();
    let result = run(&["check-fill", "--witness-stdin"], &fill.a.encode().unwrap());
    assert!(result.status.success());
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let packet = PublicPacket::decode(&public_bytes(&json, "packet")).unwrap();
    let receipt = &fill.a.owned_outputs[1];
    let recovered = decrypt_output(&packet.outputs[receipt.manifest_index as usize],
        &receipt.recovery_key, &packet.deployment.digest().unwrap(), &fill.a.input.owner_key).unwrap();
    assert_eq!(recovered.asset, Asset::Token([7; 20]));
    assert_eq!(recovered.value, U256::from(49));
    assert!(recovered.order.is_none());
    let witness = support::received_token_partial();
    assert_eq!(witness.input, recovered);
    let (witness, json) = reviewed_and_signed(witness);
    let packet = NoteWithdrawalPacket::decode(&public_bytes(&json, "packet")).unwrap();
    assert!(matches!(packet.outputs[0], OutputDescriptor::Exit { asset: Asset::Token(_), amount, .. } if amount == U256::from(40)));
    assert!(matches!(packet.outputs[2], OutputDescriptor::Fee { amount, .. } if amount == U256::one()));
    let opening = &witness.owned_outputs[0];
    let change = decrypt_output(&packet.outputs[opening.manifest_index as usize],
        &opening.recovery_key, &packet.deployment.digest().unwrap(), &witness.input.owner_key).unwrap();
    assert_eq!(change.value, U256::from(8));
    assert!(change.order.is_none());
    let next = support::change_withdrawal(&witness);
    assert_eq!(next.input, change);
    let first = NoteWithdrawalJournal::decode(&public_bytes(&json, "journal")).unwrap();
    let (_, json) = reviewed_and_signed(next);
    let second = NoteWithdrawalJournal::decode(&public_bytes(&json, "journal")).unwrap();
    assert_ne!(first.input_nullifier, second.input_nullifier);
    assert_eq!(second.input_commitment, change.commitment().unwrap());
}

#[test]
fn role_b_native_proceeds_and_cancel_return_are_ordinary_withdrawable_notes() {
    let fill = fill_support::known_fill();
    let result = run(&["check-fill", "--witness-stdin"], &fill.b.encode().unwrap());
    assert!(result.status.success());
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let packet = PublicPacket::decode(&public_bytes(&json, "packet")).unwrap();
    let receipt = &fill.b.owned_outputs[1];
    let recovered = decrypt_output(&packet.outputs[receipt.manifest_index as usize],
        &receipt.recovery_key, &packet.deployment.digest().unwrap(), &fill.b.input.owner_key).unwrap();
    assert_eq!(recovered.value, U256::from(40));
    let native = support::received_native_full();
    assert_eq!(native.input, recovered);
    let (_, checked) = reviewed_and_signed(native);
    let packet = NoteWithdrawalPacket::decode(&public_bytes(&checked, "packet")).unwrap();
    assert!(matches!(packet.outputs.as_slice(), [OutputDescriptor::Exit { role: Role::A, asset: Asset::Native, amount, .. }] if *amount == U256::from(40)));

    let cancelled = fill_support::cancel_exit(&fill, Action::Cancel);
    let result = run(&["check-cancel-exit", "--witness-stdin"], &cancelled.encode().unwrap());
    assert!(result.status.success());
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let packet = SingleOwnerPacket::decode(&public_bytes(&json, "packet")).unwrap();
    let opening = &cancelled.owned_outputs[0];
    let recovered = decrypt_output(&packet.outputs[opening.manifest_index as usize],
        &opening.recovery_key, &packet.deployment.digest().unwrap(), &cancelled.input.owner_key).unwrap();
    assert_eq!(recovered.value, U256::from(100));
    let withdrawal = support::cancelled_native_partial();
    assert_eq!(withdrawal.input, recovered);
    let (withdrawal, _) = reviewed_and_signed(withdrawal);
    assert!(matches!(withdrawal.packet.outputs[0], OutputDescriptor::Exit { amount, .. } if amount == U256::from(70)));
    assert_eq!(withdrawal.owned_outputs[0].note.value, U256::from(30));
    reviewed_and_signed(support::change_withdrawal(&withdrawal));
    reviewed_and_signed(support::max_withdrawal());
}

#[test]
fn review_requires_independently_selected_packet_and_does_not_require_existing_consent() {
    let witness = support::received_token_partial();
    for consent in [[0; 64], [1; 64]] {
        let mut unsigned = witness.clone();
        unsigned.consent = consent;
        export(&review(&unsigned.packet.encode().unwrap(), &unsigned.encode().unwrap()), true);
        rejected(check(&unsigned.encode().unwrap()));
    }
    let bytes = witness.encode().unwrap();
    let mut other = witness.packet.clone();
    other.deployment.chain_id += 1;
    rejected(review(&other.encode().unwrap(), &bytes));
    let mut other = witness.packet.clone();
    other.input.commitment[0] ^= 1;
    rejected(review(&other.encode().unwrap(), &bytes));
    let mut other = witness.packet.clone();
    other.expiry += 1;
    rejected(review(&other.encode().unwrap(), &bytes));
}

fn reject_semantics(witness: &NoteWithdrawalWitness) {
    let bytes = witness.encode().unwrap();
    rejected(review(&witness.packet.encode().unwrap(), &bytes));
    rejected(check(&bytes));
}

#[test]
fn strict_signature_and_terms_opening_guards_reject_freshly_signed_invalid_openings() {
    let good = support::received_token_partial();
    export(&check(&good.encode().unwrap()), false);
    let mut retargeted = good.clone();
    let OutputDescriptor::Exit { recipient, .. } = &mut retargeted.packet.outputs[0] else { panic!("expected exit"); };
    recipient[0] ^= 1;
    // Open changed effects but retain the old consent: exact recipient authority
    // must fail even though conservation and the new commitment remain valid.
    let old_consent = retargeted.consent;
    support::rebind(&mut retargeted);
    retargeted.consent = old_consent;
    rejected(check(&retargeted.encode().unwrap()));
    let mut signature = good.clone();
    signature.consent[0] ^= 1;
    rejected(check(&signature.encode().unwrap()));
    // A stale signature does not block review of otherwise exact semantics.
    export(&review(&signature.packet.encode().unwrap(), &signature.encode().unwrap()), true);
    let fill = fill_support::known_fill();
    for consent in [fill.a.consent, fill_support::cancel_exit(&fill, Action::Exit).consent] {
        let mut old_domain = good.clone();
        old_domain.consent = consent;
        rejected(check(&old_domain.encode().unwrap()));
    }
    let mut wrong_blind = good.clone();
    wrong_blind.blind[0] ^= 1;
    support::resign(&mut wrong_blind);
    reject_semantics(&wrong_blind);
    let mut arbitrary_terms = good;
    arbitrary_terms.packet.terms_commitment = [191; 32];
    support::resign(&mut arbitrary_terms);
    reject_semantics(&arbitrary_terms);
}

#[test]
fn recovery_ciphertext_order_asset_and_conservation_fail_without_private_exports() {
    let good = support::received_token_partial();
    export(&check(&good.encode().unwrap()), false);
    let mut wrong_key = good.clone();
    wrong_key.owned_outputs[0].recovery_key[0] ^= 1;
    reject_semantics(&wrong_key);
    let mut wrong_seed = good.clone();
    wrong_seed.owner_seed = [22; 32];
    reject_semantics(&wrong_seed);
    let mut bad_path = good.clone();
    bad_path.membership.siblings[0][0] ^= 1;
    reject_semantics(&bad_path);
    let mut damaged = good.clone();
    let OutputDescriptor::Note { ciphertext, .. } = &mut damaged.packet.outputs[1] else { panic!("expected recoverable change"); };
    ciphertext[24] ^= 1;
    support::rebind(&mut damaged);
    reject_semantics(&damaged);
    let fill = fill_support::known_fill();
    let mut order_input = good.clone();
    order_input.input.order = fill.b.input.order.clone();
    order_input.input.order.as_mut().unwrap().remaining_sell = U256::from(49);
    support::replace_input(&mut order_input);
    support::rebind(&mut order_input);
    reject_semantics(&order_input);
    let mut order_change = good.clone();
    order_change.owned_outputs[0].note.order = fill.b.input.order.clone();
    order_change.owned_outputs[0].note.order.as_mut().unwrap().remaining_sell = U256::from(8);
    support::replace_change(&mut order_change, 0);
    support::rebind(&mut order_change);
    reject_semantics(&order_change);
    let mut cross_asset = good.clone();
    let OutputDescriptor::Exit { asset, .. } = &mut cross_asset.packet.outputs[0] else { panic!("expected exit"); };
    *asset = Asset::Native;
    support::rebind(&mut cross_asset);
    reject_semantics(&cross_asset);
    let mut wrong_fee = good.clone();
    let OutputDescriptor::Fee { asset, .. } = &mut wrong_fee.packet.outputs[2] else { panic!("expected fee"); };
    *asset = Asset::Token([11; 20]);
    support::rebind(&mut wrong_fee);
    reject_semantics(&wrong_fee);
    for value in [7, 9] {
        let mut wrong_sum = good.clone();
        wrong_sum.owned_outputs[0].note.value = U256::from(value);
        support::replace_change(&mut wrong_sum, 0);
        support::rebind(&mut wrong_sum);
        reject_semantics(&wrong_sum);
    }
    let mut reused = good.clone();
    reused.owned_outputs[0].note.nf_key = reused.input.nf_key;
    reused.owned_outputs[0].note.nonce = reused.input.nonce;
    support::replace_change(&mut reused, 0);
    support::rebind(&mut reused);
    reject_semantics(&reused);
    let mut cross_asset_change = good;
    cross_asset_change.owned_outputs[0].note.asset = Asset::Native;
    support::replace_change(&mut cross_asset_change, 0);
    support::rebind(&mut cross_asset_change);
    reject_semantics(&cross_asset_change);
    let mut wide_inflation = support::max_withdrawal();
    wide_inflation.packet.outputs.push(OutputDescriptor::Fee {
        payer: Role::A, asset: Asset::Native, recipient: [10; 20], amount: U256::one(),
    });
    support::rebind(&mut wide_inflation);
    reject_semantics(&wide_inflation);
}

#[test]
fn canonical_private_stdin_and_bounded_public_files_are_fully_consumed() {
    let witness = support::received_token_partial();
    let private = witness.encode().unwrap();
    let public = witness.packet.encode().unwrap();
    let mut trailing = Zeroizing::new(vec![0; private.len() + 1]);
    trailing[..private.len()].copy_from_slice(&private);
    let oversized = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    for malformed in [&[][..], &private[..private.len() - 1], &trailing[..], &oversized[..]] {
        rejected(check(malformed));
        rejected(review(&public, malformed));
    }
    let mut trailing = public.clone();
    trailing.push(0);
    for malformed in [&[][..], &public[..public.len() - 1], &trailing[..], &vec![0; MAX_PACKET_BYTES + 1][..]] {
        rejected(review(malformed, &private));
    }
    let fill = fill_support::known_fill();
    rejected(check(&fill.a.encode().unwrap()));
    rejected(check(&fill_support::cancel_exit(&fill, Action::Exit).encode().unwrap()));
    rejected(review(&fill.packet.encode().unwrap(), &private));
    rejected(review(&fill_support::cancel_exit(&fill, Action::Exit).packet.encode().unwrap(), &private));
}

#[test]
fn private_argv_files_and_missing_stdin_opt_in_are_rejected_and_redacted() {
    for arguments in [
        vec!["check-note-withdrawal"],
        vec!["check-note-withdrawal", "--witness", "/private-withdrawal-sentinel"],
        vec!["check-note-withdrawal", "--witness-stdin", "--owner-seed", "private-key-sentinel"],
        vec!["review-note-withdrawal", "--packet", "/public-packet-sentinel"],
        vec!["review-note-withdrawal", "--packet", "/public-packet-sentinel", "--witness-stdin", "--role", "private-role-sentinel"],
    ] {
        let output = run(&arguments, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    let witness = support::received_token_partial();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("public-packet-sentinel");
    rejected(run(&["review-note-withdrawal", "--packet", missing.to_str().unwrap(), "--witness-stdin"], &witness.encode().unwrap()));
}
