//! Real native processes with generated synthetic keys; no SQL, network,
//! signing service, accepted roots, asset receipts or financial execution.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{MAX_PRIVATE_INPUT_BYTES, decrypt_output};
use ziquid_proofs::samechain::creation::NoteCreationWitness;
use ziquid_protocol::samechain::{Asset, MAX_PACKET_BYTES, OutputDescriptor, Role};
use ziquid_protocol::samechain::creation::{
    InitialOrder, NoteCreationJournal, NoteCreationPacket, validate_note_creation,
};

#[allow(dead_code)]
#[path = "../../proofs/tests/support/note_creation.rs"]
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
    if let Ok(witness) = NoteCreationWitness::decode(bytes) {
        for stream in [&output.stdout, &output.stderr] {
            for private in [&witness.owner_seed, &witness.blind, &witness.recovery_key,
                &witness.note.nf_key, &witness.note.nonce, &witness.note.salt] {
                not_disclosed(stream, private);
            }
            not_disclosed(stream, &witness.note.encode().unwrap());
            if let Some(order) = &witness.note.order {
                not_disclosed(stream, &order.encode().unwrap());
            }
        }
    }
    output
}

fn check(bytes: &[u8]) -> Output {
    run(&["check-note-creation", "--witness-stdin"], bytes)
}

fn review(packet: &[u8], bytes: &[u8]) -> Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(packet).unwrap();
    run(&["review-note-creation", "--packet", file.path().to_str().unwrap(), "--witness-stdin"], bytes)
}

fn rejected(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn public_bytes(json: &serde_json::Value, field: &str) -> Vec<u8> {
    serde_json::from_value(json[field].clone()).unwrap()
}

fn export(output: &Output, reviewing: bool, role: Role) -> serde_json::Value {
    assert!(output.status.success(), "note creation command rejected");
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], if reviewing { "review_note_creation" } else { "check_note_creation" });
    assert_eq!(json["role"], role as u8);
    assert!(json.get("action").is_none());
    for field in ["root_eligibility", "global_unspentness", "asset_backing"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["proof_certificate", "financial_execution", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    assert_eq!(json.get("journal").is_none(), reviewing);
    assert_eq!(json.get("consent_message").is_some(), reviewing);
    let packet = NoteCreationPacket::decode(&public_bytes(&json, "packet")).unwrap();
    assert_eq!(packet.role, role);
    assert_eq!(public_bytes(&json, "packet_digest"), packet.digest().unwrap());
    if !reviewing {
        let journal = NoteCreationJournal::decode(&public_bytes(&json, "journal")).unwrap();
        validate_note_creation(&packet, &journal).unwrap();
        assert_eq!(journal.amount, packet.amount);
        assert_eq!(journal.asset, packet.asset);
        assert_eq!(journal.payer, packet.payer);
        assert_eq!(journal.creation_nonce, packet.creation_nonce);
        assert_eq!(journal.owner_key, packet.owner_key);
        assert_eq!(journal.token, packet.token);
        assert_eq!(journal.order, packet.order);
    }
    json
}

fn reviewed_and_signed(mut witness: NoteCreationWitness) -> NoteCreationWitness {
    witness.consent = [0; 64];
    let public = witness.packet.encode().unwrap();
    let json = export(&review(&public, &witness.encode().unwrap()), true, witness.packet.role);
    assert_eq!(public_bytes(&json, "packet"), public);
    rejected(check(&witness.encode().unwrap()));
    // The CLI only reviews. This deterministic synthetic fixture signs outside it.
    witness.consent = SigningKey::from_bytes(&witness.owner_seed)
        .sign(&public_bytes(&json, "consent_message")).to_bytes();
    let checked = export(&check(&witness.encode().unwrap()), false, witness.packet.role);
    let packet = NoteCreationPacket::decode(&public_bytes(&checked, "packet")).unwrap();
    let recovered = decrypt_output(&packet.output, &witness.recovery_key,
        &packet.deployment.digest().unwrap(), &packet.owner_key).unwrap();
    assert_eq!(recovered, witness.note);
    witness
}

fn reject_semantics(witness: &NoteCreationWitness) {
    let private = witness.encode().unwrap();
    rejected(review(&witness.packet.encode().unwrap(), &private));
    rejected(check(&private));
}

#[test]
fn creation_check_rejects_empty_private_input_without_export() {
    rejected(check(&[]));
}

#[test]
fn ordinary_native_token_and_initial_a_b_review_sign_check_and_recover_exact_notes() {
    for witness in [support::ordinary_native(), support::ordinary_token(),
        support::initial_order_a(), support::initial_order_b()] {
        let witness = reviewed_and_signed(witness);
        if let Some(order) = &witness.note.order {
            assert_eq!(order.generation, 1);
            assert_eq!(witness.packet.order.unwrap().id, order.id);
        } else {
            assert!(witness.packet.order.is_none());
        }
    }
    let mut max = support::ordinary_native();
    max.note.value = U256::MAX;
    max.packet.amount = U256::MAX;
    support::replace_output(&mut max);
    reviewed_and_signed(max);
}

#[test]
fn freshly_consented_deposit_one_cannot_create_a_note_of_one_hundred() {
    let mut inflated = support::ordinary_native();
    inflated.packet.amount = U256::one();
    inflated.note.value = U256::from(100);
    support::replace_output(&mut inflated);
    reject_semantics(&inflated);
    inflated.packet.amount = U256::from(100);
    support::rebind(&mut inflated);
    reviewed_and_signed(inflated);
}

#[test]
fn independent_public_scope_rejects_deployment_payer_nonce_owner_role_and_terms_disagreement() {
    let good = support::ordinary_native();
    let private = good.encode().unwrap();
    let mutations: [fn(&mut NoteCreationPacket); 7] = [
        |p| p.deployment.chain_id += 1,
        |p| p.payer[0] ^= 1,
        |p| p.creation_nonce[0] ^= 1,
        |p| p.owner_key[0] ^= 1,
        |p| { p.role = Role::B; if let OutputDescriptor::Note { role, .. } = &mut p.output { *role = Role::B; } },
        |p| p.expiry += 1,
        |p| p.amount += U256::one(),
    ];
    for mutate in mutations {
        let mut independent = good.packet.clone();
        mutate(&mut independent);
        independent.terms_commitment = independent.terms_commitment_for(&good.blind).unwrap();
        rejected(review(&independent.encode().unwrap(), &private));
    }
    // A newly selected payer/nonce is a valid proposal, not account authentication.
    for mutate in [mutations[1], mutations[2]] {
        let mut changed = good.clone();
        mutate(&mut changed.packet);
        let old = changed.consent;
        support::rebind(&mut changed);
        changed.consent = old;
        rejected(check(&changed.encode().unwrap()));
        reviewed_and_signed(changed);
    }
    for consent in [[0; 64], [1; 64]] {
        let mut unsigned = good.clone();
        unsigned.consent = consent;
        export(&review(&unsigned.packet.encode().unwrap(), &unsigned.encode().unwrap()), true, unsigned.packet.role);
        rejected(check(&unsigned.encode().unwrap()));
    }
}

#[test]
fn signatures_old_consent_domains_blind_and_arbitrary_terms_cannot_authorize_creation() {
    let good = support::ordinary_native();
    let mut bad = good.clone();
    bad.consent[0] ^= 1;
    rejected(check(&bad.encode().unwrap()));
    let mut bad = good.clone();
    bad.blind[0] ^= 1;
    support::resign(&mut bad);
    reject_semantics(&bad);
    let mut bad = good.clone();
    bad.packet.terms_commitment = [191; 32];
    support::resign(&mut bad);
    reject_semantics(&bad);
    let fill = fill_support::known_fill();
    let withdrawal = withdrawal_support::received_token_partial();
    for consent in [fill.a.consent, withdrawal.consent] {
        let mut bad = good.clone();
        bad.consent = consent;
        rejected(check(&bad.encode().unwrap()));
    }
}

#[test]
fn freshly_consented_asset_deployment_owner_and_recovery_mismatches_export_nothing() {
    let good = support::ordinary_native();
    let mutations: [fn(&mut NoteCreationWitness); 11] = [
        |w| w.packet.asset = Asset::Token(w.packet.token),
        |w| w.packet.token[0] ^= 1,
        |w| w.packet.deployment.chain_id += 1,
        |w| w.owner_seed = [22; 32],
        |w| w.packet.owner_key = SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
        |w| w.recovery_key[0] ^= 1,
        |w| { if let OutputDescriptor::Note { ciphertext, .. } = &mut w.packet.output { ciphertext[24] ^= 1; } },
        |w| { if let OutputDescriptor::Note { commitment, .. } = &mut w.packet.output { commitment[0] ^= 1; } },
        |w| { if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut w.packet.output { recovery_key_commitment[0] ^= 1; } },
        |w| { if let OutputDescriptor::Note { ciphertext_version, .. } = &mut w.packet.output { *ciphertext_version += 1; } },
        |w| {
            w.packet.role = Role::B;
            if let OutputDescriptor::Note { role, .. } = &mut w.packet.output { *role = Role::B; }
        },
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut bad = good.clone();
        mutate(&mut bad);
        // An ordinary native note does not use the fixed token, so test token
        // substitution against a token note, where exact asset binding applies.
        if index == 1 {
            bad = support::ordinary_token();
            bad.packet.token[0] ^= 1;
            bad.packet.asset = Asset::Token(bad.packet.token);
        }
        support::rebind(&mut bad);
        reject_semantics(&bad);
    }
}

#[test]
fn initial_order_presence_identity_generation_pair_and_fee_role_are_authenticated() {
    let good = support::initial_order_a();
    let mut missing = good.clone();
    missing.packet.order = None;
    support::rebind(&mut missing);
    reject_semantics(&missing);
    let mut invented = support::ordinary_native();
    invented.packet.order = Some(InitialOrder { id: [11; 32] });
    support::rebind(&mut invented);
    reject_semantics(&invented);
    let mut wrong_id = good.clone();
    wrong_id.packet.order.as_mut().unwrap().id[0] ^= 1;
    support::rebind(&mut wrong_id);
    reject_semantics(&wrong_id);
    for mutate in [
        (|w: &mut NoteCreationWitness| w.note.order.as_mut().unwrap().generation = 2) as fn(&mut NoteCreationWitness),
        |w| {
            let policy = &mut w.note.order.as_mut().unwrap().policy;
            policy.buy_asset = Asset::Token([9; 20]);
            for fee in &mut policy.fee_policy.entries { fee.asset = policy.buy_asset; }
        },
        |w| { for fee in &mut w.note.order.as_mut().unwrap().policy.fee_policy.entries { fee.payer = Role::B; } },
    ] {
        let mut bad = good.clone();
        mutate(&mut bad);
        support::replace_output(&mut bad);
        reject_semantics(&bad);
    }
}

#[test]
fn zero_or_excess_initial_capacity_and_foreign_fee_bytes_fail_canonical_private_decode() {
    let witness = support::initial_order_a();
    let note = witness.note.encode().unwrap();
    let private = witness.encode().unwrap();
    let note_start = private.windows(note.len()).position(|bytes| bytes == &note[..]).unwrap();
    // Canonical note header, five 32-byte fields, Native tag, amount,
    // order-presence tag, order id and generation precede the capacity.
    let capacity = note_start + b"Z2Z_SAMECHAIN_NOTE_OPENING\0".len()
        + 2 + 160 + 1 + 32 + 1 + 32 + 8;
    for remaining in [U256::zero(), witness.note.value + U256::one()] {
        let mut bad = witness.encode().unwrap();
        remaining.to_big_endian(&mut bad[capacity..capacity + 32]);
        rejected(check(&bad));
        rejected(review(&witness.packet.encode().unwrap(), &bad));
    }
    // Policy rejects a fee in neither sell nor buy asset during decode.
    // Mutate the private fee address, not the public packet or encrypted copy.
    let policy = witness.note.order.as_ref().unwrap().policy.encode().unwrap();
    let policy_start = private.windows(policy.len()).position(|bytes| bytes == &policy[..]).unwrap();
    let fee_address = policy_start + policy.len() - 32 - 20 - 20;
    let mut bad = witness.encode().unwrap();
    bad[fee_address] ^= 1;
    rejected(check(&bad));
    rejected(review(&witness.packet.encode().unwrap(), &bad));
}

#[allow(dead_code)]
#[path = "../../proofs/tests/support/ordinary_withdrawal.rs"]
mod withdrawal_support;

#[test]
fn canonical_creation_transport_rejects_trailing_oversized_and_old_frames() {
    let witness = support::ordinary_native();
    let private = witness.encode().unwrap();
    let public = witness.packet.encode().unwrap();
    let mut trailing = Zeroizing::new(vec![0; private.len() + 1]);
    trailing[..private.len()].copy_from_slice(&private);
    let oversized = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    for malformed in [&[][..], &private[..private.len() - 1], &trailing[..], &oversized[..]] {
        rejected(check(malformed));
        rejected(review(&public, malformed));
    }
    let mut wrong_schema = witness.encode().unwrap();
    let schema = b"Z2Z_SAMECHAIN_NOTE_CREATION_WITNESS\0".len();
    wrong_schema[schema..schema + 2].copy_from_slice(&2u16.to_be_bytes());
    rejected(check(&wrong_schema));
    rejected(review(&public, &wrong_schema));
    let mut trailing = public.clone();
    trailing.push(0);
    for malformed in [&[][..], &public[..public.len() - 1], &trailing[..], &vec![0; MAX_PACKET_BYTES + 1][..]] {
        rejected(review(malformed, &private));
    }
    let fill = fill_support::known_fill();
    let withdrawal = withdrawal_support::received_token_partial();
    for old in [fill.a.encode().unwrap(), withdrawal.encode().unwrap()] {
        rejected(check(&old));
    }
    rejected(review(&fill.packet.encode().unwrap(), &private));
    rejected(review(&withdrawal.packet.encode().unwrap(), &private));
}

#[test]
fn private_argv_files_role_flags_and_missing_stdin_opt_in_are_redacted_and_rejected() {
    for arguments in [
        vec!["check-note-creation"],
        vec!["check-note-creation", "--witness", "/private-creation-sentinel"],
        vec!["check-note-creation", "--witness-stdin", "--owner-seed", "private-key-sentinel"],
        vec!["review-note-creation", "--packet", "/public-creation-sentinel"],
        vec!["review-note-creation", "--packet", "/public-creation-sentinel", "--witness-stdin", "--role", "private-role-sentinel"],
    ] {
        let output = run(&arguments, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    let witness = support::ordinary_native();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("public-creation-sentinel");
    rejected(run(&["review-note-creation", "--packet", missing.to_str().unwrap(), "--witness-stdin"], &witness.encode().unwrap()));
}
