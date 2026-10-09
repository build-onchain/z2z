//! CONTROLLED fresh synthetic owner capabilities, actual AEAD and private-stdin review.
//! No signing, backup, proof, admitted root, asset receipt or financial execution.
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{RelationError, decrypt_output};
use ziquid_proofs::samechain::creation::{
    NoteCreationWitness, note_creation_consent_message, review_note_creation,
    verify_note_creation_relation,
};
use ziquid_protocol::samechain::{
    Asset, Deployment, FeePolicy, FeeRule, OrderPolicy, OutputDescriptor, Role, SamechainError,
};
use ziquid_runtime::samechain::preparation::{
    CreationRequest, InitialOrderRequest, prepare_note_creation,
};

type RequestMutation = fn(&mut CreationRequest);
type OrderMutation = fn(&mut InitialOrderRequest);

fn request(role: Role, asset: Asset, initial_order: bool) -> CreationRequest {
    let buy_asset = match asset {
        Asset::Native => Asset::Token([7; 20]),
        Asset::Token(_) => Asset::Native,
    };
    CreationRequest {
        deployment: Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
            verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 },
        token: [7; 20], payer: [8; 20], role, asset, amount: U256::from(105), expiry: 700,
        order: initial_order.then(|| InitialOrderRequest {
            remaining_sell: U256::from(100),
            policy: OrderPolicy { sell_asset: asset, buy_asset,
                min_buy_num: U256::from(3), min_sell_den: U256::from(2),
                fee_policy: FeePolicy { entries: vec![FeeRule {
                    payer: role, asset: buy_asset, beneficiary: [9; 20], max_atoms: U256::from(4),
                }] } },
        }),
    }
}

fn assert_opening(request: &CreationRequest, witness: &NoteCreationWitness) {
    let packet = &witness.packet;
    assert_eq!(packet.deployment, request.deployment);
    assert_eq!(packet.token, request.token);
    assert_eq!(packet.payer, request.payer);
    assert_eq!(packet.role, request.role);
    assert_eq!(packet.asset, request.asset);
    assert_eq!(packet.amount, request.amount);
    assert_eq!(packet.expiry, request.expiry);
    assert_eq!(witness.consent, [0; 64]);
    assert_ne!(packet.creation_nonce, [0; 32]);
    assert_eq!(packet.owner_key,
        SigningKey::from_bytes(&witness.owner_seed).verifying_key().to_bytes());
    assert_ne!(witness.owner_seed, [0; 32]);
    assert_ne!(witness.blind, [0; 32]);
    assert_ne!(witness.recovery_key, [0; 32]);
    packet.validate_commitment(&witness.blind).unwrap();
    let deployment_digest = request.deployment.digest().unwrap();
    let recovered = decrypt_output(&packet.output, &witness.recovery_key,
        &deployment_digest, &packet.owner_key).unwrap();
    assert_eq!(recovered, witness.note);
    assert_eq!(recovered.deployment_digest, deployment_digest);
    assert_eq!(recovered.owner_key, packet.owner_key);
    assert_eq!(recovered.asset, request.asset);
    assert_eq!(recovered.value, request.amount);
    assert_ne!(recovered.nf_key, [0; 32]);
    assert_ne!(recovered.nonce, [0; 32]);
    assert_ne!(recovered.salt, [0; 32]);
    let OutputDescriptor::Note { role, commitment, ciphertext, .. } = &packet.output else {
        panic!("creation must return a recipient note");
    };
    assert_eq!(*role, request.role);
    assert_eq!(*commitment, recovered.commitment().unwrap());
    assert!(ciphertext[..24].iter().any(|byte| *byte != 0));
    match (&request.order, &recovered.order, packet.order) {
        (None, None, None) => {}
        (Some(expected), Some(order), Some(public)) => {
            assert_ne!(public.id, [0; 32]);
            assert_eq!(order.id, public.id);
            assert_eq!(order.generation, 1);
            assert_eq!(order.remaining_sell, expected.remaining_sell);
            assert_eq!(order.policy, expected.policy);
        }
        _ => panic!("initial order presence differs from the independent request"),
    }
}

fn assert_private_not_disclosed(output: &[u8], private: &[u8]) {
    assert!(!private.is_empty());
    assert!(!output.windows(private.len()).any(|bytes| bytes == private), "private bytes disclosed");
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).unwrap();
    assert!(!output.windows(json.len()).any(|bytes| bytes == &json[..]), "private array disclosed");
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut hex = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *hex, "{byte:02x}").unwrap(); }
        assert!(!output.windows(64).any(|bytes| bytes.eq_ignore_ascii_case(hex.as_bytes())),
            "private hex disclosed");
    }
}

fn review_in_cli(request: &CreationRequest, witness: &NoteCreationWitness) {
    // The only file contains public bytes. The private canonical codec already
    // returns a guarded buffer; send it solely over the child's explicit stdin.
    let public = witness.packet.encode().unwrap();
    let mut packet_file = tempfile::NamedTempFile::new().unwrap();
    packet_file.write_all(&public).unwrap();
    let private = witness.encode().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "review-note-creation", "--packet",
            packet_file.path().to_str().unwrap(), "--witness-stdin"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "fresh unsigned creation review rejected");
    assert!(output.stderr.is_empty(), "review emitted an unexpected diagnostic");
    for stream in [&output.stdout, &output.stderr] {
        assert_private_not_disclosed(stream, &private);
        assert_private_not_disclosed(stream, &witness.note.encode().unwrap());
        for secret in [&witness.owner_seed, &witness.blind, &witness.recovery_key,
            &witness.note.nf_key, &witness.note.nonce, &witness.note.salt]
        {
            assert_private_not_disclosed(stream, secret);
        }
        if let Some(order) = &witness.note.order {
            assert_private_not_disclosed(stream, &order.encode().unwrap());
        }
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut fields: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(fields, [
        "asset_backing", "consent_message", "evidence", "financial_execution",
        "global_unspentness", "kind", "packet", "packet_digest", "proof_certificate",
        "role", "root_eligibility", "strict_matching_privacy",
    ]);
    assert_eq!(json["kind"], "review_note_creation");
    assert_eq!(json["role"], request.role as u8);
    assert_eq!(json["evidence"], "native_owner_preconsent_review");
    for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["financial_execution", "proof_certificate", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    let message = review_note_creation(&witness.packet, witness, &request.deployment,
        request.payer, witness.packet.creation_nonce).unwrap();
    for (field, expected) in [
        ("packet", public),
        ("packet_digest", witness.packet.digest().unwrap().to_vec()),
        ("consent_message", message.to_vec()),
    ] {
        // Existing CLI exports arrays, not a private witness or alternate hex format.
        let bytes: Vec<u8> = serde_json::from_value(json[field].clone()).unwrap();
        assert_eq!(bytes, expected);
    }
}

fn review_unsigned(request: &CreationRequest, witness: &NoteCreationWitness) {
    assert_opening(request, witness);
    let packet = &witness.packet;
    let message = review_note_creation(packet, witness, &request.deployment,
        request.payer, packet.creation_nonce).unwrap();
    assert_eq!(message, note_creation_consent_message(packet).unwrap());
    assert_eq!(verify_note_creation_relation(witness), Err(RelationError::Signature));
    let mut wrong_deployment = request.deployment;
    wrong_deployment.chain_id += 1;
    assert_eq!(review_note_creation(packet, witness, &wrong_deployment,
        request.payer, packet.creation_nonce),
        Err(RelationError::Protocol(SamechainError::InvalidDeployment)));
    let mut wrong_payer = request.payer;
    wrong_payer[0] ^= 1;
    assert_eq!(review_note_creation(packet, witness, &request.deployment,
        wrong_payer, packet.creation_nonce), Err(RelationError::Manifest));
    let mut wrong_nonce = packet.creation_nonce;
    wrong_nonce[0] ^= 1;
    assert_eq!(review_note_creation(packet, witness, &request.deployment,
        request.payer, wrong_nonce), Err(RelationError::Manifest));
    review_in_cli(request, witness);
    assert_eq!(witness.consent, [0; 64]);
}

#[test]
fn fresh_ordinary_native_token_and_initial_a_b_decrypt_review_unsigned_and_cli() {
    // Every opening, key and ciphertext comes from the real fresh constructor;
    // no deterministic witness generator, signing helper or replacement output.
    for request in [request(Role::A, Asset::Native, false),
        request(Role::B, Asset::Token([7; 20]), false),
        request(Role::A, Asset::Native, true),
        request(Role::B, Asset::Token([7; 20]), true)]
    {
        let witness = prepare_note_creation(&request).unwrap();
        review_unsigned(&request, &witness);
    }
}

#[test]
fn full_u256_creation_and_initial_capacity_do_not_infer_asset_from_role() {
    // Role is not an intrinsic Native/token mapping. Exercise both reversed
    // pairs with full-width backing/capacity and a full-width price/fee policy.
    for mut request in [request(Role::A, Asset::Token([7; 20]), true),
        request(Role::B, Asset::Native, true)]
    {
        request.amount = U256::MAX;
        let order = request.order.as_mut().unwrap();
        order.remaining_sell = U256::MAX;
        order.policy.min_buy_num = U256::MAX;
        order.policy.min_sell_den = U256::MAX - U256::one();
        order.policy.fee_policy.entries[0].max_atoms = U256::MAX;
        let witness = prepare_note_creation(&request).unwrap();
        review_unsigned(&request, &witness);
    }
    let mut ordinary = request(Role::B, Asset::Token([7; 20]), false);
    ordinary.amount = U256::MAX;
    let witness = prepare_note_creation(&ordinary).unwrap();
    review_unsigned(&ordinary, &witness);
    let mut native = request(Role::A, Asset::Native, false);
    native.token = [10; 20];
    native.amount = U256::MAX;
    let witness = prepare_note_creation(&native).unwrap();
    review_unsigned(&native, &witness);
    let mut zero_cap = request(Role::B, Asset::Native, true);
    zero_cap.order.as_mut().unwrap().policy.fee_policy.entries[0].max_atoms = U256::zero();
    let witness = prepare_note_creation(&zero_cap).unwrap();
    review_unsigned(&zero_cap, &witness);
}

#[test]
fn repeated_creation_has_fresh_owner_nullifier_nonce_ciphertext_and_initial_identity() {
    for request in [request(Role::A, Asset::Native, false),
        request(Role::B, Asset::Token([7; 20]), true)]
    {
        let first = prepare_note_creation(&request).unwrap();
        let second = prepare_note_creation(&request).unwrap();
        assert_opening(&request, &first);
        assert_opening(&request, &second);
        assert_ne!(first.packet.owner_key, second.packet.owner_key);
        assert_ne!(first.note.nullifier().unwrap(), second.note.nullifier().unwrap());
        assert_ne!(first.packet.creation_nonce, second.packet.creation_nonce);
        assert_ne!(first.packet.output, second.packet.output);
        assert_ne!(first.packet.terms_commitment, second.packet.terms_commitment);
        if request.order.is_some() {
            assert_ne!(first.packet.order.unwrap().id, second.packet.order.unwrap().id);
        }
    }
}

#[test]
fn invalid_creation_requests_never_return_an_owner_capability() {
    let ordinary_mutations: [(RequestMutation, SamechainError); 9] = [
        (|r| r.deployment.chain_id = 0, SamechainError::InvalidDeployment),
        (|r| r.deployment.authority = [0; 20], SamechainError::InvalidDeployment),
        (|r| r.deployment.schema = 0, SamechainError::UnsupportedSchema),
        (|r| r.token = [0; 20], SamechainError::InvalidAsset),
        (|r| r.asset = Asset::Token([6; 20]), SamechainError::InvalidAsset),
        (|r| r.asset = Asset::Token([0; 20]), SamechainError::InvalidAsset),
        (|r| r.payer = [0; 20], SamechainError::InvalidTerms),
        (|r| r.amount = U256::zero(), SamechainError::InvalidTerms),
        (|r| r.expiry = 0, SamechainError::InvalidTerms),
    ];
    for (mutate, expected) in ordinary_mutations {
        let mut bad = request(Role::A, Asset::Native, false);
        mutate(&mut bad);
        assert_eq!(prepare_note_creation(&bad), Err(RelationError::Protocol(expected)));
    }
    let order_mutations: [(OrderMutation, RelationError); 12] = [
        (|o| o.remaining_sell = U256::zero(), RelationError::Note),
        (|o| o.remaining_sell = U256::from(106), RelationError::Note),
        (|o| { o.policy.sell_asset = Asset::Token([7; 20]);
            o.policy.buy_asset = Asset::Native;
            o.policy.fee_policy.entries[0].asset = Asset::Native; }, RelationError::Note),
        (|o| o.policy.buy_asset = Asset::Native,
            RelationError::Protocol(SamechainError::InvalidPolicy)),
        (|o| { o.policy.buy_asset = Asset::Token([6; 20]);
            o.policy.fee_policy.entries[0].asset = Asset::Token([6; 20]); }, RelationError::Policy),
        (|o| o.policy.min_buy_num = U256::zero(),
            RelationError::Protocol(SamechainError::InvalidPolicy)),
        (|o| o.policy.min_sell_den = U256::zero(),
            RelationError::Protocol(SamechainError::InvalidPolicy)),
        (|o| o.policy.fee_policy.entries[0].payer = Role::B,
            RelationError::Protocol(SamechainError::InvalidFeePolicy)),
        (|o| o.policy.fee_policy.entries[0].asset = Asset::Token([6; 20]),
            RelationError::Protocol(SamechainError::InvalidPolicy)),
        (|o| o.policy.fee_policy.entries[0].beneficiary = [0; 20],
            RelationError::Protocol(SamechainError::InvalidFeePolicy)),
        (|o| { let fee = o.policy.fee_policy.entries[0]; o.policy.fee_policy.entries.push(fee); },
            RelationError::Protocol(SamechainError::NonCanonical)),
        (|o| o.policy.sell_asset = Asset::Token([0; 20]),
            RelationError::Protocol(SamechainError::InvalidAsset)),
    ];
    for (mutate, expected) in order_mutations {
        let mut bad = request(Role::A, Asset::Native, true);
        mutate(bad.order.as_mut().unwrap());
        assert_eq!(prepare_note_creation(&bad), Err(expected));
    }
}

#[test]
fn freshly_prepared_capability_review_rejects_rebound_public_amount_asset_and_order_identity() {
    let request = request(Role::A, Asset::Native, true);
    let witness = prepare_note_creation(&request).unwrap();
    let mutations: [fn(&mut NoteCreationWitness); 4] = [
        |w| w.packet.amount += U256::one(),
        |w| w.packet.asset = Asset::Token(w.packet.token),
        |w| w.packet.order.as_mut().unwrap().id[0] ^= 1,
        |w| w.packet.order = None,
    ];
    for mutate in mutations {
        let mut bad = witness.clone();
        mutate(&mut bad);
        // Open each altered public commitment honestly. Reject the real private
        // semantic disagreement, not merely a stale commitment or zero consent.
        bad.packet.terms_commitment = bad.packet.terms_commitment_for(&bad.blind).unwrap();
        assert_eq!(review_note_creation(&bad.packet, &bad, &request.deployment,
            request.payer, bad.packet.creation_nonce), Err(RelationError::Note));
        assert_eq!(verify_note_creation_relation(&bad), Err(RelationError::Note));
    }
    let mut bad_payer = witness.clone();
    bad_payer.packet.payer[0] ^= 1;
    bad_payer.packet.terms_commitment =
        bad_payer.packet.terms_commitment_for(&bad_payer.blind).unwrap();
    assert_eq!(review_note_creation(&bad_payer.packet, &bad_payer, &request.deployment,
        request.payer, bad_payer.packet.creation_nonce), Err(RelationError::Manifest));
}
