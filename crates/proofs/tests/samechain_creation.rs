use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_protocol::samechain::{Asset,Role};
use ziquid_protocol::samechain::creation::NoteCreationPacket;
use ziquid_proofs::samechain::{prepare_output,RelationError};
use ziquid_proofs::samechain::creation::{NoteCreationWitness,note_creation_consent_message,review_note_creation,verify_note_creation_relation};
#[path="support/samechain.rs"]
#[allow(dead_code)]
mod support;
use support as fill_support;
#[test]
fn one_atom_deposit_terms_cannot_authenticate_one_hundred_atom_note() {
 let note=support::note(Role::A,151,Asset::Native,U256::from(100),None);
 let recovery_key=[152;32];
 let output=prepare_output(&note,Role::A,&recovery_key,[153;24]).unwrap();
 let mut packet=NoteCreationPacket{deployment:support::deployment(),token:[7;20],payer:[8;20],creation_nonce:[154;32],owner_key:note.owner_key,role:Role::A,asset:Asset::Native,amount:U256::one(),order:None,output,expiry:700,terms_commitment:[0;32]};
 let blind=[155;32];packet.terms_commitment=packet.terms_commitment_for(&blind).unwrap();
 let consent=SigningKey::from_bytes(&[21;32]).sign(&note_creation_consent_message(&packet).unwrap()).to_bytes();
 let witness=NoteCreationWitness{packet:packet.clone(),blind,owner_seed:[21;32],note,recovery_key,consent};
 assert_eq!(review_note_creation(&packet,&witness,&packet.deployment,packet.payer,packet.creation_nonce),Err(RelationError::Note));
 assert_eq!(verify_note_creation_relation(&witness),Err(RelationError::Note));
}

#[path = "support/note_creation.rs"]
#[allow(dead_code)]
mod creation;

use ziquid_protocol::samechain::{FeeRule, OutputDescriptor, SamechainError};
use ziquid_protocol::samechain::creation::{InitialOrder, NoteCreationJournal, validate_note_creation};
use ziquid_proofs::samechain::{decrypt_output, MAX_PRIVATE_INPUT_BYTES};

fn review(witness: &NoteCreationWitness) -> Result<Vec<u8>, RelationError> {
    let packet = &witness.packet;
    review_note_creation(packet, witness, &packet.deployment, packet.payer,
        packet.creation_nonce).map(|message| message.to_vec())
}

fn reject_both(witness: &NoteCreationWitness, error: RelationError) {
    assert_eq!(review(witness), Err(error));
    assert_eq!(verify_note_creation_relation(witness), Err(error));
}

#[test]
fn actual_recovered_ordinary_and_initial_order_notes_review_sign_and_roundtrip() {
    for mut witness in [creation::ordinary_native(), creation::ordinary_token(),
        creation::initial_order_a(), creation::initial_order_b()]
    {
        witness.consent = [0; 64];
        let message = review(&witness).unwrap();
        assert_eq!(verify_note_creation_relation(&witness), Err(RelationError::Signature));
        witness.consent = SigningKey::from_bytes(&witness.owner_seed).sign(&message).to_bytes();
        let journal = verify_note_creation_relation(&witness).unwrap();
        assert_eq!(journal.amount, witness.note.value);
        assert_eq!(journal.asset, witness.note.asset);
        assert_eq!(journal.payer, [8; 20]);
        assert_eq!(journal.creation_nonce, [154; 32]);
        assert_eq!(journal.note_commitment, witness.note.commitment().unwrap());
        assert_eq!(journal.order, witness.packet.order);
        validate_note_creation(&witness.packet, &journal).unwrap();
        assert_eq!(NoteCreationJournal::decode(&journal.encode().unwrap()).unwrap(), journal);
        let encoded = witness.encode().unwrap();
        let decoded = NoteCreationWitness::decode(&encoded).unwrap();
        assert_eq!(decoded, witness);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(verify_note_creation_relation(&decoded).unwrap(), journal);
        assert_eq!(decrypt_output(&witness.packet.output, &witness.recovery_key,
            &witness.note.deployment_digest, &witness.note.owner_key).unwrap(), witness.note);
    }
}

#[test]
fn max_u256_amount_is_exact_and_no_narrowing_can_hide_mismatch() {
    let mut witness = creation::ordinary_native();
    witness.note.value = U256::MAX;
    witness.packet.amount = U256::MAX;
    creation::replace_output(&mut witness);
    assert_eq!(verify_note_creation_relation(&witness).unwrap().amount, U256::MAX);
    witness.packet.amount = U256::MAX - U256::one();
    creation::rebind(&mut witness);
    // Hostile semantics remain transportable; framing is not semantic approval.
    let transported = NoteCreationWitness::decode(&witness.encode().unwrap()).unwrap();
    reject_both(&transported, RelationError::Note);
}

#[test]
fn freshly_signed_asset_fixed_token_deployment_and_owner_mismatch_reject() {
    let mut asset = creation::ordinary_native();
    asset.packet.asset = Asset::Token(asset.packet.token);
    creation::rebind(&mut asset);
    reject_both(&asset, RelationError::Note);

    let mut token = creation::ordinary_token();
    token.packet.token = [9; 20];
    token.packet.asset = Asset::Token([9; 20]);
    creation::rebind(&mut token);
    reject_both(&token, RelationError::Note);

    let mut deployment = creation::ordinary_native();
    deployment.packet.deployment.chain_id += 1;
    creation::rebind(&mut deployment);
    reject_both(&deployment, RelationError::Note);

    let mut owner = creation::ordinary_native();
    owner.owner_seed = [22; 32];
    owner.packet.owner_key = SigningKey::from_bytes(&owner.owner_seed).verifying_key().to_bytes();
    creation::rebind(&mut owner);
    reject_both(&owner, RelationError::Note);

    let mut seed = creation::ordinary_native();
    seed.owner_seed = [22; 32];
    creation::resign(&mut seed);
    reject_both(&seed, RelationError::Key);
}

#[test]
fn payer_nonce_changes_are_valid_proposals_but_selected_scope_and_stale_consent_reject() {
    let mut witness = creation::ordinary_native();
    let selected = witness.packet.clone();
    witness.packet.payer = [9; 20];
    witness.packet.creation_nonce = [156; 32];
    let old_consent = witness.consent;
    creation::rebind(&mut witness);
    verify_note_creation_relation(&witness).unwrap();
    assert_eq!(review_note_creation(&witness.packet, &witness, &selected.deployment,
        selected.payer, witness.packet.creation_nonce), Err(RelationError::Manifest));
    assert_eq!(review_note_creation(&witness.packet, &witness, &selected.deployment,
        witness.packet.payer, selected.creation_nonce), Err(RelationError::Manifest));
    assert_eq!(review_note_creation(&witness.packet, &witness, &selected.deployment,
        [0; 20], witness.packet.creation_nonce), Err(RelationError::Manifest));
    assert_eq!(review_note_creation(&witness.packet, &witness, &selected.deployment,
        witness.packet.payer, [0; 32]), Err(RelationError::Manifest));
    witness.consent = old_consent;
    review(&witness).unwrap();
    assert_eq!(verify_note_creation_relation(&witness), Err(RelationError::Signature));
}

#[test]
fn freshly_consented_payer_or_nonce_change_is_not_itself_invalid() {
    for change_payer in [true, false] {
        let mut witness = creation::ordinary_native();
        if change_payer { witness.packet.payer = [9; 20]; }
        else { witness.packet.creation_nonce = [156; 32]; }
        creation::rebind(&mut witness);
        review(&witness).unwrap();
        let journal = verify_note_creation_relation(&witness).unwrap();
        assert_eq!(journal.payer, witness.packet.payer);
        assert_eq!(journal.creation_nonce, witness.packet.creation_nonce);
    }
}

#[test]
fn descriptive_journal_exports_public_scope_not_private_creation_openings() {
    let witness = creation::initial_order_a();
    let journal = verify_note_creation_relation(&witness).unwrap();
    let bytes = journal.encode().unwrap();
    assert_eq!(journal.owner_key, witness.packet.owner_key);
    assert_eq!(journal.token, [7; 20]);
    assert_eq!(journal.role, Role::A);
    assert_eq!(journal.amount, U256::from(105));
    assert_eq!(journal.order, Some(InitialOrder { id: [11; 32] }));
    for secret in [&witness.blind, &witness.owner_seed, &witness.recovery_key,
        &witness.note.nf_key, &witness.note.nonce, &witness.note.salt]
    {
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    }
}

#[test]
fn unsigned_review_requires_exact_public_packet_and_independent_deployment() {
    let witness = creation::ordinary_native();
    let mut selected = witness.packet.deployment;
    selected.chain_id += 1;
    assert_eq!(review_note_creation(&witness.packet, &witness, &selected,
        witness.packet.payer, witness.packet.creation_nonce),
        Err(RelationError::Protocol(SamechainError::InvalidDeployment)));
    let mut packet = witness.packet.clone();
    packet.expiry += 1;
    assert_eq!(review_note_creation(&packet, &witness, &packet.deployment,
        packet.payer, packet.creation_nonce), Err(RelationError::Manifest));
}

#[test]
fn arbitrary_terms_and_blind_fail_before_consent_in_both_entrypoints() {
    let mut terms = creation::ordinary_native();
    terms.packet.terms_commitment = [201; 32];
    creation::resign(&mut terms);
    reject_both(&terms, RelationError::Protocol(SamechainError::OpeningMismatch));
    let mut blind = creation::ordinary_native();
    blind.blind = [202; 32];
    creation::resign(&mut blind);
    reject_both(&blind, RelationError::Protocol(SamechainError::OpeningMismatch));
}

#[test]
fn fresh_consent_cannot_replace_actual_ciphertext_recovery_version_commitment_or_role() {
    let mut key = creation::ordinary_native();
    key.recovery_key = [203; 32];
    creation::resign(&mut key);
    reject_both(&key, RelationError::Ciphertext);

    let mut ciphertext = creation::ordinary_native();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut ciphertext.packet.output {
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
    }
    creation::rebind(&mut ciphertext);
    reject_both(&ciphertext, RelationError::Ciphertext);

    let mut version = creation::ordinary_native();
    if let OutputDescriptor::Note { ciphertext_version, .. } = &mut version.packet.output {
        *ciphertext_version += 1;
    }
    creation::rebind(&mut version);
    reject_both(&version, RelationError::Ciphertext);

    let mut commitment = creation::ordinary_native();
    if let OutputDescriptor::Note { commitment, .. } = &mut commitment.packet.output {
        *commitment = [204; 32];
    }
    creation::rebind(&mut commitment);
    reject_both(&commitment, RelationError::Note);

    let mut role = creation::ordinary_native();
    role.packet.role = Role::B;
    if let OutputDescriptor::Note { role, .. } = &mut role.packet.output { *role = Role::B; }
    creation::rebind(&mut role);
    reject_both(&role, RelationError::Ciphertext);

    let mut opening = creation::ordinary_native();
    opening.note.salt = [205; 32];
    creation::resign(&mut opening);
    reject_both(&opening, RelationError::Note);
}

#[test]
fn initial_order_presence_id_generation_capacity_and_fixed_pair_are_authenticated() {
    let mut hidden = creation::initial_order_a();
    hidden.packet.order = None;
    creation::rebind(&mut hidden);
    reject_both(&hidden, RelationError::Note);
    let mut invented = creation::ordinary_native();
    invented.packet.order = Some(InitialOrder { id: [210; 32] });
    creation::rebind(&mut invented);
    reject_both(&invented, RelationError::Note);
    let mut id = creation::initial_order_a();
    id.packet.order.as_mut().unwrap().id = [211; 32];
    creation::rebind(&mut id);
    reject_both(&id, RelationError::Note);
    let mut generation = creation::initial_order_a();
    generation.note.order.as_mut().unwrap().generation = 2;
    creation::replace_output(&mut generation);
    reject_both(&generation, RelationError::Note);
    let mut capacity = creation::initial_order_a();
    capacity.note.order.as_mut().unwrap().remaining_sell = capacity.note.value + U256::one();
    creation::resign(&mut capacity);
    reject_both(&capacity, RelationError::Note);
    let mut zero_capacity = creation::initial_order_a();
    zero_capacity.note.order.as_mut().unwrap().remaining_sell = U256::zero();
    creation::resign(&mut zero_capacity);
    reject_both(&zero_capacity, RelationError::Note);
    let mut pair = creation::initial_order_a();
    let policy = &mut pair.note.order.as_mut().unwrap().policy;
    policy.buy_asset = Asset::Token([9; 20]);
    policy.fee_policy.entries[0].asset = policy.buy_asset;
    creation::replace_output(&mut pair);
    reject_both(&pair, RelationError::Policy);
    let mut token_pair = creation::initial_order_b();
    let policy = &mut token_pair.note.order.as_mut().unwrap().policy;
    policy.buy_asset = Asset::Token([9; 20]);
    policy.fee_policy.entries[0].asset = policy.buy_asset;
    creation::replace_output(&mut token_pair);
    reject_both(&token_pair, RelationError::Policy);
}

#[test]
fn initial_order_fee_role_and_canonical_entries_cannot_be_substituted() {
    let mut role = creation::initial_order_a();
    role.note.order.as_mut().unwrap().policy.fee_policy.entries[0].payer = Role::B;
    creation::replace_output(&mut role);
    reject_both(&role, RelationError::Protocol(SamechainError::InvalidFeePolicy));
    let mut duplicate = creation::initial_order_a();
    let entries = &mut duplicate.note.order.as_mut().unwrap().policy.fee_policy.entries;
    entries.push(entries[0]);
    creation::resign(&mut duplicate);
    reject_both(&duplicate, RelationError::Protocol(SamechainError::NonCanonical));
    let mut third_asset = creation::initial_order_a();
    third_asset.note.order.as_mut().unwrap().policy.fee_policy.entries = vec![FeeRule {
        payer: Role::A, asset: Asset::Token([9; 20]), beneficiary: [8; 20], max_atoms: U256::one(),
    }];
    creation::resign(&mut third_asset);
    reject_both(&third_asset, RelationError::Protocol(SamechainError::InvalidPolicy));
}

#[test]
fn old_fill_and_exit_consent_domains_do_not_authorize_creation() {
    let fill = support::known_fill();
    let exit = support::cancel_exit(&fill, ziquid_protocol::samechain::Action::Exit);
    let mut witness = creation::ordinary_native();
    for consent in [fill.a.consent, exit.consent] {
        witness.consent = consent;
        review(&witness).unwrap();
        assert_eq!(verify_note_creation_relation(&witness), Err(RelationError::Signature));
    }
}

#[path = "support/ordinary_withdrawal.rs"]
#[allow(dead_code)]
mod withdrawal;

#[test]
fn ordinary_withdrawal_consent_does_not_authorize_note_creation() {
    let mut witness = creation::ordinary_native();
    let old = withdrawal::from_note(witness.note.clone(), witness.owner_seed,
        witness.note.value, U256::zero(), U256::zero());
    witness.consent = old.consent;
    review(&witness).unwrap();
    assert_eq!(verify_note_creation_relation(&witness), Err(RelationError::Signature));
}

#[test]
fn invalid_note_secrets_and_value_reject_even_with_fresh_owner_consent() {
    for field in 0..4 {
        let mut witness = creation::ordinary_native();
        match field {
            0 => witness.note.nf_key = [0; 32],
            1 => witness.note.nonce = [0; 32],
            2 => witness.note.salt = [0; 32],
            _ => witness.note.value = U256::zero(),
        }
        creation::resign(&mut witness);
        reject_both(&witness, RelationError::Note);
        assert_eq!(witness.encode(), Err(RelationError::Note));
    }
}

#[test]
fn private_codec_rejects_nested_length_suffix_zero_keys_and_order_capacity() {
    let witness = creation::initial_order_a();
    let encoded = witness.encode().unwrap();
    let header = b"Z2Z_SAMECHAIN_NOTE_CREATION_WITNESS\0".len() + 2;
    let packet_len = u32::from_be_bytes(encoded[header..header + 4].try_into().unwrap()) as usize;
    let blind = header + 4 + packet_len;
    let note_length = blind + 64;
    let note_len = u32::from_be_bytes(encoded[note_length..note_length + 4].try_into().unwrap()) as usize;
    let note_start = note_length + 4;
    let recovery = note_start + note_len;
    for offset in [blind, blind + 32, recovery] {
        let mut wrong = encoded.clone();
        wrong[offset..offset + 32].fill(0);
        assert_eq!(NoteCreationWitness::decode(&wrong), Err(RelationError::Key));
    }
    let mut oversized_note = encoded.clone();
    oversized_note[note_length..note_length + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteCreationWitness::decode(&oversized_note), Err(RelationError::ResourceLimit));
    let note_body = note_start + b"Z2Z_SAMECHAIN_NOTE_OPENING\0".len() + 2;
    let order_start = note_body + 160 + 1 + 32 + 1; // native asset + value + order tag
    for amount in [U256::zero(), U256::from(106)] {
        let mut wrong = encoded.clone();
        amount.to_big_endian(&mut wrong[order_start + 40..order_start + 72]);
        assert_eq!(NoteCreationWitness::decode(&wrong), Err(RelationError::Note));
    }
    let mut nested_suffix = zeroize::Zeroizing::new(Vec::with_capacity(encoded.len() + 1));
    nested_suffix.extend_from_slice(&encoded[..recovery]);
    nested_suffix.push(0);
    nested_suffix.extend_from_slice(&encoded[recovery..]);
    nested_suffix[note_length..note_length + 4].copy_from_slice(&((note_len + 1) as u32).to_be_bytes());
    assert_eq!(NoteCreationWitness::decode(&nested_suffix), Err(RelationError::Encoding));
}

#[test]
fn private_codec_rejects_each_truncation_wrong_domain_schema_trailing_and_oversize() {
    let witness = creation::initial_order_a();
    let encoded = witness.encode().unwrap();
    for end in 0..encoded.len() { assert!(NoteCreationWitness::decode(&encoded[..end]).is_err()); }
    let mut trailing = zeroize::Zeroizing::new(Vec::with_capacity(encoded.len() + 1));
    trailing.extend_from_slice(&encoded);
    trailing.push(0);
    assert_eq!(NoteCreationWitness::decode(&trailing), Err(RelationError::Encoding));
    let mut wrong = encoded.clone();
    wrong[0] ^= 1;
    assert_eq!(NoteCreationWitness::decode(&wrong), Err(RelationError::Encoding));
    let header = b"Z2Z_SAMECHAIN_NOTE_CREATION_WITNESS\0".len();
    wrong.copy_from_slice(&encoded);
    wrong[header + 1] = 2;
    assert_eq!(NoteCreationWitness::decode(&wrong), Err(RelationError::Encoding));
    wrong.copy_from_slice(&encoded);
    wrong[header + 2..header + 6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteCreationWitness::decode(&wrong), Err(RelationError::ResourceLimit));
    let oversized = zeroize::Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    assert_eq!(NoteCreationWitness::decode(&oversized), Err(RelationError::ResourceLimit));
    assert_eq!(format!("{witness:?}"), "NoteCreationWitness([REDACTED])");
}
