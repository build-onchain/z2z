use primitive_types::U256;
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{
    Asset, Deployment, OutputDescriptor, Role, SamechainError,
    MAX_CIPHERTEXT_BYTES, MAX_PACKET_BYTES,
};
use ziquid_protocol::samechain::creation::{
    InitialOrder, NoteCreationJournal, NoteCreationPacket, validate_note_creation,
};

const BLIND: [u8; 32] = [15; 32];
const PACKET_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_CREATION_PACKET\0";
const JOURNAL_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_CREATION_JOURNAL\0";

fn packet() -> NoteCreationPacket {
    let mut packet = NoteCreationPacket {
        deployment: Deployment {
            chain_id: 31_337, authority: [1; 20], authority_code: [2; 32],
            verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1,
        },
        token: [6; 20], payer: [7; 20], creation_nonce: [8; 32], owner_key: [9; 32],
        role: Role::A, asset: Asset::Native, amount: U256::from(49), order: None,
        output: OutputDescriptor::Note {
            role: Role::A, commitment: [10; 32], recovery_key_commitment: [11; 32],
            ciphertext_version: 1, ciphertext: vec![12, 13, 14],
        },
        expiry: 600, terms_commitment: [0; 32],
    };
    packet.terms_commitment = packet.terms_commitment_for(&BLIND).unwrap();
    packet
}

fn frame(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

// Independent fixture bytes pin field order, nested bodies without extra frames,
// optional initial identity only (no hidden policy), and big-endian quantities.
fn deployment_body() -> Vec<u8> {
    let mut bytes = 31_337u64.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[1; 20]);
    bytes.extend_from_slice(&[2; 32]);
    bytes.extend_from_slice(&[3; 20]);
    bytes.extend_from_slice(&[4; 32]);
    bytes.extend_from_slice(&[5; 32]);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn public_terms_body(initial_token_b: bool) -> Vec<u8> {
    let mut bytes = deployment_body();
    bytes.extend_from_slice(&[6; 20]);
    bytes.extend_from_slice(&[7; 20]);
    bytes.extend_from_slice(&[8; 32]);
    bytes.extend_from_slice(&[9; 32]);
    bytes.push(u8::from(initial_token_b)); // packet role.
    bytes.push(u8::from(initial_token_b)); // asset tag.
    if initial_token_b { bytes.extend_from_slice(&[6; 20]); }
    bytes.extend_from_slice(&[0; 31]);
    bytes.push(49);
    bytes.push(u8::from(initial_token_b)); // initial order option.
    if initial_token_b { bytes.extend_from_slice(&[16; 32]); }
    bytes.extend_from_slice(&[0, u8::from(initial_token_b)]); // Note, output role.
    bytes.extend_from_slice(&[10; 32]);
    bytes.extend_from_slice(&[11; 32]);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(&[12, 13, 14]);
    bytes.extend_from_slice(&600u64.to_be_bytes());
    bytes
}

#[test]
fn canonical_creation_and_journal_bind_exact_terms_in_declared_order() {
    for initial_token_b in [false, true] {
        let mut packet = packet();
        if initial_token_b {
            packet.role = Role::B;
            packet.asset = Asset::Token(packet.token);
            packet.order = Some(InitialOrder { id: [16; 32] });
            if let OutputDescriptor::Note { role, .. } = &mut packet.output { *role = Role::B; }
        }
        let terms_body = public_terms_body(initial_token_b);
        let mut preimage_body = BLIND.to_vec();
        preimage_body.extend_from_slice(&terms_body);
        let expected_terms: [u8; 32] = Sha256::digest(frame(
            b"Z2Z_SAMECHAIN_NOTE_CREATION_TERMS_COMMITMENT\0", &preimage_body,
        )).into();
        assert_eq!(packet.terms_commitment_for(&BLIND).unwrap(), expected_terms);
        packet.terms_commitment = expected_terms;
        packet.validate_commitment(&BLIND).unwrap();
        let mut packet_body = terms_body;
        packet_body.extend_from_slice(&expected_terms);
        let expected_packet = frame(PACKET_DOMAIN, &packet_body);
        assert_eq!(packet.encode().unwrap(), expected_packet);
        assert_eq!(packet.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected_packet)));
        assert_eq!(NoteCreationPacket::decode(&expected_packet).unwrap(), packet);

        let expected_deployment: [u8; 32] = Sha256::digest(frame(
            b"Z2Z_SAMECHAIN_DEPLOYMENT\0", &deployment_body(),
        )).into();
        let mut journal_body = 1u16.to_be_bytes().to_vec();
        journal_body.extend_from_slice(&expected_deployment);
        journal_body.extend_from_slice(&Sha256::digest(&expected_packet));
        journal_body.extend_from_slice(&expected_terms);
        journal_body.extend_from_slice(&[8; 32]);
        journal_body.extend_from_slice(&[7; 20]);
        journal_body.extend_from_slice(&[9; 32]);
        journal_body.extend_from_slice(&[6; 20]);
        journal_body.push(u8::from(initial_token_b));
        journal_body.push(u8::from(initial_token_b));
        if initial_token_b { journal_body.extend_from_slice(&[6; 20]); }
        journal_body.extend_from_slice(&[0; 31]);
        journal_body.push(49);
        journal_body.push(u8::from(initial_token_b));
        if initial_token_b { journal_body.extend_from_slice(&[16; 32]); }
        journal_body.extend_from_slice(&[10; 32]);
        let expected_journal = frame(JOURNAL_DOMAIN, &journal_body);
        let journal = NoteCreationJournal::from_packet(&packet).unwrap();
        assert_eq!(journal.encode().unwrap(), expected_journal);
        assert_eq!(journal.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected_journal)));
        assert_eq!(NoteCreationJournal::decode(&expected_journal).unwrap(), journal);
        validate_note_creation(&packet, &journal).unwrap();
    }
}

#[test]
fn terms_placeholder_is_excluded_but_full_packet_requires_nonzero_commitment() {
    let original = packet();
    for terms in [[0; 32], [1; 32], [255; 32]] {
        let mut packet = original.clone();
        packet.terms_commitment = terms;
        assert_eq!(packet.terms_commitment_for(&BLIND).unwrap(), original.terms_commitment);
        if terms == [0; 32] {
            assert_eq!(packet.validate(), Err(SamechainError::InvalidTerms));
            assert_eq!(packet.encode(), Err(SamechainError::InvalidTerms));
            assert_eq!(packet.digest(), Err(SamechainError::InvalidTerms));
            assert_eq!(NoteCreationJournal::from_packet(&packet), Err(SamechainError::InvalidTerms));
        } else {
            assert_eq!(packet.validate_commitment(&BLIND), Err(SamechainError::OpeningMismatch));
        }
    }
    assert_eq!(original.terms_commitment_for(&[0; 32]), Err(SamechainError::InvalidBlind));
    assert_eq!(original.validate_commitment(&[0; 32]), Err(SamechainError::InvalidBlind));
    assert_eq!(original.validate_commitment(&[16; 32]), Err(SamechainError::OpeningMismatch));
}

type PacketMutation = fn(&mut NoteCreationPacket);

#[test]
fn every_public_deposit_and_recovery_field_changes_commitment_and_journal_binding() {
    let original = packet();
    let journal = NoteCreationJournal::from_packet(&original).unwrap();
    let changes: &[PacketMutation] = &[
        |p| p.deployment.chain_id += 1,
        |p| p.deployment.authority[0] ^= 1,
        |p| p.deployment.authority_code[0] ^= 1,
        |p| p.deployment.verifier[0] ^= 1,
        |p| p.deployment.verifier_code[0] ^= 1,
        |p| p.deployment.owner_program[0] ^= 1,
        |p| p.token[0] ^= 1,
        |p| p.payer[0] ^= 1,
        |p| p.creation_nonce[0] ^= 1,
        |p| p.owner_key[0] ^= 1,
        |p| { p.role = Role::B; if let OutputDescriptor::Note { role, .. } = &mut p.output { *role = Role::B; } },
        |p| p.asset = Asset::Token(p.token),
        |p| p.amount = U256::MAX,
        |p| p.order = Some(InitialOrder { id: [16; 32] }),
        |p| { if let OutputDescriptor::Note { commitment, .. } = &mut p.output { commitment[0] ^= 1; } },
        |p| { if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut p.output { recovery_key_commitment[0] ^= 1; } },
        |p| { if let OutputDescriptor::Note { ciphertext_version, .. } = &mut p.output { *ciphertext_version += 1; } },
        |p| { if let OutputDescriptor::Note { ciphertext, .. } = &mut p.output { ciphertext[0] ^= 1; } },
        |p| p.expiry += 1,
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed);
        changed.validate().unwrap();
        assert_ne!(changed.terms_commitment_for(&BLIND).unwrap(), original.terms_commitment);
        assert_eq!(changed.validate_commitment(&BLIND), Err(SamechainError::OpeningMismatch));
        assert_ne!(changed.digest().unwrap(), original.digest().unwrap());
        assert_eq!(validate_note_creation(&changed, &journal), Err(SamechainError::JournalMismatch));
        changed.terms_commitment = changed.terms_commitment_for(&BLIND).unwrap();
        changed.validate_commitment(&BLIND).unwrap();
        let changed_journal = NoteCreationJournal::from_packet(&changed).unwrap();
        assert_ne!(changed_journal, journal);
        validate_note_creation(&changed, &changed_journal).unwrap();
    }
    let mut initial = original.clone();
    initial.order = Some(InitialOrder { id: [16; 32] });
    initial.terms_commitment = initial.terms_commitment_for(&BLIND).unwrap();
    let initial_journal = NoteCreationJournal::from_packet(&initial).unwrap();
    initial.order.as_mut().unwrap().id[0] ^= 1;
    assert_eq!(initial.validate_commitment(&BLIND), Err(SamechainError::OpeningMismatch));
    assert_eq!(validate_note_creation(&initial, &initial_journal), Err(SamechainError::JournalMismatch));
}

#[test]
fn packet_rejects_unfundable_shape_before_encoding_hashing_or_terms_opening() {
    let cases: &[(PacketMutation, SamechainError)] = &[
        (|p| p.deployment.chain_id = 0, SamechainError::InvalidDeployment),
        (|p| p.deployment.schema = 2, SamechainError::UnsupportedSchema),
        (|p| p.token = [0; 20], SamechainError::InvalidAsset),
        (|p| p.asset = Asset::Token([17; 20]), SamechainError::InvalidAsset),
        (|p| p.asset = Asset::Token([0; 20]), SamechainError::InvalidAsset),
        (|p| p.payer = [0; 20], SamechainError::InvalidTerms),
        (|p| p.creation_nonce = [0; 32], SamechainError::InvalidTerms),
        (|p| p.owner_key = [0; 32], SamechainError::InvalidTerms),
        (|p| p.amount = U256::zero(), SamechainError::InvalidTerms),
        (|p| p.order = Some(InitialOrder { id: [0; 32] }), SamechainError::InvalidTerms),
        (|p| p.expiry = 0, SamechainError::InvalidTerms),
        (|p| p.output = OutputDescriptor::Exit { role: Role::A, asset: Asset::Native, recipient: [1; 20], amount: U256::one() }, SamechainError::InvalidOutput),
        (|p| p.output = OutputDescriptor::Fee { payer: Role::A, asset: Asset::Native, recipient: [1; 20], amount: U256::one() }, SamechainError::InvalidOutput),
        (|p| p.role = Role::B, SamechainError::InvalidRole),
        (|p| { if let OutputDescriptor::Note { commitment, .. } = &mut p.output { *commitment = [0; 32]; } }, SamechainError::InvalidOutput),
        (|p| { if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut p.output { *recovery_key_commitment = [0; 32]; } }, SamechainError::InvalidOutput),
        (|p| { if let OutputDescriptor::Note { ciphertext_version, .. } = &mut p.output { *ciphertext_version = 0; } }, SamechainError::InvalidOutput),
        (|p| { if let OutputDescriptor::Note { ciphertext, .. } = &mut p.output { ciphertext.clear(); } }, SamechainError::InvalidOutput),
        (|p| { if let OutputDescriptor::Note { ciphertext, .. } = &mut p.output { *ciphertext = vec![1; MAX_CIPHERTEXT_BYTES + 1]; } }, SamechainError::Oversize),
    ];
    for (change, error) in cases {
        let mut invalid = packet();
        change(&mut invalid);
        assert_eq!(invalid.validate(), Err(*error));
        assert_eq!(invalid.encode(), Err(*error));
        assert_eq!(invalid.digest(), Err(*error));
        assert_eq!(invalid.terms_commitment_for(&BLIND), Err(*error));
        assert_eq!(invalid.validate_commitment(&BLIND), Err(*error));
        assert_eq!(NoteCreationJournal::from_packet(&invalid), Err(*error));
    }
}

#[test]
fn both_roles_assets_and_optional_initial_orders_accept_full_positive_u256_range() {
    for role in [Role::A, Role::B] {
        for asset in [Asset::Native, Asset::Token([6; 20])] {
            for order in [None, Some(InitialOrder { id: [16; 32] })] {
                for amount in [U256::one(), U256::MAX] {
                    let mut packet = packet();
                    packet.role = role;
                    packet.asset = asset;
                    packet.order = order;
                    packet.amount = amount;
                    if let OutputDescriptor::Note { role: output_role, ciphertext, .. } = &mut packet.output {
                        *output_role = role;
                        *ciphertext = vec![12; MAX_CIPHERTEXT_BYTES];
                    }
                    packet.terms_commitment = packet.terms_commitment_for(&BLIND).unwrap();
                    packet.validate_commitment(&BLIND).unwrap();
                    let bytes = packet.encode().unwrap();
                    assert!(bytes.len() < MAX_PACKET_BYTES);
                    assert_eq!(NoteCreationPacket::decode(&bytes).unwrap(), packet);
                    let journal = NoteCreationJournal::from_packet(&packet).unwrap();
                    assert_eq!(journal.amount, amount);
                    assert_eq!(journal.asset, asset);
                    assert_eq!(journal.role, role);
                    assert_eq!(journal.order, order);
                    validate_note_creation(&packet, &journal).unwrap();
                }
            }
        }
    }
}

type JournalMutation = fn(&mut NoteCreationJournal);

#[test]
fn journal_rejects_every_mint_comparison_field_substitution() {
    let packet = packet();
    let journal = NoteCreationJournal::from_packet(&packet).unwrap();
    let changes: &[JournalMutation] = &[
        |j| j.deployment_digest[0] ^= 1,
        |j| j.packet_digest[0] ^= 1,
        |j| j.terms_commitment[0] ^= 1,
        |j| j.creation_nonce[0] ^= 1,
        |j| j.payer[0] ^= 1,
        |j| j.owner_key[0] ^= 1,
        |j| j.token[0] ^= 1,
        |j| j.role = Role::B,
        |j| j.asset = Asset::Token(j.token),
        |j| j.amount += U256::one(),
        |j| j.order = Some(InitialOrder { id: [16; 32] }),
        |j| j.note_commitment[0] ^= 1,
    ];
    for change in changes {
        let mut changed = journal;
        change(&mut changed);
        changed.validate().unwrap();
        assert_eq!(validate_note_creation(&packet, &changed), Err(SamechainError::JournalMismatch));
    }
}

#[test]
fn journal_shape_is_fail_closed_without_claiming_verified_creation_or_replay_state() {
    let packet = packet();
    let journal = NoteCreationJournal::from_packet(&packet).unwrap();
    let zeroes: &[JournalMutation] = &[
        |j| j.deployment_digest = [0; 32], |j| j.packet_digest = [0; 32],
        |j| j.terms_commitment = [0; 32], |j| j.creation_nonce = [0; 32],
        |j| j.payer = [0; 20], |j| j.owner_key = [0; 32],
        |j| j.token = [0; 20], |j| j.amount = U256::zero(),
        |j| j.order = Some(InitialOrder { id: [0; 32] }), |j| j.note_commitment = [0; 32],
    ];
    for change in zeroes {
        let mut invalid = journal;
        change(&mut invalid);
        assert_eq!(invalid.validate(), Err(SamechainError::InvalidJournal));
        assert_eq!(invalid.encode(), Err(SamechainError::InvalidJournal));
        assert_eq!(invalid.digest(), Err(SamechainError::InvalidJournal));
        assert_eq!(validate_note_creation(&packet, &invalid), Err(SamechainError::InvalidJournal));
    }
    let mut invalid = journal;
    invalid.relation_version = 2;
    assert_eq!(invalid.validate(), Err(SamechainError::UnsupportedSchema));
    invalid = journal;
    invalid.asset = Asset::Token([17; 20]);
    assert_eq!(invalid.validate(), Err(SamechainError::InvalidAsset));
    // Repeated descriptive binding is intentionally stateless. No owner signature,
    // note opening, receipt, admitted root or replay permission exists at this layer.
    for _ in 0..2 {
        assert_eq!(NoteCreationJournal::from_packet(&packet).unwrap(), journal);
        validate_note_creation(&packet, &journal).unwrap();
    }
}

#[test]
fn canonical_frames_reject_wrong_domains_schemas_truncation_trailing_and_oversize() {
    let packet = packet();
    let journal = NoteCreationJournal::from_packet(&packet).unwrap();
    macro_rules! rejects_malformed {
        ($kind:ty, $value:expr, $domain:expr) => {{
            let original = $value.encode().unwrap();
            for end in 0..original.len() {
                assert!(<$kind>::decode(&original[..end]).is_err());
            }
            let mut bytes = original.clone();
            bytes[0] ^= 1;
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::WrongDomain));
            let mut bytes = original.clone();
            bytes[$domain.len() + 1] = 2;
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::UnsupportedSchema));
            let mut bytes = original.clone();
            bytes.push(0);
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::TrailingBytes));
            assert_eq!(<$kind>::decode(&vec![0; MAX_PACKET_BYTES + 1]), Err(SamechainError::Oversize));
        }};
    }
    rejects_malformed!(NoteCreationPacket, packet, PACKET_DOMAIN);
    rejects_malformed!(NoteCreationJournal, journal, JOURNAL_DOMAIN);
    assert_eq!(NoteCreationPacket::decode(&journal.encode().unwrap()), Err(SamechainError::WrongDomain));
    assert_eq!(NoteCreationJournal::decode(&packet.encode().unwrap()), Err(SamechainError::WrongDomain));
}

#[test]
fn packet_decoder_rejects_noncanonical_tags_and_unbounded_nested_ciphertext() {
    let mut bytes = packet().encode().unwrap();
    let role_offset = PACKET_DOMAIN.len() + 2 + 146 + 20 + 20 + 32 + 32;
    bytes[role_offset] = 2;
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidRole));
    let mut bytes = packet().encode().unwrap();
    bytes[role_offset + 1] = 2;
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidAsset));
    let order_offset = role_offset + 1 + 1 + 32;
    let mut bytes = packet().encode().unwrap();
    bytes[order_offset] = 2;
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::NonCanonical));
    let output_offset = order_offset + 1;
    let mut bytes = packet().encode().unwrap();
    bytes[output_offset] = 3;
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidOutput));
    let ciphertext_length_offset = output_offset + 1 + 1 + 32 + 32 + 2;
    let mut bytes = packet().encode().unwrap();
    bytes[ciphertext_length_offset..ciphertext_length_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::Oversize));
    let mut bytes = packet().encode().unwrap();
    bytes[ciphertext_length_offset..ciphertext_length_offset + 4]
        .copy_from_slice(&100u32.to_be_bytes());
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidLength));
    let mut bytes = packet().encode().unwrap();
    bytes[ciphertext_length_offset..ciphertext_length_offset + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    bytes.drain(ciphertext_length_offset + 4..ciphertext_length_offset + 7);
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidOutput));
    let mut bytes = packet().encode().unwrap();
    bytes[order_offset - 32..order_offset].fill(0); // public amount.
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidTerms));
    let mut bytes = packet().encode().unwrap();
    let terms_offset = bytes.len() - 32;
    bytes[terms_offset..].fill(0);
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidTerms));
    let mut bytes = packet().encode().unwrap();
    bytes[terms_offset] ^= 1;
    let stale = NoteCreationPacket::decode(&bytes).unwrap();
    assert_eq!(stale.validate_commitment(&BLIND), Err(SamechainError::OpeningMismatch));
    let mut initial = packet();
    initial.order = Some(InitialOrder { id: [16; 32] });
    initial.terms_commitment = initial.terms_commitment_for(&BLIND).unwrap();
    let mut bytes = initial.encode().unwrap();
    bytes[order_offset + 1..order_offset + 33].fill(0);
    assert_eq!(NoteCreationPacket::decode(&bytes), Err(SamechainError::InvalidTerms));
    let journal = NoteCreationJournal::from_packet(&packet()).unwrap();
    let mut bytes = journal.encode().unwrap();
    let journal_order_offset = JOURNAL_DOMAIN.len() + 2 + 2 + 32 * 5 + 20 * 2 + 1 + 1 + 32;
    bytes[journal_order_offset] = 2;
    assert_eq!(NoteCreationJournal::decode(&bytes), Err(SamechainError::NonCanonical));
    let mut bytes = journal.encode().unwrap();
    bytes[JOURNAL_DOMAIN.len() + 3] = 2;
    assert_eq!(NoteCreationJournal::decode(&bytes), Err(SamechainError::UnsupportedSchema));
    let mut bytes = journal.encode().unwrap();
    bytes[journal_order_offset - 32..journal_order_offset].fill(0);
    assert_eq!(NoteCreationJournal::decode(&bytes), Err(SamechainError::InvalidJournal));
    let mut bytes = journal.encode().unwrap();
    let note_offset = bytes.len() - 32;
    bytes[note_offset..].fill(0);
    assert_eq!(NoteCreationJournal::decode(&bytes), Err(SamechainError::InvalidJournal));
}
