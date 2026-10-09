use primitive_types::U256;
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{
    Asset, Deployment, InputDescriptor, OutputDescriptor, Role, SamechainError,
    MAX_CIPHERTEXT_BYTES, MAX_OUTPUTS, MAX_PACKET_BYTES,
};
use ziquid_protocol::samechain::withdrawal::{
    NoteInputDescriptor, NoteWithdrawalPacket, NoteWithdrawalJournal,
    note_withdrawal_terms_commitment, validate_note_withdrawal,
};
#[test]
fn ordinary_note_packet_binds_exact_withdrawal_without_order_metadata() {
    let deployment=Deployment{chain_id:31337,authority:[1;20],authority_code:[2;32],verifier:[3;20],verifier_code:[4;32],owner_program:[5;32],schema:1};
    let input=NoteInputDescriptor{commitment:[6;32],root:[7;32],tree_id:0,index:0,nullifier:[8;32],owner_key:[9;32]};
    let outputs=vec![OutputDescriptor::Exit{role:Role::A,asset:Asset::Native,recipient:[10;20],amount:U256::from(49)}];
    let packet=NoteWithdrawalPacket{deployment,input,terms_commitment:note_withdrawal_terms_commitment(&deployment,&input,&outputs,600,&[11;32]).unwrap(),outputs,expiry:600};
    let bytes=packet.encode().unwrap();
    let mut trailing=bytes.clone();trailing.push(0);
    assert!(NoteWithdrawalPacket::decode(&trailing).is_err());
    let journal=NoteWithdrawalJournal::from_packet(&packet).unwrap();
    validate_note_withdrawal(&packet,&journal).unwrap();
    let mut shifted=packet.clone();shifted.expiry+=1;
    assert!(validate_note_withdrawal(&shifted,&journal).is_err());
}

fn packet() -> NoteWithdrawalPacket {
    let deployment = Deployment {
        chain_id: 31_337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1,
    };
    let input = NoteInputDescriptor {
        commitment: [6; 32], root: [7; 32], tree_id: 0, index: 0,
        nullifier: [8; 32], owner_key: [9; 32],
    };
    let outputs = vec![OutputDescriptor::Exit {
        role: Role::A, asset: Asset::Native, recipient: [10; 20], amount: U256::from(49),
    }];
    NoteWithdrawalPacket {
        deployment, input,
        terms_commitment: note_withdrawal_terms_commitment(
            &deployment, &input, &outputs, 600, &[11; 32],
        ).unwrap(),
        outputs, expiry: 600,
    }
}

fn note(tag: u8) -> OutputDescriptor {
    OutputDescriptor::Note {
        role: Role::A, commitment: [tag; 32], recovery_key_commitment: [tag + 1; 32],
        ciphertext_version: 1, ciphertext: vec![tag; 3],
    }
}

// Hand-built fixture bodies pin the wire and salted preimage independently of
// the production serializer, including the new input's lack of order metadata.
fn fixture_bodies() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut deployment = Vec::new();
    deployment.extend_from_slice(&31_337u64.to_be_bytes());
    deployment.extend_from_slice(&[1; 20]);
    deployment.extend_from_slice(&[2; 32]);
    deployment.extend_from_slice(&[3; 20]);
    deployment.extend_from_slice(&[4; 32]);
    deployment.extend_from_slice(&[5; 32]);
    deployment.extend_from_slice(&1u16.to_be_bytes());
    let mut input = Vec::new();
    input.extend_from_slice(&[6; 32]);
    input.extend_from_slice(&[7; 32]);
    input.extend_from_slice(&[0; 8]); // tree zero, index zero.
    input.extend_from_slice(&[8; 32]);
    input.extend_from_slice(&[9; 32]);
    let mut outputs = vec![0, 0, 0, 1, 1, 0, 0]; // count, Exit, A, Native.
    outputs.extend_from_slice(&[10; 20]);
    outputs.extend_from_slice(&[0; 31]);
    outputs.push(49);
    (deployment, input, outputs)
}

#[test]
fn canonical_bodies_and_salted_terms_use_exact_distinct_domains() {
    let packet = packet();
    let (deployment, input, outputs) = fixture_bodies();
    let mut preimage = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_TERMS_COMMITMENT\0".to_vec();
    preimage.extend_from_slice(&1u16.to_be_bytes());
    preimage.extend_from_slice(&[11; 32]);
    preimage.extend_from_slice(&deployment);
    preimage.extend_from_slice(&input);
    preimage.extend_from_slice(&outputs);
    preimage.extend_from_slice(&600u64.to_be_bytes());
    assert_eq!(packet.terms_commitment, <[u8; 32]>::from(Sha256::digest(&preimage)));
    packet.validate_commitment(&[11; 32]).unwrap();

    let mut expected_input = b"Z2Z_SAMECHAIN_NOTE_INPUT\0".to_vec();
    expected_input.extend_from_slice(&1u16.to_be_bytes());
    expected_input.extend_from_slice(&input);
    assert_eq!(packet.input.encode().unwrap(), expected_input);
    assert_eq!(packet.input.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected_input)));

    let mut expected_packet = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\0".to_vec();
    expected_packet.extend_from_slice(&1u16.to_be_bytes());
    expected_packet.extend_from_slice(&deployment);
    expected_packet.extend_from_slice(&input);
    expected_packet.extend_from_slice(&outputs);
    expected_packet.extend_from_slice(&600u64.to_be_bytes());
    expected_packet.extend_from_slice(&packet.terms_commitment);
    assert_eq!(packet.encode().unwrap(), expected_packet);
    assert_eq!(packet.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected_packet)));

    let journal = NoteWithdrawalJournal::from_packet(&packet).unwrap();
    let mut expected_journal = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_JOURNAL\0".to_vec();
    expected_journal.extend_from_slice(&1u16.to_be_bytes());
    expected_journal.extend_from_slice(&1u16.to_be_bytes());
    expected_journal.extend_from_slice(&Sha256::digest({
        let mut frame = b"Z2Z_SAMECHAIN_DEPLOYMENT\0".to_vec();
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&deployment);
        frame
    }));
    expected_journal.extend_from_slice(&packet.terms_commitment);
    expected_journal.extend_from_slice(&Sha256::digest(&expected_packet));
    expected_journal.extend_from_slice(&[6; 32]); // commitment before nullifier.
    expected_journal.extend_from_slice(&[8; 32]);
    expected_journal.extend_from_slice(&[7; 32]);
    expected_journal.extend_from_slice(&[0; 8]);
    assert_eq!(journal.encode().unwrap(), expected_journal);
    assert_eq!(journal.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected_journal)));
}

#[test]
fn all_new_frames_reject_wrong_domain_schema_truncation_and_trailing_bytes() {
    let packet = packet();
    let journal = NoteWithdrawalJournal::from_packet(&packet).unwrap();
    let input_bytes = packet.input.encode().unwrap();
    let packet_bytes = packet.encode().unwrap();
    let journal_bytes = journal.encode().unwrap();
    assert_eq!(NoteInputDescriptor::decode(&input_bytes).unwrap(), packet.input);
    assert_eq!(NoteWithdrawalPacket::decode(&packet_bytes).unwrap(), packet);
    assert_eq!(NoteWithdrawalJournal::decode(&journal_bytes).unwrap(), journal);
    for end in 0..input_bytes.len() {
        assert!(NoteInputDescriptor::decode(&input_bytes[..end]).is_err());
    }
    for end in 0..packet_bytes.len() {
        assert!(NoteWithdrawalPacket::decode(&packet_bytes[..end]).is_err());
    }
    for end in 0..journal_bytes.len() {
        assert!(NoteWithdrawalJournal::decode(&journal_bytes[..end]).is_err());
    }
    macro_rules! malformed_frame {
        ($kind:ty, $bytes:expr, $domain:expr) => {{
            let mut bytes = $bytes.clone();
            bytes[0] ^= 1;
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::WrongDomain));
            let mut bytes = $bytes.clone();
            bytes[$domain.len() + 1] = 2;
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::UnsupportedSchema));
            let mut bytes = $bytes.clone();
            bytes.push(0);
            assert_eq!(<$kind>::decode(&bytes), Err(SamechainError::TrailingBytes));
            assert_eq!(<$kind>::decode(&vec![0; MAX_PACKET_BYTES + 1]), Err(SamechainError::Oversize));
        }};
    }
    malformed_frame!(NoteInputDescriptor, input_bytes, b"Z2Z_SAMECHAIN_NOTE_INPUT\0");
    malformed_frame!(NoteWithdrawalPacket, packet_bytes, b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\0");
    malformed_frame!(NoteWithdrawalJournal, journal_bytes, b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_JOURNAL\0");
}

#[test]
fn ordinary_inputs_require_real_identity_but_allow_zero_tree_and_index() {
    let input = packet().input;
    input.validate().unwrap();
    let mut bad = [input; 4];
    bad[0].commitment = [0; 32];
    bad[1].root = [0; 32];
    bad[2].nullifier = [0; 32];
    bad[3].owner_key = [0; 32];
    for input in bad {
        assert_eq!(input.validate(), Err(SamechainError::InvalidInput));
        assert!(input.encode().is_err());
        assert!(input.digest().is_err());
    }
    let mut legacy = InputDescriptor {
        commitment: input.commitment, root: input.root, tree_id: input.tree_id,
        index: input.index, order_id: [12; 32], generation: 1,
        nullifier: input.nullifier, owner_key: input.owner_key,
    };
    assert_eq!(NoteInputDescriptor::decode(&legacy.encode().unwrap()), Err(SamechainError::WrongDomain));
    assert!(InputDescriptor::decode(&input.encode().unwrap()).is_err());
    legacy.order_id = [0; 32];
    assert_eq!(legacy.validate(), Err(SamechainError::InvalidInput));
    legacy.order_id = [12; 32];
    legacy.generation = 0;
    assert_eq!(legacy.validate(), Err(SamechainError::InvalidInput));
}

#[test]
fn withdrawal_requires_positive_exit_and_all_outputs_role_a() {
    let mut packet = packet();
    packet.outputs.clear();
    assert_eq!(packet.validate(), Err(SamechainError::InvalidOutput));
    packet.outputs = vec![note(20)];
    assert_eq!(packet.validate(), Err(SamechainError::InvalidOutput));
    packet.outputs = vec![OutputDescriptor::Fee {
        payer: Role::A, asset: Asset::Native, recipient: [10; 20], amount: U256::from(1),
    }];
    assert_eq!(packet.validate(), Err(SamechainError::InvalidOutput));
    packet.outputs = vec![OutputDescriptor::Exit {
        role: Role::A, asset: Asset::Native, recipient: [10; 20], amount: U256::zero(),
    }];
    assert_eq!(packet.validate(), Err(SamechainError::InvalidOutput));
    let mut exit = self::packet().outputs.remove(0);
    if let OutputDescriptor::Exit { role, .. } = &mut exit { *role = Role::B; }
    packet.outputs = vec![exit];
    assert_eq!(packet.validate(), Err(SamechainError::InvalidRole));
    for mut output in [note(20), OutputDescriptor::Fee {
        payer: Role::A, asset: Asset::Native, recipient: [11; 20], amount: U256::from(1),
    }] {
        match &mut output {
            OutputDescriptor::Note { role, .. } => *role = Role::B,
            OutputDescriptor::Fee { payer, .. } => *payer = Role::B,
            _ => unreachable!(),
        }
        packet.outputs = self::packet().outputs;
        packet.outputs.push(output);
        assert_eq!(packet.validate(), Err(SamechainError::InvalidRole));
    }
}

#[test]
fn manifest_reuses_duplicate_and_payment_order_guards() {
    let mut packet = packet();
    packet.outputs.extend([note(20), note(20)]);
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
    packet.outputs[2] = note(30);
    if let OutputDescriptor::Note { ciphertext, .. } = &mut packet.outputs[2] { *ciphertext = vec![20; 3]; }
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
    packet.outputs.pop();
    if let OutputDescriptor::Note { commitment, .. } = &mut packet.outputs[1] { *commitment = packet.input.commitment; }
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
    packet.outputs = self::packet().outputs;
    packet.outputs.push(OutputDescriptor::Fee {
        payer: Role::A, asset: Asset::Native, recipient: [10; 20], amount: U256::from(1),
    });
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
    packet.outputs.insert(1, note(20)); // Notes do not reset external payment ordering.
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
    if let OutputDescriptor::Fee { recipient, .. } = &mut packet.outputs[2] { *recipient = [9; 20]; }
    assert_eq!(packet.validate(), Err(SamechainError::NonCanonical));
    if let OutputDescriptor::Fee { recipient, .. } = &mut packet.outputs[2] { *recipient = [11; 20]; }
    packet.validate().unwrap();
}

#[test]
fn packet_and_decode_enforce_component_bounds_before_allocation() {
    let mut packet = packet();
    for tag in 20..27 { packet.outputs.push(note(tag)); }
    for output in &mut packet.outputs {
        if let OutputDescriptor::Note { ciphertext, commitment, .. } = output {
            *ciphertext = vec![commitment[0]; MAX_CIPHERTEXT_BYTES];
        }
    }
    assert_eq!(packet.outputs.len(), MAX_OUTPUTS);
    packet.validate().unwrap();
    assert_eq!(NoteWithdrawalPacket::decode(&packet.encode().unwrap()).unwrap(), packet);
    if let OutputDescriptor::Note { ciphertext, .. } = &mut packet.outputs[1] { ciphertext.push(0); }
    assert_eq!(packet.validate(), Err(SamechainError::Oversize));
    packet.outputs[1] = note(20);
    packet.outputs.push(note(30));
    assert_eq!(packet.validate(), Err(SamechainError::Oversize));

    let count_offset = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\0".len() + 2 + 146 + 136;
    let mut bytes = self::packet().encode().unwrap();
    bytes[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteWithdrawalPacket::decode(&bytes), Err(SamechainError::Oversize));
    let mut packet = self::packet();
    packet.outputs.insert(0, note(20));
    let mut bytes = packet.encode().unwrap();
    let ciphertext_count = count_offset + 4 + 1 + 1 + 32 + 32 + 2;
    bytes[ciphertext_count..ciphertext_count + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteWithdrawalPacket::decode(&bytes), Err(SamechainError::Oversize));
    let mut bytes = packet.encode().unwrap();
    bytes[count_offset + 4] = 99;
    assert_eq!(NoteWithdrawalPacket::decode(&bytes), Err(SamechainError::InvalidOutput));
    let mut bytes = packet.encode().unwrap();
    bytes[count_offset + 5] = 99;
    assert_eq!(NoteWithdrawalPacket::decode(&bytes), Err(SamechainError::InvalidRole));
}

#[test]
fn terms_opening_binds_blind_and_every_body_component() {
    let packet = packet();
    assert_eq!(packet.validate_commitment(&[0; 32]), Err(SamechainError::InvalidBlind));
    assert_eq!(packet.validate_commitment(&[12; 32]), Err(SamechainError::OpeningMismatch));
    let mut bad = vec![packet.clone(); 11];
    bad[0].deployment.chain_id += 1;
    bad[1].input.commitment[0] ^= 1;
    bad[2].input.root[0] ^= 1;
    bad[3].input.tree_id = 1;
    bad[4].input.index = 1;
    bad[5].input.nullifier[0] ^= 1;
    bad[6].input.owner_key[0] ^= 1;
    if let OutputDescriptor::Exit { recipient, .. } = &mut bad[7].outputs[0] { recipient[0] ^= 1; }
    if let OutputDescriptor::Exit { amount, .. } = &mut bad[8].outputs[0] { *amount += U256::from(1); }
    bad[9].expiry += 1;
    bad[10].terms_commitment = [13; 32];
    for changed in bad {
        changed.validate().unwrap();
        assert_eq!(changed.validate_commitment(&[11; 32]), Err(SamechainError::OpeningMismatch));
    }
    let mut bad = packet.clone();
    bad.terms_commitment = [0; 32];
    assert_eq!(bad.validate(), Err(SamechainError::InvalidTerms));
    bad = packet.clone();
    bad.expiry = 0;
    assert_eq!(bad.validate(), Err(SamechainError::InvalidTerms));
    bad = packet;
    bad.deployment.authority = [0; 20];
    assert_eq!(bad.validate(), Err(SamechainError::InvalidDeployment));
}

#[test]
fn descriptive_journal_rejects_every_changed_binding_and_zero_identity() {
    let packet = packet();
    let journal = NoteWithdrawalJournal::from_packet(&packet).unwrap();
    let mut bad = [journal; 8];
    bad[0].deployment_digest[0] ^= 1;
    bad[1].terms_commitment[0] ^= 1;
    bad[2].packet_digest[0] ^= 1;
    bad[3].input_commitment[0] ^= 1;
    bad[4].input_nullifier[0] ^= 1;
    bad[5].root[0] ^= 1;
    bad[6].tree_id = 1;
    bad[7].index = 1;
    for changed in bad {
        changed.validate().unwrap();
        assert_eq!(validate_note_withdrawal(&packet, &changed), Err(SamechainError::JournalMismatch));
    }
    let mut zero = [journal; 6];
    zero[0].deployment_digest = [0; 32];
    zero[1].terms_commitment = [0; 32];
    zero[2].packet_digest = [0; 32];
    zero[3].input_commitment = [0; 32];
    zero[4].input_nullifier = [0; 32];
    zero[5].root = [0; 32];
    for changed in zero {
        assert_eq!(changed.validate(), Err(SamechainError::InvalidJournal));
        assert!(changed.encode().is_err());
        assert!(changed.digest().is_err());
    }
    let mut changed = journal;
    changed.relation_version = 2;
    assert_eq!(changed.validate(), Err(SamechainError::UnsupportedSchema));
    // The journal builder only describes exact bytes; it never opens the terms.
    let mut unopened = packet;
    unopened.terms_commitment = [13; 32];
    let descriptive = NoteWithdrawalJournal::from_packet(&unopened).unwrap();
    validate_note_withdrawal(&unopened, &descriptive).unwrap();
    assert_eq!(unopened.validate_commitment(&[11; 32]), Err(SamechainError::OpeningMismatch));
}
