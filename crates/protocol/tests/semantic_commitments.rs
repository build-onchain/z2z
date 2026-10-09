//! Independent Python hashlib vectors for the fixed protocol streams. These
//! shape-only fixtures are not valid notes, proof openings, or ownership facts.
use ziquid_protocol::{
    MAX_QUOTED_RECEIVERS, MAX_SOURCE_AMOUNT, NativeAmount, PreparationBinding,
    SemanticCommitmentError, SolverCapsule, StatementContext, input_commitment,
    note_consumption_tag, payment_commitment, preparation_consent_digest,
    preparation_packet_binding, solver_capsule_commitment,
};

fn digest(literal: &str) -> [u8; 32] {
    assert_eq!(literal.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&literal[2 * i..2 * i + 2], 16).unwrap())
}

// Each argument is independently bound; replacing any with a constant must fail.
#[test]
fn actual_private_openings_and_receiver_set_bind_commitments() {
    let input = input_commitment(
        &[1; 32], b"testnet", b"ironwood", &[2; 43], 60_000,
        &[3; 32], &[4; 32], &[5; 32], &[6; 32],
    ).unwrap();
    assert_eq!(input, digest("1ffcfc3cda558dde8cd7a13a972fe8218bbbb4a752b094e0c236bfca1baaca55"));

    for (field, expected) in [
        (0, "9eb436c07621bdb5f58e321995c9e7cfba371770e00ca8000b0a9b71dcbf4adb"),
        (1, "784b4909fa74b69b09697c666ab3f3589cf4fe4b91b5999dc752857a55ba8506"),
        (2, "c70da1ed14625ef3f828c4dbc931000ba393c6da9605174bbf9c1127e69d35f6"),
        (3, "2e53bd36d3335eb49284b5b9f0de11db8f10d82ff94981d3d8f18df861727b03"),
        (4, "56ac681b8e88bf90881eca36e9f9987b03b2a9344d11371d19491ba701be88f5"),
        (5, "2507f1984ca134fad368e5ba0dc7c235eefb3a6f0d4f4238d5a4f9d5fa0dc2b8"),
        (6, "5d18f2d923ebbae48a1f409f41f310352f06f1bcb485c49239eb622d0613d13d"),
        (7, "0ab5a7f24a60d68283a3c1835f51b174320936688735a2d47835bdb29563ee27"),
    ] {
        let (mut blind, mut recipient, mut value) = ([1; 32], [2; 43], 60_000);
        let (mut rho, mut rseed, mut cmx, mut nullifier) = ([3; 32], [4; 32], [5; 32], [6; 32]);
        match field {
            0 => blind[0] ^= 1,
            1 => recipient[0] ^= 1,
            2 => value ^= 1,
            3 => rho[0] ^= 1,
            4 => rseed[0] ^= 1,
            5 => cmx[0] ^= 1,
            6 => nullifier[0] ^= 1,
            7 => recipient[42] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            input_commitment(&blind, b"testnet", b"ironwood", &recipient, value,
                &rho, &rseed, &cmx, &nullifier).unwrap(),
            digest(expected), "input field {field}",
        );
    }

    let payment = payment_commitment(
        &[7; 32], b"testnet", b"ironwood", &[8; 32], &[[9; 43], [10; 43]], 60_000,
    ).unwrap();
    assert_eq!(payment, digest("0c0b1cf5b8372b7c43bcd435964659c5ff2b64771e181e1981a99366023dc7e2"));
    for (field, expected) in [
        (0, "650201e315771115cb478d6135862a4eddd088b3525f369ade7c5ef9b2eadb83"),
        (1, "1ca266f057f25e67ace4530e704e0446efcde1758d500cf79045f82a172f26b8"),
        (2, "a19e37dfa341f3124416e3c9ad1823bd94315c498b6b95b7a60e5c416cd0a8a7"),
        (3, "996fc66614d51fa87fbd8661cfcca3c25045660344b03d377453ccdb44f50844"),
        (4, "58ce65e36cb4040d7e5afb8de4a8109e31ad69babadabe385b137be72f22113a"),
        (5, "ebe91d56ea0c2e156d90214e79887a05c6f53d2febdeb0b5ec61086f8a91e4c5"),
    ] {
        let (mut blind, mut effect, mut receivers, mut quoted) =
            ([7; 32], [8; 32], [[9; 43], [10; 43]], 60_000);
        match field {
            0 => blind[0] ^= 1,
            1 => effect[0] ^= 1,
            2 => receivers[0][0] ^= 1,
            3 => receivers[1][0] ^= 1,
            4 => quoted ^= 1,
            5 => receivers[0][42] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            payment_commitment(&blind, b"testnet", b"ironwood", &effect, &receivers, quoted).unwrap(),
            digest(expected), "payment field {field}",
        );
    }
}

#[test]
fn domain_blind_and_amount_bounds_are_rejected_without_normalizing() {
    for (network, pool) in [
        (*b"mainnet", *b"ironwood"),
        (*b"testnet", *b"orchard\0"),
        ([0; 7], *b"ironwood"),
        (*b"testnet", [0; 8]),
    ] {
        assert_eq!(
            input_commitment(&[1; 32], &network, &pool, &[2; 43], 60_000,
                &[3; 32], &[4; 32], &[5; 32], &[6; 32]),
            Err(SemanticCommitmentError::InvalidDomain),
        );
        assert_eq!(
            payment_commitment(&[7; 32], &network, &pool, &[8; 32], &[[9; 43]], 60_000),
            Err(SemanticCommitmentError::InvalidDomain),
        );
    }
    assert_eq!(
        input_commitment(&[0; 32], b"testnet", b"ironwood", &[2; 43], 60_000,
            &[3; 32], &[4; 32], &[5; 32], &[6; 32]),
        Err(SemanticCommitmentError::ZeroBlind),
    );
    assert_eq!(
        payment_commitment(&[0; 32], b"testnet", b"ironwood", &[8; 32], &[[9; 43]], 60_000),
        Err(SemanticCommitmentError::ZeroBlind),
    );
    for amount in [0, MAX_SOURCE_AMOUNT + 1, u64::MAX] {
        assert_eq!(
            input_commitment(&[1; 32], b"testnet", b"ironwood", &[2; 43], amount,
                &[3; 32], &[4; 32], &[5; 32], &[6; 32]),
            Err(SemanticCommitmentError::InvalidAmount),
        );
        assert_eq!(
            payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32], &[[9; 43]], amount),
            Err(SemanticCommitmentError::InvalidAmount),
        );
    }
    for (amount, input, payment) in [
        (1, "f58315306d5005f682b723994d841f7f17b565d85bb31ee0ea08baeefb961ff5",
            "b3a5daad44ab4ad8af6aab093592ac2f57471f703a77f0ef4f5f0bb399fd7b4a"),
        (MAX_SOURCE_AMOUNT, "49d7f48ac849e921897ae8f51f52d15c1ec99f6a57cbdf6c2908a5eb1af0df9b",
            "2fe001c1ed02761e70291ad5bc49803161cb164ba8ea1b6c39f00a54a01ca288"),
    ] {
        assert_eq!(input_commitment(&[1; 32], b"testnet", b"ironwood", &[2; 43], amount,
            &[3; 32], &[4; 32], &[5; 32], &[6; 32]).unwrap(), digest(input));
        assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
            &[[9; 43], [10; 43]], amount).unwrap(), digest(payment));
    }
    let mut blind = [0; 32];
    blind[31] = 1;
    assert_eq!(input_commitment(&blind, b"testnet", b"ironwood", &[2; 43], 60_000,
        &[3; 32], &[4; 32], &[5; 32], &[6; 32]).unwrap(),
        digest("6adc7f3771831869e54171b8d81220430a24aba79b222750be5e522ac230433b"));
    assert_eq!(payment_commitment(&blind, b"testnet", b"ironwood", &[8; 32],
        &[[9; 43], [10; 43]], 60_000).unwrap(),
        digest("d453f15f12ea85e41c73d85ab73a0891aef111e2ef7d5256bf7d22712bdfbe89"));
}

#[test]
fn effect_and_receiver_set_require_exact_strict_fixed_width_framing() {
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[0; 32],
        &[[9; 43]], 60_000), Err(SemanticCommitmentError::InvalidPaymentEffect));
    for receivers in [&[][..], &[[9; 43], [9; 43]][..], &[[10; 43], [9; 43]][..]] {
        assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
            receivers, 60_000), Err(SemanticCommitmentError::InvalidReceiverSet));
    }
    let receivers: [[u8; 43]; 65] = std::array::from_fn(|i| [i as u8; 43]);
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &receivers, 60_000), Err(SemanticCommitmentError::InvalidReceiverSet));
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &receivers[..MAX_QUOTED_RECEIVERS], 60_000).unwrap(),
        digest("e7fb59c017844dffae64f09462ade29b8dc33a36e535db64701adae0914b997c"));
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &[[9; 43]], 60_000).unwrap(),
        digest("61c537d64e3a8736c72325cc1d9b5ee3dde5fb7ef0c57981e8cd85d3b793b390"));
    let first = [9; 43];
    let mut last_byte_differs = first;
    last_byte_differs[42] = 10;
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &[first, last_byte_differs], 60_000).unwrap(),
        digest("fc71fb85c6cd4d9cd62aec534c84a494fd1f1e6f44f0d210b0184562c8930341"));
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &[last_byte_differs, first], 60_000), Err(SemanticCommitmentError::InvalidReceiverSet));

    // Raw helpers deliberately do not curve-validate or assert address ownership.
    assert_eq!(input_commitment(&[1; 32], b"testnet", b"ironwood", &[0; 43], 60_000,
        &[3; 32], &[4; 32], &[5; 32], &[6; 32]).unwrap(),
        digest("47d6eb4ad4c6f0087a393835c26638fd4f6a5509b30139e6d9783dbdbe952138"));
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
        &[[0; 43]], 60_000).unwrap(),
        digest("97f609fbe87e81bbc36fdb665f9b1dd38680440e5dd601cc54b7603329e05a8e"));
}

fn context() -> StatementContext {
    StatementContext {
        schema_version: 1,
        source_network: *b"testnet",
        source_pool: *b"ironwood",
        transaction_version: 6,
        consensus_branch: 0x1234_5678,
        source_policy_id: [0x11; 32],
        preparation_program: [0x22; 32],
        settlement_program: [0x33; 32],
        order_id: [0x44; 32],
        consumption_tag: [0x55; 32],
        source_payment_commitment: [0x66; 32],
        real_input_commitment: [0x77; 32],
        source_quoted_amount: 3,
        source_fee_cap: 1,
        source_expiry: 0x0102_0304,
        evm_chain_id: 31_337,
        escrow: [0x88; 20],
        escrow_code_hash: [0x99; 32],
        verifier: [0xaa; 20],
        verifier_code_hash: [0xbb; 32],
        u_payee: [0xcc; 20],
        s_refund: [0xdd; 20],
        native_amount: NativeAmount::from_be_bytes(std::array::from_fn(|i| i as u8 + 1)),
    }
}

#[test]
fn consent_binds_full_validated_context_and_both_signature_free_commitments() {
    let raw = context();
    assert_eq!(preparation_consent_digest(&raw.validate().unwrap(), &[0x12; 32], &[0x13; 32]).unwrap(),
        digest("c3cc24fa6fe943dc9b51eacafb854c05debf199a3938ddbae51ca95b611bb3c8"));
    macro_rules! changed {
        ($field:ident, $value:expr, $expected:literal) => {{
            let mut changed = raw;
            changed.$field = $value;
            assert_eq!(preparation_consent_digest(&changed.validate().unwrap(), &[0x12; 32], &[0x13; 32]).unwrap(),
                digest($expected), stringify!($field));
        }};
    }
    macro_rules! changed_bytes {
        ($field:ident, $expected:literal) => {{
            let mut bytes = raw.$field;
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            changed!($field, bytes, $expected);
        }};
    }
    changed!(consensus_branch, raw.consensus_branch ^ 1,
        "a0d60a9c120ec0f597c128a403a4f613f3246ec15b10b9ad7bd1c882e2209df6");
    changed_bytes!(source_policy_id, "447cb83bc5c821844fed5507cac0dc215422bb87a64ab5d51bdcaa6d106dd2bd");
    changed_bytes!(preparation_program, "1c1aeee147c73087d22752691f224dc95be4e3bfd38d286aa5dd8242f16356c2");
    changed_bytes!(settlement_program, "d932f96ce1cc8b105bb3b8866397d6a787495324f42b1ae12126090cf9893048");
    changed_bytes!(order_id, "8e5185b3ffb6dcf52eee402304f50979e033216d201dd179bc717ca79331253c");
    changed_bytes!(consumption_tag, "8bfb13a1b67a5f818db5e2c9390bebb2c9fe51507fb6bdee5441e82caadfcc33");
    changed_bytes!(source_payment_commitment, "2b191be60423ee747881adcf89bf48080ddf35909b450e61bb8d5166cfa22848");
    changed_bytes!(real_input_commitment, "c3b3cf3e44eaf010d020f87e08b3fd84fbc859852cb01b8c4e6b51de23b03ec3");
    changed!(source_quoted_amount, raw.source_quoted_amount ^ 1,
        "6cec646a3be310a33ee61502895731ac2ca47e0ea86c1a110461552815ca4fe2");
    changed!(source_fee_cap, raw.source_fee_cap ^ 1,
        "234e9497ca233fd631f3846a579c8a0da1f748805ffc2909e91d150ee631b1d6");
    changed!(source_expiry, raw.source_expiry ^ 1,
        "f66a5a9e84423c59ea00f91de04d3bf40c07a034bc04c8140c2eb5a8eba36d31");
    changed!(evm_chain_id, raw.evm_chain_id ^ 1,
        "7e581516733d23a8ac03c345eaf777e69b2b2cb9c61c40eb556ee9a9283bd970");
    changed_bytes!(escrow, "4bff6114e98cd4d19bead54ec142d91df9f95e4637346dcbc2e556cf24134c34");
    changed_bytes!(escrow_code_hash, "e66c7dac2015942135550743577cd4174a78062ae8bce15811c4c1bdfe4225f4");
    changed_bytes!(verifier, "0bdfdfb48ef025c191ad6df78c4b2c4fdbe575bd583352af72fd631fe6453ba2");
    changed_bytes!(verifier_code_hash, "10e6aecc50d243f0ff5ca8d6fdbdca27d859bb6fb216ad98886a59f08168ca7c");
    changed_bytes!(u_payee, "ad1218cbb73a14cb9be4040ae629e89798f05271d3fa042fc06c0dc2b29d0b5a");
    changed_bytes!(s_refund, "6396c3811a6a1f0d794340c7b237551dae32b1355203af0c770e9854c599a642");
    let mut amount = raw.native_amount.to_be_bytes();
    amount[31] ^= 1;
    changed!(native_amount, NativeAmount::from_be_bytes(amount),
        "567ebcd8965ea62b5d54bda3fef9a4f19f4362be0627a7119c6f04063b61eb66");
    let mut binding = [0x12; 32];
    binding[31] ^= 1;
    assert_eq!(preparation_consent_digest(&raw.validate().unwrap(), &binding, &[0x13; 32]).unwrap(),
        digest("2c7556a3fd243835c707fe0eca95c1960557e60757bd8841984540b8fdadd96e"));
    let mut capsule = [0x13; 32];
    capsule[31] ^= 1;
    assert_eq!(preparation_consent_digest(&raw.validate().unwrap(), &[0x12; 32], &capsule).unwrap(),
        digest("238a06d226c844b29f206cd7b94100e0ff02a05da88d17cc276fe118b4abc9aa"));
    assert_eq!(preparation_consent_digest(&raw.validate().unwrap(), &[0; 32], &[0x13; 32]),
        Err(SemanticCommitmentError::InvalidPacketBinding));
    assert_eq!(preparation_consent_digest(&raw.validate().unwrap(), &[0x12; 32], &[0; 32]),
        Err(SemanticCommitmentError::InvalidCapsuleCommitment));
}

#[test]
fn nonzero_means_any_byte_and_note_fields_remain_unvalidated() {
    let mut nonzero = [0; 32];
    nonzero[31] = 1;
    assert_eq!(payment_commitment(&[7; 32], b"testnet", b"ironwood", &nonzero,
        &[[9; 43], [10; 43]], 60_000).unwrap(),
        digest("3aeabe1da74db0f0af0a2d430104be2118142f452209c4b7d987861b867f13eb"));
    assert_eq!(preparation_consent_digest(&context().validate().unwrap(), &nonzero, &[0x13; 32]).unwrap(),
        digest("b4dbe3d315df8ef591679119b483e1f8179f6241bb1daea82becfc1a010c08d7"));
    assert_eq!(preparation_consent_digest(&context().validate().unwrap(), &[0x12; 32], &nonzero).unwrap(),
        digest("c4e284a9abde73d3d102763066096136776024ba391d1f0ac74eefdee0fb035a"));
    // Consensus/FVK/commitment validity belongs to the subsequent proof relation.
    assert_eq!(input_commitment(&[1; 32], b"testnet", b"ironwood", &[2; 43], 60_000,
        &[0; 32], &[0; 32], &[0; 32], &[0; 32]).unwrap(),
        digest("277e55684ba4797320c75143e7e4fd7e8c3f391abd3d2e6ecda7a4ac9d68861f"));
}

#[test]
fn diagnostics_are_redacted_categories_without_private_openings() {
    let cases = [
        (payment_commitment(&[7; 32], b"mainnet", b"ironwood", &[8; 32],
            &[[9; 43]], 60_000).unwrap_err(), "InvalidDomain"),
        (payment_commitment(&[0; 32], b"testnet", b"ironwood", &[8; 32],
            &[[9; 43]], 60_000).unwrap_err(), "ZeroBlind"),
        (payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
            &[[9; 43]], u64::MAX).unwrap_err(), "InvalidAmount"),
        (payment_commitment(&[7; 32], b"testnet", b"ironwood", &[0; 32],
            &[[9; 43]], 60_000).unwrap_err(), "InvalidPaymentEffect"),
        (payment_commitment(&[7; 32], b"testnet", b"ironwood", &[8; 32],
            &[[9; 43], [9; 43]], 60_000).unwrap_err(), "InvalidReceiverSet"),
        (preparation_consent_digest(&context().validate().unwrap(), &[0; 32], &[0x13; 32])
            .unwrap_err(), "InvalidPacketBinding"),
        (preparation_consent_digest(&context().validate().unwrap(), &[0x12; 32], &[0; 32])
            .unwrap_err(), "InvalidCapsuleCommitment"),
    ];
    for (error, category) in cases {
        assert_eq!(format!("{error:?}"), category);
        let message = error.to_string();
        for private_value in ["18446744073709551615", "60000", "mainnet", "[9, 9", "[7, 7"] {
            assert!(!message.contains(private_value), "diagnostic leaked an opening");
        }
    }
}

#[test]
fn deployment_tag_uses_keyed_blake2b_256_and_exact_domain_widths() {
    for (chain, escrow, nk, nf, expected) in [
        (31_337, [0x88; 20], [0x12; 32], [0x34; 32],
            "0f1385420631629439945d82f835f220f2ad150e396490a85a48af51b05acb96"),
        (31_338, [0x88; 20], [0x12; 32], [0x34; 32],
            "b2c0f1dd0dc85d1896324e9a3a807e09598b93a209bd1cb53750c83c486b2bf1"),
        (31_337, [0x89; 20], [0x12; 32], [0x34; 32],
            "402c963e85c984af3ce1142966e5e6844ceb298bdd946c8a84c8a3b9607686a1"),
        (31_337, [0x88; 20], [0x13; 32], [0x34; 32],
            "9a18f0db662a22278d506db8874116583ad5d3f46169f57f27633540a609c6a4"),
        (31_337, [0x88; 20], [0x12; 32], [0x35; 32],
            "e37e5255d3ea50c157461db0497a946d51912fb14d38dd292712c052d52348be"),
        // A syntactically valid zero nk is not an entropy oracle. This raw
        // encoder makes no key/ownership claim; the relation must reconstruct it.
        (31_337, [0x88; 20], [0; 32], [0x34; 32],
            "ed79b2cade76fe46a284efef3076b614cc17a4f473a5b9cb2b4fe8099a286dcf"),
    ] {
        assert_eq!(note_consumption_tag(b"testnet", b"ironwood", chain, &escrow, &nk, &nf)
            .unwrap(), digest(expected));
    }
    for (network, pool) in [(*b"mainnet", *b"ironwood"), (*b"testnet", *b"orchard\0")] {
        assert_eq!(note_consumption_tag(&network, &pool, 31_337, &[0x88; 20], &[0x12; 32], &[0x34; 32]),
            Err(SemanticCommitmentError::InvalidDomain));
    }
    for (chain, escrow) in [(0, [0x88; 20]), (31_337, [0; 20])] {
        assert_eq!(note_consumption_tag(b"testnet", b"ironwood", chain, &escrow, &[0x12; 32], &[0x34; 32]),
            Err(SemanticCommitmentError::InvalidDeployment));
    }
}

#[test]
fn packet_binding_streams_the_complete_signature_free_v2_frame() {
    let mut raw = context();
    raw.source_expiry = 4_134_040;
    let context = raw.validate().unwrap();
    let siblings = std::array::from_fn(|i| [i as u8; 32]);
    let packet = || PreparationBinding {
        context: &context,
        preparation_blind: &[1; 32],
        redacted_payment: &[0x23, 0x24, 0x25],
        recovery_transaction: &[0x26, 0x27],
        note_recipient: &[2; 43],
        note_value: 60_000,
        note_rho: &[3; 32],
        note_rseed: &[4; 32],
        full_viewing_key: &[5; 96],
        merkle_position: 0x0102_0304,
        merkle_siblings: &siblings,
        anchor: &[6; 32],
        source_target_height: 4_134_000,
    };
    let expected = digest("ebf994995bd897664aecb3370191d722c140e62120d8bbf3561ae4d33a704411");
    assert_eq!(preparation_packet_binding(packet()).unwrap(), expected);
    // Every private/public field must influence the first real consent consumer.
    for field in 0..13 {
        let mut changed = packet();
        let mut changed_raw = raw;
        changed_raw.order_id[31] ^= 1;
        let changed_context = changed_raw.validate().unwrap();
        let mut changed_siblings = siblings;
        changed_siblings[31][31] ^= 1;
        match field {
            0 => changed.context = &changed_context,
            1 => changed.preparation_blind = &[7; 32],
            2 => changed.redacted_payment = &[0x23, 0x24],
            3 => changed.recovery_transaction = &[0x26, 0x28],
            4 => changed.note_recipient = &[8; 43],
            5 => changed.note_value += 1,
            6 => changed.note_rho = &[9; 32],
            7 => changed.note_rseed = &[10; 32],
            8 => changed.full_viewing_key = &[11; 96],
            9 => changed.merkle_position ^= 1,
            10 => changed.merkle_siblings = &changed_siblings,
            11 => changed.anchor = &[12; 32],
            _ => changed.source_target_height += 1,
        }
        let binding = preparation_packet_binding(changed).unwrap();
        assert_ne!(binding, expected, "packet field {field}");
        assert_ne!(preparation_consent_digest(&context, &binding, &[0x13; 32]).unwrap(),
            preparation_consent_digest(&context, &expected, &[0x13; 32]).unwrap());
    }
    let diagnostic = format!("{:?}", packet());
    assert!(diagnostic.len() < 43 && !diagnostic.contains("60000"));
    for height in [0, 4_133_999, 4_465_026, 500_000_000, u32::MAX] {
        let mut changed = packet();
        changed.source_target_height = height;
        assert_eq!(preparation_packet_binding(changed), Err(SemanticCommitmentError::InvalidSource));
    }
    for expiry in [4_133_999, 4_465_026, 499_999_999] {
        let mut invalid = raw;
        invalid.source_expiry = expiry;
        let invalid = invalid.validate().unwrap();
        let mut changed = packet();
        changed.context = &invalid;
        assert_eq!(preparation_packet_binding(changed), Err(SemanticCommitmentError::InvalidSource));
    }
    let mut changed = packet();
    changed.preparation_blind = &[0; 32];
    assert_eq!(preparation_packet_binding(changed), Err(SemanticCommitmentError::ZeroBlind));
    for amount in [0, MAX_SOURCE_AMOUNT + 1, u64::MAX] {
        let mut changed = packet();
        changed.note_value = amount;
        assert_eq!(preparation_packet_binding(changed), Err(SemanticCommitmentError::InvalidAmount));
    }
    let oversized_p = vec![1; 16 * 1024 * 1024 + 1];
    let oversized_q = vec![1; 2 * 1024 * 1024 + 1];
    for (p, q) in [(&[][..], &b"q"[..]), (&b"p"[..], &[][..]),
        (&oversized_p[..], &b"q"[..]), (&b"p"[..], &oversized_q[..])] {
        let mut changed = packet();
        changed.redacted_payment = p;
        changed.recovery_transaction = q;
        assert_eq!(preparation_packet_binding(changed), Err(SemanticCommitmentError::InvalidPacket));
    }
    let mut bounded = packet();
    bounded.redacted_payment = &oversized_p[..16 * 1024 * 1024];
    bounded.recovery_transaction = &oversized_q[..2 * 1024 * 1024];
    assert!(preparation_packet_binding(bounded).is_ok());
    let mut last = raw;
    last.source_expiry = 4_465_025;
    let last = last.validate().unwrap();
    let mut bounded = packet();
    bounded.context = &last;
    bounded.source_target_height = 4_465_025;
    bounded.note_value = MAX_SOURCE_AMOUNT;
    assert!(preparation_packet_binding(bounded).is_ok());
}

#[test]
fn solver_private_capsule_binds_exact_export_without_user_openings() {
    let raw = context();
    let context = raw.validate().unwrap();
    let capsule = || SolverCapsule {
        context: &context,
        private_packet_binding: &[0x12; 32],
        capsule_blind: &[0x13; 32],
        redacted_payment: &[1, 2, 3],
        recovery_transaction: &[4, 5],
    };
    assert_eq!(solver_capsule_commitment(capsule()).unwrap(),
        digest("b3d8d3f3b390cf3e83ced67a51f04c3ced79271d9f0bb4ff99ba50aebcb7bcea"));
    let mut changed_raw = raw;
    changed_raw.order_id[31] ^= 1;
    let changed_context = changed_raw.validate().unwrap();
    let mut changed_binding = [0x12; 32];
    changed_binding[31] ^= 1;
    let mut changed_blind = [0x13; 32];
    changed_blind[31] ^= 1;
    let long: Vec<u8> = (0..=u8::MAX).collect();
    let mut sparse = [0; 32];
    sparse[31] = 1;
    for (field, expected) in [
        (0, "724775d8770705f09acd146199abc5c280f8eb35d7cb098dad4ebecc074a74f2"),
        (1, "1b80d7e2b4718d3bb84dd196c07d276948f284418fa7aae4ed6823a0165672df"),
        (2, "006828c08ef7f09c55e41dd1d978ceba63393f2f8c38f92ab853906d9a4c60dc"),
        (3, "16f8b76f194cd6733f06aa524cab8f98c19b5876c0ebeb0eb45ee4ca9113b0c8"),
        (4, "783716ed2fd324c81e92225d7d0342e5b611572f92bd90631078cbf39364e66f"),
        (5, "05d753022920ede0943b4bdea899570c2a9cff156cd136517a6e86e7426c9e1f"),
        (6, "5e920920236109693e3afa3aee624ccc8b492c63f98d6cf98d1b264100097f7e"),
        (7, "f585fc22ac13e44733ee9fd2cbe80aad6630a046e58d41029a40effda54d27d0"),
        (8, "f82770bde624a195ed283a8dd6c4519c0583c79280bad9050c4189d549b1362e"),
        (9, "9c34227d60defc63700c4d736446f98d8a2e50ccd8efa050e6c58c1f0ea840ac"),
    ] {
        let mut changed = capsule();
        match field {
            0 => changed.context = &changed_context,
            1 => changed.private_packet_binding = &changed_binding,
            2 => changed.capsule_blind = &changed_blind,
            3 => changed.redacted_payment = &[1, 2, 4],
            4 => changed.recovery_transaction = &[4, 6],
            5 => { changed.redacted_payment = &[1, 2]; changed.recovery_transaction = &[3, 4, 5]; },
            6 => changed.redacted_payment = &long,
            7 => changed.recovery_transaction = &long,
            8 => changed.private_packet_binding = &sparse,
            _ => changed.capsule_blind = &sparse,
        }
        assert_eq!(solver_capsule_commitment(changed).unwrap(), digest(expected), "capsule field {field}");
    }
    let mut changed = capsule();
    changed.private_packet_binding = &[0; 32];
    assert_eq!(solver_capsule_commitment(changed), Err(SemanticCommitmentError::InvalidPacketBinding));
    let mut changed = capsule();
    changed.capsule_blind = &[0; 32];
    assert_eq!(solver_capsule_commitment(changed), Err(SemanticCommitmentError::ZeroBlind));
    let oversized_p = vec![1; 16 * 1024 * 1024 + 1];
    let oversized_q = vec![1; 2 * 1024 * 1024 + 1];
    for (p, q) in [(&[][..], &b"q"[..]), (&b"p"[..], &[][..]),
        (&oversized_p[..], &b"q"[..]), (&b"p"[..], &oversized_q[..])] {
        let mut changed = capsule();
        changed.redacted_payment = p;
        changed.recovery_transaction = q;
        assert_eq!(solver_capsule_commitment(changed), Err(SemanticCommitmentError::InvalidPacket));
    }
    let mut bounded = capsule();
    bounded.redacted_payment = &oversized_p[..16 * 1024 * 1024];
    bounded.recovery_transaction = &oversized_q[..2 * 1024 * 1024];
    assert!(solver_capsule_commitment(bounded).is_ok());
    assert_eq!(format!("{:?}", capsule()), "SolverCapsule([REDACTED])");
}
