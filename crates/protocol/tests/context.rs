use primitive_types::U256;
use ziquid_protocol::{
    ContextError, ContextField, NativeAmount, StatementContext, ValidatedContext,
};

// Generated local shape fixture only: these identities and branch are not an
// approved source policy, actual program, deployment, or source-chain proof.
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
        native_amount: NativeAmount::new(U256::from_big_endian(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ])),
    }
}

fn hex_bytes(literal: &str) -> Vec<u8> {
    literal
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Exact independent DEX-native wire, not EVM ABI or a purported Zoss standard.
// All numbers are big-endian; SHA-256 was derived independently of Rust encode.
fn wire_vector() -> Vec<u8> {
    hex_bytes(concat!(
        "5a49515549445f4445585f53544154454d454e5400",
        "0001",
        "746573746e6574",
        "69726f6e776f6f64",
        "00000006",
        "12345678",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "6666666666666666666666666666666666666666666666666666666666666666",
        "7777777777777777777777777777777777777777777777777777777777777777",
        "0000000000000003",
        "0000000000000001",
        "01020304",
        "0000000000007a69",
        "8888888888888888888888888888888888888888",
        "9999999999999999999999999999999999999999999999999999999999999999",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cccccccccccccccccccccccccccccccccccccccc",
        "dddddddddddddddddddddddddddddddddddddddd",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    ))
}

#[test]
fn canonical_statement_matches_independent_wire_and_sha256_vector() {
    let raw = context();
    let validated = raw.validate().unwrap();
    let literal = wire_vector();
    assert_eq!(validated.encode(), literal);
    assert_eq!(
        validated.digest().to_vec(),
        hex_bytes("3cb96ab0d6d313f1da75f0a893948b1140171df96ad9559288697c089bb7602a"),
    );
    assert_eq!(ValidatedContext::decode(&literal).unwrap().context(), &raw);
}

fn invalid_cases() -> Vec<(StatementContext, ContextError)> {
    let mut cases = Vec::new();
    macro_rules! invalid {
        ($field:ident, $value:expr, $error:expr) => {{
            let mut raw = context();
            raw.$field = $value;
            cases.push((raw, $error));
        }};
    }
    invalid!(schema_version, 0, ContextError::UnsupportedSchema(0));
    invalid!(schema_version, 2, ContextError::UnsupportedSchema(2));
    invalid!(
        source_network,
        *b"mainnet",
        ContextError::UnsupportedNetwork
    );
    invalid!(source_pool, *b"orchard\0", ContextError::UnsupportedPool);
    invalid!(
        transaction_version,
        5,
        ContextError::UnsupportedTransactionVersion(5)
    );
    invalid!(
        consensus_branch,
        0,
        ContextError::ZeroField(ContextField::ConsensusBranch)
    );
    invalid!(
        source_policy_id,
        [0; 32],
        ContextError::ZeroField(ContextField::SourcePolicyId)
    );
    invalid!(
        preparation_program,
        [0; 32],
        ContextError::ZeroField(ContextField::PreparationProgram)
    );
    invalid!(
        settlement_program,
        [0; 32],
        ContextError::ZeroField(ContextField::SettlementProgram)
    );
    invalid!(
        order_id,
        [0; 32],
        ContextError::ZeroField(ContextField::OrderId)
    );
    invalid!(
        consumption_tag,
        [0; 32],
        ContextError::ZeroField(ContextField::ConsumptionTag)
    );
    invalid!(
        source_payment_commitment,
        [0; 32],
        ContextError::ZeroField(ContextField::SourcePaymentCommitment)
    );
    invalid!(
        real_input_commitment,
        [0; 32],
        ContextError::ZeroField(ContextField::RealInputCommitment)
    );
    invalid!(
        source_quoted_amount,
        0,
        ContextError::ZeroField(ContextField::SourceQuotedAmount)
    );
    invalid!(
        source_quoted_amount,
        2_100_000_000_000_001,
        ContextError::OutOfRange(ContextField::SourceQuotedAmount)
    );
    invalid!(
        source_fee_cap,
        2_100_000_000_000_001,
        ContextError::OutOfRange(ContextField::SourceFeeCap)
    );
    invalid!(
        source_expiry,
        0,
        ContextError::OutOfRange(ContextField::SourceExpiry)
    );
    invalid!(
        source_expiry,
        500_000_000,
        ContextError::OutOfRange(ContextField::SourceExpiry)
    );
    invalid!(
        source_expiry,
        u32::MAX,
        ContextError::OutOfRange(ContextField::SourceExpiry)
    );
    invalid!(
        evm_chain_id,
        0,
        ContextError::ZeroField(ContextField::EvmChainId)
    );
    invalid!(
        escrow,
        [0; 20],
        ContextError::ZeroField(ContextField::Escrow)
    );
    invalid!(
        escrow_code_hash,
        [0; 32],
        ContextError::ZeroField(ContextField::EscrowCodeHash)
    );
    invalid!(
        verifier,
        [0; 20],
        ContextError::ZeroField(ContextField::Verifier)
    );
    invalid!(
        verifier_code_hash,
        [0; 32],
        ContextError::ZeroField(ContextField::VerifierCodeHash)
    );
    invalid!(
        u_payee,
        [0; 20],
        ContextError::ZeroField(ContextField::UPayee)
    );
    invalid!(
        s_refund,
        [0; 20],
        ContextError::ZeroField(ContextField::SRefund)
    );
    invalid!(s_refund, [0xcc; 20], ContextError::SameBeneficiary);
    invalid!(
        native_amount,
        NativeAmount::new(U256::zero()),
        ContextError::ZeroField(ContextField::NativeAmount)
    );
    cases
}

#[test]
fn context_validation_rejects_malformed_bindings_and_amounts() {
    for (raw, expected) in invalid_cases() {
        assert_eq!(raw.validate(), Err(expected));
    }
}

#[test]
fn context_range_checks_do_not_invent_branch_fee_or_policy_authority() {
    for expiry in [1, 499_999_999] {
        for fee in [0, 2_100_000_000_000_000] {
            let mut raw = context();
            raw.consensus_branch = u32::MAX;
            raw.source_quoted_amount = 2_100_000_000_000_000;
            raw.source_fee_cap = fee;
            raw.source_expiry = expiry;
            raw.evm_chain_id = u64::MAX;
            raw.native_amount = NativeAmount::new(U256::MAX);
            let validated = raw.validate().unwrap();
            assert_eq!(
                ValidatedContext::decode(&validated.encode())
                    .unwrap()
                    .context(),
                &raw
            );
        }
    }
}

#[test]
fn decoder_rejects_every_truncation_trailing_bytes_and_wrong_domain() {
    let literal = wire_vector();
    for length in 0..474 {
        assert_eq!(
            ValidatedContext::decode(&literal[..length]),
            Err(ContextError::InvalidLength {
                expected: 474,
                actual: length
            }),
        );
    }
    let mut trailing = literal.clone();
    trailing.push(0);
    assert_eq!(
        ValidatedContext::decode(&trailing),
        Err(ContextError::InvalidLength {
            expected: 474,
            actual: 475
        }),
    );
    let mut wrong_domain = literal;
    wrong_domain[0] ^= 1;
    assert_eq!(
        ValidatedContext::decode(&wrong_domain),
        Err(ContextError::WrongDomain)
    );
}

#[test]
fn decoder_enforces_fixed_byte_offsets_and_the_same_trust_boundary() {
    use ContextField::*;
    let literal = wire_vector();
    let invalid = [
        (21, hex_bytes("0002"), ContextError::UnsupportedSchema(2)),
        (23, b"mainnet".to_vec(), ContextError::UnsupportedNetwork),
        (30, b"orchard\0".to_vec(), ContextError::UnsupportedPool),
        (
            38,
            hex_bytes("00000005"),
            ContextError::UnsupportedTransactionVersion(5),
        ),
        (42, vec![0; 4], ContextError::ZeroField(ConsensusBranch)),
        (46, vec![0; 32], ContextError::ZeroField(SourcePolicyId)),
        (78, vec![0; 32], ContextError::ZeroField(PreparationProgram)),
        (110, vec![0; 32], ContextError::ZeroField(SettlementProgram)),
        (142, vec![0; 32], ContextError::ZeroField(OrderId)),
        (174, vec![0; 32], ContextError::ZeroField(ConsumptionTag)),
        (
            206,
            vec![0; 32],
            ContextError::ZeroField(SourcePaymentCommitment),
        ),
        (
            238,
            vec![0; 32],
            ContextError::ZeroField(RealInputCommitment),
        ),
        (270, vec![0; 8], ContextError::ZeroField(SourceQuotedAmount)),
        (
            270,
            vec![0xff; 8],
            ContextError::OutOfRange(SourceQuotedAmount),
        ),
        (278, vec![0xff; 8], ContextError::OutOfRange(SourceFeeCap)),
        (286, vec![0; 4], ContextError::OutOfRange(SourceExpiry)),
        (
            286,
            hex_bytes("1dcd6500"),
            ContextError::OutOfRange(SourceExpiry),
        ),
        (290, vec![0; 8], ContextError::ZeroField(EvmChainId)),
        (298, vec![0; 20], ContextError::ZeroField(Escrow)),
        (318, vec![0; 32], ContextError::ZeroField(EscrowCodeHash)),
        (350, vec![0; 20], ContextError::ZeroField(Verifier)),
        (370, vec![0; 32], ContextError::ZeroField(VerifierCodeHash)),
        (402, vec![0; 20], ContextError::ZeroField(UPayee)),
        (422, vec![0; 20], ContextError::ZeroField(SRefund)),
        (422, vec![0xcc; 20], ContextError::SameBeneficiary),
        (442, vec![0; 32], ContextError::ZeroField(NativeAmount)),
    ];
    for (offset, replacement, expected) in invalid {
        let mut malformed = literal.clone();
        malformed[offset..offset + replacement.len()].copy_from_slice(&replacement);
        assert_eq!(ValidatedContext::decode(&malformed), Err(expected));
    }
}

#[test]
fn every_mutable_binding_is_preserved_and_affects_the_statement_digest() {
    let literal = wire_vector();
    let original = context();
    let digest = original.validate().unwrap().digest();
    // Independent last-byte offsets for every variable context field. Fixed
    // schema/network/pool/format are rejected above, not mutable options.
    for offset in [
        45, 77, 109, 141, 173, 205, 237, 269, 277, 285, 289, 297, 317, 349, 369, 401, 421, 441, 473,
    ] {
        let mut changed = literal.clone();
        changed[offset] ^= 1;
        let decoded = ValidatedContext::decode(&changed).unwrap();
        assert_ne!(decoded.context(), &original);
        assert_ne!(decoded.digest(), digest);
        assert_eq!(decoded.encode(), changed);
    }
}

#[test]
fn decoder_rejects_zero_source_tags_instead_of_assuming_defaults() {
    let literal = wire_vector();
    for (offset, width, expected) in [
        (23, 7, ContextError::UnsupportedNetwork),
        (30, 8, ContextError::UnsupportedPool),
        (38, 4, ContextError::UnsupportedTransactionVersion(0)),
    ] {
        let mut malformed = literal.clone();
        malformed[offset..offset + width].fill(0);
        assert_eq!(ValidatedContext::decode(&malformed), Err(expected));
    }
}
