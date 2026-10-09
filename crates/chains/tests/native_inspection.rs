//! Local trusted-node acquisition checks, never source finality or financial evidence.
use primitive_types::U256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ziquid_chains::native::inspection::{NativeInspectionClient, NativeInspectionError, NativeInspectionObservation};

#[path = "support/native_inspection.rs"]
mod support;
use support::{Fixture, RowState, WireFault, PROVIDER_SENTINEL, hex, reply, uint_word};

fn client(fixture: &Fixture) -> NativeInspectionClient {
    NativeInspectionClient::new(fixture.endpoint(), true).unwrap()
}
fn observation_identity(fixture: &Fixture, observation: &NativeInspectionObservation) {
    assert_eq!(observation.deployment(), &fixture.scope().expected);
    assert_eq!(observation.block_hash(), [0x66; 32]);
    assert_eq!(observation.block_number(), U256::from(42));
    assert_eq!(observation.parent_hash(), [0x65; 32]);
    assert_eq!(observation.total_liability(), U256::MAX);
    assert_eq!(observation.source_scope(), "TRUSTED_NODE_AT_SELECTED_BLOCK");
    for qualification in [observation.finality(), observation.program_qualification(),
        observation.proof_validity(), observation.asset_backing(), observation.actual_transfer()] {
        assert_eq!(qualification, "UNVERIFIED");
    }
    let digests: Vec<[u8; 32]> = fixture.responses().iter().map(|bytes| Sha256::digest(bytes).into()).collect();
    assert_eq!(observation.response_digests(), digests);
    for (index, request) in fixture.requests().iter().enumerate() {
        assert_eq!(request["id"], json!(index + 1));
        if matches!(request["method"].as_str(), Some("eth_call" | "eth_getCode")) {
            assert_eq!(request["params"].as_array().unwrap().len(), 2);
            assert_eq!(request["params"][1], json!({"blockHash":hex(&[0x66; 32]), "requireCanonical":true}));
        }
    }
}
fn getter(data: &str) -> Value { json!({"to":hex(&[5; 20]), "data":data}) }
fn mutate_word(bytes: &mut [u8], word: usize) { bytes[(word + 1) * 32 - 1] ^= 1; }

#[tokio::test]
async fn identity_only_acquires_real_hash_pinned_reads_with_independent_runtime_keccak() {
    let fixture = Fixture::start(RowState::Absent);
    let observation = client(&fixture).inspect(&fixture.scope(), None).await.unwrap();
    observation_identity(&fixture, &observation);
    assert!(observation.obligation().is_none());
    let requests = fixture.requests();
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0], json!({"jsonrpc":"2.0", "id":1, "method":"eth_chainId", "params":[]}));
    assert_eq!(requests[1]["params"], json!([hex(&[0x66; 32]), false]));
    assert_eq!(requests[2]["params"][0], getter("0x2dde9aca"));
    assert_eq!(requests[3]["params"][0], getter("0xe82ec893"));
    assert_eq!(requests[4]["method"], "eth_getCode");
    assert_eq!(requests[4]["params"][0], hex(&[5; 20]));
    assert_eq!(requests[5]["method"], "eth_getCode");
    assert_eq!(requests[5]["params"][0], hex(&[7; 20]));
    assert_eq!(requests[6]["params"][0], getter("0x0fc29349"));
}

#[tokio::test]
async fn exact_statement_reports_absent_armed_and_consumed_without_payment_or_transfer_authority() {
    for state in [RowState::Absent, RowState::Armed, RowState::Consumed] {
        let fixture = Fixture::start(state);
        let statement = fixture.statement();
        let observation = client(&fixture).inspect(&fixture.scope(), Some(&statement)).await.unwrap();
        observation_identity(&fixture, &observation);
        let row = observation.obligation().unwrap();
        let context: [u8; 32] = Sha256::digest(statement.encode()).into();
        assert_eq!(row.context_digest(), context);
        let absent = matches!(state, RowState::Absent);
        assert_eq!(row.d(), if absent { U256::zero() } else { U256::MAX });
        assert_eq!(row.a(), if absent { 0 } else { 100_000_000 });
        assert_eq!(row.payer(), if absent { [0; 20] } else { [9; 20] });
        assert_eq!(row.u_payee(), if absent { [0; 20] } else { [10; 20] });
        assert_eq!(row.s_refund(), if absent { [0; 20] } else { [11; 20] });
        assert_eq!(row.stable_jtag(), if absent { [0; 32] } else { statement.stable_jtag });
        assert_eq!(row.reported_armed(), !absent);
        assert_eq!(row.reported_consumed(), matches!(state, RowState::Consumed));
        assert_eq!(row.reported_tag_context(), if absent { [0; 32] } else { context });
        let requests = fixture.requests();
        assert_eq!(requests.len(), 9);
        assert_eq!(requests[7]["params"][0], getter(&format!("0x16d4a5c7{}", &hex(&context)[2..])));
        assert_eq!(requests[8]["params"][0], getter(&format!("0x7c52451e{}", &hex(&statement.stable_jtag)[2..])));
    }
}

#[tokio::test]
async fn local_pins_and_exact_statement_binding_are_checked_before_any_rpc() {
    let fixture = Fixture::start(RowState::Absent);
    for change in 0..9 {
        let mut scope = fixture.scope();
        match change {
            0 => scope.block_hash.fill(0), 1 => scope.expected.target_chain_id = 0,
            2 => scope.expected.obligation.fill(0), 3 => scope.expected.verifier_runtime_code.fill(0),
            4 => scope.expected.schema_version = 2, 5 => scope.expected.source_network = 2,
            6 => scope.expected.financial_program.fill(0xff),
            7 => scope.expected.origin_program.fill(0xff),
            8 => scope.expected.source_acceptance_program.fill(0xff), _ => unreachable!(),
        }
        assert_eq!(client(&fixture).inspect(&scope, None).await.unwrap_err(), NativeInspectionError::InvalidScope);
    }
    for change in 0..13 {
        let mut s = fixture.statement();
        match change {
            0 => s.schema_version ^= 1, 1 => s.source_network ^= 1, 2 => s.source_pool ^= 1,
            3 => s.transaction_version ^= 1, 4 => s.consensus_branch ^= 1,
            5 => s.financial_program[0] ^= 1, 6 => s.origin_program[0] ^= 1,
            7 => s.source_acceptance_program[0] ^= 1, 8 => s.source_policy_id[0] ^= 1,
            9 => s.target_chain_id ^= 1, 10 => s.obligation[0] ^= 1,
            11 => s.deployment_descriptor[0] ^= 1, 12 => s.a = 0, _ => unreachable!(),
        }
        assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&s)).await.unwrap_err(), NativeInspectionError::InvalidStatement);
    }
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn every_full_returned_deployment_pin_and_independent_digest_is_enforced() {
    for word in 0..14 {
        let mut bytes = support::deployment_words(); mutate_word(&mut bytes, word);
        let fixture = Fixture::with_response(RowState::Absent, 3, reply(3, json!(hex(&bytes))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::WrongIdentity, "word {word}");
    }
    for (id, result, expected) in [
        (1, json!("0x14a35"), NativeInspectionError::WrongChain),
        (2, json!({"hash":hex(&[0x67; 32]), "number":"0x2a", "parentHash":hex(&[0x65; 32])}), NativeInspectionError::WrongBlock),
        (4, json!(hex(&[0x55; 32])), NativeInspectionError::WrongIdentity),
        (5, json!("0x01"), NativeInspectionError::WrongIdentity),
        (6, json!("0x01"), NativeInspectionError::WrongIdentity),
        (5, json!("0x"), NativeInspectionError::WrongIdentity),
    ] {
        let fixture = Fixture::with_response(RowState::Absent, id, reply(id, result));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), expected);
        assert_eq!(fixture.requests().len(), id as usize);
    }
}

#[tokio::test]
async fn full_static_abi_frames_reject_truncation_trailing_words_and_invalid_scalar_padding() {
    for (id, length) in [(3,448), (4,32), (7,32), (8,256), (9,32)] {
        for result in [json!(hex(&vec![0; length - 1])), json!(hex(&vec![0; length + 1])),
            json!(hex(&vec![0; length + 32])), json!("0xgg"), Value::Null] {
            let fixture = Fixture::with_response(RowState::Armed, id, reply(id, result));
            assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::MalformedResponse);
        }
    }
    for word in [0, 1, 2, 3, 4, 9, 10, 12] {
        let mut bytes = support::deployment_words(); bytes[word * 32] = 1;
        let fixture = Fixture::with_response(RowState::Armed, 3, reply(3, json!(hex(&bytes))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    for word in [1, 2, 3, 4, 6, 7] {
        let mut bytes = support::obligation_words(RowState::Armed); bytes[word * 32] = 1;
        let fixture = Fixture::with_response(RowState::Armed, 8, reply(8, json!(hex(&bytes))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    for word in [6, 7] {
        let mut bytes = support::obligation_words(RowState::Armed);
        bytes[word * 32..(word + 1) * 32].copy_from_slice(&uint_word(2));
        let fixture = Fixture::with_response(RowState::Armed, 8, reply(8, json!(hex(&bytes))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
}

#[tokio::test]
async fn row_coherence_binds_amounts_beneficiaries_stable_tag_context_and_active_liability() {
    for state in [RowState::Absent, RowState::Armed, RowState::Consumed] {
        for word in 0..8 {
            // Both consumed flag values are reachable for an exact armed row.
            if word == 7 && !matches!(state, RowState::Absent) { continue; }
            let mut bytes = support::obligation_words(state); mutate_word(&mut bytes, word);
            let fixture = Fixture::with_response(state, 8, reply(8, json!(hex(&bytes))));
            assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::WrongState,
                "mutated row word {word}");
        }
    }
    for state in [RowState::Armed, RowState::Consumed] {
        for tag_context in [[0; 32], [0x77; 32]] {
            let fixture = Fixture::with_response(state, 9, reply(9, json!(hex(&tag_context))));
            assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::WrongState);
        }
    }
    let context = support::statement().digest();
    let fixture = Fixture::with_response(RowState::Absent, 9, reply(9, json!(hex(&context))));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::WrongState);
    let fixture = Fixture::with_response(RowState::Armed, 7, reply(7, json!(hex(&[0; 32]))));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap_err(), NativeInspectionError::WrongState);
}

#[tokio::test]
async fn tag_conflict_and_consumed_with_other_liabilities_remain_observations_not_refund_or_completed() {
    let fixture = Fixture::with_response(RowState::Absent, 9, reply(9, json!(hex(&[0x77; 32]))));
    let observation = client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap();
    let row = observation.obligation().unwrap();
    assert!(!row.reported_armed()); assert!(!row.reported_consumed());
    assert_eq!(row.reported_tag_context(), [0x77; 32]);
    for state in [RowState::Absent, RowState::Consumed] {
        let fixture = Fixture::with_response(state, 7, reply(7, json!(hex(&[0; 32]))));
        let observation = client(&fixture).inspect(&fixture.scope(), Some(&fixture.statement())).await.unwrap();
        assert_eq!(observation.total_liability(), U256::zero());
        assert_eq!(observation.actual_transfer(), "UNVERIFIED");
    }
}

#[tokio::test]
async fn raw_rpc_envelope_denies_duplicates_null_batches_positional_fields_and_result_error_ambiguity() {
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"result":"0x14a34","result":"0x14a34"}"#,
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"result":"0x14a34"}"#,
        r#"{"jsonrpc":"2.0","id":1,"id":1,"result":"0x14a34"}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":"0x14a34"}"#,
        r#"{"jsonrpc":"1.0","id":1,"result":"0x14a34"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":null}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x14a34","error":{"code":-32001,"message":"sentinel"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"code":-2,"message":"sentinel"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"first","message":"sentinel"}}"#,
        r#"["2.0",1,"0x14a34"]"#, r#"[]"#, r#"null"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x14a34"}{}"#,
    ] {
        let fixture = Fixture::with_response(RowState::Absent, 1, body.as_bytes().to_vec());
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[tokio::test]
async fn nested_block_identity_duplicates_missing_fields_and_noncanonical_quantities_are_rejected() {
    let hash = hex(&[0x66; 32]); let parent = hex(&[0x65; 32]);
    for result in [
        format!(r#"{{"hash":"{hash}","hash":"{hash}","number":"0x2a","parentHash":"{parent}"}}"#),
        format!(r#"{{"hash":"{hash}","number":"0x2a","number":"0x2a","parentHash":"{parent}"}}"#),
        format!(r#"{{"hash":"{hash}","number":"0x2a","parentHash":"{parent}","parentHash":"{parent}"}}"#),
        format!(r#"{{"hash":"{hash}","number":"0x2a"}}"#),
        format!(r#"{{"hash":null,"number":"0x2a","parentHash":"{parent}"}}"#),
        format!(r#"["{hash}","0x2a","{parent}"]"#), "null".into(),
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{result}}}"#).into_bytes();
        let fixture = Fixture::with_response(RowState::Absent, 2, body);
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    for bad in ["0x", "0x00", "0x014a34", "14a34", "0X14a34", "0xg", "-1"] {
        let fixture = Fixture::with_response(RowState::Absent, 1, reply(1, json!(bad)));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    for number in ["0x00".to_owned(), format!("0x{}", "f".repeat(65))] {
        let fixture = Fixture::with_response(RowState::Absent, 2, reply(2, json!({"hash":hash, "number":number, "parentHash":parent})));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    let fixture = Fixture::with_response(RowState::Absent, 2, reply(2, json!({"hash":hash, "number":format!("0x{}", "f".repeat(64)), "parentHash":parent})));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap().block_number(), U256::MAX);
}

#[tokio::test]
async fn code_and_whole_body_bounds_compression_redirect_and_transport_failures_are_sanitized() {
    for (wire, expected) in [
        (WireFault::Status, NativeInspectionError::HttpRejected),
        (WireFault::Redirect, NativeInspectionError::HttpRejected),
        (WireFault::Oversize, NativeInspectionError::ResponseTooLarge),
        (WireFault::ChunkedOversize, NativeInspectionError::ResponseTooLarge),
        (WireFault::Truncated, NativeInspectionError::Transport),
        (WireFault::Compressed, NativeInspectionError::MalformedResponse),
    ] {
        let fixture = Fixture::with_wire(wire);
        let endpoint = format!("{}?key={PROVIDER_SENTINEL}", fixture.endpoint());
        let client = NativeInspectionClient::new(&endpoint, true).unwrap();
        let error = client.inspect(&fixture.scope(), None).await.unwrap_err();
        assert_eq!(error, expected); assert_eq!(fixture.requests().len(), 1);
        for text in [format!("{client:?}"), format!("{error:?}"), error.to_string()] {
            assert!(!text.contains(&endpoint)); assert!(!text.contains(PROVIDER_SENTINEL));
        }
    }
    for (bytes, expected) in [(24_576, NativeInspectionError::WrongIdentity), (24_577, NativeInspectionError::ResponseTooLarge)] {
        let fixture = Fixture::with_response(RowState::Absent, 5, reply(5, json!(hex(&vec![0; bytes]))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), expected);
    }
    for code in ["0x0", "0xgg", "00"] {
        let fixture = Fixture::with_response(RowState::Absent, 5, reply(5, json!(code)));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), NativeInspectionError::MalformedResponse);
    }
    let body = json!({"jsonrpc":"2.0", "id":1, "error":{"code":-32001, "message":PROVIDER_SENTINEL, "data":PROVIDER_SENTINEL}}).to_string().into_bytes();
    let fixture = Fixture::with_response(RowState::Absent, 1, body);
    let error = client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err();
    assert_eq!(error, NativeInspectionError::RpcRejected);
    assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
}

#[test]
fn endpoint_policy_requires_explicit_tls_or_literal_loopback_permission_and_never_debugs_uri() {
    for endpoint in ["http://127.0.0.1/rpc", "https://user:secret@node.invalid/rpc", "https://node.invalid/#secret", "not-a-url"] {
        assert_eq!(NativeInspectionClient::new(endpoint, false).unwrap_err(), NativeInspectionError::InvalidEndpoint);
    }
    for endpoint in ["http://localhost/rpc", "http://127.1/rpc", "http://0x7f000001/rpc", "http://node.invalid/rpc"] {
        assert_eq!(NativeInspectionClient::new(endpoint, true).unwrap_err(), NativeInspectionError::InvalidEndpoint);
    }
}
