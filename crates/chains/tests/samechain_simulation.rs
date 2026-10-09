//! Synthetic loopback transport checks only. Invalid public proof frames and
//! one-byte runtime responses NEVER establish financial execution or proof validity.
use primitive_types::U256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ziquid_chains::samechain::{
    CallBuildError, UnsignedCall, build_creation_call, build_fill_call,
    build_single_call, build_withdrawal_call,
    inspection::{InspectionError, SamechainInspectionClient, SimulationError},
};
use ziquid_protocol::samechain::{Action, Asset, OutputDescriptor, Role, MAX_CIPHERTEXT_BYTES};

#[path = "support/samechain_inspection.rs"]
mod support;
use support::{Fault, Fixture, PROVIDER_SENTINEL, hex, unverified_frame};

fn client(fixture: &Fixture) -> SamechainInspectionClient {
    SamechainInspectionClient::new(fixture.endpoint(), true).unwrap()
}

fn creation(fixture: &Fixture) -> UnsignedCall {
    build_creation_call(&fixture.scope().expected, fixture.scope().token,
        &fixture.creation_packet(false), &unverified_frame()).unwrap()
}

fn execution_requests(fixture: &Fixture) -> Vec<Value> {
    fixture.requests().into_iter().filter(|request| {
        request["method"] == "eth_call" && request["params"][0].get("from").is_some()
    }).collect()
}

#[tokio::test]
async fn every_public_builder_executes_exact_bytes_and_quantities_only_after_fresh_identity() {
    // Dropping a field, truncating value to u64, changing the proof, using latest,
    // caching identity, or inspecting packet state before execution breaks this.
    for operation in 0..8 {
        let fixture = Fixture::start();
        let scope = fixture.scope();
        let proof_a = unverified_frame();
        let mut proof_b = unverified_frame();
        proof_b[100] = 0x5a; // Public INVALID pairing payload must remain unchanged.
        let sender = [0x42; 20];
        let (call, from, value, value_wire, selector) = match operation {
            0..=2 => {
                let mut packet = fixture.creation_packet(operation == 2);
                if operation == 0 {
                    packet.amount = U256::MAX;
                    let OutputDescriptor::Note { ciphertext, .. } = &mut packet.output else { panic!() };
                    *ciphertext = vec![0xa5; MAX_CIPHERTEXT_BYTES];
                } else if operation == 1 {
                    packet.asset = Asset::Token(scope.token);
                }
                let value = if operation == 1 { U256::zero() } else { packet.amount };
                let wire = if operation == 0 { format!("0x{}", "f".repeat(64)) }
                    else if operation == 1 { "0x0".to_owned() }
                    else { format!("0x{:x}", packet.amount) };
                let from = packet.payer;
                (build_creation_call(&scope.expected, scope.token, &packet, &proof_a).unwrap(),
                    from, value, wire, [0x94, 0x18, 0x4b, 0xa9])
            }
            3 => (build_fill_call(&scope.expected, &fixture.fill_packet(), sender, &proof_a, &proof_b).unwrap(),
                sender, U256::zero(), "0x0".to_owned(), [0xd3, 0x16, 0xbd, 0x1a]),
            4 | 5 => {
                let mut packet = fixture.single_packet();
                let role = if operation == 4 { Role::A } else { Role::B };
                for output in &mut packet.outputs {
                    match output {
                        OutputDescriptor::Note { role: output_role, .. }
                        | OutputDescriptor::Exit { role: output_role, .. }
                        | OutputDescriptor::Fee { payer: output_role, .. } => *output_role = role,
                    }
                }
                let action = if operation == 4 { Action::Cancel } else { Action::Exit };
                (build_single_call(&scope.expected, &packet, sender, role, action, &proof_a).unwrap(),
                    sender, U256::zero(), "0x0".to_owned(), [0xf6, 0x14, 0x6f, 0x41])
            }
            6 | 7 => {
                let mut packet = fixture.withdrawal_packet();
                if operation == 7 {
                    for output in &mut packet.outputs {
                        if let OutputDescriptor::Exit { asset, .. }
                            | OutputDescriptor::Fee { asset, .. } = output { *asset = Asset::Native; }
                    }
                }
                (build_withdrawal_call(&scope.expected, &packet, sender, &proof_a).unwrap(),
                    sender, U256::zero(), "0x0".to_owned(), [0x50, 0xfb, 0xe2, 0xd9])
            }
            _ => unreachable!(),
        };
        assert_eq!(&call.data()[..4], &selector);
        let gas = if operation == 0 { 30_000_000 } else { 1 };
        let gas_wire = if operation == 0 { "0x1c9c380" } else { "0x1" };
        let client = client(&fixture);
        // A previous observation never licenses skipping a new identity acquisition.
        client.inspect(&scope, None).await.unwrap();
        let observation = client.simulate(&scope, &call, gas).await.unwrap();
        let requests = fixture.requests();
        let inspection_requests = observation.authority().response_digests().len();
        assert_eq!(requests.len(), inspection_requests * 2 + 1);
        assert_eq!(&requests[..inspection_requests], &requests[inspection_requests..inspection_requests * 2]);
        assert_eq!(execution_requests(&fixture).len(), 1);
        assert_eq!(requests[inspection_requests * 2], json!({
            "jsonrpc":"2.0", "id":inspection_requests + 1, "method":"eth_call", "params":[{
                "from":hex(&from), "to":hex(&scope.expected.authority),
                "value":value_wire, "gas":gas_wire, "data":hex(call.data())
            }, {"blockHash":hex(&scope.block_hash), "requireCanonical":true}]
        }));
        for request in &requests {
            assert!(matches!(request["method"].as_str(),
                Some("eth_chainId" | "eth_getBlockByHash" | "eth_getCode" | "eth_call" | "eth_getLogs")));
            if matches!(request["method"].as_str(), Some("eth_getCode" | "eth_call")) {
                assert_eq!(request["params"].as_array().unwrap().len(), 2);
                assert_eq!(request["params"][1], json!({"blockHash":hex(&scope.block_hash), "requireCanonical":true}));
            }
        }
        assert_eq!(observation.from(), from);
        assert_eq!(observation.to(), scope.expected.authority);
        assert_eq!(observation.value(), value);
        assert_eq!(observation.gas_limit(), gas);
        assert_eq!(observation.packet_digest(), call.packet_digest());
        assert_eq!(observation.calldata_sha256(), <[u8; 32]>::from(Sha256::digest(call.data())));
        assert_eq!(observation.source_scope(), "TRUSTED_NODE_AT_SELECTED_BLOCK");
        assert_eq!(observation.outcome(), "NODE_REPORTED_VOID_EXECUTION");
        let authority = observation.authority();
        assert_eq!(authority.deployment(), &scope.expected);
        assert_eq!(authority.token(), scope.token);
        assert_eq!(authority.token_code(), scope.token_code);
        assert_eq!(authority.block_hash(), scope.block_hash);
        assert_eq!(authority.block_number(), U256::from(42));
        assert_eq!(authority.parent_hash(), [0x65; 32]);
        assert_eq!(authority.appended_notes()[0].occurrence.transaction_hash, [0x22; 32]);
        assert_eq!(authority.consumed_nullifiers()[0].nullifier, [0x55; 32]);
        assert_eq!(authority.policy_id(), scope.policy_id);
        assert_eq!(authority.packet_digest(), None);
        assert!(authority.input_states().is_empty() && authority.output_states().is_empty());
        assert_eq!(authority.creation(), None);
        let responses = fixture.responses();
        let identity_digests: Vec<[u8; 32]> = responses[inspection_requests..inspection_requests * 2].iter()
            .map(|body| Sha256::digest(body).into()).collect();
        assert_eq!(authority.response_digests(), identity_digests);
        assert_eq!(observation.response_sha256(), <[u8; 32]>::from(Sha256::digest(&responses[inspection_requests * 2])));
    }
}

#[tokio::test]
async fn invalid_gas_scope_and_call_deployment_fail_before_any_http() {
    let fixture = Fixture::start();
    let client = client(&fixture);
    let scope = fixture.scope();
    let call = creation(&fixture);
    for gas in [0, 30_000_001, u64::MAX] {
        assert_eq!(client.simulate(&scope, &call, gas).await.unwrap_err(), SimulationError::InvalidGas);
    }
    for field in 0..5 {
        let mut bad = scope;
        match field {
            0 => bad.expected.chain_id = 0,
            1 => bad.token = [0; 20],
            2 => bad.token_code = [0; 32],
            3 => bad.block_hash = [0; 32],
            4 => bad.policy_id = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(client.simulate(&bad, &call, 1).await.unwrap_err(),
            SimulationError::Inspection(InspectionError::InvalidScope));
    }
    for field in 0..6 {
        let mut packet = fixture.creation_packet(false);
        match field {
            0 => packet.deployment.chain_id += 1,
            1 => packet.deployment.authority[0] ^= 1,
            2 => packet.deployment.authority_code[0] ^= 1,
            3 => packet.deployment.verifier[0] ^= 1,
            4 => packet.deployment.verifier_code[0] ^= 1,
            5 => packet.deployment.owner_program[0] ^= 1,
            _ => unreachable!(),
        }
        let mismatched = build_creation_call(&packet.deployment, packet.token, &packet, &unverified_frame()).unwrap();
        assert_eq!(client.simulate(&scope, &mismatched, 1).await.unwrap_err(), SimulationError::InvalidCall);
    }
    // Sender/to/calldata are private and only actual validating builders construct
    // them; an invalid sender cannot become a simulatable consumer input.
    assert_eq!(build_fill_call(&scope.expected, &fixture.fill_packet(), [0; 20],
        &unverified_frame(), &unverified_frame()).unwrap_err(), CallBuildError::InvalidSender);
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn each_identity_mismatch_prevents_execution_instead_of_falling_back() {
    let mut faults = vec![
        (Fault::WrongChain, InspectionError::WrongChain),
        (Fault::WrongBlock, InspectionError::WrongBlock),
        (Fault::WrongCode, InspectionError::WrongIdentity),
        (Fault::WrongVerifierCode, InspectionError::WrongIdentity),
        (Fault::WrongTokenCode, InspectionError::WrongIdentity),
        (Fault::WrongDigest, InspectionError::WrongIdentity),
        (Fault::WrongToken, InspectionError::WrongIdentity),
        (Fault::WrongTokenPin, InspectionError::WrongIdentity),
        (Fault::RpcRejected, InspectionError::RpcRejected(-32001)),
    ];
    faults.extend((0..7).map(|index| (Fault::WrongDeployment(index), InspectionError::WrongIdentity)));
    for (fault, expected) in faults {
        let fixture = Fixture::with_fault(fault);
        assert_eq!(client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err(),
            SimulationError::Inspection(expected));
        assert!(!fixture.requests().is_empty());
        assert!(execution_requests(&fixture).is_empty());
    }
    let fixture = Fixture::start();
    let mut scope = fixture.scope();
    scope.token = [8; 20];
    assert_eq!(client(&fixture).simulate(&scope, &creation(&fixture), 1).await.unwrap_err(),
        SimulationError::Inspection(InspectionError::WrongIdentity));
    assert!(execution_requests(&fixture).is_empty());
    let fixture = Fixture::with_response(1,
        br#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_vec());
    assert_eq!(client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err(),
        SimulationError::Inspection(InspectionError::MalformedResponse));
    assert!(execution_requests(&fixture).is_empty());
}

#[tokio::test]
async fn only_exact_empty_hex_is_node_reported_void_not_a_nonempty_success_marker() {
    for result in ["", "0X", "0x0", "0x00", "0x01",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0xdeadbeef", " 0x", "0x ", PROVIDER_SENTINEL] {
        let fixture = Fixture::with_fault(Fault::SimulationResult(result));
        assert_eq!(client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err(),
            SimulationError::MalformedResponse);
        assert_eq!(execution_requests(&fixture).len(), 1);
    }
}

#[tokio::test]
async fn raw_execution_envelopes_reject_mismatched_ids_null_duplicates_and_positional_maps() {
    for body in [
        r#"{"jsonrpc":"1.0","id":13,"result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":14,"result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":"13","result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":null}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":true}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":[]}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":13}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":null}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":"0x","error":{"code":-32000,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":13,"result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":14,"id":13,"result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":"0x00","result":"0x"}"#,
        r#"["2.0",13,"0x"]"#,
        r#"{"jsonrpc":"2.0","id":13,"error":[-32000,"private"]}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":-32000,"code":-32001,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":-32000,"message":"private","message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":null,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":1.5,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":9223372036854775808,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":-9223372036854775809,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":13,"error":{"code":-32000,"message":null}}"#,
        r#"{"jsonrpc":"2.0","id":13,"result":"0x"} trailing"#,
    ] {
        let fixture = Fixture::with_response(13, body.as_bytes().to_vec());
        assert_eq!(client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err(),
            SimulationError::MalformedResponse, "{body}");
        assert_eq!(execution_requests(&fixture).len(), 1);
    }
}

#[tokio::test]
async fn numeric_execution_rejection_is_redacted_and_distinct_from_unavailable() {
    for code in [i64::MIN, -32000, 3, i64::MAX] {
        let body = json!({"jsonrpc":"2.0", "id":13, "error":{
            "code":code, "message":PROVIDER_SENTINEL, "data":{"query":PROVIDER_SENTINEL}
        }}).to_string().into_bytes();
        let fixture = Fixture::with_response(13, body);
        let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}", fixture.endpoint());
        let client = SamechainInspectionClient::new(&endpoint, true).unwrap();
        assert!(!format!("{client:?}").contains(PROVIDER_SENTINEL));
        let error = client.simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err();
        assert_eq!(error, SimulationError::RpcRejected(code));
        assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
        assert_eq!(execution_requests(&fixture).len(), 1);
    }
    let fixture = Fixture::with_fault(Fault::SimulationRpcRejected);
    assert_eq!(client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err(),
        SimulationError::RpcRejected(-32000));
}

#[tokio::test]
async fn execution_transport_failures_and_bounded_bodies_never_become_reported_execution() {
    for (fault, expected) in [
        (Fault::SimulationHttpStatus(503), InspectionError::HttpStatus(503)),
        (Fault::SimulationRedirect, InspectionError::HttpStatus(302)),
        (Fault::SimulationOversizeBody, InspectionError::ResponseTooLarge),
        (Fault::SimulationChunkedOversize, InspectionError::ResponseTooLarge),
        (Fault::SimulationTruncated, InspectionError::Transport),
        (Fault::SimulationCompressed, InspectionError::MalformedResponse),
    ] {
        let fixture = Fixture::with_fault(fault);
        let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}", fixture.endpoint());
        let client = SamechainInspectionClient::new(&endpoint, true).unwrap();
        let error = client.simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap_err();
        let expected = if expected == InspectionError::MalformedResponse {
            SimulationError::MalformedResponse
        } else { SimulationError::Inspection(expected) };
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
        assert_eq!(execution_requests(&fixture).len(), 1); // No redirect/retry/fallback.
    }
    let fixture = Fixture::start();
    let call = creation(&fixture);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = SamechainInspectionClient::new(
        &format!("http://{address}/rpc?api_key={PROVIDER_SENTINEL}"), true).unwrap();
    let error = client.simulate(&fixture.scope(), &call, 1).await.unwrap_err();
    assert_eq!(error, SimulationError::Inspection(InspectionError::Transport));
    assert!(!format!("{client:?} {error:?} {error}").contains(PROVIDER_SENTINEL));
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn ignored_provider_metadata_is_allowed_but_remains_private_and_body_bounded() {
    let body = json!({"jsonrpc":"2.0", "id":13, "result":"0x", "provider":PROVIDER_SENTINEL})
        .to_string().into_bytes();
    let fixture = Fixture::with_response(13, body.clone());
    let observation = client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap();
    assert_eq!(observation.response_sha256(), <[u8; 32]>::from(Sha256::digest(body)));
    assert!(!format!("{observation:?}").contains(PROVIDER_SENTINEL));
    let mut bounded = br#"{"jsonrpc":"2.0","id":13,"result":"0x"}"#.to_vec();
    bounded.resize(1024 * 1024, b' ');
    let fixture = Fixture::with_response(13, bounded.clone());
    let observation = client(&fixture).simulate(&fixture.scope(), &creation(&fixture), 1).await.unwrap();
    assert_eq!(observation.response_sha256(), <[u8; 32]>::from(Sha256::digest(bounded)));
}
