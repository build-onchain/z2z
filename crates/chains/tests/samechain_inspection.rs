use primitive_types::U256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ziquid_chains::samechain::inspection::{
    AppendedNote, AuthorityObservation, ConsumedNullifier, CreationState, InspectionError, InspectionPacket, LogOccurrence,
    SamechainInspectionClient,
};
use ziquid_protocol::samechain::{Asset, OutputDescriptor, Role, MAX_CIPHERTEXT_BYTES};

#[path = "support/samechain_inspection.rs"]
mod support;
use support::{Fault, Fixture, CODE_HASH, PROVIDER_SENTINEL, hex, uint_word};

fn client(fixture: &Fixture) -> SamechainInspectionClient {
    SamechainInspectionClient::new(fixture.endpoint(), true).unwrap()
}

fn assert_observation(fixture: &Fixture, observation: &AuthorityObservation) {
    let scope = fixture.scope();
    assert_eq!(observation.deployment(), &scope.expected);
    assert_eq!(observation.token(), scope.token);
    assert_eq!(observation.token_code(), CODE_HASH);
    assert_eq!(observation.block_hash(), [0x66; 32]);
    assert_eq!(observation.block_number(), U256::from(42));
    assert_eq!(observation.parent_hash(), [0x65; 32]);
    assert_eq!(observation.policy_id(), [0x44; 32]);
    assert_eq!(observation.tree_id(), 7);
    assert_eq!(observation.tree_count(), 9);
    assert_eq!(observation.tree_root(), [0xa5; 32]);
    assert_eq!(observation.appended_notes(), &[AppendedNote {
        occurrence: LogOccurrence { transaction_hash:[0x22; 32], transaction_index:0, log_index:0 },
        packet_digest: [0x11; 32], manifest_index: 2, role: Role::A, tree_id: 7,
        index: 8, count: 9, root: [0xa5; 32], commitment: [0xb6; 32],
        recovery_key_commitment: [0xc7; 32], ciphertext_version: 1,
        ciphertext: vec![0xd8, 0xe9, 0xfa],
    }]);
    assert_eq!(observation.consumed_nullifiers(), &[ConsumedNullifier {
        occurrence: LogOccurrence { transaction_hash:[0x22; 32], transaction_index:0, log_index:1 },
        packet_digest:[0x33; 32], nullifier:[0x55; 32],
    }]);
    assert_eq!(observation.source_scope(), "TRUSTED_NODE_AT_SELECTED_BLOCK");
    let digests: Vec<[u8; 32]> = fixture.responses().iter()
        .map(|body| Sha256::digest(body).into()).collect();
    assert_eq!(observation.response_digests(), digests);
    let mut event_queries = 0;
    for (index, request) in fixture.requests().iter().enumerate() {
        assert_eq!(request["id"], json!(index + 1));
        if matches!(request["method"].as_str(), Some("eth_call" | "eth_getCode")) {
            assert_eq!(request["params"][1], json!({
                "blockHash":hex(&scope.block_hash), "requireCanonical":true
            }));
            assert_eq!(request["params"].as_array().unwrap().len(), 2);
        }
        if request["method"] == "eth_getLogs" {
            let topic = [support::note_appended_topic(), support::nullifier_consumed_topic()][event_queries];
            event_queries += 1;
            assert_eq!(request["params"], json!([{
                "address": hex(&scope.expected.authority), "topics": [topic],
                "blockHash": hex(&scope.block_hash),
            }]));
            assert!(request["params"][0].get("fromBlock").is_none());
            assert!(request["params"][0].get("toBlock").is_none());
        }
    }
    assert_eq!(event_queries, 2);
}

fn getter(selector: &str, words: &[[u8; 32]]) -> String {
    format!("0x{selector}{}", &hex(&words.concat())[2..])
}

fn assert_getter(request: &Value, expected: String) {
    assert_eq!(request["method"], "eth_call");
    assert_eq!(request["params"][0], json!({
        "to":hex(&[1; 20]), "data":expected
    }));
}

#[tokio::test]
async fn acquires_exact_identity_and_actual_keccak_pins_at_one_selected_hash() {
    let fixture = Fixture::start();
    let observation = client(&fixture).inspect(&fixture.scope(), None).await.unwrap();
    assert_observation(&fixture, &observation);
    assert!(observation.input_states().is_empty());
    assert!(observation.output_states().is_empty());
    assert_eq!(observation.creation(), None);
    assert_eq!(observation.packet_digest(), None);
    let requests = fixture.requests();
    assert_eq!(requests[0], json!({"jsonrpc":"2.0", "id":1, "method":"eth_chainId", "params":[]}));
    assert_eq!(requests[1], json!({"jsonrpc":"2.0", "id":2, "method":"eth_getBlockByHash", "params":[hex(&[0x66;32]), false]}));
    for (index, selector) in [(2,"2dde9aca"),(3,"e82ec893"),(4,"fc0c546a"),(5,"b7dd2623"),(9,"b0cc6a60")] {
        assert_getter(&requests[index], getter(selector, &[]));
    }
    for (index, address) in [(6,[1;20]), (7,[3;20]), (8,[7;20])] {
        assert_eq!(requests[index]["method"], "eth_getCode");
        assert_eq!(requests[index]["params"][0], hex(&address));
    }
    assert_eq!(requests[10]["method"], "eth_getLogs");
    assert_eq!(requests[11]["params"][0]["topics"], json!([support::nullifier_consumed_topic()]));
}

#[tokio::test]
async fn history_parent_hash_is_required_and_exact_width_at_acquisition() {
    for result in [
        json!({"hash":hex(&[0x66; 32]), "number":"0x2a"}),
        json!({"hash":hex(&[0x66; 32]), "number":"0x2a", "parentHash":null}),
        json!({"hash":hex(&[0x66; 32]), "number":"0x2a", "parentHash":"0x00"}),
        json!({"hash":hex(&[0x66; 32]), "number":"0x2a", "parentHash":hex(&[0x65; 33])}),
    ] {
        let fixture = Fixture::with_response(2, reply(2, result));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(),
            InspectionError::MalformedResponse);
        assert_eq!(fixture.requests().len(), 2);
    }
}

#[tokio::test]
async fn history_nullifier_log_cannot_be_ignored_by_public_acquisition() {
    let mut log = support::nullifier_log();
    log["data"] = json!(hex(&[[0x33; 32], [0; 32]].concat()));
    let fixture = Fixture::with_response(12, reply(12, json!([log])));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(),
        InspectionError::MalformedResponse);
}

#[tokio::test]
async fn nullifier_abi_requires_exact_two_nonzero_words_and_full_exhaustion() {
    for data in [hex(&[1; 63]), hex(&[1; 65]),
        hex(&[[0; 32], [0x55; 32]].concat()), "0xgg".to_owned()] {
        let mut log = support::nullifier_log();
        log["data"] = json!(data);
        let fixture = Fixture::with_response(12, reply(12, json!([log])));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(),
            InspectionError::MalformedResponse);
    }
}

#[tokio::test]
async fn nullifier_logs_share_strict_block_scope_order_and_per_block_rejection_bounds() {
    for fault in 0..15 {
        let mut log = support::nullifier_log();
        match fault {
            0 => log["address"] = json!(hex(&[2; 20])),
            1 => log["blockHash"] = json!(hex(&[0x67; 32])),
            2 => log["blockNumber"] = json!("0x2b"),
            3 => log["removed"] = json!(true),
            4 => log["topics"] = json!([support::note_appended_topic()]),
            5 => log["topics"] = json!([support::nullifier_consumed_topic(), support::nullifier_consumed_topic()]),
            6 => log["transactionHash"] = json!(hex(&[0; 32])),
            7 => log["transactionIndex"] = json!("0x00"),
            8 => log["logIndex"] = json!("0x10000000000000000"),
            _ => {},
        }
        let mut logs = vec![log.clone()];
        match fault {
            9 => logs.push(log), // Exact duplicate.
            10 => { log["transactionHash"] = json!(hex(&[0x23; 32]));
                log["transactionIndex"] = json!("0x1"); logs.push(log); }, // Reused global logIndex.
            11 => { log["transactionHash"] = json!(hex(&[0x23; 32]));
                log["logIndex"] = json!("0x2"); logs.push(log); }, // Same txIndex, another hash.
            12 => { log["transactionIndex"] = json!("0x1");
                log["logIndex"] = json!("0x2"); logs.push(log); }, // Same hash, another txIndex.
            13 => { log["logIndex"] = json!("0x0"); logs.push(log); }, // Out of order.
            14 => logs = (0..257).map(|index| {
                let mut log = log.clone(); log["logIndex"] = json!(format!("0x{index:x}")); log
            }).collect(),
            _ => {},
        }
        let fixture = Fixture::with_response(12, reply(12, json!(logs)));
        let expected = if fault == 14 { InspectionError::ResponseTooLarge } else { InspectionError::MalformedResponse };
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), expected, "fault {fault}");
    }
    let logs: Vec<_> = (0..256).map(|index| {
        let mut log = support::nullifier_log(); log["logIndex"] = json!(format!("0x{index:x}")); log
    }).collect();
    let fixture = Fixture::with_response(12, reply(12, json!(logs)));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap().consumed_nullifiers().len(), 256);
    // Schema acquisition accepts duplicate N payloads at distinct positions;
    // only history can reject them globally across blocks.
}

#[tokio::test]
async fn nullifier_nested_log_objects_reject_duplicate_fields_null_and_positional_sequences() {
    let valid = support::nullifier_log().to_string();
    let duplicate = valid.replace(&format!("\"transactionHash\":\"{}\"", hex(&[0x22; 32])),
        &format!("\"transactionHash\":\"{}\",\"transactionHash\":\"{}\"", hex(&[0x23; 32]), hex(&[0x22; 32])));
    let mut missing = support::nullifier_log();
    missing.as_object_mut().unwrap().remove("blockNumber");
    for raw in [format!("[{duplicate}]"), "[null]".to_owned(), "[[\"0x\"]]".to_owned(),
        format!("[{missing}]")] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":12,"result":{raw}}}"#);
        let fixture = Fixture::with_response(12, body.into_bytes());
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
}

#[tokio::test]
async fn append_abi_rejects_width_offset_length_padding_and_trailing_mutations() {
    for (word, replacement) in [
        (1, { let mut word = uint_word(2); word[0] = 1; word }),
        (2, uint_word(2)), (3, { let mut word = uint_word(7); word[0] = 1; word }),
        (4, { let mut word = uint_word(8); word[0] = 1; word }),
        (5, { let mut word = uint_word(9); word[0] = 1; word }),
        (9, { let mut word = uint_word(1); word[0] = 1; word }),
        (10, uint_word(384)), (11, uint_word(0)), (11, uint_word(33)),
    ] {
        let mut log = support::note_log(Fault::None);
        let mut data = log["data"].as_str().unwrap().to_owned();
        data.replace_range(2 + word * 64..2 + (word + 1) * 64, &hex(&replacement)[2..]);
        log["data"] = json!(data);
        let fixture = Fixture::with_response(11, reply(11, json!([log])));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
    for fault in 0..3 {
        let mut log = support::note_log(Fault::None);
        let mut data = log["data"].as_str().unwrap().to_owned();
        match fault {
            0 => { let length = data.len(); data.replace_range(length - 2..length, "01"); },
            1 => data.push_str(&"00".repeat(32)),
            2 => { data.truncate(data.len() - 2); },
            _ => unreachable!(),
        }
        log["data"] = json!(data);
        let fixture = Fixture::with_response(11, reply(11, json!([log])));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
}

#[tokio::test]
async fn rejects_malformed_or_unexpected_note_appended_logs_without_latest_or_range_fallback() {
    for fault in [
        Fault::MalformedLogTopic, Fault::MalformedLogData, Fault::WrongLogAddress,
        Fault::WrongLogBlock, Fault::WrongLogNumber, Fault::RemovedLog, Fault::DuplicateLog,
        Fault::OversizedCiphertext, Fault::OversizedLogCount,
    ] {
        let fixture = Fixture::with_fault(fault);
        let error = match client(&fixture).inspect(&fixture.scope(), None).await {
            Ok(observation) => panic!("fault {fault:?} unexpectedly accepted: {observation:?}"),
            Err(error) => error,
        };
        let expected = if matches!(fault, Fault::OversizedCiphertext | Fault::OversizedLogCount) {
            InspectionError::ResponseTooLarge
        } else {
            InspectionError::MalformedResponse
        };
        assert_eq!(error, expected, "fault {fault:?}");
        let requests = fixture.requests();
        assert_eq!(requests.last().unwrap()["method"], "eth_getLogs");
        assert!(requests.iter().all(|request| request["method"] != "eth_getLogs"
            || (request["params"][0].get("blockHash").is_some()
                && request["params"][0].get("fromBlock").is_none()
                && request["params"][0].get("toBlock").is_none())));
    }
}

#[tokio::test]
async fn accepts_log_order_by_transaction_and_log_index_not_transaction_hash() {
    let fixture = Fixture::with_fault(Fault::CrossTransactionOrder);
    let observation = client(&fixture).inspect(&fixture.scope(), None).await.unwrap();
    assert_eq!(observation.appended_notes().len(), 2);
}

#[tokio::test]
async fn creation_inspects_exact_output_nonce_and_only_a_present_initial_order_id() {
    for initial in [false, true] {
        let fixture = Fixture::start();
        let packet = fixture.creation_packet(initial);
        let observation = client(&fixture).inspect(&fixture.scope(), Some(InspectionPacket::Creation(&packet))).await.unwrap();
        assert_observation(&fixture, &observation);
        assert_eq!(observation.packet_digest(), Some(packet.digest().unwrap()));
        assert_eq!(observation.creation(), Some(CreationState { nonce_used:false, initial_order_used:initial.then_some(false) }));
        assert!(observation.input_states().is_empty());
        let OutputDescriptor::Note { commitment, .. } = packet.output else { panic!() };
        assert_eq!(observation.output_states().len(), 1);
        assert_eq!(observation.output_states()[0].commitment, commitment);
        assert_eq!(observation.output_states()[0].manifest_index, 0);
        assert!(!observation.output_states()[0].reported_seen);
        let requests = fixture.requests();
        assert_getter(&requests[10], getter("12c7da4a", &[commitment]));
        let mut payer = [0;32];
        payer[12..].copy_from_slice(&packet.payer);
        assert_getter(&requests[11], getter("f685e4c2", &[payer, packet.creation_nonce]));
        if let Some(order) = packet.order {
            assert_getter(&requests[12], getter("7ced31e6", &[order.id]));
        }
        assert_eq!(requests.last().unwrap()["method"], "eth_getLogs");
    }
}

#[tokio::test]
async fn fill_single_and_withdrawal_keep_exact_historical_roots_and_note_manifest_indices() {
    let fixture = Fixture::start();
    let fill = fixture.fill_packet();
    let single = fixture.single_packet();
    let withdrawal = fixture.withdrawal_packet();
    for packet in [InspectionPacket::Fill(&fill), InspectionPacket::Single(&single), InspectionPacket::Withdrawal(&withdrawal)] {
        let before = fixture.requests().len();
        let observation = client(&fixture).inspect(&fixture.scope(), Some(packet)).await.unwrap();
        let requests = fixture.requests();
        let requests = &requests[before..];
        let (inputs, outputs, digest): (Vec<_>, _, _) = match packet {
            InspectionPacket::Fill(packet) => (packet.inputs.iter().map(|input| (input.tree_id,input.index,input.root,input.nullifier)).collect(), &packet.outputs, packet.digest().unwrap()),
            InspectionPacket::Single(packet) => (vec![(packet.input.tree_id,packet.input.index,packet.input.root,packet.input.nullifier)], &packet.outputs, packet.digest().unwrap()),
            InspectionPacket::Withdrawal(packet) => (vec![(packet.input.tree_id,packet.input.index,packet.input.root,packet.input.nullifier)], &packet.outputs, packet.digest().unwrap()),
            InspectionPacket::Creation(_) => unreachable!(),
        };
        assert_eq!(observation.packet_digest(), Some(digest));
        assert_eq!(observation.input_states().len(), inputs.len());
        assert_eq!(observation.creation(), None);
        for (index, (tree,index_in_tree,root,nullifier)) in inputs.iter().copied().enumerate() {
            let state = observation.input_states()[index];
            assert_eq!((state.tree_id,state.index,state.root,state.nullifier), (tree,index_in_tree,root,nullifier));
            assert_eq!(state.reported_root_count, 5);
            assert!(!state.reported_spent);
            assert_getter(&requests[10 + index * 2], getter("f14ef567", &[uint_word(u64::from(tree)),root]));
            assert_getter(&requests[11 + index * 2], getter("ae20bed3", &[nullifier]));
        }
        let notes: Vec<_> = outputs.iter().enumerate().filter_map(|(index, output)| {
            if let OutputDescriptor::Note { commitment, .. } = output { Some((index,*commitment)) } else { None }
        }).collect();
        assert_eq!(observation.output_states().len(), notes.len());
        for (index, (manifest_index,commitment)) in notes.iter().copied().enumerate() {
            let state = observation.output_states()[index];
            assert_eq!((state.manifest_index,state.commitment,state.reported_seen), (manifest_index as u32,commitment,false));
            assert_getter(&requests[10 + inputs.len()*2 + index], getter("12c7da4a", &[commitment]));
        }
        assert_eq!(requests.last().unwrap()["method"], "eth_getLogs");
    }
}

#[tokio::test]
async fn malformed_borrowed_packets_and_scope_fail_before_any_http_request() {
    let fixture = Fixture::start();
    let client = client(&fixture);
    let scope = fixture.scope();
    for field in 0..5 {
        let mut bad = scope;
        match field {
            0 => bad.expected.chain_id = 0,
            1 => bad.token = [0;20],
            2 => bad.token_code = [0;32],
            3 => bad.block_hash = [0;32],
            4 => bad.policy_id = [0;32],
            _ => unreachable!(),
        }
        assert_eq!(client.inspect(&bad, None).await.unwrap_err(), InspectionError::InvalidScope);
    }
    let mut fill = fixture.fill_packet();
    fill.outputs = (0..9).map(|index| OutputDescriptor::Note {
        role:if index == 0 { Role::A } else { Role::B }, commitment:[index+20;32],
        recovery_key_commitment:[index+40;32], ciphertext_version:1, ciphertext:vec![index+1],
    }).collect();
    assert_eq!(client.inspect(&scope, Some(InspectionPacket::Fill(&fill))).await.unwrap_err(), InspectionError::InvalidPacket);
    let mut fill = fixture.fill_packet();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut fill.outputs[0] { *ciphertext = vec![1; MAX_CIPHERTEXT_BYTES+1]; }
    assert_eq!(client.inspect(&scope, Some(InspectionPacket::Fill(&fill))).await.unwrap_err(), InspectionError::InvalidPacket);
    let mut creation = fixture.creation_packet(false);
    creation.creation_nonce = [0;32];
    let mut single = fixture.single_packet();
    single.input.nullifier = [0;32];
    let mut withdrawal = fixture.withdrawal_packet();
    withdrawal.expiry = 0;
    for packet in [InspectionPacket::Creation(&creation), InspectionPacket::Single(&single), InspectionPacket::Withdrawal(&withdrawal)] {
        assert_eq!(client.inspect(&scope, Some(packet)).await.unwrap_err(), InspectionError::InvalidPacket);
    }
    let mut creation = fixture.creation_packet(false);
    creation.token = [8;20];
    let mut fill = fixture.fill_packet();
    fill.deployment.owner_program[0] ^= 1;
    let mut single = fixture.single_packet();
    single.deployment.chain_id += 1;
    let mut withdrawal = fixture.withdrawal_packet();
    withdrawal.deployment.authority[0] ^= 1;
    for packet in [InspectionPacket::Creation(&creation), InspectionPacket::Fill(&fill), InspectionPacket::Single(&single), InspectionPacket::Withdrawal(&withdrawal)] {
        assert_eq!(client.inspect(&scope, Some(packet)).await.unwrap_err(), InspectionError::InvalidScope);
    }
    let mut single = fixture.single_packet();
    single.outputs.push(OutputDescriptor::Note {
        role:Role::B,commitment:[0x91;32],recovery_key_commitment:[0x92;32],
        ciphertext_version:1,ciphertext:vec![0x93],
    });
    assert_eq!(client.inspect(&scope,Some(InspectionPacket::Single(&single))).await.unwrap_err(),InspectionError::InvalidPacket);
    assert!(fixture.requests().is_empty());
}

#[test]
fn explicit_https_or_literal_loopback_http_only_and_diagnostics_are_private() {
    for endpoint in ["https://example.invalid/rpc?apikey=secret", "https://127.0.0.1/rpc"] {
        assert!(SamechainInspectionClient::new(endpoint, false).is_ok());
    }
    for endpoint in ["http://127.0.0.1:8545/rpc", "http://[::1]:8545/rpc"] {
        assert!(SamechainInspectionClient::new(endpoint, true).is_ok());
        assert_eq!(SamechainInspectionClient::new(endpoint, false).unwrap_err(), InspectionError::InvalidEndpoint);
    }
    for endpoint in ["http://localhost/rpc", "http://192.168.1.2/rpc", "http://127.1/rpc", "http://2130706433/rpc", "http://0x7f000001/rpc", "ftp://127.0.0.1/rpc", "https://user:password@example.invalid/", "https://example.invalid/#secret", "https:///example.invalid/", "not a URL"] {
        assert_eq!(SamechainInspectionClient::new(endpoint, true).unwrap_err(), InspectionError::InvalidEndpoint);
    }
    let client = SamechainInspectionClient::new("https://example.invalid/rpc?inspection-private-query-sentinel", false).unwrap();
    assert!(!format!("{client:?}").contains(PROVIDER_SENTINEL));
}

#[tokio::test]
async fn rejects_every_independent_identity_pin_and_never_falls_back_after_rpc_failure() {
    let mut cases = vec![
        (Fault::WrongChain, InspectionError::WrongChain),
        (Fault::WrongBlock, InspectionError::WrongBlock),
        (Fault::WrongCode, InspectionError::WrongIdentity),
        (Fault::WrongVerifierCode, InspectionError::WrongIdentity),
        (Fault::WrongTokenCode, InspectionError::WrongIdentity),
        (Fault::WrongDigest, InspectionError::WrongIdentity),
        (Fault::WrongToken, InspectionError::WrongIdentity),
        (Fault::WrongTokenPin, InspectionError::WrongIdentity),
        (Fault::NoCode, InspectionError::WrongIdentity),
        (Fault::OversizeCode, InspectionError::ResponseTooLarge),
        (Fault::RpcRejected, InspectionError::RpcRejected(-32001)),
        (Fault::HttpStatus(503), InspectionError::HttpStatus(503)),
        (Fault::Redirect, InspectionError::HttpStatus(302)),
        (Fault::OversizeBody, InspectionError::ResponseTooLarge),
        (Fault::ChunkedOversize, InspectionError::ResponseTooLarge),
        (Fault::Truncated, InspectionError::Transport),
        (Fault::Compressed, InspectionError::MalformedResponse),
        (Fault::ZeroTreeRoot, InspectionError::WrongState),
    ];
    cases.extend((0..7).map(|field| (Fault::WrongDeployment(field), InspectionError::WrongIdentity)));
    for (fault, expected) in cases {
        let fixture = Fixture::with_fault(fault);
        let error = client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err();
        assert_eq!(error, expected, "fault {fault:?}");
        assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
        let requests = fixture.requests();
        assert!(requests.len() <= 11);
        if matches!(fault, Fault::WrongChain | Fault::RpcRejected | Fault::HttpStatus(_) | Fault::Redirect | Fault::OversizeBody | Fault::ChunkedOversize | Fault::Truncated | Fault::Compressed) {
            assert_eq!(requests.len(), 1); // No retry, redirect, or alternate request.
        }
    }
}

#[tokio::test]
async fn strict_raw_envelope_rejects_duplicates_null_batch_and_result_error_presence() {
    for body in [
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":1,"id":1,"result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"},"error":{"code":-1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69","error":{"code":-1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69","error":null}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":null}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"1.0","id":1,"result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":"1","result":"0x7a69"}"#,
        r#"{"jsonrpc":"2.0","id":1.0,"result":"0x7a69"}"#,
        r#"[{"jsonrpc":"2.0","id":1,"result":"0x7a69"}]"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"code":-2,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x","message":"y"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"-1","message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69"}{}"#,
    ] {
        let fixture = Fixture::with_response(1, body.as_bytes().to_vec());
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse, "{body}");
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[tokio::test]
async fn raw_typed_block_detects_nested_duplicates_even_when_last_identity_is_expected() {
    let hash = hex(&[0x66;32]);
    for result in [
        format!(r#"{{"hash":"{}","hash":"{hash}","number":"0x2a","parentHash":"{}"}}"#, hex(&[0x67;32]), hex(&[0x65;32])),
        format!(r#"{{"hash":"{hash}","number":"0x1","number":"0x2a","parentHash":"{}"}}"#, hex(&[0x65;32])),
        format!(r#"{{"hash":"{hash}","number":"0x2a","parentHash":"{}","parentHash":"{}"}}"#, hex(&[0x64;32]), hex(&[0x65;32])),
        format!(r#"{{"hash":null,"number":"0x2a","parentHash":"{}"}}"#, hex(&[0x65;32])),
        format!(r#"{{"hash":"{hash}","number":null,"parentHash":"{}"}}"#, hex(&[0x65;32])),
        format!(r#"{{"hash":"{hash}","parentHash":"{}"}}"#, hex(&[0x65;32])),
        format!(r#"{{"number":"0x2a","parentHash":"{}"}}"#, hex(&[0x65;32])),
        "null".to_owned(),
        "[]".to_owned(),
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{result}}}"#);
        let fixture = Fixture::with_response(2, body.into_bytes());
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
        assert_eq!(fixture.requests().len(), 2);
    }
}

fn reply(id: u64, result: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string().into_bytes()
}

#[tokio::test]
async fn quantities_are_canonical_bounded_and_null_never_becomes_zero() {
    for bad in ["0x", "0x00", "0x07a69", "7a69", "0X7a69", "0xg", "-1"] {
        let fixture = Fixture::with_response(1, reply(1, json!(bad)));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
    for number in ["0x", "0x00", "0x02a", "42", "-1"] {
        let body = reply(2, json!({"hash":hex(&[0x66;32]), "parentHash":hex(&[0x65;32]), "number":number}));
        let fixture = Fixture::with_response(2, body);
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
    let fixture = Fixture::with_fault(Fault::MaxBlockNumber);
    let observation = client(&fixture).inspect(&fixture.scope(), None).await.unwrap();
    assert_eq!(observation.block_number(), U256::MAX);
    let fixture = Fixture::with_response(2, reply(2, json!({"hash":hex(&[0x66;32]), "parentHash":hex(&[0x65;32]), "number":format!("0x{}", "1".repeat(65))})));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
}

#[tokio::test]
async fn exact_abi_lengths_and_high_zero_padding_are_required() {
    // Capture public synthetic bytes from a separately acquired good baseline;
    // mutate one wire word, never compute expectations with client ABI helpers.
    let baseline = Fixture::start();
    client(&baseline).inspect(&baseline.scope(), None).await.unwrap();
    let replies = baseline.responses();
    for (id, byte) in [(3,0),(3,32),(3,96),(3,192),(5,0),(10,0),(10,32)] {
        let value: Value = serde_json::from_slice(&replies[id-1]).unwrap();
        let text = value["result"].as_str().unwrap();
        let mut bytes: Vec<u8> = text.as_bytes()[2..].as_chunks::<2>().0.iter().map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()
        }).collect();
        bytes[byte] = 1;
        let fixture = Fixture::with_response(id as u64, reply(id as u64, json!(hex(&bytes))));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
    for (id, count) in [(3,224),(4,32),(5,32),(6,32),(10,96)] {
        for result in [json!(hex(&vec![0;count-1])),json!(hex(&vec![0;count+1])),json!("0xzz"),Value::Null] {
            let fixture = Fixture::with_response(id, reply(id,result));
            assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
        }
    }
    for result in [json!("0x0"),json!("0xgg"),json!("00"),Value::Null] {
        let fixture = Fixture::with_response(7,reply(7,result));
        assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::MalformedResponse);
    }
    // The maximum runtime size parses before the independent hash pin fails;
    // one extra byte instead produces ResponseTooLarge above.
    let code = vec![0;24576];
    let fixture = Fixture::with_response(7,reply(7,json!(hex(&code))));
    assert_eq!(client(&fixture).inspect(&fixture.scope(), None).await.unwrap_err(), InspectionError::WrongIdentity);
}

#[tokio::test]
async fn historical_capacity_and_maximum_index_are_reported_without_current_root_substitution() {
    let fixture = Fixture::with_fault(Fault::State {
        tree_count:1<<32, root_count:1<<32, spent:true, seen:true, nonce:true,
    });
    let mut packet = fixture.fill_packet();
    packet.inputs[0].tree_id = u32::MAX;
    packet.inputs[0].index = u32::MAX;
    let observation = client(&fixture).inspect(&fixture.scope(), Some(InspectionPacket::Fill(&packet))).await.unwrap();
    assert_eq!(observation.tree_count(),1<<32);
    assert_eq!(observation.tree_root(),[0xa5;32]);
    assert_eq!(observation.input_states()[0].tree_id,u32::MAX);
    assert_eq!(observation.input_states()[0].index,u32::MAX);
    assert_eq!(observation.input_states()[0].root,packet.inputs[0].root);
    assert_eq!(observation.input_states()[0].reported_root_count,1<<32);
    assert!(observation.input_states().iter().all(|state|state.reported_spent));
    assert!(observation.output_states().iter().all(|state|state.reported_seen));
    assert_getter(&fixture.requests()[10],getter("f14ef567",&[uint_word(u64::from(u32::MAX)),packet.inputs[0].root]));
    for (tree_count,root_count) in [((1_u64<<32)+1,5),(9,(1_u64<<32)+1)] {
        let fixture = Fixture::with_fault(Fault::State { tree_count, root_count, spent:false, seen:false, nonce:false });
        let packet = fixture.fill_packet();
        assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Fill(&packet))).await.unwrap_err(),InspectionError::WrongState);
    }
}

#[tokio::test]
async fn absent_root_and_replay_flags_are_node_claims_not_readiness_or_unavailability() {
    let fixture = Fixture::with_fault(Fault::State { tree_count:0,root_count:0,spent:true,seen:true,nonce:true });
    let packet = fixture.single_packet();
    let observation = client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Single(&packet))).await.unwrap();
    assert_eq!(observation.tree_count(),0);
    assert_eq!(observation.input_states()[0].reported_root_count,0);
    assert!(observation.input_states()[0].reported_spent);
    let packet = fixture.creation_packet(true);
    let observation = client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Creation(&packet))).await.unwrap();
    assert_eq!(observation.creation(),Some(CreationState {nonce_used:true,initial_order_used:Some(true)}));
    assert!(observation.output_states()[0].reported_seen);
    assert_eq!(observation.source_scope(),"TRUSTED_NODE_AT_SELECTED_BLOCK");
    let fixture = Fixture::with_response(11,reply(11,Value::Null));
    let packet = fixture.single_packet();
    assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Single(&packet))).await.unwrap_err(),InspectionError::MalformedResponse);
    let body = json!({"jsonrpc":"2.0","id":12,"error":{"code":-32000,"message":PROVIDER_SENTINEL}}).to_string().into_bytes();
    let fixture = Fixture::with_response(12,body);
    let packet = fixture.single_packet();
    assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Single(&packet))).await.unwrap_err(),InspectionError::RpcRejected(-32000));
}

#[tokio::test]
async fn state_boolean_and_uint64_words_never_accept_padding_or_non_boolean_values() {
    for (id,word) in [(11,{ let mut word=uint_word(5); word[23]=1; word }), (12,uint_word(2)), (12,{ let mut word=uint_word(1); word[0]=1; word }), (13,uint_word(2))] {
        let fixture = Fixture::with_response(id,reply(id,json!(hex(&word))));
        let packet = fixture.single_packet();
        assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Single(&packet))).await.unwrap_err(),InspectionError::MalformedResponse);
    }
    for id in [12,13] {
        let fixture = Fixture::with_response(id,reply(id,json!(hex(&uint_word(2)))));
        let packet = fixture.creation_packet(true);
        assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Creation(&packet))).await.unwrap_err(),InspectionError::MalformedResponse);
    }
}

#[tokio::test]
async fn public_native_and_token_creation_use_the_same_explicit_fixed_token_scope() {
    let fixture = Fixture::start();
    let mut packet = fixture.creation_packet(false);
    packet.asset = Asset::Token(fixture.scope().token);
    let observation = client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Creation(&packet))).await.unwrap();
    assert_observation(&fixture,&observation);
    let mut packet = fixture.creation_packet(false);
    packet.asset = Asset::Token([8;20]);
    assert_eq!(client(&fixture).inspect(&fixture.scope(),Some(InspectionPacket::Creation(&packet))).await.unwrap_err(),InspectionError::InvalidPacket);
    assert_eq!(fixture.requests().iter().filter(|request| request["method"] == "eth_getLogs").count(), 2);
}

#[tokio::test]
async fn endpoint_query_and_provider_transport_diagnostics_never_expose_credentials() {
    let fixture = Fixture::with_fault(Fault::RpcRejected);
    let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}",fixture.endpoint());
    let client = SamechainInspectionClient::new(&endpoint,true).unwrap();
    assert!(!format!("{client:?}").contains(PROVIDER_SENTINEL));
    let error = client.inspect(&fixture.scope(),None).await.unwrap_err();
    assert_eq!(error,InspectionError::RpcRejected(-32001));
    assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = SamechainInspectionClient::new(&format!("http://{address}/?key={PROVIDER_SENTINEL}"),true).unwrap();
    let error = client.inspect(&support::scope(),None).await.unwrap_err();
    assert_eq!(error,InspectionError::Transport);
    assert!(!format!("{error:?} {error}").contains(PROVIDER_SENTINEL));
}

#[test]
fn query_embedded_scheme_cannot_authorize_a_remote_http_endpoint() {
    for endpoint in [
        "http:example.invalid/rpc?next=http://127.0.0.1",
        "http:example.invalid/rpc?next=http://[::1]",
        "http:example.invalid/rpc?next=https://127.0.0.1",
    ] {
        assert_eq!(SamechainInspectionClient::new(endpoint,true).unwrap_err(),InspectionError::InvalidEndpoint);
    }
}

#[tokio::test]
async fn rpc_envelope_requires_an_object_instead_of_positional_struct_arrays() {
    for body in [
        r#"["2.0",1,"0x7a69"]"#,
        r#"["2.0",1,"0x7a69",null]"#,
        r#"["2.0",1,"0x7a69",[-32001,"inspection-private-query-sentinel"]]"#,
    ] {
        let fixture = Fixture::with_response(1,body.as_bytes().to_vec());
        assert_eq!(client(&fixture).inspect(&fixture.scope(),None).await.unwrap_err(),InspectionError::MalformedResponse);
        assert_eq!(fixture.requests().len(),1);
    }
}

#[tokio::test]
async fn nested_block_result_requires_an_object_instead_of_a_nonempty_positional_array() {
    let body = reply(2,json!([hex(&[0x66;32]),"0x2a"]));
    let fixture = Fixture::with_response(2,body);
    assert_eq!(client(&fixture).inspect(&fixture.scope(),None).await.unwrap_err(),InspectionError::MalformedResponse);
    assert_eq!(fixture.requests().len(),2);
}

#[tokio::test]
async fn nested_rpc_error_requires_an_object_instead_of_a_nonempty_positional_array() {
    let body = json!({"jsonrpc":"2.0","id":1,"error":[-32001,PROVIDER_SENTINEL]}).to_string().into_bytes();
    let fixture = Fixture::with_response(1,body);
    assert_eq!(client(&fixture).inspect(&fixture.scope(),None).await.unwrap_err(),InspectionError::MalformedResponse);
    assert_eq!(fixture.requests().len(),1);
}
