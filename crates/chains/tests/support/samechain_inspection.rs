//! Public synthetic RPC transport, NOT a deployed authority or financial verifier.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use primitive_types::U256;

use std::{
    cell::RefCell,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle},
    time::Duration,
};
use serde_json::{json, Value};
use ziquid_chains::samechain::inspection::InspectionScope;
use ziquid_protocol::samechain::{
    Deployment, PublicPacket, SingleOwnerPacket,
    creation::NoteCreationPacket, withdrawal::NoteWithdrawalPacket,
};

pub const PROVIDER_SENTINEL: &str = "inspection-private-query-sentinel";
// Independently known Keccak-256 of the single byte 0x00. All three synthetic
// runtimes are that byte; none implements a financial authorization predicate.
pub const CODE_HASH: [u8; 32] = [
    0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14,
    0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
    0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91,
    0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    WrongChain,
    WrongBlock,
    WrongCode,
    WrongVerifierCode,
    WrongTokenCode,
    WrongDeployment(usize),
    WrongDigest,
    WrongToken,
    WrongTokenPin,
    RpcRejected,
    NoCode,
    OversizeCode,
    HttpStatus(u16),
    Redirect,
    OversizeBody,
    ChunkedOversize,
    Truncated,
    Compressed,
    State { tree_count: u64, root_count: u64, spent: bool, seen: bool, nonce: bool },
    ZeroTreeRoot,
    MalformedLogTopic,
    MalformedLogData,
    WrongLogAddress,
    WrongLogBlock,
    WrongLogNumber,
    MaxBlockNumber,
    CrossTransactionOrder,
    RemovedLog,
    DuplicateLog,
    OversizedCiphertext,
    OversizedLogCount,
    SimulationResult(&'static str),
    SimulationRpcRejected,
    SimulationHttpStatus(u16),
    SimulationRedirect,
    SimulationOversizeBody,
    SimulationChunkedOversize,
    SimulationTruncated,
    SimulationCompressed,
}

/// Generated PUBLIC history bytes for transport/replay checks, never mined or backed notes.
#[derive(Clone)]
pub struct HistoryBlockFixture {
    pub scope: InspectionScope,
    pub number: U256,
    pub parent_hash: [u8; 32],
    pub tree_id: u32,
    pub tree_count: u64,
    pub tree_root: [u8; 32],
    pub appended_logs: Vec<Value>,
    pub nullifier_logs: Vec<Value>,
    pub root_counts: BTreeMap<(u32, [u8; 32]), u64>,
    pub spent: BTreeSet<[u8; 32]>,
}

pub struct Fixture {
    endpoint: String,
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    request_rx: mpsc::Receiver<Value>,
    response_rx: mpsc::Receiver<Vec<u8>>,
    requests: RefCell<Vec<Value>>,
    responses: RefCell<Vec<Vec<u8>>>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn start() -> Self { Self::with_fault(Fault::None) }

    pub fn with_fault(fault: Fault) -> Self { Self::serve(fault, None, Vec::new()) }

    pub fn with_response(request_id: u64, body: Vec<u8>) -> Self {
        Self::serve(Fault::None, Some((request_id, body)), Vec::new())
    }

    pub fn with_history(blocks: Vec<HistoryBlockFixture>) -> Self {
        Self::serve(Fault::None, None, blocks)
    }

    fn serve(fault: Fault, replacement: Option<(u64, Vec<u8>)>, blocks: Vec<HistoryBlockFixture>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (request_tx, request_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut previous = None;
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                if worker_stop.load(Ordering::Acquire) { break; }
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let request = read_request(&mut stream);
                let id = request["id"].as_u64().unwrap();
                let simulation = request["method"] == "eth_call"
                    && request["params"][0].get("from").is_some();
                let method = request["method"].as_str().unwrap();
                let event_fault = method == "eth_getLogs"
                    && matches!(fault, Fault::MalformedLogTopic | Fault::MalformedLogData
                        | Fault::WrongLogAddress | Fault::WrongLogBlock | Fault::WrongLogNumber
                        | Fault::RemovedLog | Fault::DuplicateLog | Fault::OversizedCiphertext
                        | Fault::OversizedLogCount | Fault::MaxBlockNumber);
                let max_block_fault = fault == Fault::MaxBlockNumber
                    && method == "eth_getBlockByHash";
                let wire_fault = match fault {
                    Fault::SimulationHttpStatus(status) if simulation => Fault::HttpStatus(status),
                    Fault::SimulationRedirect if simulation => Fault::Redirect,
                    Fault::SimulationOversizeBody if simulation => Fault::OversizeBody,
                    Fault::SimulationChunkedOversize if simulation => Fault::ChunkedOversize,
                    Fault::SimulationTruncated if simulation => Fault::Truncated,
                    Fault::SimulationCompressed if simulation => Fault::Compressed,
                    _ if id == 1 || event_fault || max_block_fault => fault,
                    _ => Fault::None,
                };
                // The server owns sequencing; the test receives public logs over channels.
                // Each inspect starts a fresh bounded sequence; shared client calls
                // never depend on a mutable process-global request counter.
                assert!(id == 1 || previous == Some(id - 1));
                let result_fault = if event_fault || max_block_fault { wire_fault } else { fault };
                let result = result_for(&request, result_fault, &blocks);
                previous = Some(id);
                request_tx.send(request).unwrap();
                let mut body = if fault == Fault::RpcRejected && id == 1 {
                    json!({"jsonrpc":"2.0", "id":id, "error":{
                        "code":-32001, "message":PROVIDER_SENTINEL
                    }}).to_string().into_bytes()
                } else if simulation && fault == Fault::SimulationRpcRejected {
                    json!({"jsonrpc":"2.0", "id":id, "error":{
                        "code":-32000, "message":PROVIDER_SENTINEL,
                        "data":{"private_query":PROVIDER_SENTINEL}
                    }}).to_string().into_bytes()
                } else {
                    json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string().into_bytes()
                };
                if let Some((selected, bytes)) = &replacement && *selected == id {
                    body.clone_from(bytes);
                }
                let status = match wire_fault {
                    Fault::HttpStatus(status) => status,
                    Fault::Redirect => 302,
                    _ => 200,
                };
                if matches!(wire_fault, Fault::OversizeBody | Fault::ChunkedOversize) {
                    body = vec![b' '; 1024 * 1024 + 1];
                }
                response_tx.send(body.clone()).unwrap();
                let header = if wire_fault == Fault::ChunkedOversize {
                    format!("HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                } else {
                    let length = body.len() + usize::from(wire_fault == Fault::Truncated);
                    let extra = match wire_fault {
                        Fault::Redirect => format!("Location: http://{address}/redirected?{PROVIDER_SENTINEL}\r\n"),
                        Fault::Compressed => "Content-Encoding: gzip\r\n".to_owned(),
                        _ => String::new(),
                    };
                    format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n{extra}\r\n")
                };
                if stream.write_all(header.as_bytes()).is_err() { continue; }
                if wire_fault == Fault::ChunkedOversize {
                    let _ = write!(stream, "{:x}\r\n", body.len());
                    let _ = stream.write_all(&body);
                    let _ = stream.write_all(b"\r\n0\r\n\r\n");
                } else {
                    let _ = stream.write_all(&body);
                }
            }
        });
        Self {
            endpoint: format!("http://{address}/rpc"), address, stop, request_rx,
            response_rx, requests: RefCell::new(Vec::new()), responses: RefCell::new(Vec::new()),
            worker: Some(worker),
        }
    }

    pub fn endpoint(&self) -> &str { &self.endpoint }
    pub fn scope(&self) -> InspectionScope { scope() }
    pub fn requests(&self) -> Vec<Value> {
        let mut requests = self.requests.borrow_mut();
        requests.extend(self.request_rx.try_iter());
        requests.clone()
    }
    pub fn responses(&self) -> Vec<Vec<u8>> {
        let mut responses = self.responses.borrow_mut();
        responses.extend(self.response_rx.try_iter());
        responses.clone()
    }

    pub fn creation_packet(&self, initial: bool) -> NoteCreationPacket {
        let raw = vector(if initial { "initial_order_a" } else { "ordinary_native" });
        let mut packet = NoteCreationPacket::decode(&raw).unwrap();
        packet.deployment = self.scope().expected;
        packet.token = self.scope().token;
        packet.validate().unwrap();
        packet
    }

    pub fn fill_packet(&self) -> PublicPacket {
        let mut packet = PublicPacket::decode(&vector("known_pair")).unwrap();
        packet.deployment = self.scope().expected;
        packet.validate().unwrap();
        packet
    }

    pub fn single_packet(&self) -> SingleOwnerPacket {
        let mut packet = SingleOwnerPacket::decode(&vector("single_cancel")).unwrap();
        packet.deployment = self.scope().expected;
        packet.validate().unwrap();
        packet
    }

    pub fn withdrawal_packet(&self) -> NoteWithdrawalPacket {
        let mut packet = NoteWithdrawalPacket::decode(&vector("received_token_partial")).unwrap();
        packet.deployment = self.scope().expected;
        packet.validate().unwrap();
        packet
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() { result.unwrap(); }
        }
    }
}

pub fn scope() -> InspectionScope {
    InspectionScope {
        expected: Deployment {
            chain_id: 31337, authority: [1; 20], authority_code: CODE_HASH,
            verifier: [3; 20], verifier_code: CODE_HASH, owner_program: [5; 32], schema: 1,
        },
        token: [7; 20], token_code: CODE_HASH, block_hash: [0x66; 32], policy_id: [0x44; 32],
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 + bytes.len() * 2);
    text.push_str("0x");
    for byte in bytes { use std::fmt::Write; write!(text, "{byte:02x}").unwrap(); }
    text
}

pub fn uint_word(number: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&number.to_be_bytes());
    word
}

// Independently computed full Keccak-256 topic of the Solidity event declaration.
pub fn note_appended_topic() -> &'static str {
    "0x20a951e74ed20c78c1e79c5e63ff82077d82dd3df035daa572fd6dad5910243c"
}

pub fn nullifier_consumed_topic() -> &'static str {
    "0xd2b8c72ea263b0960a5bc0e03134c79956a8b85f589ac92f56fc06e6f0f6b83f"
}

pub fn nullifier_log() -> Value {
    let mut log = note_log(Fault::None);
    log["topics"] = json!([nullifier_consumed_topic()]);
    log["data"] = json!(hex(&[[0x33; 32], [0x55; 32]].concat()));
    log["logIndex"] = json!("0x1");
    log
}

pub fn note_appended_data(ciphertext: &[u8]) -> String {
    let mut data = [
        [0x11; 32], uint_word(2), uint_word(0), uint_word(7), uint_word(8), uint_word(9),
        [0xa5; 32], [0xb6; 32], [0xc7; 32], uint_word(1), uint_word(352),
    ].concat();
    let mut tail = [uint_word(ciphertext.len() as u64)].concat();
    tail.extend_from_slice(ciphertext);
    tail.resize(tail.len() + (32 - ciphertext.len() % 32) % 32, 0);
    data.extend_from_slice(&tail);
    hex(&data)
}

pub fn note_log(fault: Fault) -> Value {
    let scope = scope();
    let ciphertext = if fault == Fault::OversizedCiphertext { vec![0xd8; 4097] } else { vec![0xd8, 0xe9, 0xfa] };
    let data = if fault == Fault::MalformedLogData { "0x00".to_owned() } else { note_appended_data(&ciphertext) };
    json!({
        "address": hex(&if fault == Fault::WrongLogAddress { [2; 20] } else { scope.expected.authority }),
        "blockHash": hex(&if fault == Fault::WrongLogBlock { [0x67; 32] } else { scope.block_hash }),
        "removed": fault == Fault::RemovedLog,
        "topics": [if fault == Fault::MalformedLogTopic { hex(&[0; 32]) } else { note_appended_topic().to_owned() }],
        "data": data,
        "blockNumber": if fault == Fault::WrongLogNumber { "0x2b".to_owned() } else if fault == Fault::MaxBlockNumber { format!("0x{}", "f".repeat(64)) } else { "0x2a".to_owned() },
        "transactionHash": hex(&if fault == Fault::CrossTransactionOrder { [0x01; 32] } else { [0x22; 32] }), "transactionIndex": if fault == Fault::CrossTransactionOrder { "0x1" } else { "0x0" }, "logIndex": "0x0",
    })
}

fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn words(words: &[[u8; 32]]) -> Value {
    Value::String(hex(&words.concat()))
}

fn read_request(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() <= 16 * 1024);
        if bytes.ends_with(b"\r\n\r\n") { break bytes.len(); }
    };
    let header = std::str::from_utf8(&bytes).unwrap();
    let line = header.lines().next().unwrap();
    let parts: Vec<_> = line.split(' ').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "POST");
    assert!(parts[1] == "/rpc" || parts[1].starts_with("/rpc?"));
    assert_eq!(parts[2], "HTTP/1.1");
    assert!(!header.to_ascii_lowercase().contains("accept-encoding:"));
    let length: usize = header.lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        })
    }).unwrap();
    assert!(length <= 2 * 70 * 1024 + 1024);
    bytes.resize(end + length, 0);
    stream.read_exact(&mut bytes[end..]).unwrap();
    let value: Value = serde_json::from_slice(&bytes[end..]).unwrap();
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value.as_object().unwrap().len(), 4);
    value
}

fn result_for(request: &Value, fault: Fault, blocks: &[HistoryBlockFixture]) -> Value {
    let selected_hash = match request["method"].as_str().unwrap() {
        "eth_getBlockByHash" => &request["params"][0],
        "eth_getCode" | "eth_call" => &request["params"][1]["blockHash"],
        "eth_getLogs" => &request["params"][0]["blockHash"],
        _ => &Value::Null,
    };
    let selected = blocks.iter().find(|block| *selected_hash == hex(&block.scope.block_hash));
    assert!(blocks.is_empty() || request["method"] == "eth_chainId" || selected.is_some());
    let scope = selected.or(blocks.first()).map_or_else(scope, |block| block.scope);
    let block = json!({"blockHash":hex(&scope.block_hash), "requireCanonical":true});
    let method = request["method"].as_str().unwrap();
    let params = request["params"].as_array().unwrap();
    match method {
        "eth_chainId" => {
            assert!(params.is_empty());
            json!(if fault == Fault::WrongChain { "0x1" } else { "0x7a69" })
        }
        "eth_getBlockByHash" => {
            assert_eq!(params, &[json!(hex(&scope.block_hash)), json!(false)]);
            if let Some(selected) = selected {
                json!({"hash":hex(&scope.block_hash), "parentHash":hex(&selected.parent_hash),
                    "number":format!("0x{:x}", selected.number), "transactions":[]})
            } else {
                json!({
                    "hash":hex(&if fault == Fault::WrongBlock { [0x67; 32] } else { scope.block_hash }),
                    "parentHash":hex(&[0x65; 32]),
                    "number":if fault == Fault::MaxBlockNumber { format!("0x{}", "f".repeat(64)) } else { "0x2a".to_owned() }, "transactions":[], "gasUsed":"0x0"
                })
            }
        }
        "eth_getCode" => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[1], block);
            let address = params[0].as_str().unwrap();
            let authority = address == hex(&scope.expected.authority);
            let verifier = address == hex(&scope.expected.verifier);
            let token = address == hex(&scope.token);
            assert!(authority || verifier || token);
            let wrong = (authority && fault == Fault::WrongCode)
                || (verifier && fault == Fault::WrongVerifierCode)
                || (token && fault == Fault::WrongTokenCode);
            json!(if fault == Fault::NoCode { "0x".to_owned() }
                else if fault == Fault::OversizeCode { format!("0x{}", "00".repeat(24577)) }
                else if wrong { "0x01".to_owned() } else { "0x00".to_owned() })
        }
        "eth_getLogs" => {
            assert_eq!(params.len(), 1);
            let filter = params[0].as_object().unwrap();
            assert_eq!(filter.get("address"), Some(&json!(hex(&scope.expected.authority))));
            let note_event = filter.get("topics") == Some(&json!([note_appended_topic()]));
            assert!(note_event || filter.get("topics") == Some(&json!([nullifier_consumed_topic()])));
            assert_eq!(filter.get("blockHash"), Some(&json!(hex(&scope.block_hash))));
            assert!(!filter.contains_key("fromBlock") && !filter.contains_key("toBlock"));
            if let Some(selected) = selected {
                return json!(if note_event { &selected.appended_logs } else { &selected.nullifier_logs });
            }
            if !note_event {
                let mut log = nullifier_log();
                if fault == Fault::MaxBlockNumber { log["blockNumber"] = json!(format!("0x{}", "f".repeat(64))); }
                return json!([log]);
            }
            let mut logs = if fault == Fault::OversizedLogCount {
                (0..257).map(|_| note_log(Fault::MalformedLogData)).collect()
            } else if fault == Fault::CrossTransactionOrder {
                let first = note_log(Fault::None);
                let mut second = note_log(Fault::None);
                second["transactionHash"] = json!(hex(&[0x01; 32]));
                second["transactionIndex"] = json!("0x1");
                second["logIndex"] = json!("0x1");
                vec![first, second]
            } else {
                vec![note_log(fault)]
            };
            if fault == Fault::DuplicateLog { logs.push(note_log(Fault::None)); }
            json!(logs)
        }
        "eth_call" => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[1], block);
            let call = params[0].as_object().unwrap();
            if call.contains_key("from") {
                assert_eq!(request["id"], 13); // Twelve fresh public inspection reads precede execution.
                assert_eq!(call.len(), 5);
                assert_eq!(call["to"], hex(&scope.expected.authority));
                let from = call["from"].as_str().unwrap();
                assert_eq!(from.len(), 42);
                assert!(from.starts_with("0x") && from[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
                assert_ne!(from, hex(&[0; 20]));
                for field in ["value", "gas"] {
                    let digits = call[field].as_str().unwrap().strip_prefix("0x").unwrap();
                    assert!(!digits.is_empty() && digits.len() <= 64);
                    assert!(digits.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
                    assert!(digits.len() == 1 || !digits.starts_with('0'));
                }
                let gas = u64::from_str_radix(call["gas"].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap();
                assert!((1..=30_000_000).contains(&gas));
                let data = call["data"].as_str().unwrap();
                assert!(data.starts_with("0x") && data.len() <= 2 + 2 * 70 * 1024);
                assert!((data.len() - 2).is_multiple_of(2));
                assert!(data[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
                assert!(matches!(&data[..10], "0x94184ba9" | "0xd316bd1a" | "0xf6146f41" | "0x50fbe2d9"));
                return json!(match fault { Fault::SimulationResult(result) => result, _ => "0x" });
            }
            assert_eq!(call.len(), 2); // Inspection remains getter-only.
            assert_eq!(call["to"], hex(&scope.expected.authority));
            let data = call["data"].as_str().unwrap();
            let selector = &data[..10];
            let (tree_count, root_count, spent, seen, nonce) = match fault {
                Fault::State { tree_count, root_count, spent, seen, nonce } =>
                    (tree_count, root_count, spent, seen, nonce),
                _ => (9, 5, false, false, false),
            };
            match selector {
                "0x2dde9aca" => {
                    assert_eq!(data.len(), 10);
                    let d = scope.expected;
                    let mut result = [uint_word(d.chain_id), address_word(d.authority), d.authority_code,
                        address_word(d.verifier), d.verifier_code, d.owner_program, uint_word(u64::from(d.schema))];
                    if let Fault::WrongDeployment(index) = fault { result[index][31] ^= 1; }
                    words(&result)
                }
                "0xe82ec893" => {
                    assert_eq!(data.len(), 10);
                    let mut digest = scope.expected.digest().unwrap();
                    if fault == Fault::WrongDigest { digest[0] ^= 1; }
                    words(&[digest])
                }
                "0xfc0c546a" => {
                    assert_eq!(data.len(), 10);
                    words(&[address_word(if fault == Fault::WrongToken { [8; 20] } else { scope.token })])
                }
                "0xb7dd2623" => {
                    assert_eq!(data.len(), 10);
                    words(&[if fault == Fault::WrongTokenPin { [8; 32] } else { scope.token_code }])
                }
                "0xb0cc6a60" => {
                    assert_eq!(data.len(), 10);
                    if let Some(selected) = selected {
                        return words(&[uint_word(u64::from(selected.tree_id)),
                            uint_word(selected.tree_count), selected.tree_root]);
                    }
                    words(&[uint_word(7), uint_word(tree_count), if fault == Fault::ZeroTreeRoot { [0; 32] } else { [0xa5; 32] }])
                }
                "0xf14ef567" => {
                    assert_eq!(data.len(), 138);
                    let count = selected.map_or(root_count, |selected| {
                        let tree = u32::from_str_radix(&data[66..74], 16).unwrap();
                        let root = decode_fixture_hash(&data[74..138]);
                        selected.root_counts.get(&(tree, root)).copied().unwrap_or(0)
                    });
                    words(&[uint_word(count)])
                }
                "0xae20bed3" => {
                    assert_eq!(data.len(), 74);
                    let spent = selected.map_or(spent, |selected| {
                        selected.spent.contains(&decode_fixture_hash(&data[10..74]))
                    });
                    words(&[uint_word(u64::from(spent))])
                }
                "0x12c7da4a" => { assert_eq!(data.len(), 74); words(&[uint_word(u64::from(seen))]) }
                "0xf685e4c2" => { assert_eq!(data.len(), 138); words(&[uint_word(u64::from(nonce))]) }
                "0x7ced31e6" => { assert_eq!(data.len(), 74); words(&[uint_word(u64::from(nonce))]) }
                _ => panic!("unapproved getter selector"),
            }
        }
        _ => panic!("unapproved RPC method"),
    }
}

fn decode_fixture_hash(text: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

fn vector(name: &str) -> Vec<u8> {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../contracts/evm/test/fixtures/samechain-native-vectors.json"
    )).unwrap();
    let fill2: Value = serde_json::from_str(include_str!(
        "../../../../contracts/evm/test/fixtures/samechain-fill2-vectors.json"
    )).unwrap();
    let packet = fill2["packets"].as_array().unwrap().iter()
        .chain(vectors["packets"].as_array().unwrap())
        .find(|value| value["name"] == name).unwrap();
    let text = packet["packethex"].as_str().unwrap();
    text.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

// Public frame only: deliberately invalid infinite pairing points, never a
// certificate, successful financial proof, or asset execution fixture.
pub fn unverified_frame() -> Vec<u8> {
    let mut frame = vec![0; 356];
    frame[..4].copy_from_slice(&[0x43, 0x88, 0xa2, 0x1c]);
    frame[36..68].copy_from_slice(&[
        0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d,
        0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
        0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28,
        0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
    ]);
    frame
}
