//! Public synthetic HTTP observations only; no deployed verifier, proof or funded transfer.
#![allow(dead_code)]

use std::{
    cell::RefCell,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ziquid_chains::native::inspection::NativeInspectionScope;
use ziquid_protocol::native::{DeploymentDescriptor, Statement};

pub const PROVIDER_SENTINEL: &str = "native-inspection-private-query-sentinel";
// Independently known Keccak-256(0x00). The fixture runtime is a STOP byte,
// not an implementation of NativeEthObligation or proof verification.
pub const CODE_HASH: [u8; 32] = [
    0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14,
    0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
    0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91,
    0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a,
];

#[derive(Clone, Copy)]
pub enum RowState { Absent, Armed, Consumed }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WireFault { None, Status, Redirect, Oversize, ChunkedOversize, Truncated, Compressed }

pub struct Fixture {
    endpoint: String,
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests_rx: mpsc::Receiver<Value>,
    responses_rx: mpsc::Receiver<Vec<u8>>,
    requests: RefCell<Vec<Value>>,
    responses: RefCell<Vec<Vec<u8>>>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn start(state: RowState) -> Self { Self::serve(state, WireFault::None, None) }
    pub fn with_response(state: RowState, id: u64, body: Vec<u8>) -> Self {
        Self::serve(state, WireFault::None, Some((id, body)))
    }
    pub fn with_wire(fault: WireFault) -> Self { Self::serve(RowState::Absent, fault, None) }

    fn serve(state: RowState, fault: WireFault, replacement: Option<(u64, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (requests_tx, requests_rx) = mpsc::channel();
        let (responses_tx, responses_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut previous = None;
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                if worker_stop.load(Ordering::Acquire) { break; }
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let request = read_request(&mut stream);
                let id = request["id"].as_u64().unwrap();
                assert!(id == 1 || previous == Some(id - 1));
                previous = Some(id);
                let result = result_for(&request, state);
                requests_tx.send(request).unwrap();
                let mut body = reply(id, result);
                if let Some((selected, bytes)) = &replacement && *selected == id {
                    body.clone_from(bytes);
                }
                let wire = if id == 1 { fault } else { WireFault::None };
                if matches!(wire, WireFault::Oversize | WireFault::ChunkedOversize) {
                    body = vec![b' '; 1024 * 1024 + 1];
                }
                responses_tx.send(body.clone()).unwrap();
                let status = match wire { WireFault::Status => 429, WireFault::Redirect => 302, _ => 200 };
                let header = if wire == WireFault::ChunkedOversize {
                    format!("HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                } else {
                    let length = body.len() + usize::from(wire == WireFault::Truncated);
                    let extra = match wire {
                        WireFault::Redirect => format!("Location: http://{address}/redirected?{PROVIDER_SENTINEL}\r\n"),
                        WireFault::Compressed => "Content-Encoding: gzip\r\n".into(),
                        _ => String::new(),
                    };
                    format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n{extra}\r\n")
                };
                if stream.write_all(header.as_bytes()).is_err() { continue; }
                if wire == WireFault::ChunkedOversize {
                    let _ = write!(stream, "{:x}\r\n", body.len());
                    let _ = stream.write_all(&body);
                    let _ = stream.write_all(b"\r\n0\r\n\r\n");
                } else { let _ = stream.write_all(&body); }
            }
        });
        Self {
            endpoint: format!("http://{address}/rpc"), address, stop, requests_rx, responses_rx,
            requests: RefCell::new(Vec::new()), responses: RefCell::new(Vec::new()), worker: Some(worker),
        }
    }

    pub fn endpoint(&self) -> &str { &self.endpoint }
    pub fn scope(&self) -> NativeInspectionScope { scope() }
    pub fn statement(&self) -> Statement { statement() }
    pub fn requests(&self) -> Vec<Value> {
        let mut requests = self.requests.borrow_mut();
        requests.extend(self.requests_rx.try_iter());
        requests.clone()
    }
    pub fn responses(&self) -> Vec<Vec<u8>> {
        let mut responses = self.responses.borrow_mut();
        responses.extend(self.responses_rx.try_iter());
        responses.clone()
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

pub fn scope() -> NativeInspectionScope {
    NativeInspectionScope {
        expected: DeploymentDescriptor {
            schema_version: 1, source_network: 1, source_pool: 3, transaction_version: 6,
            consensus_branch: 0x37a5165b, financial_program: [1; 32], origin_program: [20; 32],
            source_acceptance_program: [2; 32], source_policy_id: [3; 32],
            target_chain_id: 84532, obligation: [5; 20], obligation_runtime_code: CODE_HASH,
            verifier: [7; 20], verifier_runtime_code: CODE_HASH,
        },
        block_hash: [0x66; 32],
    }
}

pub fn statement() -> Statement {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../contracts/evm/test/fixtures/native-financial-vectors.json"
    )).unwrap();
    let mut statement = Statement::decode(&unhex(vectors["statement"].as_str().unwrap())).unwrap();
    statement.deployment_descriptor = Sha256::digest(scope().expected.encode()).into();
    statement.validate().unwrap();
    statement
}

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 + bytes.len() * 2);
    text.push_str("0x");
    for byte in bytes { use std::fmt::Write; write!(text, "{byte:02x}").unwrap(); }
    text
}
pub fn unhex(text: &str) -> Vec<u8> {
    text.strip_prefix("0x").unwrap_or(text).as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
pub fn uint_word(value: u64) -> [u8; 32] {
    let mut word = [0; 32]; word[24..].copy_from_slice(&value.to_be_bytes()); word
}
pub fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0; 32]; word[12..].copy_from_slice(&address); word
}
pub fn deployment_words() -> Vec<u8> {
    [uint_word(1), uint_word(1), uint_word(3), uint_word(6), uint_word(0x37a5165b),
        [1; 32], [20; 32], [2; 32], [3; 32], uint_word(84532), address_word([5; 20]),
        CODE_HASH, address_word([7; 20]), CODE_HASH].concat()
}
pub fn obligation_words(state: RowState) -> Vec<u8> {
    let s = statement();
    match state {
        RowState::Absent => vec![0; 256],
        RowState::Armed | RowState::Consumed => [
            [0xff; 32], uint_word(100_000_000), address_word([9; 20]), address_word([10; 20]),
            address_word([11; 20]), s.stable_jtag, uint_word(1),
            uint_word(u64::from(matches!(state, RowState::Consumed))),
        ].concat(),
    }
}
pub fn reply(id: u64, result: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string().into_bytes()
}

fn read_request(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let end = loop {
        let mut byte = [0]; stream.read_exact(&mut byte).unwrap(); bytes.push(byte[0]);
        assert!(bytes.len() <= 16 * 1024);
        if bytes.ends_with(b"\r\n\r\n") { break bytes.len(); }
    };
    let header = std::str::from_utf8(&bytes).unwrap();
    let parts: Vec<_> = header.lines().next().unwrap().split(' ').collect();
    assert_eq!(parts.len(), 3); assert_eq!(parts[0], "POST");
    assert!(parts[1] == "/rpc" || parts[1].starts_with("/rpc?"));
    assert_eq!(parts[2], "HTTP/1.1");
    assert!(!header.to_ascii_lowercase().contains("accept-encoding:"));
    let length: usize = header.lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        })
    }).unwrap();
    assert!(length <= 4096);
    bytes.resize(end + length, 0); stream.read_exact(&mut bytes[end..]).unwrap();
    let request: Value = serde_json::from_slice(&bytes[end..]).unwrap();
    assert_eq!(request["jsonrpc"], "2.0"); assert_eq!(request.as_object().unwrap().len(), 4);
    request
}

fn result_for(request: &Value, state: RowState) -> Value {
    let scope = scope();
    let params = request["params"].as_array().unwrap();
    match request["method"].as_str().unwrap() {
        "eth_chainId" => { assert!(params.is_empty()); json!("0x14a34") }
        "eth_getBlockByHash" => {
            assert_eq!(params, &[json!(hex(&scope.block_hash)), json!(false)]);
            json!({"hash":hex(&scope.block_hash), "number":"0x2a", "parentHash":hex(&[0x65; 32])})
        }
        method @ ("eth_call" | "eth_getCode") => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[1], json!({"blockHash":hex(&scope.block_hash), "requireCanonical":true}));
            if method == "eth_getCode" {
                assert!(params[0] == hex(&[5; 20]) || params[0] == hex(&[7; 20]));
                return json!("0x00");
            }
            assert_eq!(params[0].as_object().unwrap().len(), 2);
            assert_eq!(params[0]["to"], hex(&[5; 20]));
            let data = params[0]["data"].as_str().unwrap();
            let s = statement();
            let context: [u8; 32] = Sha256::digest(s.encode()).into();
            match data {
                "0x2dde9aca" => json!(hex(&deployment_words())),
                "0xe82ec893" => json!(hex(&Sha256::digest(scope.expected.encode()))),
                "0x0fc29349" => json!(hex(&[0xff; 32])),
                _ if data == format!("0x16d4a5c7{}", &hex(&context)[2..]) => json!(hex(&obligation_words(state))),
                _ if data == format!("0x7c52451e{}", &hex(&s.stable_jtag)[2..]) => {
                    json!(hex(&if matches!(state, RowState::Absent) { [0; 32] } else { context }))
                }
                _ => panic!("unapproved native getter"),
            }
        }
        _ => panic!("unapproved native RPC method"),
    }
}
