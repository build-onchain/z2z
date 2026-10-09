//! Fabricated HTTP framing around immutable primary testnet raw bodies.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread::{self, JoinHandle},
    time::Duration,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SENTINEL: &str = "raw-source-private-sentinel";
pub const BODIES: [&[u8]; 11] = [
    include_bytes!("../../../proofs/tests/fixtures/testnet-genesis.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-1.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-2.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-3.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-4.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-5.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-6.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-7.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-8.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-9.bin"),
    include_bytes!("../../../proofs/tests/fixtures/testnet-block-10.bin"),
];

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

pub fn hash(height: usize) -> [u8; 32] {
    Sha256::digest(Sha256::digest(&BODIES[height][..1487])).into()
}

pub fn display_hash(height: usize) -> String {
    let mut bytes = hash(height);
    bytes.reverse();
    hex(&bytes)
}

pub fn reply(id: u64, result: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0", "id":id, "result":result, "error":null})
        .to_string().into_bytes()
}

pub enum Wire {
    Json(Vec<u8>),
    Chunked(Vec<u8>, usize),
    Advertised(u64),
    Truncated(Vec<u8>),
    Status(u16, String),
    Encoded,
    HoldHeaders,
    HoldBody,
    SlowChunks,
}

pub struct Step {
    pub request: Value,
    pub wire: Wire,
}

impl Step {
    pub fn hash(id: u64, height: u32) -> Self {
        Self {
            request: json!({"jsonrpc":"2.0", "id":id,
                "method":"getblockhash", "params":[height]}),
            wire: Wire::Json(reply(id, json!(display_hash(height as usize)))),
        }
    }

    pub fn body(id: u64, height: usize) -> Self {
        Self {
            request: json!({"jsonrpc":"2.0", "id":id,
                "method":"getblock", "params":[display_hash(height), 0]}),
            wire: Wire::Json(reply(id, json!(hex(BODIES[height])))),
        }
    }
}

pub struct Fixture {
    endpoint: String,
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    release: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (release, held) = mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker_calls = Arc::clone(&calls);
        let worker = thread::spawn(move || {
            let mut steps = steps.into_iter();
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                if worker_stop.load(Ordering::Acquire) { break; }
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let request = read_request(&mut stream);
                let step = steps.next().expect("unexpected extra RPC request");
                assert_eq!(request, step.request);
                worker_calls.fetch_add(1, Ordering::Release);
                match step.wire {
                    Wire::Json(body) => {
                        let _ = write!(stream, "HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        let _ = stream.write_all(&body);
                    }
                    Wire::Chunked(body, size) => {
                        let _ = stream.write_all(b"HTTP/1.1 200 Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                        for chunk in body.chunks(size) {
                            if write!(stream, "{:x}\r\n", chunk.len()).is_err()
                                || stream.write_all(chunk).is_err()
                                || stream.write_all(b"\r\n").is_err() { break; }
                        }
                        let _ = stream.write_all(b"0\r\n\r\n");
                    }
                    Wire::Advertised(length) => {
                        let _ = write!(stream, "HTTP/1.1 200 Fixture\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
                    }
                    Wire::Truncated(body) => {
                        let _ = write!(stream, "HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len() + 1);
                        let _ = stream.write_all(&body);
                    }
                    Wire::Status(status, location) => {
                        let _ = write!(stream, "HTTP/1.1 {status} Fixture\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Wire::Encoded => {
                        let _ = stream.write_all(b"HTTP/1.1 200 Fixture\r\nContent-Encoding: identity\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Wire::HoldHeaders => { let _ = held.recv(); }
                    Wire::HoldBody => {
                        let _ = stream.write_all(b"HTTP/1.1 200 Fixture\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{");
                        let _ = held.recv();
                    }
                    Wire::SlowChunks => {
                        let _ = stream.write_all(b"HTTP/1.1 200 Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                        loop {
                            if held.recv_timeout(Duration::from_millis(10)).is_ok()
                                || stream.write_all(b"1\r\n \r\n").is_err() { break; }
                        }
                    }
                }
            }
        });
        Self { endpoint: format!("http://{address}/rpc?{SENTINEL}"), address,
            stop, calls, release, worker: Some(worker) }
    }

    pub fn endpoint(&self) -> &str { &self.endpoint }
    pub fn calls(&self) -> usize { self.calls.load(Ordering::Acquire) }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.release.send(());
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() { result.unwrap(); }
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 16_384);
        if bytes.ends_with(b"\r\n\r\n") { break bytes.len(); }
    };
    let header = std::str::from_utf8(&bytes).unwrap();
    assert!(header.starts_with("POST /rpc?raw-source-private-sentinel HTTP/1.1\r\n"));
    let mut length = None;
    for line in header.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            assert!(!matches!(name.to_ascii_lowercase().as_str(), "authorization" | "cookie"));
            if name.eq_ignore_ascii_case("content-length") {
                assert!(length.is_none());
                length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
    }
    let length = length.unwrap();
    assert!(length < 16_384);
    bytes.resize(header_end + length, 0);
    stream.read_exact(&mut bytes[header_end..]).unwrap();
    serde_json::from_slice(&bytes[header_end..]).unwrap()
}
