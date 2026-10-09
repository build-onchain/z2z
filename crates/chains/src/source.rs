//! Finite raw-body acquisition only: RPC hashes are untrusted selection metadata.
//! No checkpoint, fork choice, freshness, finality or financial authority is created.

use std::{borrow::Cow, error::Error, fmt, time::{Duration, Instant}};
use serde::{Deserialize, Deserializer, de::{self, IgnoredAny, MapAccess, Visitor}};
use serde_json::json;
use url::Url;

const MAX_BLOCK_BYTES: usize = 2_000_000;
const HASH_REPLY_BYTES: usize = 4096;
const BLOCK_REPLY_BYTES: usize = 2 * MAX_BLOCK_BYTES + 4096;

/// Fixed categories retain no URL, provider message, response bytes or private data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawBlockError {
    InvalidEndpoint,
    InvalidPolicy,
    Transport,
    HttpStatus(u16),
    ResponseTooLarge,
    RpcBudgetExceeded,
    DeadlineExceeded,
    RpcRejected(i64),
    MalformedResponse,
    BodyTooLarge,
    HashChanged,
}

impl fmt::Display for RawBlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("invalid raw source endpoint"),
            Self::InvalidPolicy => formatter.write_str("raw source policy rejected"),
            Self::Transport => formatter.write_str("raw source transport unavailable"),
            Self::HttpStatus(status) => write!(formatter, "raw source HTTP status {status}"),
            Self::ResponseTooLarge => formatter.write_str("raw source response exceeds limit"),
            Self::RpcBudgetExceeded => formatter.write_str("raw source RPC byte budget exceeded"),
            Self::DeadlineExceeded => formatter.write_str("raw source deadline exceeded"),
            Self::RpcRejected(code) => write!(formatter, "raw source RPC rejected ({code})"),
            Self::MalformedResponse => formatter.write_str("malformed raw source response"),
            Self::BodyTooLarge => formatter.write_str("raw source body exceeds limit"),
            Self::HashChanged => formatter.write_str("raw source selected hash changed"),
        }
    }
}
impl Error for RawBlockError {}

/// One explicitly selected endpoint, with no retries, proxy, redirect or history store.
/// Limits count HTTP response-body bytes and cooperative elapsed wall time, not
/// network headers/TLS traffic or hard preemption of synchronous ledger work.
pub struct RawBlockClient {
    endpoint: Url,
    client: reqwest::Client,
    next_id: u64,
    used_rpc_bytes: u64,
    max_rpc_bytes: u64,
    deadline: Instant,
    response: Vec<u8>,
}

impl fmt::Debug for RawBlockClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RawBlockClient").finish_non_exhaustive()
    }
}

impl RawBlockClient {
    /// Validates locally and constructs transport; never issues a request.
    pub fn new(
        endpoint: &str, allow_loopback_http: bool, max_rpc_bytes: u64,
        max_elapsed: Duration,
    ) -> Result<Self, RawBlockError> {
        if max_rpc_bytes == 0 || max_elapsed.is_zero() {
            return Err(RawBlockError::InvalidPolicy);
        }
        let deadline = Instant::now().checked_add(max_elapsed).ok_or(RawBlockError::InvalidPolicy)?;
        let (endpoint, client) = crate::http::client(endpoint, allow_loopback_http, max_elapsed)
            .map_err(|error| match error {
                crate::http::HttpClientError::InvalidEndpoint => RawBlockError::InvalidEndpoint,
                crate::http::HttpClientError::Transport => RawBlockError::Transport,
            })?;
        let client = Self { endpoint, client, next_id: 1, used_rpc_bytes: 0,
            max_rpc_bytes, deadline, response: Vec::new() };
        client.check_deadline()?;
        Ok(client)
    }

    /// Fetches the exact height's claimed hash, then its complete original raw body.
    /// The caller must bind the returned wire-order hash to the actual header and
    /// validate the whole original body; acquisition metadata alone proves nothing.
    pub async fn read_block(
        &mut self, height: u32, body: &mut Vec<u8>, max_body_bytes: usize,
    ) -> Result<[u8; 32], RawBlockError> {
        body.clear();
        if max_body_bytes == 0 { return Err(RawBlockError::InvalidPolicy); }
        let id = self.request("getblockhash", json!([height]), HASH_REPLY_BYTES).await?;
        let claimed = result(&self.response, id)?;
        let hash = decode_hash(&claimed.0)?;
        // Borrow the bounded result directly into request serialization: no 4MB
        // hex String copy. Only the 64-character selected hash is copied here.
        let params = json!([claimed.0.as_ref(), 0]);
        let id = self.request("getblock", params, BLOCK_REPLY_BYTES).await?;
        let raw = result(&self.response, id)?;
        if raw.0.is_empty() || !raw.0.len().is_multiple_of(2) {
            return Err(RawBlockError::MalformedResponse);
        }
        let length = raw.0.len() / 2;
        if length > max_body_bytes.min(MAX_BLOCK_BYTES) { return Err(RawBlockError::BodyTooLarge); }
        if !raw.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RawBlockError::MalformedResponse);
        }
        // Check the decoded ceiling BEFORE reserve/resize. Reuse the caller's
        // allocation across heights, while retaining only one current body.
        if body.capacity() < length {
            body.try_reserve_exact(length).map_err(|_| RawBlockError::BodyTooLarge)?;
        }
        body.resize(length, 0);
        decode_into(&raw.0, body)?;
        self.check_deadline()?;
        Ok(hash)
    }

    /// Rechecks only the selected finite boundary, never tip/canonicality/finality.
    pub async fn recheck_hash(&mut self, height: u32, expected: [u8; 32]) -> Result<(), RawBlockError> {
        let id = self.request("getblockhash", json!([height]), HASH_REPLY_BYTES).await?;
        let acquired = decode_hash(&result(&self.response, id)?.0)?;
        if acquired != expected { return Err(RawBlockError::HashChanged); }
        self.check_deadline()
    }

    /// Cooperative seam for synchronous consumers and final publication.
    pub fn check_deadline(&self) -> Result<(), RawBlockError> {
        self.remaining().map(|_| ())
    }

    fn remaining(&self) -> Result<Duration, RawBlockError> {
        self.deadline.checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero()).ok_or(RawBlockError::DeadlineExceeded)
    }

    fn transport_error(&self, error: &reqwest::Error) -> RawBlockError {
        if error.is_timeout() || self.check_deadline().is_err() {
            RawBlockError::DeadlineExceeded
        } else { RawBlockError::Transport }
    }

    async fn request(
        &mut self, method: &str, params: serde_json::Value, limit: usize,
    ) -> Result<u64, RawBlockError> {
        let timeout = self.remaining()?.min(Duration::from_secs(30));
        if self.used_rpc_bytes >= self.max_rpc_bytes { return Err(RawBlockError::RpcBudgetExceeded); }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(RawBlockError::InvalidPolicy)?;
        self.response.clear();
        let mut response = self.client.post(self.endpoint.as_str()).timeout(timeout)
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .send().await.map_err(|error| self.transport_error(&error))?;
        self.check_deadline()?;
        if !response.status().is_success() {
            return Err(RawBlockError::HttpStatus(response.status().as_u16()));
        }
        if response.headers().contains_key(reqwest::header::CONTENT_ENCODING) {
            return Err(RawBlockError::MalformedResponse);
        }
        let remaining_bytes = self.max_rpc_bytes - self.used_rpc_bytes;
        if let Some(length) = response.content_length() {
            if length > limit as u64 { return Err(RawBlockError::ResponseTooLarge); }
            if length > remaining_bytes { return Err(RawBlockError::RpcBudgetExceeded); }
        }
        let ceiling = limit.min(usize::try_from(remaining_bytes).unwrap_or(usize::MAX));
        let capacity = response.content_length().map_or(ceiling.min(4096), |length| length as usize);
        if self.response.capacity() < capacity {
            self.response.try_reserve_exact(capacity).map_err(|_| RawBlockError::ResponseTooLarge)?;
        }
        while let Some(chunk) = response.chunk().await.map_err(|error| self.transport_error(&error))? {
            self.check_deadline()?;
            if chunk.len() > limit - self.response.len() { return Err(RawBlockError::ResponseTooLarge); }
            let used = self.used_rpc_bytes.checked_add(chunk.len() as u64)
                .filter(|used| *used <= self.max_rpc_bytes).ok_or(RawBlockError::RpcBudgetExceeded)?;
            // Actual streamed bytes are authoritative even without Content-Length.
            // Both cumulative and per-response checks precede buffer extension.
            let length = self.response.len() + chunk.len();
            if self.response.capacity() < length {
                let capacity = length.max(self.response.capacity().saturating_mul(2).min(ceiling));
                self.response.try_reserve_exact(capacity - self.response.len())
                    .map_err(|_| RawBlockError::ResponseTooLarge)?;
            }
            self.used_rpc_bytes = used;
            self.response.extend_from_slice(&chunk);
        }
        self.check_deadline()?;
        Ok(id)
    }
}

// Borrow ordinary unescaped strings from the bounded response. JSON escapes may
// require an owned string; the same response byte ceiling still bounds that work.
struct Text<'a>(Cow<'a, str>);
impl<'de> Deserialize<'de> for Text<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl<'de> Visitor<'de> for TextVisitor {
            type Value = Text<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }
            fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
                Ok(Text(Cow::Borrowed(value)))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Text(Cow::Owned(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(Text(Cow::Owned(value)))
            }
        }
        deserializer.deserialize_str(TextVisitor)
    }
}

struct RpcError { code: i64 }
impl<'de> Deserialize<'de> for RpcError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ErrorVisitor;
        impl<'de> Visitor<'de> for ErrorVisitor {
            type Value = RpcError;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RPC error object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut code, mut message, mut data) = (None, false, false);
                while let Some(key) = map.next_key::<Text<'de>>()? {
                    match key.0.as_ref() {
                        "code" if code.is_none() => code = Some(map.next_value::<i64>()?),
                        "message" if !message => { map.next_value::<Text<'de>>()?; message = true; }
                        "data" if !data => { map.next_value::<IgnoredAny>()?; data = true; }
                        _ => return Err(de::Error::custom("invalid or duplicate RPC error field")),
                    }
                }
                if !message { return Err(de::Error::missing_field("message")); }
                Ok(RpcError { code: code.ok_or_else(|| de::Error::missing_field("code"))? })
            }
        }
        deserializer.deserialize_map(ErrorVisitor)
    }
}

struct Envelope<'a> {
    jsonrpc: Text<'a>,
    id: u64,
    result: Option<Text<'a>>,
    error: Option<RpcError>,
}
impl<'de> Deserialize<'de> for Envelope<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;
        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON-RPC object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut jsonrpc, mut id, mut result, mut error) = (None, None, None, None);
                while let Some(key) = map.next_key::<Text<'de>>()? {
                    match key.0.as_ref() {
                        "jsonrpc" if jsonrpc.is_none() => jsonrpc = Some(map.next_value::<Text<'de>>()?),
                        "id" if id.is_none() => id = Some(map.next_value::<u64>()?),
                        "result" if result.is_none() => result = Some(map.next_value::<Option<Text<'de>>>()?),
                        "error" if error.is_none() => error = Some(map.next_value::<Option<RpcError>>()?),
                        _ => return Err(de::Error::custom("invalid or duplicate JSON-RPC field")),
                    }
                }
                Ok(Envelope {
                    jsonrpc: jsonrpc.ok_or_else(|| de::Error::missing_field("jsonrpc"))?,
                    id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                    result: result.flatten(), error: error.flatten(),
                })
            }
        }
        // No visit_seq: batches and positional struct envelopes are never accepted.
        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

fn result(bytes: &[u8], id: u64) -> Result<Text<'_>, RawBlockError> {
    // from_slice enforces complete JSON exhaustion; Value would erase duplicates.
    let envelope: Envelope<'_> = serde_json::from_slice(bytes).map_err(|_| RawBlockError::MalformedResponse)?;
    if envelope.jsonrpc.0 != "2.0" || envelope.id != id { return Err(RawBlockError::MalformedResponse); }
    match (envelope.result, envelope.error) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => Err(RawBlockError::RpcRejected(error.code)),
        _ => Err(RawBlockError::MalformedResponse),
    }
}

fn decode_hash(text: &str) -> Result<[u8; 32], RawBlockError> {
    let mut hash = [0; 32];
    decode_into(text, &mut hash)?;
    hash.reverse();
    Ok(hash)
}

fn decode_into(text: &str, bytes: &mut [u8]) -> Result<(), RawBlockError> {
    if text.len() != bytes.len() * 2 { return Err(RawBlockError::MalformedResponse); }
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0.iter()) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(())
}

fn nibble(byte: u8) -> Result<u8, RawBlockError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RawBlockError::MalformedResponse),
    }
}
