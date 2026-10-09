//! Read-only genesis-to-explicit-height raw acquisition and complete ledger replay.
//! Usage: acquire_replay_source --endpoint-env ENV_NAME --through-height H
//!   --max-blocks N --max-input-bytes B --max-rpc-bytes W --max-elapsed-seconds T
//!   [--allow-loopback-http]
//! Success stdout is exactly the existing 374-byte journal, never a SNARK,
//! fork-choice/freshness/finality assertion or financial authorization. The caller
//! must require exact output length AND successful process completion.

use std::{ffi::OsStr, io::{self, Read, Write}, process::ExitCode, time::Duration};
use tokio::runtime::Runtime;
use zcash_primitives::block::BlockHeader;
use zeroize::Zeroizing;
use ziquid_chains::source::{RawBlockClient, RawBlockError};
use ziquid_proofs::source_replay::{MAX_BLOCK_BYTES, MAX_BLOCK_COUNT, replay_framed_testnet};

const INVALID_ARGUMENTS: &str = "invalid source acquisition arguments";
const INVALID_POLICY: &str = "source acquisition policy rejected";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

struct Arguments {
    endpoint_env: String,
    through_height: u32,
    max_blocks: u32,
    max_input_bytes: u64,
    max_rpc_bytes: u64,
    max_elapsed: Duration,
    allow_loopback_http: bool,
}

fn decimal(argument: &OsStr) -> Result<u64, &'static str> {
    let text = argument.to_str().ok_or(INVALID_ARGUMENTS)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(INVALID_ARGUMENTS);
    }
    text.parse().map_err(|_| INVALID_ARGUMENTS)
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let (mut endpoint_env, mut height, mut blocks, mut input, mut rpc, mut seconds) =
        (None, None, None, None, None, None);
    let mut allow_loopback_http = false;
    while let Some(flag) = arguments.next() {
        match flag.to_str().ok_or(INVALID_ARGUMENTS)? {
            "--endpoint-env" if endpoint_env.is_none() => {
                let name = arguments.next().ok_or(INVALID_ARGUMENTS)?;
                let name = name.to_str().ok_or(INVALID_ARGUMENTS)?;
                let mut bytes = name.bytes();
                if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                    || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    return Err("source endpoint environment unavailable");
                }
                endpoint_env = Some(name.to_owned());
            }
            "--through-height" if height.is_none() => {
                height = Some(decimal(&arguments.next().ok_or(INVALID_ARGUMENTS)?)?);
            }
            "--max-blocks" if blocks.is_none() => {
                blocks = Some(decimal(&arguments.next().ok_or(INVALID_ARGUMENTS)?)?);
            }
            "--max-input-bytes" if input.is_none() => {
                input = Some(decimal(&arguments.next().ok_or(INVALID_ARGUMENTS)?)?);
            }
            "--max-rpc-bytes" if rpc.is_none() => {
                rpc = Some(decimal(&arguments.next().ok_or(INVALID_ARGUMENTS)?)?);
            }
            "--max-elapsed-seconds" if seconds.is_none() => {
                seconds = Some(decimal(&arguments.next().ok_or(INVALID_ARGUMENTS)?)?);
            }
            "--allow-loopback-http" if !allow_loopback_http => allow_loopback_http = true,
            _ => return Err(INVALID_ARGUMENTS),
        }
    }
    let through_height = u32::try_from(height.ok_or(INVALID_ARGUMENTS)?).map_err(|_| INVALID_POLICY)?;
    let max_blocks = u32::try_from(blocks.ok_or(INVALID_ARGUMENTS)?).map_err(|_| INVALID_POLICY)?;
    let max_input_bytes = input.ok_or(INVALID_ARGUMENTS)?;
    let max_rpc_bytes = rpc.ok_or(INVALID_ARGUMENTS)?;
    let seconds = seconds.ok_or(INVALID_ARGUMENTS)?;
    let count = through_height.checked_add(1).ok_or(INVALID_POLICY)?;
    let minimum = u64::from(count).checked_mul(4)
        .and_then(|bytes| bytes.checked_add(4 + 1692)).ok_or(INVALID_POLICY)?;
    if through_height >= MAX_BLOCK_COUNT || !(count..=MAX_BLOCK_COUNT).contains(&max_blocks)
        || max_input_bytes < minimum || max_rpc_bytes == 0 || seconds == 0
    {
        return Err(INVALID_POLICY);
    }
    Ok(Arguments { endpoint_env: endpoint_env.ok_or(INVALID_ARGUMENTS)?, through_height,
        max_blocks, max_input_bytes, max_rpc_bytes, max_elapsed: Duration::from_secs(seconds),
        allow_loopback_http })
}

fn run() -> Result<(), &'static str> {
    let arguments = arguments()?;
    // The name and private value never appear in diagnostics. No URL argv or
    // userinfo-generated authentication capability is introduced.
    let endpoint = std::env::var(&arguments.endpoint_env).map(Zeroizing::new)
        .map_err(|_| "source endpoint environment unavailable")?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "source acquisition runtime unavailable")?;
    let client = runtime.block_on(async {
        RawBlockClient::new(&endpoint, arguments.allow_loopback_http,
            arguments.max_rpc_bytes, arguments.max_elapsed).map_err(raw_error)
    })?;
    let mut reader = RpcHistoryReader::new(&runtime, client, arguments.through_height, arguments.max_input_bytes)?;
    reader.client.check_deadline().map_err(raw_error)?;
    // Replay is synchronous OUTSIDE block_on. Read drives one bounded RPC frame
    // when needed, never a nested runtime or an eager full-history buffer.
    let replay = replay_framed_testnet(&mut reader, arguments.max_blocks, arguments.max_input_bytes);
    let journal = replay.map_err(|error| reader.failure.unwrap_or(match error {
        ziquid_proofs::source_replay::SourceReplayError::InvalidPolicy => "source replay policy rejected",
        ziquid_proofs::source_replay::SourceReplayError::InvalidFraming => "source history framing rejected",
        ziquid_proofs::source_replay::SourceReplayError::LimitExceeded => "source history exceeds replay limits",
        ziquid_proofs::source_replay::SourceReplayError::InputUnavailable => "source history unavailable",
        ziquid_proofs::source_replay::SourceReplayError::InvalidGenesis => "authentic testnet genesis rejected",
        ziquid_proofs::source_replay::SourceReplayError::UnsupportedEra => "unsupported source era",
        ziquid_proofs::source_replay::SourceReplayError::InvalidTransition => "complete source ledger transition rejected",
        ziquid_proofs::source_replay::SourceReplayError::TrailingBytes => "source history has trailing bytes",
    }))?;
    // Replay's real EOF probe already performed the final selected-hash recheck.
    // These cooperative seams catch elapsed CPU work before publication; they do
    // not claim hard CPU preemption or constant total ledger-state memory.
    reader.client.check_deadline().map_err(raw_error)?;
    let mut stdout = io::stdout().lock();
    reader.client.check_deadline().map_err(raw_error)?;
    // Nothing is written before replay, transport completion and recheck succeed.
    // A failed output sink may still partially write: this is not atomic storage.
    stdout.write_all(&journal).and_then(|()| stdout.flush())
        .map_err(|_| "source journal output unavailable")?;
    reader.client.check_deadline().map_err(raw_error)
}

fn raw_error(error: RawBlockError) -> &'static str {
    match error {
        RawBlockError::InvalidEndpoint => "invalid raw source endpoint",
        RawBlockError::InvalidPolicy => "raw source policy rejected",
        RawBlockError::Transport => "raw source transport unavailable",
        RawBlockError::HttpStatus(_) => "raw source HTTP rejected",
        RawBlockError::ResponseTooLarge => "raw source response exceeds limit",
        RawBlockError::RpcBudgetExceeded => "raw source RPC byte budget exceeded",
        RawBlockError::DeadlineExceeded => "raw source deadline exceeded",
        RawBlockError::RpcRejected(_) => "raw source RPC rejected",
        RawBlockError::MalformedResponse => "malformed raw source response",
        RawBlockError::BodyTooLarge => "raw source body exceeds limit",
        RawBlockError::HashChanged => "raw source selected hash changed",
    }
}

struct RpcHistoryReader<'a> {
    runtime: &'a Runtime,
    client: RawBlockClient,
    count: u32,
    next_height: u32,
    prefix: [u8; 4],
    prefix_offset: usize,
    body: Vec<u8>,
    body_offset: usize,
    remaining_input_bytes: u64,
    last_hash: Option<[u8; 32]>,
    rechecked: bool,
    failure: Option<&'static str>,
}

impl<'a> RpcHistoryReader<'a> {
    fn new(runtime: &'a Runtime, client: RawBlockClient, through_height: u32, budget: u64) -> Result<Self, &'static str> {
        let count = through_height.checked_add(1).ok_or(INVALID_POLICY)?;
        let remaining_input_bytes = budget.checked_sub(4).ok_or(INVALID_POLICY)?;
        Ok(Self { runtime, client, count, next_height: 0, prefix: count.to_le_bytes(),
            prefix_offset: 0, body: Vec::new(), body_offset: 0, remaining_input_bytes,
            last_hash: None, rechecked: false, failure: None })
    }

    fn acquire_next(&mut self) -> Result<(), &'static str> {
        self.client.check_deadline().map_err(raw_error)?;
        // Reserve every still-required prefix so decoded bytes cannot consume
        // tomorrow's framing budget. Charge the complete current frame BEFORE
        // emitting its length or any body bytes to the real ledger.
        let prefixes = u64::from(self.count - self.next_height).checked_mul(4)
            .ok_or("source history exceeds replay limits")?;
        let available = self.remaining_input_bytes.checked_sub(prefixes)
            .filter(|bytes| *bytes > 0).ok_or("source history exceeds replay limits")?;
        let body_limit = usize::try_from(available.min(MAX_BLOCK_BYTES as u64))
            .map_err(|_| "source history exceeds replay limits")?;
        let hash = self.runtime.block_on(self.client.read_block(self.next_height, &mut self.body, body_limit))
            .map_err(raw_error)?;
        bind_header(&self.body, hash)?;
        self.client.check_deadline().map_err(raw_error)?;
        let length = u32::try_from(self.body.len()).map_err(|_| "source history exceeds replay limits")?;
        self.remaining_input_bytes = self.remaining_input_bytes.checked_sub(u64::from(length) + 4)
            .ok_or("source history exceeds replay limits")?;
        self.prefix = length.to_le_bytes();
        self.prefix_offset = 0;
        self.body_offset = 0;
        self.next_height = self.next_height.checked_add(1).ok_or(INVALID_POLICY)?;
        self.last_hash = Some(hash);
        Ok(())
    }

    fn read_part(&mut self, output: &mut [u8]) -> Result<usize, &'static str> {
        self.client.check_deadline().map_err(raw_error)?;
        if self.prefix_offset < self.prefix.len() {
            let size = output.len().min(self.prefix.len() - self.prefix_offset);
            output[..size].copy_from_slice(&self.prefix[self.prefix_offset..self.prefix_offset + size]);
            self.prefix_offset += size;
            self.client.check_deadline().map_err(raw_error)?;
            return Ok(size);
        }
        if self.body_offset < self.body.len() {
            let size = output.len().min(self.body.len() - self.body_offset);
            output[..size].copy_from_slice(&self.body[self.body_offset..self.body_offset + size]);
            self.body_offset += size;
            self.client.check_deadline().map_err(raw_error)?;
            return Ok(size);
        }
        if self.next_height < self.count {
            self.acquire_next()?;
            // A new complete body always begins with its four-byte frame length.
            let size = output.len().min(self.prefix.len());
            output[..size].copy_from_slice(&self.prefix[..size]);
            self.prefix_offset = size;
            self.client.check_deadline().map_err(raw_error)?;
            return Ok(size);
        }
        if !self.rechecked {
            let hash = self.last_hash.ok_or("source history unavailable")?;
            self.runtime.block_on(self.client.recheck_hash(self.count - 1, hash)).map_err(raw_error)?;
            self.client.check_deadline().map_err(raw_error)?;
            self.rechecked = true;
        }
        self.client.check_deadline().map_err(raw_error)?;
        Ok(0)
    }
}

impl Read for RpcHistoryReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // Empty reads never fetch, alter terminal state or perform a recheck.
        if output.is_empty() { return Ok(0); }
        if let Some(error) = self.failure { return Err(io::Error::other(error)); }
        self.read_part(output).map_err(|error| {
            self.failure = Some(error);
            io::Error::other(error)
        })
    }
}

fn bind_header(body: &[u8], expected: [u8; 32]) -> Result<(), &'static str> {
    // Only the bounded canonical header goes through the maintained parser.
    // Block::read rejects genesis; claimed height is not ledger truth here.
    const HEADER_BYTES: usize = 1487;
    let raw = body.get(..HEADER_BYTES).ok_or("raw source header rejected")?;
    if raw[140..143] != [0xfd, 0x40, 0x05] { return Err("raw source header rejected"); }
    let mut input = raw;
    let header = BlockHeader::read(&mut input).map_err(|_| "raw source header rejected")?;
    let mut canonical = CanonicalHeader { remaining: raw };
    header.write(&mut canonical).map_err(|_| "raw source header rejected")?;
    if !input.is_empty() || !canonical.remaining.is_empty() { return Err("raw source header rejected"); }
    if header.hash().0 != expected { return Err("raw source body hash mismatch"); }
    Ok(())
}

struct CanonicalHeader<'a> { remaining: &'a [u8] }
impl Write for CanonicalHeader<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.remaining.starts_with(bytes) { return Err(io::Error::other("raw source header rejected")); }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
