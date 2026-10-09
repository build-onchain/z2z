//! Read-only finite linear-ledger replay, not a SNARK or full R2.2 acceptance.
//! Usage: replay_source HISTORY_FILE MAX_BLOCKS MAX_INPUT_BYTES
//! Input: count:u32LE, then length:u32LE/complete raw bodies from authentic genesis.
//! Success stdout is exactly one 374-byte v11 journal, with no newline. The
//! caller must require that exact length AND successful process completion.
//! No network, stdin, SQL, private stores, signing, or proving is involved.

use std::{ffi::OsStr, fs::File, io::{self, BufReader, Write}, process::ExitCode};
use ziquid_proofs::source_replay::{MAX_BLOCK_COUNT, replay_framed_testnet};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn decimal(argument: &OsStr) -> Result<u64, &'static str> {
    let text = argument.to_str().ok_or("invalid source replay arguments")?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid source replay arguments");
    }
    text.parse().map_err(|_| "invalid source replay arguments")
}

#[cfg(target_os = "linux")]
fn open_source(path: &OsStr) -> Result<File, &'static str> {
    use std::os::unix::fs::OpenOptionsExt;
    // Opening a FIFO must not wait for a writer before opened-fd metadata can
    // reject it. O_NONBLOCK does not change regular-file replay semantics.
    std::fs::OpenOptions::new().read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path).map_err(|_| "source history unavailable")
}

#[cfg(not(target_os = "linux"))]
fn open_source(_path: &OsStr) -> Result<File, &'static str> {
    Err("source replay requires Linux")
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().ok_or("invalid source replay arguments")?;
    let max_blocks = arguments.next().ok_or("invalid source replay arguments")?;
    let max_input_bytes = arguments.next().ok_or("invalid source replay arguments")?;
    if arguments.next().is_some() {
        return Err("invalid source replay arguments");
    }
    let max_blocks = u32::try_from(decimal(&max_blocks)?)
        .map_err(|_| "invalid source replay arguments")?;
    let max_input_bytes = decimal(&max_input_bytes)?;
    if !(1..=MAX_BLOCK_COUNT).contains(&max_blocks) || max_input_bytes == 0 {
        return Err("source replay policy rejected");
    }
    let file = open_source(&path)?;
    let metadata = file.metadata().map_err(|_| "source history unavailable")?;
    if !metadata.is_file() {
        return Err("source history unavailable");
    }
    if metadata.len() > max_input_bytes {
        return Err("source history exceeds replay limits");
    }
    let journal = replay_framed_testnet(&mut BufReader::new(file), max_blocks, max_input_bytes)
        .map_err(|error| match error {
            ziquid_proofs::source_replay::SourceReplayError::InvalidPolicy => "source replay policy rejected",
            ziquid_proofs::source_replay::SourceReplayError::InvalidFraming => "source history framing rejected",
            ziquid_proofs::source_replay::SourceReplayError::LimitExceeded => "source history exceeds replay limits",
            ziquid_proofs::source_replay::SourceReplayError::InputUnavailable => "source history unavailable",
            ziquid_proofs::source_replay::SourceReplayError::InvalidGenesis => "authentic testnet genesis rejected",
            ziquid_proofs::source_replay::SourceReplayError::UnsupportedEra => "unsupported source era",
            ziquid_proofs::source_replay::SourceReplayError::InvalidTransition => "complete source ledger transition rejected",
            ziquid_proofs::source_replay::SourceReplayError::TrailingBytes => "source history has trailing bytes",
        })?;
    // Nothing reaches stdout before complete replay and actual EOF. write_all
    // may partially publish on a sink failure; it is not crash-atomic storage.
    let mut stdout = io::stdout().lock();
    stdout.write_all(&journal).and_then(|()| stdout.flush())
        .map_err(|_| "source journal output unavailable")
}
