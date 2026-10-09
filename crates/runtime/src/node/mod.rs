//! Bounded authenticated direct-peer transport and explicit ephemeral threshold DKG.
//! No financial authority, wallet custody, SQL, chain actions or recovery lifecycle.
mod config;
#[cfg(target_os = "linux")]
mod discovery;
#[cfg(target_os = "linux")]
mod dkg;
#[cfg(target_os = "linux")]
mod identity;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod reconnect;
#[cfg(target_os = "linux")]
mod tui;
pub(crate) mod session;
mod state;

/// Explicit native coordination caller seam; no economic or transaction authority.
pub use session::SessionTable as NativeQuoteSessions;

use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "z2z-node",
    version,
    about = "Direct TCP/Noise/yamux transport node; TUI dashboard on a terminal, NDJSON with --headless"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run authenticated direct-peer transport until Ctrl-C or an explicit duration.
    Run(config::Options),
    /// Print the latest public node-state snapshot written by a run (--state-file).
    Status {
        /// Path of the state snapshot written by `run --state-file PATH`.
        #[arg(long)]
        state_file: PathBuf,
    },
    /// One-shot /z2z/session/1 Hello handshake against a known peer.
    SendHello(network::hello::Options),
    /// Ephemeral authenticated 2-of-2 FROST DKG with caller-frozen public contexts.
    #[cfg(target_os = "linux")]
    DkgHandshake(dkg::Options),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub(crate) enum Error {
    Configuration,
    Transport,
    Signal,
    Output,
    OutputBackpressure,
    #[cfg(target_os = "linux")]
    IdentityPath,
    #[cfg(target_os = "linux")]
    IdentityEncoding,
    #[cfg(target_os = "linux")]
    IdentityLock,
    #[cfg(target_os = "linux")]
    IdentityIo,
    #[cfg(target_os = "linux")]
    IdentityDurability,
    /// TUI requested (or auto-selected) but stdin/stdout are not both a terminal.
    #[cfg(target_os = "linux")]
    TuiNotTerminal,
    /// The --state-file snapshot could not be written/renamed.
    #[cfg(target_os = "linux")]
    StateFile,
    /// A session envelope failed to build/parse.
    #[cfg(target_os = "linux")]
    SessionEnvelope,
    /// The session handshake timed out or failed outbound.
    #[cfg(target_os = "linux")]
    SessionTimeout,
    /// The ceremony context, identity, ordering or public commitment mismatched.
    #[cfg(target_os = "linux")]
    DkgProtocol,
    /// A real threshold package or crypto operation failed.
    #[cfg(target_os = "linux")]
    DkgCrypto,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        if matches!(self, Self::UnsupportedPlatform) {
            return formatter.write_str("node transport requires Linux nonblocking public output");
        }
        write!(formatter, "node rejected: {self:?}")
    }
}

impl std::error::Error for Error {}

#[cfg(target_os = "linux")]
fn diagnostic(error: &Error) {
    let message: &[u8] = match error {
        Error::Configuration => b"node rejected: Configuration\n",
        Error::Transport => b"node rejected: Transport\n",
        Error::Signal => b"node rejected: Signal\n",
        Error::Output => b"node rejected: Output\n",
        Error::OutputBackpressure => b"node rejected: OutputBackpressure\n",
        Error::IdentityPath => b"node rejected: IdentityPath\n",
        Error::IdentityEncoding => b"node rejected: IdentityEncoding\n",
        Error::IdentityLock => b"node rejected: IdentityLock\n",
        Error::IdentityIo => b"node rejected: IdentityIo\n",
        Error::IdentityDurability => b"node rejected: IdentityDurability\n",
        Error::TuiNotTerminal => b"node rejected: TuiNotTerminal (dashboard needs an interactive terminal; use --headless)\n",
        Error::StateFile => b"node rejected: StateFile\n",
        Error::SessionEnvelope => b"node rejected: SessionEnvelope\n",
        Error::SessionTimeout => b"node rejected: SessionTimeout\n",
        Error::DkgProtocol => b"node rejected: DkgProtocol\n",
        Error::DkgCrypto => b"node rejected: DkgCrypto\n",
    };
    let stderr = std::io::stderr();
    let Ok(original) = rustix::fs::fcntl_getfl(&stderr) else { return };
    if rustix::fs::fcntl_setfl(&stderr, original | rustix::fs::OFlags::NONBLOCK).is_err() {
        return;
    }
    // A full stderr (including stdout merged with 2>&1) cannot prevent exit.
    // Diagnostics are best-effort atomic pipe records, not a blocking fallback.
    for _ in 0..2 {
        match rustix::io::write(&stderr, message) {
            Err(rustix::io::Errno::INTR) => continue,
            _ => break,
        }
    }
    let _ = rustix::fs::fcntl_setfl(&stderr, original);
}

#[cfg(not(target_os = "linux"))]
fn diagnostic(_: &Error) {}

/// Parse public transport/ceremony options; this entry point has no financial capability.
pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let argv = std::iter::once(OsString::from("z2z-node")).chain(arguments);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            if error.print().is_err() {
                return ExitCode::FAILURE;
            }
            return ExitCode::from(code as u8);
        }
    };
    match cli.command {
        Command::Status { state_file } => status_command(&state_file),
        Command::SendHello(options) => send_hello_command(options),
        #[cfg(target_os = "linux")]
        Command::DkgHandshake(options) => dkg_command(options),
        Command::Run(options) => run_command(options),
    }
}

#[cfg(target_os = "linux")]
fn send_hello_command(options: network::hello::Options) -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Transport)
        .and_then(|runtime| runtime.block_on(network::send_hello(options)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic(&error);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn send_hello_command(_: network::hello::Options) -> ExitCode {
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn dkg_command(options: dkg::Options) -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Transport)
        .and_then(|runtime| runtime.block_on(dkg::handshake(options)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic(&error);
            ExitCode::FAILURE
        }
    }
}

fn status_command(state_file: &std::path::Path) -> ExitCode {
    const MAX_STATE_BYTES: u64 = 16 * 1024;
    match std::fs::File::open(state_file) {
        Ok(file) => {
            let meta = file.metadata();
            let bounded = meta.as_ref().is_ok_and(|m| m.len() <= MAX_STATE_BYTES);
            let value: Result<serde_json::Value, _> = if bounded {
                serde_json::from_reader(file).map_err(|_| ())
            } else {
                Err(())
            };
            match value {
                Ok(value) if value.get("schema_version").and_then(serde_json::Value::as_i64) == Some(1) => {
                    match serde_json::to_vec_pretty(&value) {
                        Ok(bytes) => {
                            use std::io::Write as _;
                            let mut out = std::io::stdout().lock();
                            let ok = out.write_all(&bytes).is_ok()
                                && out.write_all(b"\n").is_ok()
                                && out.flush().is_ok();
                            if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
                        }
                        Err(_) => ExitCode::FAILURE,
                    }
                }
                _ => {
                    eprintln!("status rejected: invalid or oversize snapshot");
                    ExitCode::FAILURE
                }
            }
        }
        Err(_) => {
            eprintln!("status rejected: no snapshot at {}", state_file.display());
            ExitCode::FAILURE
        }
    }
}

fn run_command(options: config::Options) -> ExitCode {
    let config = match config::Config::from_options(options) {
        Ok(config) => config,
        Err(error) => {
            diagnostic(&error);
            return ExitCode::from(2);
        }
    };
    #[cfg(target_os = "linux")]
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Transport)
        .and_then(|runtime| runtime.block_on(network::run(config)));
    #[cfg(not(target_os = "linux"))]
    let result: Result<()> = {
        let _ = config;
        Err(Error::UnsupportedPlatform)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic(&error);
            ExitCode::FAILURE
        }
    }
}
