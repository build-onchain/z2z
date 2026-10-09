//! Public fixed-frame unsigned calls only. No stdin, private keys, SQL, RPC,
//! signing, submission or proof/source/financial execution qualification.
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use std::{ffi::OsString, io::Write, path::{Path, PathBuf}, process::ExitCode};
use ziquid_chains::native::{UnsignedCall, build_fund_and_arm_call, build_resolve_call};
use ziquid_protocol::native::{
    BOUNDARY_ENCODED_LEN, DEPLOYMENT_ENCODED_LEN, STATEMENT_ENCODED_LEN,
    DeploymentDescriptor, Resolution, SourceBoundary, Statement,
};

#[derive(Parser)]
#[command(name = "ziquid native", version, about = "Offline public unsigned native calls; no signing, submission or financial execution")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Common {
    /// Exact 638-byte canonical PUBLIC statement.
    #[arg(long)]
    statement: PathBuf,
    /// Exact 100-byte canonical PUBLIC boundary; not a source finality claim.
    #[arg(long)]
    boundary: PathBuf,
    /// Independently pinned exact 279-byte PUBLIC deployment descriptor.
    #[arg(long)]
    deployment: PathBuf,
    /// Exact 356-byte public SP1 wrapper; shape is not proof validity.
    #[arg(long)]
    acceptance_proof: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Describe unsigned payable funding/arming calldata; does not arm anything.
    BuildArmCall {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        arm_proof: PathBuf,
        #[arg(long)]
        origin_proof: PathBuf,
    },
    /// Describe unsigned resolution calldata; does not classify payment or transfer funds.
    BuildResolveCall {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        financial_proof: PathBuf,
        #[arg(long, value_parser = public_address)]
        sender: [u8; 20],
        #[arg(long, value_enum)]
        outcome: Outcome,
        #[arg(long, value_parser = decimal_u64)]
        cnet: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Outcome { Completion, Recovery }

pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let cli = match Cli::try_parse_from(std::iter::once(OsString::from("ziquid native")).chain(arguments)) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return if error.print().is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
            // Clap's default rendering may disclose argument values or paths.
            eprintln!("invalid native command arguments");
            return ExitCode::from(2);
        }
    };
    match execute(cli.command) {
        Ok(bytes) => {
            if std::io::stdout().lock().write_all(&bytes).is_err() {
                eprintln!("native public export unavailable");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(message) => { eprintln!("{message}"); ExitCode::from(2) }
    }
}

fn execute(command: Command) -> Result<Vec<u8>, &'static str> {
    let common = match &command {
        Command::BuildArmCall { common, .. } | Command::BuildResolveCall { common, .. } => common,
    };
    let deployment = DeploymentDescriptor::decode(&read_frame(&common.deployment, DEPLOYMENT_ENCODED_LEN)?)
        .map_err(|_| "invalid native public deployment encoding")?;
    let statement = Statement::decode(&read_frame(&common.statement, STATEMENT_ENCODED_LEN)?)
        .map_err(|_| "invalid native public statement encoding")?;
    let boundary = SourceBoundary::decode(&read_frame(&common.boundary, BOUNDARY_ENCODED_LEN)?)
        .map_err(|_| "invalid native public boundary encoding")?;
    let acceptance = read_frame(&common.acceptance_proof, 356)?;
    let (operation, call) = match command {
        Command::BuildArmCall { arm_proof, origin_proof, .. } => {
            let arm = read_frame(&arm_proof, 356)?;
            let origin = read_frame(&origin_proof, 356)?;
            ("build_fund_and_arm_call", build_fund_and_arm_call(
                &deployment, &statement, &boundary, &arm, &origin, &acceptance,
            ))
        }
        Command::BuildResolveCall { financial_proof, sender, outcome, cnet, .. } => {
            let financial = read_frame(&financial_proof, 356)?;
            let outcome = match outcome { Outcome::Completion => Resolution::Completion, Outcome::Recovery => Resolution::Recovery };
            ("build_resolve_call", build_resolve_call(
                &deployment, &statement, &boundary, sender, outcome, cnet, &financial, &acceptance,
            ))
        }
    };
    let call = call.map_err(|_| "native public call rejected")?;
    encode_call(operation, &call)
}

#[cfg(target_os = "linux")]
fn read_frame(path: &Path, length: usize) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    use rustix::fs::{Mode, OFlags};
    let mut file: std::fs::File = rustix::fs::open(path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty()).map_err(|_| "native public file unavailable")?.into();
    let metadata = file.metadata().map_err(|_| "native public file unavailable")?;
    if !metadata.is_file() || metadata.len() != length as u64 {
        return Err("invalid native public file frame");
    }
    // One excess byte detects growth/trailing data after metadata inspection;
    // allocation and total read are bounded even for a concurrently changed file.
    let mut bytes = vec![0; length + 1];
    let mut used = 0;
    while used < bytes.len() {
        let count = match file.read(&mut bytes[used..]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("native public file unavailable"),
        };
        if count == 0 { break; }
        used += count;
    }
    if used != length { return Err("invalid native public file frame"); }
    bytes.truncate(length);
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_frame(_path: &Path, _length: usize) -> Result<Vec<u8>, &'static str> {
    Err("native bounded public file input unsupported on this operating system")
}

fn public_address(value: &str) -> Result<[u8; 20], &'static str> {
    let bytes = value.strip_prefix("0x").filter(|hex| hex.len() == 40)
        .ok_or("invalid native public address")?.as_bytes();
    let mut decoded = [0; 20];
    for (out, pair) in decoded.iter_mut().zip(bytes.as_chunks::<2>().0.iter()) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10), _ => None,
        };
        *out = digit(pair[0]).and_then(|high| digit(pair[1]).map(|low| high * 16 + low))
            .ok_or("invalid native public address")?;
    }
    if decoded == [0; 20] { return Err("invalid native public address"); }
    Ok(decoded)
}

fn decimal_u64(value: &str) -> Result<u64, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid native consideration");
    }
    value.parse().map_err(|_| "invalid native consideration")
}

fn public_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    encoded
}

#[derive(Serialize)]
struct CallExport<'a> {
    kind: &'static str,
    operation: &'static str,
    source: &'static str,
    from: String,
    to: String,
    value_wei: String,
    data: String,
    context_digest: String,
    expected_journals: &'a [Vec<u8>],
    proof_validity: &'static str,
    deployment_validity: &'static str,
    source_acceptance: &'static str,
    source_finality: &'static str,
    asset_backing: &'static str,
    proof_certificate: bool,
    signing: bool,
    submission: bool,
    financial_execution: bool,
}

fn encode_call(operation: &'static str, call: &UnsignedCall) -> Result<Vec<u8>, &'static str> {
    let export = CallExport {
        kind: "unsigned_native_call", operation, source: "caller_public_files",
        from: public_hex(&call.from()), to: public_hex(&call.to()),
        value_wei: call.value().to_string(), data: public_hex(call.data()),
        context_digest: public_hex(&call.context_digest()), expected_journals: call.expected_journals(),
        proof_validity: "UNVERIFIED", deployment_validity: "UNVERIFIED",
        source_acceptance: "UNVERIFIED", source_finality: "UNVERIFIED", asset_backing: "UNVERIFIED",
        proof_certificate: false, signing: false, submission: false, financial_execution: false,
    };
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "native public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}
