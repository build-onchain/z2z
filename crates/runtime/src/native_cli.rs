//! Public fixed-frame unsigned calls and explicit block-pinned RPC observations.
//! No private stdin, keys, SQL, signing, submission or financial authority.
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use std::{ffi::OsString, io::Write, path::{Path, PathBuf}, process::ExitCode};
use ziquid_chains::native::{UnsignedCall, build_fund_and_arm_call, build_resolve_call};
use ziquid_chains::native::inspection::{NativeInspectionClient, NativeInspectionError, NativeInspectionObservation, NativeInspectionScope};
use zeroize::Zeroizing;
use ziquid_protocol::native::{
    BOUNDARY_ENCODED_LEN, DEPLOYMENT_ENCODED_LEN, STATEMENT_ENCODED_LEN,
    DeploymentDescriptor, Resolution, SourceBoundary, Statement,
};

#[derive(Parser)]
#[command(name = "ziquid native", version, about = "Public native calls and trusted-node observations; no signing, submission or financial authority")]
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
    /// Observe one exact native deployment at a selected hash; never financial authority.
    InspectObligation {
        /// Independently retained exact 279-byte PUBLIC deployment descriptor.
        #[arg(long)]
        deployment: PathBuf,
        /// Explicit nonzero 0x-prefixed 32-byte target block hash; no latest fallback.
        #[arg(long, value_parser = public_block_hash)]
        block_hash: [u8; 32],
        /// Environment variable containing the private endpoint; never a URI on argv.
        #[arg(long)]
        endpoint_env: String,
        #[arg(long)]
        allow_loopback_http: bool,
        /// Optional exact 638-byte PUBLIC statement for tag-bound obligation reads.
        #[arg(long)]
        statement: Option<PathBuf>,
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
    if let Command::InspectObligation { deployment, block_hash, endpoint_env, allow_loopback_http, statement } = &command {
        return execute_inspection(deployment, *block_hash, endpoint_env, *allow_loopback_http, statement.as_deref());
    }
    let common = match &command {
        Command::BuildArmCall { common, .. } | Command::BuildResolveCall { common, .. } => common,
        Command::InspectObligation { .. } => return Err("invalid native command arguments"),
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
        Command::InspectObligation { .. } => return Err("invalid native command arguments"),
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
    public_fixed(value).map_err(|_| "invalid native public address")
}

fn public_block_hash(value: &str) -> Result<[u8; 32], &'static str> {
    public_fixed(value).map_err(|_| "invalid native public block hash")
}

fn public_fixed<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let bytes = value.strip_prefix("0x").filter(|hex| hex.len() == N * 2)
        .ok_or("invalid native public hex")?.as_bytes();
    let mut decoded = [0; N];
    for (out, pair) in decoded.iter_mut().zip(bytes.as_chunks::<2>().0.iter()) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10), _ => None,
        };
        *out = digit(pair[0]).and_then(|high| digit(pair[1]).map(|low| high * 16 + low))
            .ok_or("invalid native public hex")?;
    }
    if decoded == [0; N] { return Err("invalid native public hex"); }
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

fn execute_inspection(
    deployment: &Path, block_hash: [u8; 32], endpoint_env: &str,
    allow_loopback_http: bool, statement: Option<&Path>,
) -> Result<Vec<u8>, &'static str> {
    let expected = DeploymentDescriptor::decode(&read_frame(deployment, DEPLOYMENT_ENCODED_LEN)?)
        .map_err(|_| "invalid native public deployment encoding")?;
    let scope = NativeInspectionScope { expected, block_hash };
    scope.validate().map_err(NativeInspectionError::message)?;
    let statement = statement.map(|path| {
        Statement::decode(&read_frame(path, STATEMENT_ENCODED_LEN)?)
            .map_err(|_| "invalid native public statement encoding")
    }).transpose()?;
    let mut name = endpoint_env.bytes();
    if !name.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !name.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("native inspection endpoint environment unavailable");
    }
    let endpoint = std::env::var(endpoint_env).map(Zeroizing::new)
        .map_err(|_| "native inspection endpoint environment unavailable")?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "native inspection runtime unavailable")?;
    let observation = runtime.block_on(async {
        let client = NativeInspectionClient::new(&endpoint, allow_loopback_http)
            .map_err(NativeInspectionError::message)?;
        client.inspect(&scope, statement.as_ref()).await.map_err(NativeInspectionError::message)
    })?;
    encode_inspection(&observation)
}

fn encode_inspection(observation: &NativeInspectionObservation) -> Result<Vec<u8>, &'static str> {
    let d = observation.deployment();
    let mut export = serde_json::json!({
        "kind":"native_obligation_observation", "source_scope":observation.source_scope(),
        "block_hash":public_hex(&observation.block_hash()), "block_number":observation.block_number().to_string(),
        "parent_hash":public_hex(&observation.parent_hash()), "deployment_digest":public_hex(&d.digest()),
        "expected_deployment":{
            "schema_version":d.schema_version, "source_network":d.source_network, "source_pool":d.source_pool,
            "transaction_version":d.transaction_version, "consensus_branch":d.consensus_branch,
            "financial_program":public_hex(&d.financial_program), "origin_program":public_hex(&d.origin_program),
            "source_acceptance_program":public_hex(&d.source_acceptance_program), "source_policy_id":public_hex(&d.source_policy_id),
            "target_chain_id":d.target_chain_id.to_string(), "obligation":public_hex(&d.obligation),
            "obligation_runtime_code":public_hex(&d.obligation_runtime_code), "verifier":public_hex(&d.verifier),
            "verifier_runtime_code":public_hex(&d.verifier_runtime_code),
        },
        "reported_total_liability_wei":observation.total_liability().to_string(),
        "finality":observation.finality(), "program_qualification":observation.program_qualification(),
        "proof_validity":observation.proof_validity(), "source_acceptance":"UNVERIFIED", "source_finality":"UNVERIFIED",
        "asset_backing":observation.asset_backing(), "actual_transfer":observation.actual_transfer(),
        "proof_certificate":false, "signing":false, "submission":false, "financial_execution":false,
        "response_sha256":observation.response_digests().iter().map(|digest| public_hex(digest)).collect::<Vec<_>>(),
    });
    if let Some(row) = observation.obligation() {
        export["obligation"] = serde_json::json!({
            "context_digest":public_hex(&row.context_digest()), "queried_stable_jtag":public_hex(&row.queried_stable_jtag()),
            "reported_d_wei":row.d().to_string(), "reported_a_zat":row.a().to_string(),
            "reported_payer":public_hex(&row.payer()), "reported_u_payee":public_hex(&row.u_payee()),
            "reported_s_refund":public_hex(&row.s_refund()), "reported_stable_jtag":public_hex(&row.stable_jtag()),
            "reported_armed":row.reported_armed(), "reported_consumed":row.reported_consumed(),
            "reported_tag_context":public_hex(&row.reported_tag_context()),
        });
    }
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "native public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}
