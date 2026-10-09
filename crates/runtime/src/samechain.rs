//! Owner-local preflight, public unsigned calls, pinned inspection and void-call simulation.
//! Native relation evidence and trusted-node answers never verify financial certificates.
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use std::{ffi::OsString, io::{Read, Write}, path::{Path, PathBuf}, process::ExitCode};
use zeroize::Zeroizing;
use ziquid_chains::samechain::{
    UnsignedCall, build_creation_call, build_fill_call, build_single_call, build_withdrawal_call,
};
use ziquid_chains::samechain::inspection::{
    AppendedNote, AuthorityObservation, ConsumedNullifier, InspectionError, InspectionPacket, InspectionScope,
    MAX_SIMULATION_GAS, SamechainInspectionClient, SimulationError, SimulationObservation,
};
use ziquid_proofs::samechain::{
    CancelExitWitness, MAX_PRIVATE_INPUT_BYTES, OwnerWitness,
    review_owner_cancel_exit, review_owner_fill, verify_cancel_exit_relation, verify_owner_relation,
};
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, review_note_withdrawal, verify_note_withdrawal_relation,
};
use ziquid_proofs::samechain::creation::{
    NoteCreationWitness, review_note_creation, verify_note_creation_relation,
};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, MAX_PACKET_BYTES, OutputDescriptor, OwnerJournal,
    PublicPacket, Role, SingleOwnerPacket,
};
use ziquid_protocol::samechain::withdrawal::NoteWithdrawalPacket;
use ziquid_protocol::samechain::fill::FillExecution;
use ziquid_protocol::samechain::creation::NoteCreationPacket;
#[cfg(feature = "sp1-execute")]
use ziquid_proofs::artifacts::{check_private_environment, owner::OwnerInput, execution::execute_owner};

mod history_cli;
pub mod backup;
pub mod release;
pub mod journal;
pub mod preparation;
#[cfg(all(feature = "sp1-local", target_os = "linux"))]
mod owner_worker;
#[cfg(feature = "sp1-local")]
pub mod verified_call;


#[derive(Parser)]
#[command(name = "ziquid samechain", version, about = "Owner-local checks, public calls and trusted-node observations; no signing or financial execution")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive a public ELF's exact program key; no witness, proof or source qualification.
    #[cfg(feature = "sp1-local")]
    OwnerProgram {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        elf_sha256: String,
    },
    /// Execute the actual owner guest locally; CPU evidence is not a proof certificate.
    #[cfg(feature = "sp1-execute")]
    ExecuteOwner {
        #[arg(long, value_enum)]
        operation: SimulationOperation,
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        elf_sha256: String,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long, required = true)]
        witness_stdin: bool,
        #[arg(long, required_if_eq("operation", "fill"))]
        packet: Option<PathBuf>,
    },
    /// Produce an isolated owner proof into committed encrypted custody; stdout contains no certificate.
    #[cfg(feature = "sp1-local")]
    ProveOwner {
        #[arg(long, value_enum)]
        operation: SimulationOperation,
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        elf_sha256: String,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        program_vkey: String,
        #[arg(long, required = true)]
        witness_stdin: bool,
        #[arg(long, required_if_eq("operation", "fill"))]
        packet: Option<PathBuf>,
        /// Existing owner-private 0700 root for SDK-generated private temporary files.
        #[arg(long)]
        private_temp_dir: PathBuf,
        /// Proof/transport deadline plus an equal cleanup allowance, each 1..=86400 seconds.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        timeout_seconds: u64,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        backup_key_file: PathBuf,
        #[arg(long, value_parser = public_fixed_hex::<32>)]
        op_id: [u8; 32],
    },
    /// Export an authenticated certificate only from a matching committed Released operation.
    #[cfg(feature = "sp1-local")]
    ExportCertificate {
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        backup_key_file: PathBuf,
        #[arg(long, value_parser = public_fixed_hex::<32>)]
        op_id: [u8; 32],
        /// Canonical ReleaseBinding bytes encoded in a public 0x-prefixed hex file.
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        database_config: PathBuf,
    },
    #[cfg(feature = "sp1-local")]
    #[command(hide = true)]
    OwnerProofWorker {
        #[arg(long, value_enum)]
        operation: SimulationOperation,
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        elf_sha256: String,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        program_vkey: String,
        #[arg(long, required_if_eq("operation", "fill"))]
        packet: Option<PathBuf>,
        /// Parent-validated pinned Groth16 artifact directory; never accepted from user CLI directly.
        #[arg(long, hide = true)]
        groth16_artifact_dir: PathBuf,
    },
    #[cfg(feature = "sp1-local")]
    #[command(hide = true)]
    OwnerProofReapProbe,
    /// Check one owner's exact fill relation from canonical private stdin bytes.
    CheckFill {
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Check one cancel/exit relation without consuming or cancelling backing.
    CheckCancelExit {
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Review independently pinned cancellation/exit terms before owner consent.
    ReviewCancelExit {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        order_id: String,
        #[arg(long, value_enum)]
        role: OwnerRole,
        #[arg(long, value_enum)]
        action: SingleAction,
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Check an ordinary note withdrawal without consuming backing or transferring assets.
    CheckNoteWithdrawal {
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Review an independently selected ordinary withdrawal before owner consent.
    ReviewNoteWithdrawal {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Check note creation semantics without receiving assets or admitting a root.
    CheckNoteCreation {
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Review independently selected deposit terms before owner consent.
    ReviewNoteCreation {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Review an independently selected public fill before creating consent.
    ReviewFill {
        #[arg(long)]
        packet: PathBuf,
        /// Independently approved canonical public FillExecution version-2 frame.
        #[arg(long)]
        execution: PathBuf,
        #[arg(long, value_enum)]
        role: OwnerRole,
        #[arg(long, required = true)]
        witness_stdin: bool,
    },
    /// Build unsigned note-creation calldata from public files, without stdin.
    BuildNoteCreationCall {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        token: String,
    },
    /// Build unsigned bilateral fill calldata; both public proof frames are required.
    BuildFillCall {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        proof_b: PathBuf,
        #[arg(long)]
        sender: String,
    },
    /// Build unsigned cancellation/exit calldata for one exact public owner role.
    BuildCancelExitCall {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        sender: String,
        #[arg(long, value_enum)]
        role: OwnerRole,
        #[arg(long, value_enum)]
        action: SingleAction,
    },
    /// Build unsigned ordinary-note withdrawal calldata from public files.
    BuildNoteWithdrawalCall {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        sender: String,
    },
    /// Build an unsigned call only after SHA Groth16 verification against the selected program and route journal.
    #[cfg(feature = "sp1-local")]
    BuildVerifiedCall {
        #[arg(long, value_enum)]
        operation: VerifiedOperation,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        proof_b: Option<PathBuf>,
        #[arg(long)]
        sender: Option<String>,
        #[arg(long, value_enum)]
        role: Option<OwnerRole>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Inspect public authority identity and state at one explicit block hash.
    InspectAuthority {
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        token: String,
        #[arg(long)]
        token_code: String,
        #[arg(long)]
        block_hash: String,
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        endpoint_env: String,
        #[arg(long)]
        allow_loopback_http: bool,
        #[arg(long, requires = "packet_kind")]
        packet: Option<PathBuf>,
        #[arg(long, value_enum, requires = "packet")]
        packet_kind: Option<InspectionPacketKind>,
    },
    /// Replay public append state from independently pinned adjacent block hashes.
    InspectHistory {
        #[arg(long)]
        config: PathBuf,
    },
    /// Simulate one exact public call at an explicit block, without signing or sending.
    SimulateCall {
        #[arg(long, value_enum)]
        operation: SimulationOperation,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        proof_b: Option<PathBuf>,
        #[arg(long)]
        sender: Option<String>,
        #[arg(long, value_enum)]
        role: Option<OwnerRole>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        token_code: String,
        #[arg(long)]
        block_hash: String,
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        endpoint_env: String,
        #[arg(long)]
        allow_loopback_http: bool,
        #[arg(long)]
        gas_limit: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SimulationOperation { Creation, Fill, Cancel, Exit, Withdrawal }

#[cfg(feature = "sp1-local")]
#[derive(Clone, Copy, ValueEnum)]
enum VerifiedOperation { Creation, Fill, Cancel, Exit, Withdrawal }

#[derive(Clone, Copy, ValueEnum)]
enum OwnerRole { A, B }

impl From<OwnerRole> for Role {
    fn from(role: OwnerRole) -> Self {
        match role { OwnerRole::A => Self::A, OwnerRole::B => Self::B }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum InspectionPacketKind { Creation, Fill, Single, Withdrawal }

#[derive(Clone, Copy, ValueEnum)]
enum SingleAction { Cancel, Exit }


#[derive(Serialize)]
struct PublicExport<'a> {
    kind: &'static str,
    role: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<u8>,
    packet: &'a [u8],
    #[serde(skip_serializing_if = "Option::is_none")]
    journal: Option<&'a [u8]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consent_message: Option<&'a [u8]>,
    packet_digest: [u8; 32],
    evidence: &'static str,
    proof_certificate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing: Option<bool>,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    financial_execution: bool,
    strict_matching_privacy: bool,
}

/// Embedded callers retain existing commands, but isolated proving is standalone-only.
pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    run_cli_inner(arguments, false)
}

/// Standalone native CLI entrypoint. The caller must exclusively reap its own
/// children and keep SIGCHLD policy stable for the complete call. A no-secret
/// live process probe also rejects inherited auto-reaping before private scratch.
pub fn run_standalone_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    run_cli_inner(arguments, true)
}

fn run_cli_inner(arguments: impl IntoIterator<Item = OsString>, _standalone: bool) -> ExitCode {
    let cli = match Cli::try_parse_from(std::iter::once(OsString::from("ziquid samechain")).chain(arguments)) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return if error.print().is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
            eprintln!("invalid samechain command arguments");
            return ExitCode::from(2);
        }
    };
    #[cfg(feature = "sp1-local")]
    if matches!(&cli.command, Command::ProveOwner { .. } | Command::ExportCertificate { .. }
        | Command::OwnerProofWorker { .. } | Command::OwnerProofReapProbe)
    {
        if !_standalone {
            eprintln!("samechain isolated owner proving requires the standalone native CLI");
            return ExitCode::FAILURE;
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("samechain isolated owner proving is unsupported on this operating system");
            return ExitCode::FAILURE;
        }
        #[cfg(target_os = "linux")]
        match &cli.command {
            Command::OwnerProofReapProbe => return ExitCode::SUCCESS,
            Command::OwnerProofWorker { .. } => return owner_worker::run_child(&cli.command),
            Command::ProveOwner { operation, packet, .. }
                if matches!(operation, SimulationOperation::Fill) != packet.is_some() =>
            {
                eprintln!("invalid samechain command arguments");
                return ExitCode::from(2);
            }
            _ => {},
        }
    }
    #[cfg(all(feature = "sp1-local", target_os = "linux"))]
    if matches!(&cli.command, Command::ProveOwner { .. } | Command::ExportCertificate { .. }) {
        return owner_worker::release_command(&cli.command);
    }
    #[cfg(feature = "sp1-execute")]
    if let Command::ExecuteOwner { operation, packet, .. } = &cli.command
        && matches!(operation, SimulationOperation::Fill) != packet.is_some()
    {
        eprintln!("invalid samechain command arguments");
        return ExitCode::from(2);
    }
    #[cfg(feature = "sp1-local")]
    if let Command::BuildVerifiedCall { operation, proof_b, sender, role, token, .. } = &cli.command {
        let shape_valid = match operation {
            VerifiedOperation::Creation => proof_b.is_none() && sender.is_none() && role.is_none() && token.is_some(),
            VerifiedOperation::Fill => proof_b.is_some() && sender.is_some() && role.is_none() && token.is_none(),
            VerifiedOperation::Cancel | VerifiedOperation::Exit => proof_b.is_none() && sender.is_some() && role.is_some() && token.is_none(),
            VerifiedOperation::Withdrawal => proof_b.is_none() && sender.is_some() && role.is_none() && token.is_none(),
        };
        if !shape_valid {
            eprintln!("invalid samechain command arguments");
            return ExitCode::from(2);
        }
    }
    // Public branches precede any private stdin read and never accept witness flags.
    #[cfg(feature = "sp1-local")]
    let public_command = matches!(&cli.command, Command::BuildNoteCreationCall { .. }
        | Command::BuildFillCall { .. } | Command::BuildCancelExitCall { .. }
        | Command::BuildNoteWithdrawalCall { .. } | Command::BuildVerifiedCall { .. }
        | Command::OwnerProgram { .. }
        | Command::InspectAuthority { .. } | Command::InspectHistory { .. } | Command::SimulateCall { .. });
    #[cfg(not(feature = "sp1-local"))]
    let public_command = matches!(&cli.command, Command::BuildNoteCreationCall { .. }
        | Command::BuildFillCall { .. } | Command::BuildCancelExitCall { .. }
        | Command::BuildNoteWithdrawalCall { .. }
        | Command::InspectAuthority { .. } | Command::InspectHistory { .. } | Command::SimulateCall { .. });
    let result = if public_command {
        match &cli.command {
            #[cfg(feature = "sp1-local")]
            Command::OwnerProgram { elf, elf_sha256 } => owner_program_command(elf, elf_sha256),
            Command::InspectAuthority { .. } => execute_inspection(&cli.command),
            Command::InspectHistory { config } => history_cli::execute(config),
            Command::SimulateCall { .. } => execute_simulation(&cli.command),
            _ => execute_public(&cli.command),
        }
    } else {
        // Preserve explicit private stdin opt-in; no argv/file witness fallback.
        let stdin_selected = match &cli.command {
            Command::CheckFill { witness_stdin }
            | Command::CheckCancelExit { witness_stdin }
            | Command::ReviewCancelExit { witness_stdin, .. }
            | Command::CheckNoteWithdrawal { witness_stdin }
            | Command::ReviewNoteWithdrawal { witness_stdin, .. }
            | Command::CheckNoteCreation { witness_stdin }
            | Command::ReviewNoteCreation { witness_stdin, .. }
            | Command::ReviewFill { witness_stdin, .. } => *witness_stdin,
            #[cfg(feature = "sp1-execute")]
            Command::ExecuteOwner { witness_stdin, .. } => *witness_stdin,
            _ => false,
        };
        if !stdin_selected {
            eprintln!("invalid samechain command arguments");
            return ExitCode::from(2);
        }
        read_private_input().and_then(|(bytes, length)| execute(cli.command, &bytes[..length]))
    };
    print_result(result.map_err(str::to_owned))
}

fn print_result(result: Result<Vec<u8>, String>) -> ExitCode {
    match result {
        Ok(output) => {
            let stdout = std::io::stdout();
            let mut locked = stdout.lock();
            if locked.write_all(&output).is_err() {
                eprintln!("samechain public output unavailable");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn read_private_input() -> Result<(Zeroizing<Vec<u8>>, usize), &'static str> {
    // Fill the entire bounded allocation before reading any private bytes.
    // The final byte is the excess probe; no reserve, push or private realloc.
    let mut bytes = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    let mut length = 0;
    loop {
        let count = locked.read(&mut bytes[length..])
            .map_err(|_| "samechain private witness input unavailable")?;
        if count == 0 {
            return Ok((bytes, length));
        }
        length += count;
        if length > MAX_PRIVATE_INPUT_BYTES {
            return Err("samechain private witness exceeds size limit");
        }
    }
}

fn execute(command: Command, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    match command {
        #[cfg(feature = "sp1-execute")]
        Command::ExecuteOwner { operation, elf, elf_sha256, deployment, packet, .. } =>
            execute_owner_command(operation, &elf, &elf_sha256, &deployment, packet.as_deref(), bytes),
        #[cfg(feature = "sp1-local")]
        Command::ProveOwner { .. } | Command::ExportCertificate { .. }
        | Command::OwnerProgram { .. } | Command::OwnerProofWorker { .. } | Command::OwnerProofReapProbe =>
            Err("invalid samechain command arguments"),
        Command::CheckFill { .. } => {
            let witness = OwnerWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let packet = &witness.packet;
            let journal = verify_owner_relation(packet, &witness)
                .map_err(|_| "samechain owner relation rejected")?;
            export("check_fill", &packet.encode().map_err(|_| "samechain public export rejected")?, &journal)
        }
        Command::CheckCancelExit { .. } => {
            let witness = CancelExitWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let journal = verify_cancel_exit_relation(&witness)
                .map_err(|_| "samechain owner relation rejected")?;
            export("check_cancel_exit", &witness.packet.encode().map_err(|_| "samechain public export rejected")?, &journal)
        }
        Command::ReviewCancelExit { packet: path, deployment, order_id, role, action, .. } => {
            let (packet_bytes, length) = read_public_packet_bytes(&path)?;
            let packet = SingleOwnerPacket::decode(&packet_bytes[..length])
                .map_err(|_| "invalid samechain public packet encoding")?;
            let (deployment_bytes, deployment_length) = read_public_packet_bytes(&deployment)?;
            let expected = Deployment::decode(&deployment_bytes[..deployment_length])
                .map_err(|_| "invalid samechain expected deployment encoding")?;
            let order = public_fixed_hex::<32>(&order_id)
                .map_err(|_| "invalid samechain public order id")?;
            let role = Role::from(role);
            let action = match action { SingleAction::Cancel => Action::Cancel, SingleAction::Exit => Action::Exit };
            let witness = CancelExitWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let message = review_owner_cancel_exit(&packet, &witness, &expected, order, role, action)
                .map_err(|_| "samechain owner relation rejected")?;
            let digest = packet.digest().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("review_cancel_exit", &packet_bytes[..length], digest, role, Some(action as u8));
            output.evidence = "native_owner_preconsent_review";
            output.consent_message = Some(&message);
            output.signing = Some(false);
            encode_export(&output)
        }
        Command::CheckNoteWithdrawal { .. } => {
            let witness = NoteWithdrawalWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let journal = verify_note_withdrawal_relation(&witness)
                .map_err(|_| "samechain owner relation rejected")?;
            let packet_bytes = witness.packet.encode().map_err(|_| "samechain public export rejected")?;
            let journal_bytes = journal.encode().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("check_note_withdrawal", &packet_bytes,
                journal.packet_digest, Role::A, Some(Action::Exit as u8));
            output.journal = Some(&journal_bytes);
            encode_export(&output)
        }
        Command::ReviewNoteWithdrawal { packet: path, .. } => {
            let (packet_bytes, length) = read_public_packet_bytes(&path)?;
            let packet = NoteWithdrawalPacket::decode(&packet_bytes[..length])
                .map_err(|_| "invalid samechain public packet encoding")?;
            let witness = NoteWithdrawalWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            // Deployment and commitment scope come only from the independently
            // selected PUBLIC packet, not the private witness or its consent.
            let message = review_note_withdrawal(&packet, &witness, &packet.deployment,
                packet.input.commitment).map_err(|_| "samechain owner relation rejected")?;
            let digest = packet.digest().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("review_note_withdrawal", &packet_bytes[..length],
                digest, Role::A, Some(Action::Exit as u8));
            output.evidence = "native_owner_preconsent_review";
            output.consent_message = Some(&message);
            encode_export(&output)
        }
        Command::CheckNoteCreation { .. } => {
            let witness = NoteCreationWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let journal = verify_note_creation_relation(&witness)
                .map_err(|_| "samechain owner relation rejected")?;
            let packet_bytes = witness.packet.encode().map_err(|_| "samechain public export rejected")?;
            let journal_bytes = journal.encode().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("check_note_creation", &packet_bytes,
                journal.packet_digest, witness.packet.role, None);
            output.journal = Some(&journal_bytes);
            encode_export(&output)
        }
        Command::ReviewNoteCreation { packet: path, .. } => {
            let (packet_bytes, length) = read_public_packet_bytes(&path)?;
            let packet = NoteCreationPacket::decode(&packet_bytes[..length])
                .map_err(|_| "invalid samechain public packet encoding")?;
            let witness = NoteCreationWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            // Deployment, payer and nonce are independently selected public
            // proposal terms, not scope inferred from the private witness.
            let message = review_note_creation(&packet, &witness, &packet.deployment,
                packet.payer, packet.creation_nonce).map_err(|_| "samechain owner relation rejected")?;
            let digest = packet.digest().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("review_note_creation", &packet_bytes[..length],
                digest, packet.role, None);
            output.evidence = "native_owner_preconsent_review";
            output.consent_message = Some(&message);
            encode_export(&output)
        }
        Command::ReviewFill { packet: path, execution, role, .. } => {
            let packet = read_public_packet(&path)?;
            let (execution_bytes, execution_length) = read_public_packet_bytes(&execution)?;
            let expected_execution = FillExecution::decode(&execution_bytes[..execution_length])
                .map_err(|_| "invalid samechain public execution encoding")?;
            let witness = OwnerWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?;
            let role = Role::from(role);
            // Scope and execution come from separately selected PUBLIC frames,
            // never inferred from the witness. No consent is generated or signed.
            let message = review_owner_fill(&packet, &witness, &packet.deployment,
                packet.inputs[role.index()].order_id, role, &expected_execution)
                .map_err(|_| "samechain owner relation rejected")?;
            let packet_bytes = packet.encode().map_err(|_| "samechain public export rejected")?;
            let digest = packet.digest().map_err(|_| "samechain public export rejected")?;
            let mut output = public_export("review_fill", &packet_bytes, digest, role, Some(Action::Fill as u8));
            output.evidence = "native_owner_preconsent_review";
            output.consent_message = Some(&message);
            encode_export(&output)
        }
        #[cfg(feature = "sp1-local")]
        Command::BuildVerifiedCall { .. } => Err("invalid samechain command arguments"),
        Command::BuildNoteCreationCall { .. } | Command::BuildFillCall { .. }
        | Command::BuildCancelExitCall { .. } | Command::BuildNoteWithdrawalCall { .. }
        | Command::InspectAuthority { .. } | Command::InspectHistory { .. } | Command::SimulateCall { .. } =>
            Err("invalid samechain command arguments"),
    }
}

// These typed witnesses own erasing secret fields. The guest adapter borrows
// them; snapshot custody neither clones nor exposes their contents.
#[allow(clippy::large_enum_variant)]
pub enum OwnedOwnerInput {
    Fill(OwnerWitness),
    CancelExit(CancelExitWitness),
    Withdrawal(NoteWithdrawalWitness),
    Creation(NoteCreationWitness),
}

impl std::fmt::Debug for OwnedOwnerInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Fill(_) => "OwnedOwnerInput::Fill([redacted])",
            Self::CancelExit(_) => "OwnedOwnerInput::CancelExit([redacted])",
            Self::Withdrawal(_) => "OwnedOwnerInput::Withdrawal([redacted])",
            Self::Creation(_) => "OwnedOwnerInput::Creation([redacted])",
        })
    }
}

#[cfg(feature = "sp1-execute")]
impl OwnedOwnerInput {
    fn decode(operation: SimulationOperation, packet: Option<&Path>, bytes: &[u8]) -> Result<Self, &'static str> {
        if matches!(operation, SimulationOperation::Fill) != packet.is_some() {
            return Err("invalid samechain command arguments");
        }
        match operation {
            SimulationOperation::Fill => {
                let selected = read_public_packet(packet.ok_or("invalid samechain command arguments")?)?;
                let witness = OwnerWitness::decode(bytes)
                    .map_err(|_| "invalid samechain private witness encoding")?;
                if selected != witness.packet {
                    return Err("samechain owner packet mismatch");
                }
                // Drop the separate public selection before any ELF or worker
                // work; the accepted witness owns exactly one frozen packet.
                Ok(Self::Fill(witness))
            }
            SimulationOperation::Cancel | SimulationOperation::Exit => {
                let witness = CancelExitWitness::decode(bytes)
                    .map_err(|_| "invalid samechain private witness encoding")?;
                let action = if matches!(operation, SimulationOperation::Cancel) { Action::Cancel } else { Action::Exit };
                if witness.action != action { return Err("samechain owner operation mismatch"); }
                Ok(Self::CancelExit(witness))
            }
            SimulationOperation::Withdrawal => Ok(Self::Withdrawal(NoteWithdrawalWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?)),
            SimulationOperation::Creation => Ok(Self::Creation(NoteCreationWitness::decode(bytes)
                .map_err(|_| "invalid samechain private witness encoding")?)),
        }
    }

    fn as_input(&self) -> OwnerInput<'_> {
        match self {
            Self::Fill(witness) => OwnerInput::Fill(witness),
            Self::CancelExit(witness) => OwnerInput::CancelExit(witness),
            Self::Withdrawal(witness) => OwnerInput::Withdrawal(witness),
            Self::Creation(witness) => OwnerInput::Creation(witness),
        }
    }
}

#[cfg(feature = "sp1-execute")]
fn read_owner_elf(path: &Path) -> Result<Vec<u8>, &'static str> {
    // Operational resource bound, not a claim about the SP1 ELF format limit.
    const MAX_OWNER_ELF_BYTES: usize = 16 * 1024 * 1024;
    let mut file = std::fs::File::open(path).map_err(|_| "samechain public owner ELF unavailable")?;
    let mut bytes = vec![0; MAX_OWNER_ELF_BYTES + 1];
    let mut length = 0;
    loop {
        let count = file.read(&mut bytes[length..]).map_err(|_| "samechain public owner ELF unavailable")?;
        if count == 0 { break; }
        length += count;
        if length > MAX_OWNER_ELF_BYTES { return Err("samechain public owner ELF exceeds size limit"); }
    }
    bytes.truncate(length);
    Ok(bytes)
}

#[cfg(feature = "sp1-local")]
#[derive(Serialize)]
struct OwnerProgramExport {
    kind: &'static str,
    elf_sha256: String,
    program_vkey: String,
    evidence: &'static str,
    source_qualification: &'static str,
    setup_qualification: &'static str,
    proof_certificate: bool,
    program_identity: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    finality: &'static str,
    deployment_profile_qualification: &'static str,
    financial_execution: bool,
    strict_matching_privacy: bool,
}

#[cfg(feature = "sp1-local")]
fn owner_program_command(elf_path: &Path, elf_sha256: &str) -> Result<Vec<u8>, &'static str> {
    use sha2::{Digest, Sha256};
    let expected_hash: [u8; 32] = public_fixed_hex(elf_sha256)
        .map_err(|_| "invalid samechain owner ELF hash pin")?;
    let elf = read_owner_elf(elf_path)?;
    if <[u8; 32]>::from(Sha256::digest(&elf)) != expected_hash {
        return Err("samechain owner ELF hash mismatch");
    }
    check_private_environment().map_err(|_| "samechain private guest environment rejected")?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()
        .map_err(|_| "samechain public owner program setup unavailable")?;
    let program = runtime.block_on(ziquid_proofs::artifacts::local::owner_program(
        sp1_primitives::Elf::from(elf), &expected_hash,
    )).map_err(|_| "samechain public owner program setup rejected")?;
    let export = OwnerProgramExport {
        kind: "samechain_owner_program", elf_sha256: public_hex(&expected_hash),
        program_vkey: public_hex(&program), evidence: "actual_local_light_program_setup",
        source_qualification: "UNVERIFIED", setup_qualification: "UNVERIFIED",
        proof_certificate: false, program_identity: "UNVERIFIED", root_eligibility: "UNVERIFIED",
        global_unspentness: "UNVERIFIED", asset_backing: "UNVERIFIED", finality: "UNVERIFIED",
        deployment_profile_qualification: "UNVERIFIED", financial_execution: false,
        strict_matching_privacy: false,
    };
    let mut output = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    output.push(b'\n');
    Ok(output)
}

#[cfg(feature = "sp1-execute")]
#[derive(Serialize)]
struct OwnerExecutionExport {
    kind: &'static str,
    operation: &'static str,
    expected_deployment: InspectionDeployment,
    elf_sha256: String,
    journal: String,
    instructions: u64,
    exit_code: u32,
    evidence: &'static str,
    proof_certificate: bool,
    program_identity: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    finality: &'static str,
    deployment_profile_qualification: &'static str,
    financial_execution: bool,
    strict_matching_privacy: bool,
}

#[cfg(feature = "sp1-execute")]
fn execute_owner_command(operation: SimulationOperation, elf_path: &Path, elf_sha256: &str,
    deployment_path: &Path, packet: Option<&Path>, bytes: &[u8]) -> Result<Vec<u8>, &'static str>
{
    use sha2::{Digest, Sha256};
    check_private_environment().map_err(|_| "samechain private guest environment rejected")?;
    let expected_hash: [u8; 32] = public_fixed_hex(elf_sha256)
        .map_err(|_| "invalid samechain owner ELF hash pin")?;
    let (deployment_bytes, length) = read_public_packet_bytes(deployment_path)?;
    let expected = Deployment::decode(&deployment_bytes[..length])
        .map_err(|_| "invalid samechain expected deployment encoding")?;
    let owned = OwnedOwnerInput::decode(operation, packet, bytes)?;
    let input = owned.as_input();
    if input.deployment() != &expected { return Err("samechain owner deployment mismatch"); }
    let elf = read_owner_elf(elf_path)?;
    let actual_hash: [u8; 32] = Sha256::digest(&elf).into();
    if actual_hash != expected_hash { return Err("samechain owner ELF hash mismatch"); }
    // Native signed relation, actual guest halt and byte-exact expected journal
    // are checked by the existing adapter. Never format its private diagnostics.
    let execution = execute_owner(sp1_primitives::Elf::from(elf), &input).map_err(|error| {
        if error.downcast_ref::<ziquid_proofs::samechain::RelationError>().is_some() {
            "samechain owner relation rejected"
        } else {
            "samechain owner guest execution rejected"
        }
    })?;
    let export = OwnerExecutionExport {
        kind: "samechain_owner_execution",
        operation: match operation {
            SimulationOperation::Fill => "fill", SimulationOperation::Cancel => "cancel",
            SimulationOperation::Exit => "exit", SimulationOperation::Withdrawal => "withdrawal",
            SimulationOperation::Creation => "creation",
        },
        expected_deployment: InspectionDeployment {
            chain_id: expected.chain_id.to_string(), authority: public_hex(&expected.authority),
            authority_code: public_hex(&expected.authority_code), verifier: public_hex(&expected.verifier),
            verifier_code: public_hex(&expected.verifier_code), owner_program: public_hex(&expected.owner_program),
            schema: expected.schema,
        },
        elf_sha256: public_hex(&actual_hash), journal: public_hex(&execution.journal),
        instructions: execution.instructions, exit_code: execution.exit_code,
        evidence: "actual_cpu_owner_guest_execution", proof_certificate: false,
        program_identity: "UNVERIFIED", root_eligibility: "UNVERIFIED", global_unspentness: "UNVERIFIED",
        asset_backing: "UNVERIFIED", finality: "UNVERIFIED", deployment_profile_qualification: "UNVERIFIED",
        financial_execution: false, strict_matching_privacy: false,
    };
    let mut output = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    output.push(b'\n');
    Ok(output)
}

fn read_public_packet(path: &Path) -> Result<PublicPacket, &'static str> {
    let (bytes, length) = read_public_packet_bytes(path)?;
    PublicPacket::decode(&bytes[..length]).map_err(|_| "invalid samechain public packet encoding")
}

fn read_public_packet_bytes(path: &Path) -> Result<(Vec<u8>, usize), &'static str> {
    let mut bytes = vec![0; MAX_PACKET_BYTES + 1];
    let mut file = std::fs::File::open(path).map_err(|_| "samechain public packet unavailable")?;
    let mut length = 0;
    loop {
        let count = file.read(&mut bytes[length..]).map_err(|_| "samechain public packet unavailable")?;
        if count == 0 {
            return Ok((bytes, length));
        }
        length += count;
        if length > MAX_PACKET_BYTES {
            return Err("samechain public packet exceeds size limit");
        }
    }
}

fn export(kind: &'static str, packet: &[u8], journal: &OwnerJournal) -> Result<Vec<u8>, &'static str> {
    let journal_bytes = journal.encode().map_err(|_| "samechain public export rejected")?;
    let mut output = public_export(kind, packet, journal.packet_digest, journal.role, Some(journal.action as u8));
    output.journal = Some(&journal_bytes);
    encode_export(&output)
}

fn public_export<'a>(kind: &'static str, packet: &'a [u8], packet_digest: [u8; 32], role: Role, action: Option<u8>)
    -> PublicExport<'a>
{
    PublicExport {
        kind,
        role: role as u8,
        action,
        packet,
        journal: None,
        consent_message: None,
        packet_digest,
        evidence: "native_owner_relation",
        proof_certificate: false,
        signing: None,
        root_eligibility: "UNVERIFIED",
        global_unspentness: "UNVERIFIED",
        asset_backing: "UNVERIFIED",
        financial_execution: false,
        strict_matching_privacy: false,
    }
}

fn encode_export(export: &PublicExport<'_>) -> Result<Vec<u8>, &'static str> {
    // Only public fields are serialized; complete encoding before stdout.
    let mut output = serde_json::to_vec(export).map_err(|_| "samechain public export rejected")?;
    output.push(b'\n');
    Ok(output)
}

#[cfg(feature = "sp1-local")]
fn execute_verified_public(command: &Command) -> Result<Vec<u8>, &'static str> {
    let Command::BuildVerifiedCall { operation, packet, deployment, proof, proof_b, sender, role, token } = command else {
        return Err("invalid samechain command arguments");
    };
    let (deployment_bytes, deployment_length) = read_public_packet_bytes(deployment)?;
    let expected = Deployment::decode(&deployment_bytes[..deployment_length])
        .map_err(|_| "invalid samechain expected deployment encoding")?;
    expected.validate().map_err(|_| "invalid samechain expected deployment encoding")?;
    let (packet_bytes, packet_length) = read_public_packet_bytes(packet)?;
    let packet_bytes = &packet_bytes[..packet_length];
    let proof = read_public_proof(proof)?;
    match operation {
        VerifiedOperation::Creation => {
            if proof_b.is_some() || sender.is_some() || role.is_some() || token.is_none() { return Err("invalid samechain command arguments"); }
            let packet = NoteCreationPacket::decode(packet_bytes).map_err(|_| "invalid samechain public packet encoding")?;
            let token = public_address(token.as_deref().ok_or("invalid samechain command arguments")?)?;
            build_verified_export(&expected, verified_call::VerifiedCallRequest::Creation { packet: &packet, proof: &proof, token: &token }, "creation")
        }
        VerifiedOperation::Fill => {
            if proof_b.is_none() || sender.is_none() || role.is_some() || token.is_some() { return Err("invalid samechain command arguments"); }
            let packet = PublicPacket::decode(packet_bytes).map_err(|_| "invalid samechain public packet encoding")?;
            let proof_b = read_public_proof(proof_b.as_ref().ok_or("invalid samechain command arguments")?)?;
            let sender = public_address(sender.as_deref().ok_or("invalid samechain command arguments")?)?;
            build_verified_export(&expected, verified_call::VerifiedCallRequest::Fill { packet: &packet, proof: &proof, proof_b: &proof_b, sender: &sender }, "fill")
        }
        VerifiedOperation::Cancel | VerifiedOperation::Exit => {
            if proof_b.is_some() || sender.is_none() || role.is_none() || token.is_some() { return Err("invalid samechain command arguments"); }
            let packet = SingleOwnerPacket::decode(packet_bytes).map_err(|_| "invalid samechain public packet encoding")?;
            let sender = public_address(sender.as_deref().ok_or("invalid samechain command arguments")?)?;
            let role = Role::from(role.ok_or("invalid samechain command arguments")?);
            let action = if matches!(operation, VerifiedOperation::Cancel) { Action::Cancel } else { Action::Exit };
            build_verified_export(&expected, verified_call::VerifiedCallRequest::CancelExit { packet: &packet, proof: &proof, sender: &sender, role: &role, action: &action }, if matches!(operation, VerifiedOperation::Cancel) { "cancel" } else { "exit" })
        }
        VerifiedOperation::Withdrawal => {
            if proof_b.is_some() || sender.is_none() || role.is_some() || token.is_some() { return Err("invalid samechain command arguments"); }
            let packet = NoteWithdrawalPacket::decode(packet_bytes).map_err(|_| "invalid samechain public packet encoding")?;
            let sender = public_address(sender.as_deref().ok_or("invalid samechain command arguments")?)?;
            build_verified_export(&expected, verified_call::VerifiedCallRequest::Withdrawal { packet: &packet, proof: &proof, sender: &sender }, "withdrawal")
        }
    }
}

#[cfg(feature = "sp1-local")]
fn build_verified_export(
    expected: &Deployment,
    request: verified_call::VerifiedCallRequest<'_>,
    operation: &'static str,
) -> Result<Vec<u8>, &'static str> {
    let call = verified_call::build_verified_call(expected, request)
        .map_err(verified_call_error)?;
    encode_verified_call(operation, &call)
}

#[cfg(feature = "sp1-local")]
fn verified_call_error(error: verified_call::VerifiedCallError) -> &'static str {
    match error {
        verified_call::VerifiedCallError::InvalidDeployment => "invalid samechain expected deployment encoding",
        verified_call::VerifiedCallError::DeploymentMismatch => "samechain packet deployment mismatch",
        verified_call::VerifiedCallError::InvalidPacket => "invalid samechain public packet encoding",
        verified_call::VerifiedCallError::InvalidSender => "invalid samechain public sender",
        verified_call::VerifiedCallError::WrongToken => "samechain token mismatch",
        verified_call::VerifiedCallError::InvalidRoleAction => "invalid samechain role or action",
        verified_call::VerifiedCallError::CertificateRejected => "samechain owner certificate verification rejected",
        verified_call::VerifiedCallError::CallRejected => "samechain verified unsigned call rejected",
    }
}

#[cfg(feature = "sp1-local")]
fn encode_verified_call(operation: &'static str, call: &UnsignedCall) -> Result<Vec<u8>, &'static str> {
    let effects = call.outputs().iter().enumerate().filter_map(|(manifest_index, output)| {
        let (kind, role, asset, recipient, amount) = match output {
            OutputDescriptor::Exit { role, asset, recipient, amount } => ("Exit", *role, *asset, recipient, amount),
            OutputDescriptor::Fee { payer, asset, recipient, amount } => ("Fee", *payer, *asset, recipient, amount),
            OutputDescriptor::Note { .. } => return None,
        };
        Some(CallEffect { manifest_index, kind, role: role as u8,
            asset: match asset { Asset::Native => "native".to_owned(), Asset::Token(address) => public_hex(&address) },
            recipient: public_hex(recipient), amount_atoms: amount.to_string() })
    }).collect();
    let export = CallExport {
        kind: "unsigned_samechain_call", operation, source: "verified_owner_certificate",
        from: public_hex(&call.from()), to: public_hex(&call.to()), value_atoms: call.value().to_string(),
        data: public_hex(call.data()), packet_digest: call.packet_digest(), expected_journals: call.expected_journals(), effects,
        proof_validity: "SHA_VERIFIED_AGAINST_SELECTED_PROGRAM_AND_JOURNAL",
        deployment_validity: "UNVERIFIED", root_eligibility: "UNVERIFIED", global_unspentness: "UNVERIFIED",
        asset_backing: "UNVERIFIED", signing: false, submission: false, financial_execution: false,
    };
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn execute_public(command: &Command) -> Result<Vec<u8>, &'static str> {
    #[cfg(feature = "sp1-local")]
    if matches!(command, Command::BuildVerifiedCall { .. }) {
        return execute_verified_public(command);
    }
    let (deployment_path, operation) = match command {
        Command::BuildNoteCreationCall { deployment, .. } =>
            (deployment, "build_note_creation_call"),
        Command::BuildFillCall { deployment, .. } =>
            (deployment, "build_fill_call"),
        Command::BuildCancelExitCall { deployment, .. } =>
            (deployment, "build_cancel_exit_call"),
        Command::BuildNoteWithdrawalCall { deployment, .. } =>
            (deployment, "build_note_withdrawal_call"),
        _ => return Err("invalid samechain command arguments"),
    };
    let (expected_bytes, length) = read_public_packet_bytes(deployment_path)?;
    let expected = Deployment::decode(&expected_bytes[..length])
        .map_err(|_| "invalid samechain expected deployment encoding")?;
    let call = build_public_call(command, &expected)?;
    encode_call(operation, &call)
}

fn build_public_call(command: &Command, expected: &Deployment) -> Result<UnsignedCall, &'static str> {
    let (operation, packet_path, proof_path, proof_b, sender, role) = match command {
        Command::BuildNoteCreationCall { packet, proof, .. } =>
            (SimulationOperation::Creation, packet, proof, None, None, None),
        Command::BuildFillCall { packet, proof, proof_b, sender, .. } =>
            (SimulationOperation::Fill, packet, proof, Some(proof_b), Some(sender.as_str()), None),
        Command::BuildCancelExitCall { packet, proof, sender, role, action, .. } =>
            (match action { SingleAction::Cancel => SimulationOperation::Cancel,
                SingleAction::Exit => SimulationOperation::Exit }, packet, proof, None,
                Some(sender.as_str()), Some(*role)),
        Command::BuildNoteWithdrawalCall { packet, proof, sender, .. } =>
            (SimulationOperation::Withdrawal, packet, proof, None, Some(sender.as_str()), None),
        Command::SimulateCall { operation, packet, proof, proof_b, sender, role, .. } =>
            (*operation, packet, proof, proof_b.as_ref(), sender.as_deref(), *role),
        _ => return Err("invalid samechain command arguments"),
    };
    let creation = matches!(operation, SimulationOperation::Creation);
    let fill = matches!(operation, SimulationOperation::Fill);
    let single = matches!(operation, SimulationOperation::Cancel | SimulationOperation::Exit);
    if sender.is_some() == creation || proof_b.is_some() != fill || role.is_some() != single {
        return Err("invalid samechain command arguments");
    }
    let (packet_bytes, length) = read_public_packet_bytes(packet_path)?;
    let packet_bytes = &packet_bytes[..length];
    let proof = read_public_proof(proof_path)?;
    let sender = sender.map(public_address).transpose()?;
    match operation {
        SimulationOperation::Creation => {
            let token = match command {
                Command::BuildNoteCreationCall { token, .. } | Command::SimulateCall { token, .. } => token,
                _ => return Err("invalid samechain command arguments"),
            };
            let packet = NoteCreationPacket::decode(packet_bytes)
                .map_err(|_| "invalid samechain public packet encoding")?;
            build_creation_call(expected, public_address(token)?, &packet, &proof)
        }
        SimulationOperation::Fill => {
            let packet = PublicPacket::decode(packet_bytes)
                .map_err(|_| "invalid samechain public packet encoding")?;
            let proof_b = read_public_proof(proof_b.ok_or("invalid samechain command arguments")?)?;
            build_fill_call(expected, &packet, sender.ok_or("invalid samechain command arguments")?, &proof, &proof_b)
        }
        SimulationOperation::Cancel | SimulationOperation::Exit => {
            let packet = SingleOwnerPacket::decode(packet_bytes)
                .map_err(|_| "invalid samechain public packet encoding")?;
            let action = if matches!(operation, SimulationOperation::Cancel) { Action::Cancel } else { Action::Exit };
            build_single_call(expected, &packet, sender.ok_or("invalid samechain command arguments")?,
                role.ok_or("invalid samechain command arguments")?.into(), action, &proof)
        }
        SimulationOperation::Withdrawal => {
            let packet = NoteWithdrawalPacket::decode(packet_bytes)
                .map_err(|_| "invalid samechain public packet encoding")?;
            build_withdrawal_call(expected, &packet, sender.ok_or("invalid samechain command arguments")?, &proof)
        }
    }.map_err(|_| "samechain unsigned call rejected")
}


fn read_public_proof(path: &Path) -> Result<Vec<u8>, &'static str> {
    // One excess byte detects oversized/trailing frames without unbounded reads.
    const WRAPPED_PROOF_BYTES: usize = 356;
    let mut bytes = vec![0; WRAPPED_PROOF_BYTES + 1];
    let mut file = std::fs::File::open(path).map_err(|_| "samechain public proof unavailable")?;
    let mut length = 0;
    loop {
        let count = file.read(&mut bytes[length..]).map_err(|_| "samechain public proof unavailable")?;
        if count == 0 { break; }
        length += count;
        if length > WRAPPED_PROOF_BYTES { return Err("invalid samechain public proof frame"); }
    }
    if length != WRAPPED_PROOF_BYTES { return Err("invalid samechain public proof frame"); }
    bytes.truncate(length);
    Ok(bytes)
}

fn public_address(value: &str) -> Result<[u8; 20], &'static str> {
    public_fixed_hex(value).map_err(|_| "invalid samechain public address")
}

fn public_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let bytes = value.strip_prefix("0x").filter(|hex| hex.len() == N * 2)
        .ok_or("invalid samechain public fixed-width hex")?.as_bytes();
    let mut decoded = [0; N];
    for (out, pair) in decoded.iter_mut().zip(bytes.as_chunks::<2>().0.iter()) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        *out = digit(pair[0]).and_then(|high| digit(pair[1]).map(|low| high * 16 + low))
            .ok_or("invalid samechain public fixed-width hex")?;
    }
    if decoded == [0; N] { return Err("invalid samechain public fixed-width hex"); }
    Ok(decoded)
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
struct CallEffect {
    manifest_index: usize,
    kind: &'static str,
    role: u8,
    asset: String,
    recipient: String,
    amount_atoms: String,
}

#[derive(Serialize)]
struct CallExport<'a> {
    kind: &'static str,
    operation: &'static str,
    source: &'static str,
    from: String,
    to: String,
    value_atoms: String,
    data: String,
    packet_digest: [u8; 32],
    expected_journals: &'a [Vec<u8>],
    effects: Vec<CallEffect>,
    proof_validity: &'static str,
    deployment_validity: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    signing: bool,
    submission: bool,
    financial_execution: bool,
}

fn encode_call(operation: &'static str, call: &UnsignedCall) -> Result<Vec<u8>, &'static str> {
    let effects = call.outputs().iter().enumerate().filter_map(|(manifest_index, output)| {
        let (kind, role, asset, recipient, amount) = match output {
            OutputDescriptor::Exit { role, asset, recipient, amount } =>
                ("Exit", *role, *asset, recipient, amount),
            OutputDescriptor::Fee { payer, asset, recipient, amount } =>
                ("Fee", *payer, *asset, recipient, amount),
            // Complete encrypted notes remain in ABI data, never private openings.
            OutputDescriptor::Note { .. } => return None,
        };
        Some(CallEffect { manifest_index, kind, role: role as u8,
            asset: match asset { Asset::Native => "native".to_owned(), Asset::Token(address) => public_hex(&address) },
            recipient: public_hex(recipient), amount_atoms: amount.to_string() })
    }).collect();
    let export = CallExport {
        kind: "unsigned_samechain_call", operation, source: "caller_public_files",
        from: public_hex(&call.from()), to: public_hex(&call.to()), value_atoms: call.value().to_string(),
        data: public_hex(call.data()), packet_digest: call.packet_digest(),
        expected_journals: call.expected_journals(), effects,
        proof_validity: "UNVERIFIED", deployment_validity: "UNVERIFIED", root_eligibility: "UNVERIFIED",
        global_unspentness: "UNVERIFIED", asset_backing: "UNVERIFIED",
        signing: false, submission: false, financial_execution: false,
    };
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn inspection_scope(deployment: &Path, token: &str, token_code: &str,
    block_hash: &str, policy_id: &str) -> Result<InspectionScope, &'static str>
{
    let (bytes, length) = read_public_packet_bytes(deployment)?;
    let scope = InspectionScope {
        expected: Deployment::decode(&bytes[..length])
            .map_err(|_| "invalid samechain expected deployment encoding")?,
        token: public_address(token)?, token_code: public_fixed_hex(token_code)?,
        block_hash: public_fixed_hex(block_hash)?, policy_id: public_fixed_hex(policy_id)?,
    };
    scope.validate().map_err(inspection_error)?;
    Ok(scope)
}

fn inspection_endpoint(endpoint_env: &str) -> Result<Zeroizing<String>, &'static str> {
    // Validate the environment VARIABLE, never print its name or private value.
    let mut name = endpoint_env.bytes();
    if !name.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !name.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err("samechain inspection endpoint environment unavailable");
    }
    std::env::var(endpoint_env).map(Zeroizing::new)
        .map_err(|_| "samechain inspection endpoint environment unavailable")
}

fn execute_simulation(command: &Command) -> Result<Vec<u8>, &'static str> {
    let Command::SimulateCall { deployment, token, token_code, block_hash, policy_id,
        endpoint_env, allow_loopback_http, gas_limit, .. } = command else {
        return Err("invalid samechain command arguments");
    };
    if *gas_limit == 0 || *gas_limit > MAX_SIMULATION_GAS {
        return Err("invalid samechain simulation gas limit");
    }
    let scope = inspection_scope(deployment, token, token_code, block_hash, policy_id)?;
    let call = build_public_call(command, &scope.expected)?;
    let endpoint = inspection_endpoint(endpoint_env)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "samechain simulation runtime unavailable")?;
    let observation = runtime.block_on(async {
        let client = SamechainInspectionClient::new(&endpoint, *allow_loopback_http)
            .map_err(inspection_error)?;
        client.simulate(&scope, &call, *gas_limit).await.map_err(simulation_error)
    })?;
    encode_simulation(&observation)
}

fn simulation_error(error: SimulationError) -> &'static str {
    match error {
        SimulationError::InvalidCall => "invalid samechain simulation call",
        SimulationError::InvalidGas => "invalid samechain simulation gas limit",
        SimulationError::Inspection(error) => inspection_error(error),
        SimulationError::RpcRejected(_) => "samechain simulation RPC rejected",
        SimulationError::MalformedResponse => "invalid samechain simulation response",
    }
}

#[derive(Serialize)]
struct SimulationExport {
    kind: &'static str,
    source_scope: &'static str,
    outcome: &'static str,
    block_hash: String,
    block_number: String,
    parent_hash: String,
    appended_notes: Vec<InspectionAppendedNote>,
    consumed_nullifiers: Vec<InspectionConsumedNullifier>,
    policy_id: String,
    from: String,
    to: String,
    value_atoms: String,
    gas_limit: u64,
    packet_digest: String,
    calldata_sha256: String,
    response_sha256: String,
    inspection_response_sha256: Vec<String>,
    finality: &'static str,
    proof_validity: &'static str,
    deployment_profile_qualification: &'static str,
    asset_backing: &'static str,
    signing: bool,
    submission: bool,
    financial_execution: bool,
}

fn encode_simulation(observation: &SimulationObservation) -> Result<Vec<u8>, &'static str> {
    let authority = observation.authority();
    let export = SimulationExport {
        kind: "samechain_simulation_observation", source_scope: observation.source_scope(),
        outcome: observation.outcome(), block_hash: public_hex(&authority.block_hash()),
        block_number: authority.block_number().to_string(), policy_id: public_hex(&authority.policy_id()),
        parent_hash: public_hex(&authority.parent_hash()),
        appended_notes: authority.appended_notes().iter().map(encode_appended_note).collect(),
        consumed_nullifiers: authority.consumed_nullifiers().iter().map(encode_consumed_nullifier).collect(),
        from: public_hex(&observation.from()), to: public_hex(&observation.to()),
        value_atoms: observation.value().to_string(), gas_limit: observation.gas_limit(),
        packet_digest: public_hex(&observation.packet_digest()),
        calldata_sha256: public_hex(&observation.calldata_sha256()),
        response_sha256: public_hex(&observation.response_sha256()),
        inspection_response_sha256: authority.response_digests().iter().map(|digest| public_hex(digest)).collect(),
        finality: "UNVERIFIED", proof_validity: "UNVERIFIED", deployment_profile_qualification: "UNVERIFIED",
        asset_backing: "UNVERIFIED", signing: false, submission: false, financial_execution: false,
    };
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn execute_inspection(command: &Command) -> Result<Vec<u8>, &'static str> {
    let Command::InspectAuthority { deployment, token, token_code, block_hash, policy_id,
        endpoint_env, allow_loopback_http, packet, packet_kind } = command else {
        return Err("invalid samechain command arguments");
    };
    let scope = inspection_scope(deployment, token, token_code, block_hash, policy_id)?;
    let endpoint = inspection_endpoint(endpoint_env)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "samechain inspection runtime unavailable")?;
    let public_packet = packet.as_ref().map(|path| read_public_packet_bytes(path)).transpose()?;
    let packet_bytes = public_packet.as_ref().map(|(bytes, length)| &bytes[..*length]);
    let observation = runtime.block_on(async {
        // Construct inside the current-thread runtime; no service, retries or fallback.
        let client = SamechainInspectionClient::new(&endpoint, *allow_loopback_http)
            .map_err(inspection_error)?;
        match (packet_kind, packet_bytes) {
            (None, None) => client.inspect(&scope, None).await.map_err(inspection_error),
            (Some(InspectionPacketKind::Creation), Some(bytes)) => {
                let packet = NoteCreationPacket::decode(bytes)
                    .map_err(|_| "invalid samechain public packet encoding")?;
                client.inspect(&scope, Some(InspectionPacket::Creation(&packet))).await.map_err(inspection_error)
            }
            (Some(InspectionPacketKind::Fill), Some(bytes)) => {
                let packet = PublicPacket::decode(bytes)
                    .map_err(|_| "invalid samechain public packet encoding")?;
                client.inspect(&scope, Some(InspectionPacket::Fill(&packet))).await.map_err(inspection_error)
            }
            (Some(InspectionPacketKind::Single), Some(bytes)) => {
                let packet = SingleOwnerPacket::decode(bytes)
                    .map_err(|_| "invalid samechain public packet encoding")?;
                client.inspect(&scope, Some(InspectionPacket::Single(&packet))).await.map_err(inspection_error)
            }
            (Some(InspectionPacketKind::Withdrawal), Some(bytes)) => {
                let packet = NoteWithdrawalPacket::decode(bytes)
                    .map_err(|_| "invalid samechain public packet encoding")?;
                client.inspect(&scope, Some(InspectionPacket::Withdrawal(&packet))).await.map_err(inspection_error)
            }
            _ => Err("invalid samechain command arguments"),
        }
    })?;
    encode_inspection(&observation)
}

fn inspection_error(error: InspectionError) -> &'static str {
    // Provider messages, URLs and transport diagnostics never cross this boundary.
    match error {
        InspectionError::InvalidEndpoint => "invalid samechain inspection endpoint",
        InspectionError::InvalidScope => "invalid samechain inspection scope",
        InspectionError::InvalidPacket => "invalid samechain inspection packet",
        InspectionError::Transport => "samechain inspection transport unavailable",
        InspectionError::HttpStatus(_) => "samechain inspection HTTP rejected",
        InspectionError::ResponseTooLarge => "samechain inspection response exceeds size limit",
        InspectionError::RpcRejected(_) => "samechain inspection RPC rejected",
        InspectionError::MalformedResponse => "invalid samechain inspection response",
        InspectionError::WrongChain => "samechain inspection chain mismatch",
        InspectionError::WrongBlock => "samechain inspection block mismatch",
        InspectionError::WrongIdentity => "samechain inspection identity mismatch",
        InspectionError::WrongState => "samechain inspection state rejected",
    }
}

#[derive(Serialize)]
struct InspectionDeployment {
    chain_id: String,
    authority: String,
    authority_code: String,
    verifier: String,
    verifier_code: String,
    owner_program: String,
    schema: u16,
}

#[derive(Serialize)]
struct InspectionTree { tree_id: u32, count: u64, root: String }

#[derive(Serialize)]
struct InspectionInput {
    tree_id: u32,
    index: u32,
    root: String,
    nullifier: String,
    reported_root_count: u64,
    reported_spent: bool,
}

#[derive(Serialize)]
struct InspectionOutput { manifest_index: u32, commitment: String, reported_seen: bool }

#[derive(Serialize)]
struct InspectionAppendedNote {
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
    packet_digest: String,
    manifest_index: u32,
    role: u8,
    tree_id: u32,
    index: u32,
    count: u64,
    root: String,
    commitment: String,
    recovery_key_commitment: String,
    ciphertext_version: u16,
    ciphertext: String,
}

#[derive(Serialize)]
struct InspectionConsumedNullifier {
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
    packet_digest: String,
    nullifier: String,
}

fn encode_consumed_nullifier(event: &ConsumedNullifier) -> InspectionConsumedNullifier {
    InspectionConsumedNullifier {
        transaction_hash: public_hex(&event.occurrence.transaction_hash),
        transaction_index: event.occurrence.transaction_index, log_index: event.occurrence.log_index,
        packet_digest: public_hex(&event.packet_digest), nullifier: public_hex(&event.nullifier),
    }
}

#[derive(Serialize)]
struct InspectionCreation { nonce_used: bool, initial_order_used: Option<bool> }

fn encode_appended_note(note: &AppendedNote) -> InspectionAppendedNote {
    InspectionAppendedNote {
        transaction_hash: public_hex(&note.occurrence.transaction_hash),
        transaction_index: note.occurrence.transaction_index, log_index: note.occurrence.log_index,
        packet_digest: public_hex(&note.packet_digest), manifest_index: note.manifest_index,
        role: note.role as u8, tree_id: note.tree_id, index: note.index, count: note.count,
        root: public_hex(&note.root), commitment: public_hex(&note.commitment),
        recovery_key_commitment: public_hex(&note.recovery_key_commitment),
        ciphertext_version: note.ciphertext_version, ciphertext: public_hex(&note.ciphertext),
    }
}

#[derive(Serialize)]
struct InspectionExport {
    kind: &'static str,
    source_scope: &'static str,
    block_hash: String,
    block_number: String,
    parent_hash: String,
    policy_id: String,
    expected_deployment: InspectionDeployment,
    token: String,
    token_code: String,
    tree: InspectionTree,
    inputs: Vec<InspectionInput>,
    outputs: Vec<InspectionOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creation: Option<InspectionCreation>,
    appended_notes: Vec<InspectionAppendedNote>,
    consumed_nullifiers: Vec<InspectionConsumedNullifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_digest: Option<String>,
    request_count: usize,
    response_sha256: Vec<String>,
    finality: &'static str,
    proof_validity: &'static str,
    deployment_profile_qualification: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    signing: bool,
    submission: bool,
    financial_execution: bool,
}

fn encode_inspection(observation: &AuthorityObservation) -> Result<Vec<u8>, &'static str> {
    let deployment = observation.deployment();
    let export = InspectionExport {
        kind: "samechain_authority_observation", source_scope: observation.source_scope(),
        block_hash: public_hex(&observation.block_hash()), block_number: observation.block_number().to_string(),
        parent_hash: public_hex(&observation.parent_hash()),
        policy_id: public_hex(&observation.policy_id()),
        expected_deployment: InspectionDeployment {
            chain_id: deployment.chain_id.to_string(),
            authority: public_hex(&deployment.authority), authority_code: public_hex(&deployment.authority_code),
            verifier: public_hex(&deployment.verifier), verifier_code: public_hex(&deployment.verifier_code),
            owner_program: public_hex(&deployment.owner_program), schema: deployment.schema,
        },
        token: public_hex(&observation.token()), token_code: public_hex(&observation.token_code()),
        tree: InspectionTree { tree_id: observation.tree_id(), count: observation.tree_count(),
            root: public_hex(&observation.tree_root()) },
        inputs: observation.input_states().iter().map(|input| InspectionInput {
            tree_id: input.tree_id, index: input.index, root: public_hex(&input.root),
            nullifier: public_hex(&input.nullifier), reported_root_count: input.reported_root_count,
            reported_spent: input.reported_spent,
        }).collect(),
        outputs: observation.output_states().iter().map(|output| InspectionOutput {
            manifest_index: output.manifest_index, commitment: public_hex(&output.commitment),
            reported_seen: output.reported_seen,
        }).collect(),
        appended_notes: observation.appended_notes().iter().map(encode_appended_note).collect(),
        consumed_nullifiers: observation.consumed_nullifiers().iter().map(encode_consumed_nullifier).collect(),
        creation: observation.creation().map(|creation| InspectionCreation {
            nonce_used: creation.nonce_used, initial_order_used: creation.initial_order_used,
        }),
        packet_digest: observation.packet_digest().map(|digest| public_hex(&digest)),
        request_count: observation.response_digests().len(),
        response_sha256: observation.response_digests().iter().map(|digest| public_hex(digest)).collect(),
        finality: "UNVERIFIED", proof_validity: "UNVERIFIED", deployment_profile_qualification: "UNVERIFIED",
        root_eligibility: "UNVERIFIED", global_unspentness: "UNVERIFIED", asset_backing: "UNVERIFIED",
        signing: false, submission: false, financial_execution: false,
    };
    let mut bytes = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    bytes.push(b'\n');
    Ok(bytes)
}
