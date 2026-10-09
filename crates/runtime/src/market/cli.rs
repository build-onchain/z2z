use clap::{Parser, Subcommand};
use super::{Error, Result, config, coordinator, native, process};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "ziquid market",
    version,
    about = "Explicit local safety storage/inspection; no native signing, network send or private funded enablement"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    Replica {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        local_fixture_key_stdin: bool,
    },
    InspectLedger {
        #[arg(long)]
        config: PathBuf,
    },
    InspectPczt {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        pczt: PathBuf,
    },
    Reconcile {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        local_fixture_keys_stdin: bool,
    },
    LocalSafetyScenario {
        #[arg(long)]
        config: PathBuf,
    },
}

/// Execute the market command arguments remaining after the parent `market` selector.
/// Replica success writes binary process frames only, never a JSON summary.
pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let argv = std::iter::once(OsString::from("ziquid market")).chain(arguments);
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
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Process)
        .and_then(|runtime| runtime.block_on(execute(cli)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<()> {
    let result = match cli.command {
        Command::Migrate { config: path } => coordinator::migrate(config::read(&path)?).await?,
        Command::Replica {
            config: path,
            local_fixture_key_stdin,
        } => {
            process::replica(config::read(&path)?, local_fixture_key_stdin).await?;
            return Ok(());
        }
        Command::InspectLedger { config: path } => {
            coordinator::inspect(config::read(&path)?).await?
        }
        Command::InspectPczt { config: path, pczt } => native::inspect_file(&path, &pczt)?,
        Command::Reconcile {
            config: path,
            local_fixture_keys_stdin,
        } => {
            let keys = if local_fixture_keys_stdin {
                Some(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        process::read_fixture_keys::<3>(&mut tokio::io::stdin()),
                    )
                    .await
                    .map_err(|_| Error::ProcessTimeout)??,
                )
            } else {
                None
            };
            let executable = std::env::current_exe().map_err(|_| Error::Process)?;
            coordinator::reconcile(config::read(&path)?, &executable, keys).await?
        }
        Command::LocalSafetyScenario { config: path } => {
            let executable = std::env::current_exe().map_err(|_| Error::Process)?;
            super::local_safety_scenario(config::read(&path)?, &executable).await?
        }
    };
    let bytes = serde_json::to_vec(&result).map_err(|_| Error::Input)?;
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes).map_err(|_| Error::Process)?;
    stdout.write_all(b"\n").map_err(|_| Error::Process)?;
    Ok(())
}

