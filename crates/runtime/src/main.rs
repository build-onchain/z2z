//! Native protocol driver. Arithmetic is executable; source proof verification,
//! funded settlement and solver orchestration are not implied by local output.

use std::process::ExitCode;

const HELP: &str = "Ziquid native protocol tools

Usage: ziquid [--help | --version]
       ziquid allocation QUOTED_ZATOSHIS FUNDED_WEI CONSIDERED_ZATOSHIS
       ziquid market <COMMAND> [OPTIONS]
       ziquid hypercore <COMMAND> [OPTIONS]
       ziquid samechain <COMMAND> [OPTIONS]
       ziquid native <COMMAND> [OPTIONS]

Options:
  -h, --help     Show this help
  -V, --version  Show the package version

Allocation calculates arithmetic only; it does not verify payment or move funds.
Market tools inspect effects and manage explicit safety journals; they do not
establish private matching, source consensus or complete cross-chain settlement.";

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let argument = arguments.next();
    if argument.as_deref() == Some(std::ffi::OsStr::new("allocation")) {
        return allocation_command(arguments);
    }
    if argument.as_deref() == Some(std::ffi::OsStr::new("market")) {
        return ziquid_runtime::market::run_cli(arguments);
    }
    if argument.as_deref() == Some(std::ffi::OsStr::new("hypercore")) {
        return ziquid_runtime::hypercore::run_cli(arguments);
    }
    if argument.as_deref() == Some(std::ffi::OsStr::new("samechain")) {
        return ziquid_runtime::samechain::run_standalone_cli(arguments);
    }
    if argument.as_deref() == Some(std::ffi::OsStr::new("native")) {
        return ziquid_runtime::native_cli::run_cli(arguments);
    }

    if arguments.next().is_some() {
        eprintln!("{HELP}");
        return ExitCode::from(2);
    }

    match argument {
        None => println!("{HELP}"),
        Some(argument) if argument == "--help" || argument == "-h" => println!("{HELP}"),
        Some(argument) if argument == "--version" || argument == "-V" => {
            println!("ziquid {}", env!("CARGO_PKG_VERSION"));
        }
        Some(_) => {
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}

fn allocation_command(arguments: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    use primitive_types::U256;
    use ziquid_protocol::{NativeAmount, SourceAmount, allocate};

    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        let mut args = arguments;
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "allocation requires three decimal amounts",
            )
        };
        let quoted = args.next().ok_or_else(invalid)?;
        let funded = args.next().ok_or_else(invalid)?;
        let considered = args.next().ok_or_else(invalid)?;
        if args.next().is_some() {
            return Err(invalid().into());
        }
        let decimal = |value: &std::ffi::OsStr| -> Result<(), std::io::Error> {
            let value = value.to_str().ok_or_else(invalid)?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            Ok(())
        };
        decimal(&quoted)?;
        decimal(&funded)?;
        decimal(&considered)?;
        let quoted = SourceAmount::new(quoted.to_str().ok_or_else(invalid)?.parse()?)?;
        let funded = NativeAmount::new(U256::from_dec_str(funded.to_str().ok_or_else(invalid)?)?);
        let considered = SourceAmount::new(considered.to_str().ok_or_else(invalid)?.parse()?)?;
        Ok(allocate(quoted, funded, considered)?)
    })();
    match result {
        Ok(allocation) => {
            println!(
                "user_wei={} solver_wei={}",
                allocation.user.get(),
                allocation.solver.get()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
