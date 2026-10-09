//! Read-only NU6.3 testnet acquisition plus DEX full-body structural checks.
//! No wallet keys, private stores, signing, or financial verification are involved.

use std::{error::Error, io, process::ExitCode};
use zcash_protocol::consensus::TEST_NETWORK;
use ziquid_proofs::history::ParsedBlockBody;
use ziquid_zcash::source::acquire_historical_block;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: acquire_source ENDPOINT HEIGHT NONZERO_POLICY_ID_HEX_64",
        )
    };
    let endpoint = arguments.next().ok_or_else(invalid)?;
    let height = arguments.next().ok_or_else(invalid)?;
    let policy = arguments.next().ok_or_else(invalid)?;
    if arguments.next().is_some() {
        return Err(invalid().into());
    }
    let endpoint = endpoint.to_str().ok_or_else(invalid)?;
    let height = height.to_str().ok_or_else(invalid)?;
    if height.is_empty() || !height.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid().into());
    }
    let height: u32 = height.parse().map_err(|_| invalid())?;
    let policy = policy.to_str().ok_or_else(invalid)?;
    if policy.len() != 64 || !policy.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid().into());
    }
    let mut policy_id = [0; 32];
    for (index, byte) in policy_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&policy[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }

    let acquired = acquire_historical_block(endpoint, height, policy_id)?;
    // Keep the stronger DEX relation: Zoss acquisition is only raw node data.
    let body = ParsedBlockBody::parse(&acquired.raw_block, &TEST_NETWORK)?;
    println!(
        "source_class=STRUCTURE_ONLY provenance=UNVERIFIED eligibility={:?} transactions={}",
        acquired.canonical.eligibility,
        body.transaction_count(),
    );
    Ok(())
}
