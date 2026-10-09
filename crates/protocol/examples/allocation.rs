use std::{error::Error, io};

use primitive_types::U256;
use ziquid_protocol::{NativeAmount, SourceAmount, allocate};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: allocation QUOTED_ZATOSHIS FUNDED_WEI CONSIDERED_ZATOSHIS",
        )
        .into());
    }
    if arguments
        .iter()
        .any(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "amounts must be unsigned decimal digits",
        )
        .into());
    }
    let quoted = SourceAmount::new(arguments[0].parse()?)?;
    let funded = NativeAmount::new(U256::from_dec_str(&arguments[1])?);
    let considered = SourceAmount::new(arguments[2].parse()?)?;
    let allocation = allocate(quoted, funded, considered)?;
    println!(
        "user_wei={} solver_wei={}",
        allocation.user.get(),
        allocation.solver.get()
    );
    Ok(())
}
