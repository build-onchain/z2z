use crate::state::{Epoch, Hold, Pair, Portion, Stored};
use crate::{fail, Error};
use solana_program::{
    account_info::AccountInfo,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_option::COption,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_program_pack::Pack;
use spl_token_interface::state::{Account as TokenAccount, AccountState, Mint};

pub const SYSTEM: Pubkey = Pubkey::new_from_array([0; 32]);

pub fn roles(
    accounts: &[AccountInfo],
    writable: &[bool],
    signer: Option<usize>,
) -> Result<(), ProgramError> {
    if accounts.len() != writable.len() {
        return Err(fail(Error::Accounts));
    }
    for (index, account) in accounts.iter().enumerate() {
        if account.is_writable != writable[index] {
            return Err(fail(Error::Writable));
        }
        if account.is_signer != (signer == Some(index)) {
            return Err(fail(Error::Signer));
        }
        if accounts[..index]
            .iter()
            .any(|earlier| earlier.key == account.key)
        {
            return Err(fail(Error::Alias));
        }
    }
    Ok(())
}
fn pda(account: &AccountInfo, expected: ([u8; 32], u8), bump: u8) -> Result<(), ProgramError> {
    if account.key.to_bytes() != expected.0 || bump != expected.1 {
        return Err(fail(Error::Pda));
    }
    Ok(())
}
pub fn pair(account: &AccountInfo, program: &Pubkey) -> Result<Pair, ProgramError> {
    let state = Pair::load(account, program)?;
    if state.domain.solana_program != program.to_bytes()
        || state.domain.epoch != 0
        || state.domain.token_program != spl_token_interface::ID.to_bytes()
    {
        return Err(fail(Error::Domain));
    }
    pda(
        account,
        ziquid_solana_interface::pair_pda(&state.domain, &state.admin),
        state.bump,
    )?;
    Ok(state)
}
pub fn epoch(
    account: &AccountInfo,
    pair: &AccountInfo,
    program: &Pubkey,
) -> Result<Epoch, ProgramError> {
    let state = Epoch::load(account, program)?;
    if state.pair != pair.key.to_bytes() || state.number == 0 {
        return Err(fail(Error::Domain));
    }
    pda(
        account,
        ziquid_solana_interface::epoch_pda_at(
            &program.to_bytes(),
            &pair.key.to_bytes(),
            state.number,
        ),
        state.bump,
    )?;
    Ok(state)
}
pub fn hold(
    account: &AccountInfo,
    epoch: &AccountInfo,
    program: &Pubkey,
) -> Result<Hold, ProgramError> {
    let state = Hold::load(account, program)?;
    if state.epoch != epoch.key.to_bytes() {
        return Err(fail(Error::Domain));
    }
    pda(
        account,
        ziquid_solana_interface::hold_pda_at(&program.to_bytes(), &epoch.key.to_bytes(), &state.id),
        state.bump,
    )?;
    Ok(state)
}
pub fn portion(
    account: &AccountInfo,
    hold: &AccountInfo,
    program: &Pubkey,
) -> Result<Portion, ProgramError> {
    let state = Portion::load(account, program)?;
    if state.hold != hold.key.to_bytes() {
        return Err(fail(Error::Domain));
    }
    pda(
        account,
        ziquid_solana_interface::portion_pda_at(&program.to_bytes(), &hold.key.to_bytes(), &state.id),
        state.bump,
    )?;
    Ok(state)
}
pub fn token_program(account: &AccountInfo) -> Result<(), ProgramError> {
    if account.key != &spl_token_interface::ID || !account.executable {
        return Err(fail(Error::Token));
    }
    Ok(())
}
pub fn mint(account: &AccountInfo, pair: &Pair) -> Result<Mint, ProgramError> {
    if account.key.to_bytes() != pair.domain.mint
        || account.owner != &spl_token_interface::ID
        || account.executable
    {
        return Err(fail(Error::Token));
    }
    let state = Mint::unpack(&account.try_borrow_data()?)?;
    if state.decimals != pair.decimals || !state.is_initialized {
        return Err(fail(Error::Token));
    }
    Ok(state)
}
pub fn token(
    account: &AccountInfo,
    pair: &Pair,
    expected_owner: Option<&Pubkey>,
) -> Result<TokenAccount, ProgramError> {
    if account.owner != &spl_token_interface::ID || account.executable {
        return Err(fail(Error::Token));
    }
    let state = TokenAccount::unpack(&account.try_borrow_data()?)?;
    if state.mint.to_bytes() != pair.domain.mint
        || !matches!(
            state.state,
            AccountState::Initialized | AccountState::Frozen
        )
        || state.delegate != COption::None
        || state.close_authority != COption::None
        || state.is_native != COption::None
        || expected_owner.is_some_and(|owner| state.owner != *owner)
    {
        return Err(fail(Error::Token));
    }
    Ok(state)
}
pub fn escrow(
    account: &AccountInfo,
    hold_account: &AccountInfo,
    hold: &Hold,
    pair: &Pair,
    program: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _) =
        ziquid_solana_interface::escrow_pda_at(&program.to_bytes(), &hold_account.key.to_bytes());
    if account.key.to_bytes() != expected || account.key.to_bytes() != hold.escrow {
        return Err(fail(Error::Pda));
    }
    let state = token(account, pair, Some(hold_account.key))?;
    if state.amount
        < hold
            .amount
            .checked_sub(hold.consumed)
            .ok_or_else(|| fail(Error::Arithmetic))?
    {
        return Err(fail(Error::Conservation));
    }
    Ok(())
}

pub fn create<'a>(
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    owner: &Pubkey,
    length: usize,
    seeds: &[&[u8]],
) -> Result<(), ProgramError> {
    if system.key != &SYSTEM
        || !system.executable
        || !payer.is_signer
        || !payer.is_writable
        || !account.is_writable
    {
        return Err(fail(Error::Accounts));
    }
    if payer.owner != &SYSTEM
        || !payer.data_is_empty()
        || account.owner != &SYSTEM
        || !account.data_is_empty()
        || account.executable
    {
        return Err(fail(Error::AlreadyInitialized));
    }
    let rent = Rent::get()?.minimum_balance(length);
    if account.lamports() < rent {
        invoke(
            &solana_system_interface::instruction::transfer(
                payer.key,
                account.key,
                rent - account.lamports(),
            ),
            &[payer.clone(), account.clone(), system.clone()],
        )?;
    }
    invoke_signed(
        &solana_system_interface::instruction::allocate(account.key, length as u64),
        &[account.clone(), system.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &solana_system_interface::instruction::assign(account.key, owner),
        &[account.clone(), system.clone()],
        &[seeds],
    )?;
    Ok(())
}

pub fn transfer<'a>(
    accounts: [&AccountInfo<'a>; 5],
    amount: u64,
    decimals: u8,
    seeds: Option<&[&[u8]]>,
) -> Result<(), ProgramError> {
    let [source, mint, destination, authority, program] = accounts;
    if amount == 0 || source.key == destination.key {
        return Err(fail(Error::Conservation));
    }
    let instruction = spl_token_interface::instruction::transfer_checked(
        &spl_token_interface::ID,
        source.key,
        mint.key,
        destination.key,
        authority.key,
        &[],
        amount,
        decimals,
    )?;
    let infos = [
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
        program.clone(),
    ];
    match seeds {
        Some(seeds) => invoke_signed(&instruction, &infos, &[seeds]),
        None => invoke(&instruction, &infos),
    }
}
