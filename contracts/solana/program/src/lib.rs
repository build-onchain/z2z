//! Public local safety escrow; allocation and custody heads are unanimous authority testimony,
//! not MPC, source-history, native-spend-absence or network-finality proofs.
mod accounts;
mod authorization;
mod state;

use accounts as a;
use authorization::{authorize, Envelope, OperationContext};
use ziquid_protocol::market::{validate_authorization_key, Domain, Transition, DOMAIN_LEN};
use ziquid_solana_interface::{CompactEnvelope, PrepareFillEffects, ReleaseEffects};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke,
    program_error::ProgramError, pubkey::Pubkey,
};
use solana_program_pack::Pack;
use spl_token_interface::state::{Account as TokenAccount, Mint};
use state::*;

solana_program::entrypoint!(process_instruction);

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Error {
    Data = 1,
    Accounts,
    Owner,
    Writable,
    Signer,
    Alias,
    Pda,
    Token,
    Domain,
    AlreadyInitialized,
    Authorization,
    Version,
    Arithmetic,
    State,
    Conservation,
    Recipient,
    Incomplete,
}
pub fn fail(error: Error) -> ProgramError {
    ProgramError::Custom(error as u32)
}
fn require(condition: bool, error: Error) -> ProgramResult {
    if condition {
        Ok(())
    } else {
        Err(fail(error))
    }
}
fn add(left: u64, right: u64) -> Result<u64, ProgramError> {
    left.checked_add(right)
        .ok_or_else(|| fail(Error::Arithmetic))
}
fn nonzero(id: &[u8; 32]) -> ProgramResult {
    require(*id != [0; 32], Error::Data)
}
fn envelope(r: &mut Reader<'_>) -> Result<CompactEnvelope, ProgramError> {
    CompactEnvelope::decode(r.take(64)?).map_err(|_| fail(Error::Data))
}
fn bind(compact: CompactEnvelope, pair: &Pair, prior: u64) -> Result<Envelope, ProgramError> {
    compact
        .bind(add(pair.generation, 1)?, prior)
        .map_err(|_| fail(Error::Version))
}
fn domain(pair: &Pair, epoch: &Epoch) -> Domain {
    Domain {
        epoch: epoch.number,
        ..pair.domain
    }
}
fn advance(
    pair: &mut Pair,
    decision: ziquid_protocol::market::Decision,
    account: &AccountInfo,
) -> ProgramResult {
    pair.generation = decision.operation.generation;
    pair.head = decision.next_head;
    pair.save(account)
}

pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let mut reader = Reader::new(data);
    match reader.byte()? {
        1 => initialize(program, accounts, reader),
        2 => open(program, accounts, data, reader),
        3 => lock(program, accounts, reader),
        4 => prepare(program, accounts, data, reader),
        6 | 7 => epoch_decision(program, accounts, data, reader),
        8 => allocation(program, accounts, data, reader),
        9 => activate(program, accounts, data, reader),
        10 | 12 => fill_decision(program, accounts, data, reader),
        11 => release(program, accounts, data, reader),
        13 => return_unused(program, accounts, data, reader),
        _ => Err(fail(Error::Data)),
    }
}

fn initialize<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, true, false, false, false], Some(0))?;
    let domain = Domain::decode(r.take(DOMAIN_LEN)?).map_err(|_| fail(Error::Domain))?;
    let admin = r.id()?;
    let roster = [r.id()?, r.id()?, r.id()?];
    let decimals = r.byte()?;
    r.end()?;
    require(
        domain.solana_program == program.to_bytes()
            && domain.epoch == 0
            && domain.token_program == spl_token_interface::ID.to_bytes(),
        Error::Domain,
    )?;
    require(
        accounts[0].key.to_bytes() == admin && accounts[2].key.to_bytes() == domain.mint,
        Error::Signer,
    )?;
    for (i, key) in roster.iter().enumerate() {
        validate_authorization_key(key).map_err(|_| fail(Error::Authorization))?;
        require(!roster[..i].contains(key), Error::Authorization)?;
    }
    a::token_program(&accounts[3])?;
    require(
        accounts[2].owner == &spl_token_interface::ID && !accounts[2].executable,
        Error::Token,
    )?;
    let mint = Mint::unpack(&accounts[2].try_borrow_data()?)?;
    require(
        mint.is_initialized && mint.decimals == decimals,
        Error::Token,
    )?;
    let (expected, bump) = ziquid_solana_interface::pair_pda(&domain, &admin);
    require(accounts[1].key.to_bytes() == expected, Error::Pda)?;
    a::create(
        &accounts[0],
        &accounts[1],
        &accounts[4],
        program,
        Pair::LEN,
        &[b"pair", &admin, &domain.deployment, &domain.pair, &[bump]],
    )?;
    Pair {
        bump,
        domain,
        admin,
        roster,
        decimals,
        generation: 0,
        head: [0; 32],
    }
    .save(&accounts[1])
}

fn open<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, true, true, false, false], Some(0))?;
    let compact = envelope(&mut r)?;
    let number = r.u64()?;
    r.end()?;
    require(number != 0, Error::Version)?;
    let mut pair = a::pair(&accounts[1], program)?;
    let envelope = bind(compact, &pair, 0)?;
    let (expected, bump) = ziquid_solana_interface::epoch_pda_at(
        &program.to_bytes(),
        &accounts[1].key.to_bytes(),
        number,
    );
    require(accounts[2].key.to_bytes() == expected, Error::Pda)?;
    let epoch = Epoch {
        bump,
        pair: accounts[1].key.to_bytes(),
        number,
        version: 1,
        phase: OPEN,
        locked_holds: 0,
        prepared_holds: 0,
        completed_holds: 0,
        locked_atoms: 0,
        prepared_atoms: 0,
        allocated_atoms: 0,
        result: [0; 32],
        journal: [0; 32],
    };
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[2].key,
            portion: None,
            transition: Transition::OpenEpoch,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[4],
        true,
    )?;
    a::create(
        &accounts[0],
        &accounts[2],
        &accounts[3],
        program,
        Epoch::LEN,
        &[
            b"epoch",
            accounts[1].key.as_ref(),
            &number.to_le_bytes(),
            &[bump],
        ],
    )?;
    epoch.save(&accounts[2])?;
    advance(&mut pair, decision, &accounts[1])
}

fn lock<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], mut r: Reader<'_>) -> ProgramResult {
    a::roles(
        accounts,
        &[true, false, true, true, true, true, false, false, false],
        Some(0),
    )?;
    let id = r.id()?;
    let amount = r.u64()?;
    let expected_chunks = r.u32()?;
    r.end()?;
    nonzero(&id)?;
    require(
        amount != 0 && expected_chunks != 0 && u64::from(expected_chunks) <= amount,
        Error::Conservation,
    )?;
    let pair = a::pair(&accounts[1], program)?;
    let mut epoch = a::epoch(&accounts[2], &accounts[1], program)?;
    require(epoch.phase == OPEN, Error::State)?;
    a::token_program(&accounts[7])?;
    a::mint(&accounts[6], &pair)?;
    let source = a::token(&accounts[5], &pair, Some(accounts[0].key))?;
    require(source.amount >= amount, Error::Conservation)?;
    let (hold_key, bump) =
        ziquid_solana_interface::hold_pda_at(&program.to_bytes(), &accounts[2].key.to_bytes(), &id);
    require(accounts[3].key.to_bytes() == hold_key, Error::Pda)?;
    let (escrow_key, escrow_bump) =
        ziquid_solana_interface::escrow_pda_at(&program.to_bytes(), &accounts[3].key.to_bytes());
    require(accounts[4].key.to_bytes() == escrow_key, Error::Pda)?;
    a::create(
        &accounts[0],
        &accounts[3],
        &accounts[8],
        program,
        Hold::LEN,
        &[b"hold", accounts[2].key.as_ref(), &id, &[bump]],
    )?;
    a::create(
        &accounts[0],
        &accounts[4],
        &accounts[8],
        &spl_token_interface::ID,
        TokenAccount::LEN,
        &[b"escrow", accounts[3].key.as_ref(), &[escrow_bump]],
    )?;
    invoke(
        &spl_token_interface::instruction::initialize_account3(
            &spl_token_interface::ID,
            accounts[4].key,
            accounts[6].key,
            accounts[3].key,
        )?,
        &[
            accounts[4].clone(),
            accounts[6].clone(),
            accounts[7].clone(),
        ],
    )?;
    a::transfer(
        [
            &accounts[5],
            &accounts[6],
            &accounts[4],
            &accounts[0],
            &accounts[7],
        ],
        amount,
        pair.decimals,
        None,
    )?;
    Hold {
        bump,
        epoch: accounts[2].key.to_bytes(),
        id,
        seller: accounts[0].key.to_bytes(),
        refund: accounts[5].key.to_bytes(),
        escrow: accounts[4].key.to_bytes(),
        amount,
        expected_chunks,
        version: 1,
        state: LOCKED,
        allocated: 0,
        chunks: 0,
        consumed: 0,
        result: [0; 32],
    }
    .save(&accounts[3])?;
    epoch.locked_holds = add(epoch.locked_holds, 1)?;
    epoch.locked_atoms = add(epoch.locked_atoms, amount)?;
    epoch.version = add(epoch.version, 1)?;
    epoch.save(&accounts[2])
}

fn prepare(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, true, true, false], None)?;
    let compact = envelope(&mut r)?;
    r.end()?;
    let mut pair = a::pair(&accounts[0], program)?;
    let mut epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let mut hold = a::hold(&accounts[2], &accounts[1], program)?;
    let envelope = bind(compact, &pair, hold.version)?;
    require(
        epoch.phase == OPEN && hold.state == LOCKED && hold.version == envelope.prior,
        Error::State,
    )?;
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[2].key,
            portion: None,
            transition: Transition::PrepareSeller,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[3],
        false,
    )?;
    hold.state = PREPARED;
    hold.version = add(hold.version, 1)?;
    epoch.prepared_holds = add(epoch.prepared_holds, 1)?;
    epoch.prepared_atoms = add(epoch.prepared_atoms, hold.amount)?;
    epoch.version = add(epoch.version, 1)?;
    hold.save(&accounts[2])?;
    epoch.save(&accounts[1])?;
    advance(&mut pair, decision, &accounts[0])
}

fn epoch_decision(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, true, false], None)?;
    let compact = envelope(&mut r)?;
    let commit = data[0] == 6;
    let result = if commit { r.id()? } else { [0; 32] };
    r.end()?;
    if commit {
        nonzero(&result)?;
    }
    let mut pair = a::pair(&accounts[0], program)?;
    let mut epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let envelope = bind(compact, &pair, epoch.version)?;
    require(
        epoch.phase == OPEN
            && epoch.version == envelope.prior
            && epoch.prepared_holds <= epoch.locked_holds
            && epoch.prepared_atoms <= epoch.locked_atoms,
        Error::State,
    )?;
    let transition = if commit {
        Transition::CommitEpoch
    } else {
        Transition::AbortEpoch
    };
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[1].key,
            portion: None,
            transition,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[2],
        false,
    )?;
    epoch.phase = if commit { COMMITTED } else { ABORTED };
    epoch.result = result;
    epoch.version = add(epoch.version, 1)?;
    epoch.save(&accounts[1])?;
    advance(&mut pair, decision, &accounts[0])
}

fn allocation<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(
        accounts,
        &[
            true, true, true, true, true, false, false, false, false, false,
        ],
        Some(0),
    )?;
    let compact = envelope(&mut r)?;
    let id = r.id()?;
    let offset = r.u64()?;
    let amount = r.u64()?;
    let kind = r.byte()?;
    let result = r.id()?;
    r.end()?;
    nonzero(&id)?;
    let mut pair = a::pair(&accounts[1], program)?;
    let mut epoch = a::epoch(&accounts[2], &accounts[1], program)?;
    let mut hold = a::hold(&accounts[3], &accounts[2], program)?;
    let envelope = bind(compact, &pair, hold.version)?;
    require(
        epoch.phase == COMMITTED
            && result == epoch.result
            && hold.state == PREPARED
            && hold.version == envelope.prior,
        Error::State,
    )?;
    require(
        amount != 0
            && offset == hold.allocated
            && add(offset, amount)? <= hold.amount
            && hold.chunks < hold.expected_chunks
            && matches!(kind, FILL | UNUSED),
        Error::Conservation,
    )?;
    a::token_program(&accounts[7])?;
    a::mint(&accounts[6], &pair)?;
    let recipient = a::token(&accounts[5], &pair, None)?;
    require(accounts[5].key.to_bytes() != hold.escrow, Error::Alias)?;
    if kind == UNUSED {
        require(
            accounts[5].key.to_bytes() == hold.refund && recipient.owner.to_bytes() == hold.seller,
            Error::Recipient,
        )?;
    }
    let (key, bump) = ziquid_solana_interface::portion_pda_at(
        &program.to_bytes(),
        &accounts[3].key.to_bytes(),
        &id,
    );
    require(accounts[4].key.to_bytes() == key, Error::Pda)?;
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[3].key,
            portion: Some(accounts[4].key),
            transition: Transition::RecordAllocation,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[9],
        true,
    )?;
    let chunks = hold
        .chunks
        .checked_add(1)
        .ok_or_else(|| fail(Error::Arithmetic))?;
    let allocated = add(hold.allocated, amount)?;
    require(
        (chunks == hold.expected_chunks) == (allocated == hold.amount),
        Error::Conservation,
    )?;
    a::create(
        &accounts[0],
        &accounts[4],
        &accounts[8],
        program,
        Portion::LEN,
        &[b"portion", accounts[3].key.as_ref(), &id, &[bump]],
    )?;
    Portion {
        bump,
        hold: accounts[3].key.to_bytes(),
        id,
        recipient: accounts[5].key.to_bytes(),
        recipient_owner: recipient.owner.to_bytes(),
        offset,
        amount,
        version: 1,
        kind,
        state: ALLOCATED,
        allocation: result,
        first_leg_intent: [0; 32],
        fence: [0; 32],
        custody: [0; 32],
    }
    .save(&accounts[4])?;
    hold.chunks = chunks;
    hold.allocated = allocated;
    hold.result = result;
    hold.version = add(hold.version, 1)?;
    epoch.allocated_atoms = add(epoch.allocated_atoms, amount)?;
    if chunks == hold.expected_chunks {
        epoch.completed_holds = add(epoch.completed_holds, 1)?;
    }
    epoch.version = add(epoch.version, 1)?;
    hold.save(&accounts[3])?;
    epoch.save(&accounts[2])?;
    advance(&mut pair, decision, &accounts[1])
}

fn activate(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, true, false], None)?;
    let compact = envelope(&mut r)?;
    let result = r.id()?;
    let journal = r.id()?;
    r.end()?;
    nonzero(&journal)?;
    let mut pair = a::pair(&accounts[0], program)?;
    let mut epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let envelope = bind(compact, &pair, epoch.version)?;
    require(
        epoch.phase == COMMITTED && epoch.version == envelope.prior && result == epoch.result,
        Error::State,
    )?;
    require(
        epoch.completed_holds == epoch.prepared_holds
            && epoch.allocated_atoms == epoch.prepared_atoms,
        Error::Incomplete,
    )?;
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[1].key,
            portion: None,
            transition: Transition::ActivateAllocation,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[2],
        false,
    )?;
    epoch.phase = ACTIVE;
    epoch.journal = journal;
    epoch.version = add(epoch.version, 1)?;
    epoch.save(&accounts[1])?;
    advance(&mut pair, decision, &accounts[0])
}

fn active(epoch: &Epoch, hold: &Hold, portion: &Portion) -> ProgramResult {
    require(
        epoch.phase == ACTIVE
            && hold.state == PREPARED
            && hold.allocated == hold.amount
            && hold.chunks == hold.expected_chunks
            && hold.result == epoch.result
            && portion.allocation == epoch.result,
        Error::Incomplete,
    )
}

fn fill_decision(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(accounts, &[true, false, false, true, false], None)?;
    let compact = envelope(&mut r)?;
    let prepare = data[0] == 10;
    let (amount, first, fence) = if prepare {
        let effect = PrepareFillEffects::decode(r.take(72)?).map_err(|_| fail(Error::Data))?;
        (effect.amount, effect.journal, effect.fence)
    } else {
        (0, r.id()?, [0; 32])
    };
    r.end()?;
    nonzero(&first)?;
    let mut pair = a::pair(&accounts[0], program)?;
    let epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let hold = a::hold(&accounts[2], &accounts[1], program)?;
    let mut portion = a::portion(&accounts[3], &accounts[2], program)?;
    let envelope = bind(compact, &pair, portion.version)?;
    active(&epoch, &hold, &portion)?;
    require(
        portion.kind == FILL && portion.version == envelope.prior,
        Error::State,
    )?;
    if prepare {
        require(
            portion.state == ALLOCATED && first == epoch.journal && amount == portion.amount,
            Error::State,
        )?;
        nonzero(&fence)?;
    } else {
        require(
            matches!(portion.state, ALLOCATED | FIRST_PREPARED),
            Error::State,
        )?;
        if portion.state == FIRST_PREPARED {
            require(portion.first_leg_intent == envelope.intent, Error::Version)?;
        }
    }
    let transition = if prepare {
        Transition::PrepareFill
    } else {
        Transition::CancelFill
    };
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[3].key,
            portion: Some(accounts[3].key),
            transition,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[4],
        false,
    )?;
    portion.version = add(portion.version, 1)?;
    if prepare {
        portion.state = FIRST_PREPARED;
        portion.first_leg_intent = envelope.intent;
        portion.fence = fence;
    } else {
        portion.state = CANCELLED;
        portion.custody = first;
    }
    portion.save(&accounts[3])?;
    advance(&mut pair, decision, &accounts[0])
}

fn release<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    a::roles(
        accounts,
        &[true, false, true, true, true, false, true, false, false],
        None,
    )?;
    let compact = envelope(&mut r)?;
    let effects = ReleaseEffects::decode(r.take(72)?).map_err(|_| fail(Error::Data))?;
    r.end()?;
    let mut pair = a::pair(&accounts[0], program)?;
    let epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let mut hold = a::hold(&accounts[2], &accounts[1], program)?;
    let mut portion = a::portion(&accounts[3], &accounts[2], program)?;
    let envelope = bind(compact, &pair, portion.version)?;
    active(&epoch, &hold, &portion)?;
    require(
        portion.kind == FILL
            && portion.state == FIRST_PREPARED
            && portion.version == envelope.prior
            && portion.fence == effects.fence
            && portion.allocation == effects.result
            && portion.amount == effects.amount
            && portion.first_leg_intent == envelope.intent,
        Error::State,
    )?;
    require(
        accounts[6].key.to_bytes() == portion.recipient,
        Error::Recipient,
    )?;
    a::token_program(&accounts[7])?;
    a::mint(&accounts[5], &pair)?;
    a::token(
        &accounts[6],
        &pair,
        Some(&Pubkey::new_from_array(portion.recipient_owner)),
    )?;
    a::escrow(&accounts[4], &accounts[2], &hold, &pair, program)?;
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject: accounts[3].key,
            portion: Some(accounts[3].key),
            transition: Transition::ReleaseSpl,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[8],
        false,
    )?;
    // Deliberately persist non-paid consumption/version/head before CPI: Solana atomic rollback
    // must restore all bytes on a genuine issuer freeze failure. Paid is written only after CPI.
    hold.consumed = add(hold.consumed, portion.amount)?;
    require(hold.consumed <= hold.amount, Error::Conservation)?;
    hold.version = add(hold.version, 1)?;
    portion.version = add(portion.version, 1)?;
    hold.save(&accounts[2])?;
    portion.save(&accounts[3])?;
    advance(&mut pair, decision, &accounts[0])?;
    a::transfer(
        [
            &accounts[4],
            &accounts[5],
            &accounts[6],
            &accounts[2],
            &accounts[7],
        ],
        portion.amount,
        pair.decimals,
        Some(&[b"hold", &hold.epoch, &hold.id, &[hold.bump]]),
    )?;
    portion.state = RELEASED;
    portion.save(&accounts[3])
}

fn return_unused<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    mut r: Reader<'_>,
) -> ProgramResult {
    let compact = envelope(&mut r)?;
    let mode = r.byte()?;
    let custody = r.id()?;
    r.end()?;
    if mode == 0 {
        a::roles(
            accounts,
            &[true, false, true, true, false, true, false, false],
            None,
        )?;
    } else {
        require(mode <= 2, Error::Data)?;
        a::roles(
            accounts,
            &[true, false, true, true, false, true, false, false, true],
            None,
        )?;
    }
    let mut pair = a::pair(&accounts[0], program)?;
    let epoch = a::epoch(&accounts[1], &accounts[0], program)?;
    let mut hold = a::hold(&accounts[2], &accounts[1], program)?;
    require(accounts[5].key.to_bytes() == hold.refund, Error::Recipient)?;
    a::token_program(&accounts[6])?;
    a::mint(&accounts[4], &pair)?;
    a::token(
        &accounts[5],
        &pair,
        Some(&Pubkey::new_from_array(hold.seller)),
    )?;
    a::escrow(&accounts[3], &accounts[2], &hold, &pair, program)?;
    let mut portion = if mode == 0 {
        None
    } else {
        Some(a::portion(&accounts[8], &accounts[2], program)?)
    };
    let envelope = bind(
        compact,
        &pair,
        portion
            .as_ref()
            .map(|portion| portion.version)
            .unwrap_or(hold.version),
    )?;
    let amount = match &portion {
        None => {
            require(
                hold.version == envelope.prior
                    && hold.state != WHOLE_RETURNED
                    && hold.consumed == 0
                    && hold.chunks == 0
                    && custody == [0; 32]
                    && (epoch.phase == ABORTED
                        || (matches!(epoch.phase, COMMITTED | ACTIVE) && hold.state == LOCKED)),
                Error::State,
            )?;
            hold.amount
        }
        Some(portion) => {
            active(&epoch, &hold, portion)?;
            require(portion.version == envelope.prior, Error::Version)?;
            if mode == 1 {
                require(
                    portion.kind == UNUSED && portion.state == ALLOCATED && custody == [0; 32],
                    Error::State,
                )?;
            } else {
                require(
                    portion.kind == FILL
                        && portion.state == CANCELLED
                        && custody == portion.custody,
                    Error::State,
                )?;
                nonzero(&custody)?;
            }
            portion.amount
        }
    };
    let subject = if mode == 0 {
        accounts[2].key
    } else {
        accounts[8].key
    };
    let decision = authorize(
        &pair,
        OperationContext {
            domain: domain(&pair, &epoch),
            subject,
            portion: if mode == 0 { None } else { Some(subject) },
            transition: Transition::ReturnUnused,
            envelope,
        },
        &data[65..],
        accounts,
        &accounts[7],
        false,
    )?;
    hold.consumed = add(hold.consumed, amount)?;
    require(hold.consumed <= hold.amount, Error::Conservation)?;
    hold.version = add(hold.version, 1)?;
    if mode == 0 {
        hold.state = WHOLE_RETURNED;
    }
    if let Some(portion) = &mut portion {
        portion.version = add(portion.version, 1)?;
        portion.save(&accounts[8])?;
    }
    hold.save(&accounts[2])?;
    advance(&mut pair, decision, &accounts[0])?;
    a::transfer(
        [
            &accounts[3],
            &accounts[4],
            &accounts[5],
            &accounts[2],
            &accounts[6],
        ],
        amount,
        pair.decimals,
        Some(&[b"hold", &hold.epoch, &hold.id, &[hold.bump]]),
    )?;
    if let Some(portion) = &mut portion {
        portion.state = RETURNED;
        portion.save(&accounts[8])?;
    }
    Ok(())
}
