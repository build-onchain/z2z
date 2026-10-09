use crate::state::{Pair, Reader};
use crate::{fail, Error};
use ziquid_protocol::market::{validate_signature_encoding, Decision, Domain, Id, Transition};
pub use ziquid_solana_interface::Envelope;
use solana_program::{
    account_info::AccountInfo, instruction::get_stack_height, program_error::ProgramError,
    pubkey::Pubkey,
};

pub const INSTRUCTIONS: Pubkey =
    Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");
const SYSVAR_OWNER: Pubkey = Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111");
const ED25519: Pubkey = Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");

fn native_data(sysvar: &[u8], index: usize) -> Result<(&[u8], &[u8]), ProgramError> {
    let count = u16::from_le_bytes(
        sysvar
            .get(..2)
            .ok_or_else(|| fail(Error::Authorization))?
            .try_into()
            .map_err(|_| fail(Error::Authorization))?,
    ) as usize;
    if index >= count {
        return Err(fail(Error::Authorization));
    }
    let offset_pos = 2 + index * 2;
    let offset = u16::from_le_bytes(
        sysvar
            .get(offset_pos..offset_pos + 2)
            .ok_or_else(|| fail(Error::Authorization))?
            .try_into()
            .map_err(|_| fail(Error::Authorization))?,
    ) as usize;
    let mut reader = Reader::new(
        sysvar
            .get(
                offset
                    ..sysvar
                        .len()
                        .checked_sub(2)
                        .ok_or_else(|| fail(Error::Authorization))?,
            )
            .ok_or_else(|| fail(Error::Authorization))?,
    );
    let accounts = u16::from_le_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| fail(Error::Authorization))?,
    ) as usize;
    reader.take(
        accounts
            .checked_mul(33)
            .ok_or_else(|| fail(Error::Authorization))?,
    )?;
    let program = reader.take(32)?;
    let length = u16::from_le_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| fail(Error::Authorization))?,
    ) as usize;
    let data = reader.take(length)?;
    if program == ED25519.as_ref() && accounts != 0 {
        return Err(fail(Error::Authorization));
    }
    Ok((program, data))
}

pub struct OperationContext<'a> {
    pub domain: Domain,
    pub subject: &'a Pubkey,
    pub portion: Option<&'a Pubkey>,
    pub transition: Transition,
    pub envelope: Envelope,
}

pub fn authorize(
    pair: &Pair,
    operation: OperationContext<'_>,
    payload: &[u8],
    accounts: &[AccountInfo],
    sysvar: &AccountInfo,
    skip_payer: bool,
) -> Result<Decision, ProgramError> {
    let OperationContext {
        domain,
        subject,
        portion,
        transition,
        envelope,
    } = operation;
    if envelope.generation
        != pair
            .generation
            .checked_add(1)
            .ok_or_else(|| fail(Error::Arithmetic))?
        || envelope.predecessor != pair.head
    {
        return Err(fail(Error::Version));
    }
    if get_stack_height() != 1
        || sysvar.key != &INSTRUCTIONS
        || sysvar.owner != &SYSVAR_OWNER
        || sysvar.is_writable
        || sysvar.is_signer
        || sysvar.executable
    {
        return Err(fail(Error::Authorization));
    }
    let mut semantic_accounts = [[0; 32]; 10];
    let count = accounts
        .len()
        .checked_sub(usize::from(skip_payer))
        .ok_or_else(|| fail(Error::Accounts))?;
    if count > semantic_accounts.len() {
        return Err(fail(Error::Accounts));
    }
    for (destination, account) in semantic_accounts
        .iter_mut()
        .zip(accounts.iter().skip(usize::from(skip_payer)))
    {
        *destination = account.key.to_bytes();
    }
    let decision = ziquid_solana_interface::decision(
        domain,
        subject.to_bytes(),
        portion.map(Pubkey::to_bytes),
        transition,
        envelope,
        payload,
        &semantic_accounts[..count],
    )
    .map_err(|_| fail(Error::Domain))?;
    let message = decision.signing_bytes().map_err(|_| fail(Error::Domain))?;
    let data = sysvar.try_borrow_data()?;
    let current = u16::from_le_bytes(
        data.get(
            data.len()
                .checked_sub(2)
                .ok_or_else(|| fail(Error::Authorization))?..,
        )
        .ok_or_else(|| fail(Error::Authorization))?
        .try_into()
        .map_err(|_| fail(Error::Authorization))?,
    ) as usize;
    if current < 3 {
        return Err(fail(Error::Authorization));
    }
    let mut seen = [false; 3];
    for index in current - 3..current {
        let (program, native) = native_data(&data, index)?;
        // Canonical single self-contained signature only; no cross-instruction offset abstraction.
        if program != ED25519.as_ref()
            || native.len() != 176
            || native[..16]
                != [
                    1, 0, 48, 0, 255, 255, 16, 0, 255, 255, 112, 0, 64, 0, 255, 255,
                ]
            || native[112..] != message
        {
            return Err(fail(Error::Authorization));
        }
        let key: Id = native[16..48]
            .try_into()
            .map_err(|_| fail(Error::Authorization))?;
        let signature: [u8; 64] = native[48..112]
            .try_into()
            .map_err(|_| fail(Error::Authorization))?;
        validate_signature_encoding(&signature).map_err(|_| fail(Error::Authorization))?;
        let enrolled = pair
            .roster
            .iter()
            .position(|expected| expected == &key)
            .ok_or_else(|| fail(Error::Authorization))?;
        if seen[enrolled] {
            return Err(fail(Error::Authorization));
        }
        seen[enrolled] = true;
    }
    if seen != [true; 3] {
        return Err(fail(Error::Authorization));
    }
    Ok(decision)
}
