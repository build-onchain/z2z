use crate::{fail, Error};
use ziquid_protocol::market::{Domain, Id, DOMAIN_LEN};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

pub const PAIR_LEN: usize = 503;
pub const EPOCH_LEN: usize = 170;
pub const HOLD_LEN: usize = 242;
pub const PORTION_LEN: usize = 291;
pub const OPEN: u8 = 1;
pub const COMMITTED: u8 = 2;
pub const ABORTED: u8 = 3;
pub const ACTIVE: u8 = 4;
pub const LOCKED: u8 = 1;
pub const PREPARED: u8 = 2;
pub const WHOLE_RETURNED: u8 = 3;
pub const FILL: u8 = 1;
pub const UNUSED: u8 = 2;
pub const ALLOCATED: u8 = 1;
pub const FIRST_PREPARED: u8 = 2;
pub const RELEASED: u8 = 3;
pub const CANCELLED: u8 = 4;
pub const RETURNED: u8 = 5;

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| fail(Error::Data))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| fail(Error::Data))?;
        self.offset = end;
        Ok(value)
    }
    pub fn id(&mut self) -> Result<Id, ProgramError> {
        self.take(32)?.try_into().map_err(|_| fail(Error::Data))
    }
    pub fn byte(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| fail(Error::Data))?,
        ))
    }
    pub fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| fail(Error::Data))?,
        ))
    }
    pub fn end(&self) -> Result<(), ProgramError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(fail(Error::Data))
        }
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}
impl<'a> Writer<'a> {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        self.offset += bytes.len();
    }
    fn byte(&mut self, value: u8) {
        self.put(&[value]);
    }
    fn u32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.put(&value.to_le_bytes());
    }
}

pub trait Stored: Sized {
    const LEN: usize;
    const TAG: &'static [u8; 8];
    fn read(r: &mut Reader<'_>) -> Result<Self, ProgramError>;
    fn write(&self, w: &mut [u8]) -> Result<(), ProgramError>;
    fn load(account: &AccountInfo, program: &Pubkey) -> Result<Self, ProgramError> {
        if account.owner != program || account.executable {
            return Err(fail(Error::Owner));
        }
        let data = account.try_borrow_data()?;
        if data.len() != Self::LEN || data.get(..8) != Some(Self::TAG.as_slice()) {
            return Err(fail(Error::Data));
        }
        let mut r = Reader::new(&data[8..]);
        let state = Self::read(&mut r)?;
        r.end()?;
        Ok(state)
    }
    fn save(&self, account: &AccountInfo) -> Result<(), ProgramError> {
        if !account.is_writable {
            return Err(fail(Error::Writable));
        }
        let mut data = account.try_borrow_mut_data()?;
        if data.len() != Self::LEN {
            return Err(fail(Error::Data));
        }
        data[..8].copy_from_slice(Self::TAG);
        self.write(&mut data[8..])
    }
}

#[derive(Clone, Copy)]
pub struct Pair {
    pub bump: u8,
    pub domain: Domain,
    pub admin: Id,
    pub roster: [Id; 3],
    pub decimals: u8,
    pub generation: u64,
    pub head: Id,
}
impl Stored for Pair {
    const LEN: usize = PAIR_LEN;
    const TAG: &'static [u8; 8] = b"KERBPR01";
    fn read(r: &mut Reader<'_>) -> Result<Self, ProgramError> {
        let bump = r.byte()?;
        let domain = Domain::decode(r.take(DOMAIN_LEN)?).map_err(|_| fail(Error::Domain))?;
        let admin = r.id()?;
        let roster = [r.id()?, r.id()?, r.id()?];
        Ok(Self {
            bump,
            domain,
            admin,
            roster,
            decimals: r.byte()?,
            generation: r.u64()?,
            head: r.id()?,
        })
    }
    fn write(&self, bytes: &mut [u8]) -> Result<(), ProgramError> {
        bytes[0] = self.bump;
        self.domain
            .encode_into(&mut bytes[1..1 + DOMAIN_LEN])
            .map_err(|_| fail(Error::Domain))?;
        let mut w = Writer {
            bytes,
            offset: 1 + DOMAIN_LEN,
        };
        w.put(&self.admin);
        for key in &self.roster {
            w.put(key);
        }
        w.byte(self.decimals);
        w.u64(self.generation);
        w.put(&self.head);
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Epoch {
    pub bump: u8,
    pub pair: Id,
    pub number: u64,
    pub version: u64,
    pub phase: u8,
    pub locked_holds: u64,
    pub prepared_holds: u64,
    pub completed_holds: u64,
    pub locked_atoms: u64,
    pub prepared_atoms: u64,
    pub allocated_atoms: u64,
    pub result: Id,
    pub journal: Id,
}
impl Stored for Epoch {
    const LEN: usize = EPOCH_LEN;
    const TAG: &'static [u8; 8] = b"KERBEP01";
    fn read(r: &mut Reader<'_>) -> Result<Self, ProgramError> {
        let state = Self {
            bump: r.byte()?,
            pair: r.id()?,
            number: r.u64()?,
            version: r.u64()?,
            phase: r.byte()?,
            locked_holds: r.u64()?,
            prepared_holds: r.u64()?,
            completed_holds: r.u64()?,
            locked_atoms: r.u64()?,
            prepared_atoms: r.u64()?,
            allocated_atoms: r.u64()?,
            result: r.id()?,
            journal: r.id()?,
        };
        if !(OPEN..=ACTIVE).contains(&state.phase) {
            return Err(fail(Error::State));
        }
        Ok(state)
    }
    fn write(&self, bytes: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer { bytes, offset: 0 };
        w.byte(self.bump);
        w.put(&self.pair);
        w.u64(self.number);
        w.u64(self.version);
        w.byte(self.phase);
        for value in [
            self.locked_holds,
            self.prepared_holds,
            self.completed_holds,
            self.locked_atoms,
            self.prepared_atoms,
            self.allocated_atoms,
        ] {
            w.u64(value);
        }
        w.put(&self.result);
        w.put(&self.journal);
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Hold {
    pub bump: u8,
    pub epoch: Id,
    pub id: Id,
    pub seller: Id,
    pub refund: Id,
    pub escrow: Id,
    pub amount: u64,
    pub expected_chunks: u32,
    pub version: u64,
    pub state: u8,
    pub allocated: u64,
    pub chunks: u32,
    pub consumed: u64,
    pub result: Id,
}
impl Stored for Hold {
    const LEN: usize = HOLD_LEN;
    const TAG: &'static [u8; 8] = b"KERBHL01";
    fn read(r: &mut Reader<'_>) -> Result<Self, ProgramError> {
        let state = Self {
            bump: r.byte()?,
            epoch: r.id()?,
            id: r.id()?,
            seller: r.id()?,
            refund: r.id()?,
            escrow: r.id()?,
            amount: r.u64()?,
            expected_chunks: r.u32()?,
            version: r.u64()?,
            state: r.byte()?,
            allocated: r.u64()?,
            chunks: r.u32()?,
            consumed: r.u64()?,
            result: r.id()?,
        };
        if !(LOCKED..=WHOLE_RETURNED).contains(&state.state)
            || state.amount == 0
            || state.expected_chunks == 0
            || state.consumed > state.amount
            || state.allocated > state.amount
            || state.chunks > state.expected_chunks
        {
            return Err(fail(Error::State));
        }
        Ok(state)
    }
    fn write(&self, bytes: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer { bytes, offset: 0 };
        w.byte(self.bump);
        for id in [
            &self.epoch,
            &self.id,
            &self.seller,
            &self.refund,
            &self.escrow,
        ] {
            w.put(id);
        }
        w.u64(self.amount);
        w.u32(self.expected_chunks);
        w.u64(self.version);
        w.byte(self.state);
        w.u64(self.allocated);
        w.u32(self.chunks);
        w.u64(self.consumed);
        w.put(&self.result);
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Portion {
    pub bump: u8,
    pub hold: Id,
    pub id: Id,
    pub recipient: Id,
    pub recipient_owner: Id,
    pub offset: u64,
    pub amount: u64,
    pub version: u64,
    pub kind: u8,
    pub state: u8,
    pub allocation: Id,
    pub first_leg_intent: Id,
    pub fence: Id,
    pub custody: Id,
}
impl Stored for Portion {
    const LEN: usize = PORTION_LEN;
    const TAG: &'static [u8; 8] = b"KERBPT01";
    fn read(r: &mut Reader<'_>) -> Result<Self, ProgramError> {
        let state = Self {
            bump: r.byte()?,
            hold: r.id()?,
            id: r.id()?,
            recipient: r.id()?,
            recipient_owner: r.id()?,
            offset: r.u64()?,
            amount: r.u64()?,
            version: r.u64()?,
            kind: r.byte()?,
            state: r.byte()?,
            allocation: r.id()?,
            first_leg_intent: r.id()?,
            fence: r.id()?,
            custody: r.id()?,
        };
        if !(FILL..=UNUSED).contains(&state.kind)
            || !(ALLOCATED..=RETURNED).contains(&state.state)
            || state.amount == 0
        {
            return Err(fail(Error::State));
        }
        Ok(state)
    }
    fn write(&self, bytes: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer { bytes, offset: 0 };
        w.byte(self.bump);
        for id in [&self.hold, &self.id, &self.recipient, &self.recipient_owner] {
            w.put(id);
        }
        w.u64(self.offset);
        w.u64(self.amount);
        w.u64(self.version);
        w.byte(self.kind);
        w.byte(self.state);
        for id in [
            &self.allocation,
            &self.first_leg_intent,
            &self.fence,
            &self.custody,
        ] {
            w.put(id);
        }
        Ok(())
    }
}
