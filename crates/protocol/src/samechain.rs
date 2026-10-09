//! Bounded native samechain descriptors and canonical shape checks.
//!
//! No validation, digest, journal constructor or pair check here authenticates
//! ownership, membership, proof validity, asset backing, spentness or transfers.
//! Input owner public keys are disclosed in this finite candidate, not strict GD2.
//! Private order policies remain owner-local, never the public packet.

use std::{error::Error, fmt, io::{self, Write}};

use primitive_types::{U256, U512};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SCHEMA_VERSION: u16 = 1;
pub const RELATION_VERSION: u16 = 1;
pub const MAX_FEE_ENTRIES: usize = 4;
pub const MAX_OUTPUTS: usize = 8;
pub const MAX_CIPHERTEXT_BYTES: usize = 4096;
pub const MAX_PACKET_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamechainError {
    WrongDomain,
    UnsupportedSchema,
    InvalidLength,
    TrailingBytes,
    Oversize,
    InvalidDeployment,
    InvalidAsset,
    InvalidRole,
    InvalidAction,
    InvalidFeePolicy,
    UnlistedFee,
    FeeCapExceeded,
    NonCanonical,
    InvalidPolicy,
    InvalidInput,
    OverlappingInputs,
    InvalidOutput,
    DuplicateOutput,
    InvalidTerms,
    LimitNotMet,
    InvalidBlind,
    OpeningMismatch,
    InvalidJournal,
    JournalMismatch,
    Encoding,
}

impl fmt::Display for SamechainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongDomain => "wrong samechain domain",
            Self::UnsupportedSchema => "unsupported samechain schema",
            Self::InvalidLength => "invalid samechain length",
            Self::TrailingBytes => "trailing samechain bytes",
            Self::Oversize => "samechain bound exceeded",
            Self::InvalidDeployment => "invalid deployment shape",
            Self::InvalidAsset => "invalid asset shape",
            Self::InvalidRole => "invalid role",
            Self::InvalidAction => "invalid action",
            Self::InvalidFeePolicy => "invalid fee policy shape",
            Self::UnlistedFee => "fee not allowed by opened policy",
            Self::FeeCapExceeded => "aggregate fee cap exceeded",
            Self::NonCanonical => "noncanonical samechain ordering",
            Self::InvalidPolicy => "invalid order policy shape",
            Self::InvalidInput => "invalid input shape",
            Self::OverlappingInputs => "overlapping samechain inputs",
            Self::InvalidOutput => "invalid output shape",
            Self::DuplicateOutput => "duplicate samechain output or payment",
            Self::InvalidTerms => "invalid terms shape",
            Self::LimitNotMet => "net buy limit not met",
            Self::InvalidBlind => "invalid terms blind",
            Self::OpeningMismatch => "terms opening mismatch",
            Self::InvalidJournal => "invalid journal shape",
            Self::JournalMismatch => "journal binding mismatch",
            Self::Encoding => "samechain encoding failed",
        })
    }
}

impl Error for SamechainError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub chain_id: u64,
    pub authority: [u8; 20],
    pub authority_code: [u8; 32],
    pub verifier: [u8; 20],
    pub verifier_code: [u8; 32],
    pub owner_program: [u8; 32],
    pub schema: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Asset {
    Native = 0,
    Token([u8; 20]) = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    A = 0,
    B = 1,
}

impl Role {
    pub const fn index(self) -> usize {
        self as usize
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        match reader.byte()? {
            0 => Ok(Self::A),
            1 => Ok(Self::B),
            _ => Err(SamechainError::InvalidRole),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Fill = 0,
    Cancel = 1,
    Exit = 2,
}

impl Action {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        match reader.byte()? {
            0 => Ok(Self::Fill),
            1 => Ok(Self::Cancel),
            2 => Ok(Self::Exit),
            _ => Err(SamechainError::InvalidAction),
        }
    }
}

/// Fill2 is isolated from unchanged cancellation/exit relation identities.
pub const fn owner_relation_version(action: Action) -> u16 {
    match action { Action::Fill => fill::FILL_RELATION_VERSION,
        Action::Cancel | Action::Exit => RELATION_VERSION }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRule {
    pub payer: Role,
    pub asset: Asset,
    pub beneficiary: [u8; 20],
    pub max_atoms: U256,
}

// FeeRule remains Copy; private owners and parsing guards erase their copies.
// Erases owned storage, not all transient arithmetic copies or CPU registers.
impl Zeroize for FeeRule {
    fn zeroize(&mut self) {
        self.beneficiary.zeroize();
        self.max_atoms.0.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    pub entries: Vec<FeeRule>,
}

impl Zeroize for FeePolicy {
    fn zeroize(&mut self) {
        for entry in &mut self.entries { entry.zeroize(); }
        self.entries.spare_capacity_mut().zeroize();
    }
}
impl Drop for FeePolicy {
    fn drop(&mut self) { self.zeroize(); }
}
impl ZeroizeOnDrop for FeePolicy {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderPolicy {
    pub sell_asset: Asset,
    pub buy_asset: Asset,
    pub min_buy_num: U256,
    pub min_sell_den: U256,
    pub fee_policy: FeePolicy,
}

impl Zeroize for OrderPolicy {
    fn zeroize(&mut self) {
        self.min_buy_num.0.zeroize();
        self.min_sell_den.0.zeroize();
        self.fee_policy.zeroize();
    }
}
impl Drop for OrderPolicy {
    fn drop(&mut self) {
        self.min_buy_num.0.zeroize();
        self.min_sell_den.0.zeroize();
        // fee_policy is erased by its own Drop after this body.
    }
}
impl ZeroizeOnDrop for OrderPolicy {}

/// The owner signing public key is public in this finite construction. This is
/// not an ownership certificate and does not satisfy strict own-result GD2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputDescriptor {
    pub commitment: [u8; 32],
    pub root: [u8; 32],
    pub tree_id: u32,
    pub index: u32,
    pub order_id: [u8; 32],
    pub generation: u64,
    pub nullifier: [u8; 32],
    pub owner_key: [u8; 32],
}

/// Ordered opaque notes or exclusive external effects. A payment cannot be
/// declared again under a different Fee/Exit tag or amount for the same key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputDescriptor {
    Note {
        role: Role,
        commitment: [u8; 32],
        recovery_key_commitment: [u8; 32],
        ciphertext_version: u16,
        ciphertext: Vec<u8>,
    },
    Exit {
        role: Role,
        asset: Asset,
        recipient: [u8; 20],
        amount: U256,
    },
    Fee {
        payer: Role,
        asset: Asset,
        recipient: [u8; 20],
        amount: U256,
    },
}


/// Explicit public shape: no plaintext limits, fee-policy openings, nfKey,
/// private note opening or common terms blind. Expiry is target-qualified;
/// this module does not interpret its clock or establish current eligibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPacket {
    pub deployment: Deployment,
    pub inputs: [InputDescriptor; 2],
    pub outputs: Vec<OutputDescriptor>,
    pub expiry: u64,
    pub terms_commitment: [u8; 32],
}

/// Single real backing input for cancellation/exit, not a fabricated second
/// participant. Fee-policy/conservation semantics remain owner-relation checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleOwnerPacket {
    pub deployment: Deployment,
    pub input: InputDescriptor,
    pub outputs: Vec<OutputDescriptor>,
    pub expiry: u64,
    pub terms_commitment: [u8; 32],
}

/// Public statement bytes only. Constructing this journal verifies no proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerJournal {
    pub relation_version: u16,
    pub action: Action,
    pub role: Role,
    pub deployment_digest: [u8; 32],
    pub terms_commitment: [u8; 32],
    pub packet_digest: [u8; 32],
    pub input_nullifier: [u8; 32],
    pub input_commitment: [u8; 32],
    pub root: [u8; 32],
    pub tree_id: u32,
    pub index: u32,
    pub order_id: [u8; 32],
    pub generation: u64,
}

impl Deployment {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if self.schema != SCHEMA_VERSION {
            return Err(SamechainError::UnsupportedSchema);
        }
        if self.chain_id == 0 || is_zero(&self.authority) || is_zero(&self.authority_code)
            || is_zero(&self.verifier) || is_zero(&self.verifier_code) || is_zero(&self.owner_program)
        {
            return Err(SamechainError::InvalidDeployment);
        }
        Ok(())
    }

    fn body_len(&self) -> usize { 8 + 20 + 32 + 20 + 32 + 32 + 2 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.chain_id.to_be_bytes())?;
        out.write_all(&self.authority)?;
        out.write_all(&self.authority_code)?;
        out.write_all(&self.verifier)?;
        out.write_all(&self.verifier_code)?;
        out.write_all(&self.owner_program)?;
        out.write_all(&self.schema.to_be_bytes())
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            chain_id: reader.u64()?, authority: reader.array()?, authority_code: reader.array()?,
            verifier: reader.array()?, verifier_code: reader.array()?, owner_program: reader.array()?,
            schema: reader.u16()?,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }
}

impl Asset {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if matches!(self, Self::Token(address) if is_zero(address)) {
            return Err(SamechainError::InvalidAsset);
        }
        Ok(())
    }

    fn body_len(&self) -> usize { match self { Self::Native => 1, Self::Token(_) => 21 } }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Native => out.write_all(&[0]),
            Self::Token(address) => { out.write_all(&[1])?; out.write_all(address) }
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        match reader.byte()? {
            0 => Ok(Self::Native),
            1 => Ok(Self::Token(reader.array()?)),
            _ => Err(SamechainError::InvalidAsset),
        }
    }
}

impl FeeRule {
    pub fn validate(&self) -> Result<(), SamechainError> {
        self.asset.validate()?;
        if is_zero(&self.beneficiary) { return Err(SamechainError::InvalidFeePolicy); }
        // A zero cap is canonical: this entry authorizes no positive fee.
        Ok(())
    }

    fn key(&self) -> (Role, Asset, [u8; 20]) { (self.payer, self.asset, self.beneficiary) }
    fn body_len(&self) -> usize { 1 + self.asset.body_len() + 20 + 32 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&[self.payer as u8])?;
        self.asset.write_body(out)?;
        out.write_all(&self.beneficiary)?;
        write_atoms(out, self.max_atoms)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        let mut rule = Zeroizing::new(Self { payer: Role::read(reader)?,
            asset: Asset::read_body(reader)?, beneficiary: [0; 20], max_atoms: U256::zero() });
        rule.beneficiary = reader.array()?;
        rule.max_atoms = reader.atoms()?;
        Ok(*rule)
    }
}

impl FeePolicy {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if self.entries.len() > MAX_FEE_ENTRIES { return Err(SamechainError::Oversize); }
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if index > 0 && self.entries[index - 1].key() >= entry.key() {
                return Err(SamechainError::NonCanonical);
            }
        }
        Ok(())
    }

    pub fn validate_for(&self, role: Role, sell: Asset, buy: Asset) -> Result<(), SamechainError> {
        self.validate()?;
        sell.validate()?;
        buy.validate()?;
        if sell == buy || self.entries.iter().any(|entry|
            entry.payer != role || (entry.asset != sell && entry.asset != buy))
        {
            return Err(SamechainError::InvalidFeePolicy);
        }
        Ok(())
    }

    /// Individual descriptive check retained for consumers. Checking entries
    /// one by one is insufficient: use `validate_fees` for a complete manifest.
    pub fn check_fee(&self, payer: Role, asset: Asset, beneficiary: [u8; 20], amount: U256)
        -> Result<(), SamechainError>
    {
        self.validate()?;
        asset.validate()?;
        if amount.is_zero() || is_zero(&beneficiary) { return Err(SamechainError::InvalidOutput); }
        let rule = self.entries.iter().find(|entry| entry.key() == (payer, asset, beneficiary))
            .ok_or(SamechainError::UnlistedFee)?;
        if amount > rule.max_atoms { return Err(SamechainError::FeeCapExceeded); }
        Ok(())
    }

    /// Match every fee for this owner to explicit opened keys, sum in U512,
    /// then reject duplicate/split payments. Other owners are checked separately.
    pub fn validate_fees(&self, role: Role, outputs: &[OutputDescriptor])
        -> Result<(), SamechainError>
    {
        self.aggregate_fees(role, outputs)?;
        validate_outputs(outputs)
    }

    fn aggregate_fees(&self, role: Role, outputs: &[OutputDescriptor])
        -> Result<[U512; MAX_FEE_ENTRIES], SamechainError>
    {
        self.validate()?;
        if self.entries.iter().any(|entry| entry.payer != role) {
            return Err(SamechainError::InvalidFeePolicy);
        }
        if outputs.len() > MAX_OUTPUTS { return Err(SamechainError::Oversize); }
        let mut totals = [U512::zero(); MAX_FEE_ENTRIES];
        for output in outputs {
            output.validate()?;
            if let OutputDescriptor::Fee { payer, asset, recipient, amount } = output {
                if *payer != role { continue; }
                let index = self.entries.iter().position(|entry|
                    entry.key() == (*payer, *asset, *recipient))
                    .ok_or(SamechainError::UnlistedFee)?;
                // At most eight U256 amounts, so the widened sum cannot overflow.
                totals[index] += U512::from(*amount);
            }
        }
        for (entry, total) in self.entries.iter().zip(totals.iter()) {
            if *total > U512::from(entry.max_atoms) { return Err(SamechainError::FeeCapExceeded); }
        }
        Ok(totals)
    }

    pub fn commitment(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }
    fn body_len(&self) -> usize { 4 + self.entries.iter().map(FeeRule::body_len).sum::<usize>() }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        write_count(out, self.entries.len())?;
        for entry in &self.entries { entry.write_body(out)?; }
        Ok(())
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        let count = reader.count(MAX_FEE_ENTRIES)?;
        // Own the fully preallocated vector before any private entry is parsed.
        let mut policy = Self { entries: Vec::with_capacity(count) };
        for _ in 0..count {
            let rule = Zeroizing::new(FeeRule::read_body(reader)?);
            policy.entries.push(*rule);
        }
        Ok(policy)
    }
}

impl OrderPolicy {
    pub fn validate(&self) -> Result<(), SamechainError> {
        self.sell_asset.validate()?;
        self.buy_asset.validate()?;
        self.fee_policy.validate()?;
        if self.sell_asset == self.buy_asset || self.min_buy_num.is_zero() || self.min_sell_den.is_zero()
            || self.fee_policy.entries.iter().any(|entry|
                entry.asset != self.sell_asset && entry.asset != self.buy_asset)
        {
            return Err(SamechainError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn validate_for(&self, role: Role) -> Result<(), SamechainError> {
        self.validate()?;
        self.fee_policy.validate_for(role, self.sell_asset, self.buy_asset)
    }

    /// Exact canonical capacity for owner-local guarded serialization.
    pub fn encoded_len(&self) -> Result<usize, SamechainError> {
        self.validate()?;
        check_frame_size(self)
    }

    /// Stream the canonical frame into caller-owned (possibly guarded) storage.
    pub fn encode_into(&self, out: &mut impl Write) -> Result<(), SamechainError> {
        self.validate()?;
        check_frame_size(self)?;
        write_frame(self, out).map_err(encoding_error)
    }

    fn body_len(&self) -> usize {
        self.sell_asset.body_len() + self.buy_asset.body_len() + 64 + self.fee_policy.body_len()
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        self.sell_asset.write_body(out)?;
        self.buy_asset.write_body(out)?;
        write_atoms(out, self.min_buy_num)?;
        write_atoms(out, self.min_sell_den)?;
        self.fee_policy.write_body(out)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        let mut policy = Self { sell_asset: Asset::read_body(reader)?,
            buy_asset: Asset::read_body(reader)?, min_buy_num: U256::zero(),
            min_sell_den: U256::zero(), fee_policy: FeePolicy { entries: Vec::new() } };
        policy.min_buy_num = reader.atoms()?;
        policy.min_sell_den = reader.atoms()?;
        policy.fee_policy = FeePolicy::read_body(reader)?;
        Ok(policy)
    }
}

impl InputDescriptor {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if is_zero(&self.commitment) || is_zero(&self.root) || is_zero(&self.order_id)
            || is_zero(&self.nullifier) || is_zero(&self.owner_key) || self.generation == 0
        {
            return Err(SamechainError::InvalidInput);
        }
        // Tree zero/index zero are real depth-32 membership positions.
        Ok(())
    }

    fn body_len(&self) -> usize { 32 + 32 + 4 + 4 + 32 + 8 + 32 + 32 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.commitment)?;
        out.write_all(&self.root)?;
        out.write_all(&self.tree_id.to_be_bytes())?;
        out.write_all(&self.index.to_be_bytes())?;
        out.write_all(&self.order_id)?;
        out.write_all(&self.generation.to_be_bytes())?;
        out.write_all(&self.nullifier)?;
        out.write_all(&self.owner_key)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self { commitment: reader.array()?, root: reader.array()?, tree_id: reader.u32()?,
            index: reader.u32()?, order_id: reader.array()?, generation: reader.u64()?,
            nullifier: reader.array()?, owner_key: reader.array()? })
    }
}

impl OutputDescriptor {
    pub const fn role(&self) -> Role {
        match self { Self::Note { role, .. } | Self::Exit { role, .. } => *role,
            Self::Fee { payer, .. } => *payer }
    }

    pub fn validate(&self) -> Result<(), SamechainError> {
        match self {
            Self::Note { commitment, recovery_key_commitment, ciphertext_version, ciphertext, .. } => {
                if ciphertext.len() > MAX_CIPHERTEXT_BYTES { return Err(SamechainError::Oversize); }
                if is_zero(commitment) || is_zero(recovery_key_commitment)
                    || *ciphertext_version == 0 || ciphertext.is_empty()
                {
                    return Err(SamechainError::InvalidOutput);
                }
            }
            Self::Exit { asset, recipient, amount, .. } | Self::Fee { asset, recipient, amount, .. } => {
                asset.validate()?;
                if is_zero(recipient) || amount.is_zero() { return Err(SamechainError::InvalidOutput); }
            }
        }
        // A nonzero ciphertext format is a descriptor, not proof of decryptability.
        Ok(())
    }

    fn payment_key(&self) -> Option<(Role, Asset, [u8; 20])> {
        match self {
            Self::Exit { role, asset, recipient, .. } => Some((*role, *asset, *recipient)),
            Self::Fee { payer, asset, recipient, .. } => Some((*payer, *asset, *recipient)),
            Self::Note { .. } => None,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            Self::Note { ciphertext, .. } => 1 + 1 + 32 + 32 + 2 + 4 + ciphertext.len(),
            Self::Exit { asset, .. } | Self::Fee { asset, .. } => 1 + 1 + asset.body_len() + 20 + 32,
        }
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Note { role, commitment, recovery_key_commitment, ciphertext_version, ciphertext } => {
                out.write_all(&[0, *role as u8])?;
                out.write_all(commitment)?;
                out.write_all(recovery_key_commitment)?;
                out.write_all(&ciphertext_version.to_be_bytes())?;
                write_count(out, ciphertext.len())?;
                out.write_all(ciphertext)
            }
            Self::Exit { role, asset, recipient, amount } => {
                out.write_all(&[1, *role as u8])?;
                asset.write_body(out)?;
                out.write_all(recipient)?;
                write_atoms(out, *amount)
            }
            Self::Fee { payer, asset, recipient, amount } => {
                out.write_all(&[2, *payer as u8])?;
                asset.write_body(out)?;
                out.write_all(recipient)?;
                write_atoms(out, *amount)
            }
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        let tag = reader.byte()?;
        let role = Role::read(reader)?;
        match tag {
            0 => Ok(Self::Note { role, commitment: reader.array()?,
                recovery_key_commitment: reader.array()?, ciphertext_version: reader.u16()?,
                ciphertext: reader.bytes(MAX_CIPHERTEXT_BYTES)?.to_vec() }),
            1 => Ok(Self::Exit { role, asset: Asset::read_body(reader)?,
                recipient: reader.array()?, amount: reader.atoms()? }),
            2 => Ok(Self::Fee { payer: role, asset: Asset::read_body(reader)?,
                recipient: reader.array()?, amount: reader.atoms()? }),
            _ => Err(SamechainError::InvalidOutput),
        }
    }
}


impl PublicPacket {
    pub fn validate(&self) -> Result<(), SamechainError> {
        self.validate_body()?;
        if is_zero(&self.terms_commitment) { return Err(SamechainError::InvalidTerms); }
        Ok(())
    }

    // Fill construction omits only the terminal aggregate commitment check.
    fn validate_body(&self) -> Result<(), SamechainError> {
        self.deployment.validate()?;
        validate_inputs(&self.inputs)?;
        validate_manifest(&self.outputs, &self.inputs)?;
        if self.expiry == 0 { return Err(SamechainError::InvalidTerms); }
        if !self.outputs.iter().any(|output| output.role() == Role::A)
            || !self.outputs.iter().any(|output| output.role() == Role::B)
        {
            return Err(SamechainError::InvalidOutput);
        }
        check_frame_size(self)?;
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize, SamechainError> {
        self.validate()?;
        check_frame_size(self)
    }

    /// Stream the validated canonical frame into caller-owned storage.
    pub fn encode_into(&self, out: &mut impl Write) -> Result<(), SamechainError> {
        self.validate()?;
        write_frame(self, out).map_err(encoding_error)
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_without_commitment_len(&self) -> usize {
        self.deployment.body_len() + 4 + self.inputs.iter().map(InputDescriptor::body_len).sum::<usize>()
            + outputs_len(&self.outputs) + 8
    }

    fn body_len(&self) -> usize { self.body_without_commitment_len() + 32 }

    fn write_body_without_commitment(&self, out: &mut impl Write) -> io::Result<()> {
        self.deployment.write_body(out)?;
        write_count(out, 2)?;
        for input in &self.inputs { input.write_body(out)?; }
        write_outputs(out, &self.outputs)?;
        out.write_all(&self.expiry.to_be_bytes())
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        self.write_body_without_commitment(out)?;
        out.write_all(&self.terms_commitment)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self { deployment: Deployment::read_body(reader)?, inputs: read_inputs(reader)?,
            outputs: read_outputs(reader)?, expiry: reader.u64()?, terms_commitment: reader.array()? })
    }
}

impl SingleOwnerPacket {
    pub fn validate(&self) -> Result<(), SamechainError> {
        validate_single_body(&self.deployment, &self.input, &self.outputs, self.expiry)?;
        if is_zero(&self.terms_commitment) { return Err(SamechainError::InvalidTerms); }
        check_frame_size(self)?;
        Ok(())
    }

    pub fn validate_for(&self, role: Role) -> Result<(), SamechainError> {
        self.validate()?;
        if self.outputs.iter().any(|output| output.role() != role) {
            return Err(SamechainError::InvalidRole);
        }
        Ok(())
    }

    pub fn validate_commitment(&self, blind: &[u8; 32]) -> Result<(), SamechainError> {
        self.validate()?;
        if self.terms_commitment != single_terms_commitment(&self.deployment, &self.input,
            &self.outputs, self.expiry, blind)?
        {
            return Err(SamechainError::OpeningMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize {
        self.deployment.body_len() + self.input.body_len() + outputs_len(&self.outputs) + 8 + 32
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        write_single_body(out, &self.deployment, &self.input, &self.outputs, self.expiry)?;
        out.write_all(&self.terms_commitment)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self { deployment: Deployment::read_body(reader)?, input: InputDescriptor::read_body(reader)?,
            outputs: read_outputs(reader)?, expiry: reader.u64()?, terms_commitment: reader.array()? })
    }
}

/// Salted single-owner terms opening, excluding its own commitment field.
/// Descriptive only: no private input policy, signature or backing is verified.
pub fn single_terms_commitment(deployment: &Deployment, input: &InputDescriptor,
    outputs: &[OutputDescriptor], expiry: u64, blind: &[u8; 32])
    -> Result<[u8; 32], SamechainError>
{
    validate_single_body(deployment, input, outputs, expiry)?;
    if is_zero(blind) { return Err(SamechainError::InvalidBlind); }
    let mut hash = HashWriter(Sha256::new());
    write_header(&mut hash, b"Z2Z_SAMECHAIN_SINGLE_TERMS_COMMITMENT\0").map_err(encoding_error)?;
    hash.write_all(blind).map_err(encoding_error)?;
    write_single_body(&mut hash, deployment, input, outputs, expiry).map_err(encoding_error)?;
    Ok(hash.0.finalize().into())
}

fn validate_single_body(deployment: &Deployment, input: &InputDescriptor,
    outputs: &[OutputDescriptor], expiry: u64) -> Result<(), SamechainError>
{
    deployment.validate()?;
    input.validate()?;
    validate_manifest(outputs, std::slice::from_ref(input))?;
    if expiry == 0 { return Err(SamechainError::InvalidTerms); }
    let owner = outputs[0].role(); // validated nonempty above.
    if outputs.iter().any(|output| output.role() != owner) {
        return Err(SamechainError::InvalidRole);
    }
    // Bounded components total <64KB; no packet or ciphertext clone is needed.
    Ok(())
}

fn write_single_body(out: &mut impl Write, deployment: &Deployment,
    input: &InputDescriptor, outputs: &[OutputDescriptor], expiry: u64) -> io::Result<()>
{
    deployment.write_body(out)?;
    input.write_body(out)?;
    write_outputs(out, outputs)?;
    out.write_all(&expiry.to_be_bytes())
}

impl OwnerJournal {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if self.relation_version != owner_relation_version(self.action) {
            return Err(SamechainError::UnsupportedSchema);
        }
        if is_zero(&self.deployment_digest) || is_zero(&self.terms_commitment)
            || is_zero(&self.packet_digest) || is_zero(&self.input_nullifier)
            || is_zero(&self.input_commitment) || is_zero(&self.root) || is_zero(&self.order_id)
            || self.generation == 0
        {
            return Err(SamechainError::InvalidJournal);
        }
        Ok(())
    }

    /// Descriptive constructor, not verification of the owner's relation/proof.
    pub fn from_packet(packet: &PublicPacket, role: Role, action: Action)
        -> Result<Self, SamechainError>
    {
        if action != Action::Fill { return Err(SamechainError::InvalidAction); }
        packet.validate()?;
        Ok(Self::bind(&packet.inputs[role.index()], role, action, digest_validated_frame(&packet.deployment)?,
            packet.terms_commitment, digest_validated_frame(packet)?))
    }

    /// Cancellation/exit constructor using a single real input.
    pub fn from_single_packet(packet: &SingleOwnerPacket, role: Role, action: Action)
        -> Result<Self, SamechainError>
    {
        if action == Action::Fill { return Err(SamechainError::InvalidAction); }
        packet.validate_for(role)?;
        Ok(Self::bind(&packet.input, role, action, digest_validated_frame(&packet.deployment)?,
            packet.terms_commitment, digest_validated_frame(packet)?))
    }

    fn bind(input: &InputDescriptor, role: Role, action: Action, deployment_digest: [u8; 32],
        terms_commitment: [u8; 32], packet_digest: [u8; 32]) -> Self
    {
        Self { relation_version: owner_relation_version(action), action, role, deployment_digest,
            terms_commitment, packet_digest, input_nullifier: input.nullifier,
            input_commitment: input.commitment, root: input.root, tree_id: input.tree_id,
            index: input.index, order_id: input.order_id, generation: input.generation }
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }
    fn body_len(&self) -> usize { 2 + 1 + 1 + 32 * 7 + 4 + 4 + 8 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.relation_version.to_be_bytes())?;
        out.write_all(&[self.action as u8, self.role as u8])?;
        out.write_all(&self.deployment_digest)?;
        out.write_all(&self.terms_commitment)?;
        out.write_all(&self.packet_digest)?;
        out.write_all(&self.input_nullifier)?;
        out.write_all(&self.input_commitment)?;
        out.write_all(&self.root)?;
        out.write_all(&self.tree_id.to_be_bytes())?;
        out.write_all(&self.index.to_be_bytes())?;
        out.write_all(&self.order_id)?;
        out.write_all(&self.generation.to_be_bytes())
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self { relation_version: reader.u16()?, action: Action::read(reader)?, role: Role::read(reader)?,
            deployment_digest: reader.array()?, terms_commitment: reader.array()?, packet_digest: reader.array()?,
            input_nullifier: reader.array()?, input_commitment: reader.array()?, root: reader.array()?,
            tree_id: reader.u32()?, index: reader.u32()?, order_id: reader.array()?, generation: reader.u64()? })
    }
}

/// Exact A/B descriptive bindings, not proof verification or asset permission.
/// All errors are fixed redacted categories, never journal/terms contents.
pub fn validate_pair(packet: &PublicPacket, journal_a: &OwnerJournal, journal_b: &OwnerJournal)
    -> Result<(), SamechainError>
{
    packet.validate()?;
    journal_a.validate()?;
    journal_b.validate()?;
    let deployment_digest = digest_validated_frame(&packet.deployment)?;
    let packet_digest = digest_validated_frame(packet)?;
    let expected_a = OwnerJournal::bind(&packet.inputs[0], Role::A, Action::Fill,
        deployment_digest, packet.terms_commitment, packet_digest);
    let expected_b = OwnerJournal::bind(&packet.inputs[1], Role::B, Action::Fill,
        deployment_digest, packet.terms_commitment, packet_digest);
    if *journal_a != expected_a || *journal_b != expected_b {
        return Err(SamechainError::JournalMismatch);
    }
    Ok(())
}

/// Bind one cancellation/exit journal to one real input and complete manifest.
/// This does not check proof validity, live backing or actual withdrawal effects.
pub fn validate_single(packet: &SingleOwnerPacket, journal: &OwnerJournal, role: Role, action: Action)
    -> Result<(), SamechainError>
{
    if action == Action::Fill { return Err(SamechainError::InvalidAction); }
    packet.validate_for(role)?;
    journal.validate()?;
    let expected = OwnerJournal::bind(&packet.input, role, action, digest_validated_frame(&packet.deployment)?,
        packet.terms_commitment, digest_validated_frame(packet)?);
    if *journal != expected { return Err(SamechainError::JournalMismatch); }
    Ok(())
}

fn is_zero(bytes: &[u8]) -> bool { bytes.iter().all(|byte| *byte == 0) }

fn validate_inputs(inputs: &[InputDescriptor; 2]) -> Result<(), SamechainError> {
    for input in inputs { input.validate()?; }
    let [a, b] = inputs;
    // This finite two-owner candidate excludes self-trade; not a universal DEX rule.
    if a.commitment == b.commitment || a.nullifier == b.nullifier || a.owner_key == b.owner_key
        || a.order_id == b.order_id || (a.tree_id == b.tree_id && a.index == b.index)
    {
        return Err(SamechainError::OverlappingInputs);
    }
    Ok(())
}

fn validate_outputs(outputs: &[OutputDescriptor]) -> Result<(), SamechainError> {
    if outputs.len() > MAX_OUTPUTS { return Err(SamechainError::Oversize); }
    if outputs.is_empty() { return Err(SamechainError::InvalidOutput); }
    let mut previous_payment = None;
    // Bounded eight-entry scan avoids an allocating set or alternate canonical list.
    for (index, output) in outputs.iter().enumerate() {
        output.validate()?;
        for prior in &outputs[..index] {
            if let (OutputDescriptor::Note { commitment: a, ciphertext: a_bytes, .. },
                OutputDescriptor::Note { commitment: b, ciphertext: b_bytes, .. }) = (prior, output)
                && (a == b || a_bytes == b_bytes)
            {
                return Err(SamechainError::DuplicateOutput);
            }
        }
        if let Some(key) = output.payment_key() {
            if let Some(previous) = previous_payment {
                if key == previous { return Err(SamechainError::DuplicateOutput); }
                if key < previous { return Err(SamechainError::NonCanonical); }
            }
            previous_payment = Some(key);
        }
    }
    Ok(())
}

fn validate_manifest(outputs: &[OutputDescriptor], inputs: &[InputDescriptor])
    -> Result<(), SamechainError>
{
    validate_outputs(outputs)?;
    for output in outputs {
        if let OutputDescriptor::Note { commitment, .. } = output
            && inputs.iter().any(|input| input.commitment == *commitment)
        {
            return Err(SamechainError::DuplicateOutput);
        }
    }
    Ok(())
}

fn outputs_len(outputs: &[OutputDescriptor]) -> usize {
    4 + outputs.iter().map(OutputDescriptor::body_len).sum::<usize>()
}

fn write_count(out: &mut impl Write, count: usize) -> io::Result<()> {
    let count = u32::try_from(count).map_err(|_| io::Error::other("samechain count bound"))?;
    out.write_all(&count.to_be_bytes())
}

fn write_atoms(out: &mut impl Write, mut amount: U256) -> io::Result<()> {
    let mut bytes = Zeroizing::new([0; 32]);
    amount.to_big_endian(&mut *bytes);
    // The fixed-size conversion cannot fail; erase the value before writer errors.
    amount.0.zeroize();
    out.write_all(&*bytes)
}

fn write_outputs(out: &mut impl Write, outputs: &[OutputDescriptor]) -> io::Result<()> {
    write_count(out, outputs.len())?;
    for output in outputs { output.write_body(out)?; }
    Ok(())
}

fn read_inputs(reader: &mut Reader<'_>) -> Result<[InputDescriptor; 2], SamechainError> {
    if reader.count(2)? != 2 { return Err(SamechainError::InvalidLength); }
    Ok([InputDescriptor::read_body(reader)?, InputDescriptor::read_body(reader)?])
}

fn read_outputs(reader: &mut Reader<'_>) -> Result<Vec<OutputDescriptor>, SamechainError> {
    let count = reader.count(MAX_OUTPUTS)?;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count { outputs.push(OutputDescriptor::read_body(reader)?); }
    Ok(outputs)
}

// One serializer feeds both the byte encoder and streaming SHA-256 writer.
// This follows the existing native Write/hash pattern, not separate hash framing.
trait CanonicalFrame: Sized {
    const DOMAIN: &'static [u8];
    const VERSION: u16 = SCHEMA_VERSION;
    fn validate_frame(&self) -> Result<(), SamechainError>;
    fn body_len(&self) -> usize;
    fn write_body(&self, out: &mut impl Write) -> io::Result<()>;
    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError>;
}

macro_rules! frame_codec {
    ($kind:ty, $domain:literal) => {
        impl CanonicalFrame for $kind {
            const DOMAIN: &'static [u8] = $domain;
            fn validate_frame(&self) -> Result<(), SamechainError> { self.validate() }
            fn body_len(&self) -> usize { <$kind>::body_len(self) }
            fn write_body(&self, out: &mut impl Write) -> io::Result<()> { <$kind>::write_body(self, out) }
            fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> { <$kind>::read_body(reader) }
        }
        impl $kind {
            pub fn encode(&self) -> Result<Vec<u8>, SamechainError> { encode_frame(self) }
            pub fn decode(bytes: &[u8]) -> Result<Self, SamechainError> { decode_frame(bytes) }
        }
    };
}

frame_codec!(Deployment, b"Z2Z_SAMECHAIN_DEPLOYMENT\0");
frame_codec!(Asset, b"Z2Z_SAMECHAIN_ASSET\0");
frame_codec!(FeeRule, b"Z2Z_SAMECHAIN_FEE_RULE\0");
frame_codec!(FeePolicy, b"Z2Z_SAMECHAIN_FEE_POLICY\0");
frame_codec!(OrderPolicy, b"Z2Z_SAMECHAIN_ORDER_POLICY\0");
frame_codec!(InputDescriptor, b"Z2Z_SAMECHAIN_INPUT\0");
frame_codec!(OutputDescriptor, b"Z2Z_SAMECHAIN_OUTPUT\0");
frame_codec!(PublicPacket, b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0");
frame_codec!(SingleOwnerPacket, b"Z2Z_SAMECHAIN_SINGLE_PACKET\0");
frame_codec!(OwnerJournal, b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0");

fn check_frame_size<T: CanonicalFrame>(value: &T) -> Result<usize, SamechainError> {
    value.body_len().checked_add(T::DOMAIN.len()).and_then(|len| len.checked_add(2))
        .filter(|len| *len <= MAX_PACKET_BYTES).ok_or(SamechainError::Oversize)
}

fn write_header(out: &mut impl Write, domain: &[u8]) -> io::Result<()> {
    out.write_all(domain)?;
    out.write_all(&SCHEMA_VERSION.to_be_bytes())
}

fn write_frame<T: CanonicalFrame>(value: &T, out: &mut impl Write) -> io::Result<()> {
    out.write_all(T::DOMAIN)?;
    out.write_all(&T::VERSION.to_be_bytes())?;
    value.write_body(out)
}

fn encode_frame<T: CanonicalFrame>(value: &T) -> Result<Vec<u8>, SamechainError> {
    value.validate_frame()?;
    let mut bytes = Vec::with_capacity(check_frame_size(value)?);
    write_frame(value, &mut bytes).map_err(encoding_error)?;
    Ok(bytes)
}

fn decode_frame<T: CanonicalFrame>(bytes: &[u8]) -> Result<T, SamechainError> {
    if bytes.len() > MAX_PACKET_BYTES { return Err(SamechainError::Oversize); }
    let mut reader = Reader(bytes);
    if reader.take(T::DOMAIN.len())? != T::DOMAIN { return Err(SamechainError::WrongDomain); }
    if reader.u16()? != T::VERSION { return Err(SamechainError::UnsupportedSchema); }
    let value = T::read_body(&mut reader)?;
    if !reader.0.is_empty() { return Err(SamechainError::TrailingBytes); }
    value.validate_frame()?;
    Ok(value)
}

fn digest_frame<T: CanonicalFrame>(value: &T) -> Result<[u8; 32], SamechainError> {
    value.validate_frame()?;
    digest_validated_frame(value)
}

// Internal callers have validated the complete record, including nested bodies.
fn digest_validated_frame<T: CanonicalFrame>(value: &T) -> Result<[u8; 32], SamechainError> {
    check_frame_size(value)?;
    let mut hash = HashWriter(Sha256::new());
    write_frame(value, &mut hash).map_err(encoding_error)?;
    Ok(hash.0.finalize().into())
}

fn encoding_error(_: io::Error) -> SamechainError { SamechainError::Encoding }

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SamechainError> {
        let (value, rest) = self.0.split_at_checked(len).ok_or(SamechainError::InvalidLength)?;
        self.0 = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SamechainError> {
        self.take(N)?.try_into().map_err(|_| SamechainError::InvalidLength)
    }

    fn byte(&mut self) -> Result<u8, SamechainError> { Ok(self.array::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, SamechainError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> Result<u32, SamechainError> { Ok(u32::from_be_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, SamechainError> { Ok(u64::from_be_bytes(self.array()?)) }
    fn atoms(&mut self) -> Result<U256, SamechainError> { Ok(U256::from_big_endian(self.take(32)?)) }

    fn count(&mut self, max: usize) -> Result<usize, SamechainError> {
        let count = usize::try_from(self.u32()?).map_err(|_| SamechainError::Oversize)?;
        if count > max { return Err(SamechainError::Oversize); }
        Ok(count)
    }

    fn bytes(&mut self, max: usize) -> Result<&'a [u8], SamechainError> {
        let count = self.count(max)?;
        self.take(count)
    }
}

pub mod withdrawal;

#[path = "samechain/creation.rs"]
pub mod creation;

#[path = "samechain/tree.rs"]
pub mod tree;

#[path = "samechain/fill.rs"]
pub mod fill;
