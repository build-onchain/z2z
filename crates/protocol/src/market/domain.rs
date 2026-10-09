use super::{Id, ProtocolError};

pub const SCHEMA_VERSION: u16 = 1;
pub const SOURCE_NETWORK_TESTNET: u8 = 2;
/// Upstream Ironwood pool discriminant, not a note-encryption domain.
pub const SOURCE_POOL_IRONWOOD: u8 = 4;
pub const SOURCE_BRANCH_NU6_3: u32 = 0x37a5165b;
pub const SOURCE_TRANSACTION_VERSION: u32 = 6;
pub const SIGNATURE_SCHEME_ED25519: u8 = 1;
pub const DOMAIN_LEN: usize = 325;
/// `spl-token-interface`'s legacy Tokenkeg program, not Token-2022.
pub const LEGACY_TOKEN_PROGRAM: Id = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// Exact caller-enrolled monetary context. Its validity does not establish
/// accepted source history, a configured deployment, or an authority roster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Domain {
    pub schema_version: u16,
    pub deployment: Id,
    pub solana_genesis: Id,
    pub solana_program: Id,
    pub mint: Id,
    pub token_program: Id,
    pub source_network: u8,
    pub source_pool: u8,
    pub source_branch: u32,
    pub source_tx_version: u32,
    pub source_genesis: Id,
    pub receiver_policy: Id,
    pub pair: Id,
    pub epoch: u64,
    pub rules_hash: Id,
    pub roster_version: u64,
    pub signature_scheme: u8,
}

impl Domain {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.source_network != SOURCE_NETWORK_TESTNET {
            return Err(ProtocolError::UnsupportedSourceNetwork);
        }
        if self.source_pool != SOURCE_POOL_IRONWOOD {
            return Err(ProtocolError::UnsupportedSourcePool);
        }
        if self.source_branch != SOURCE_BRANCH_NU6_3 {
            return Err(ProtocolError::UnsupportedSourceBranch);
        }
        if self.source_tx_version != SOURCE_TRANSACTION_VERSION {
            return Err(ProtocolError::UnsupportedTransactionVersion);
        }
        if self.signature_scheme != SIGNATURE_SCHEME_ED25519 {
            return Err(ProtocolError::UnsupportedSignatureScheme);
        }
        if self.token_program != LEGACY_TOKEN_PROGRAM {
            return Err(ProtocolError::TokenProgramMismatch);
        }
        if self.roster_version == 0
            || [
                &self.deployment,
                &self.solana_genesis,
                &self.solana_program,
                &self.mint,
                &self.source_genesis,
                &self.receiver_policy,
                &self.pair,
                &self.rules_hash,
            ]
            .iter()
            .any(|id| **id == [0; 32])
        {
            return Err(ProtocolError::InvalidDomain);
        }
        Ok(())
    }

    /// Writes the canonical prefix only; the caller retains any remaining capacity.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate()?;
        let bytes = output
            .get_mut(..DOMAIN_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBDM01");
        bytes[8..10].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[10..42].copy_from_slice(&self.deployment);
        bytes[42..74].copy_from_slice(&self.solana_genesis);
        bytes[74..106].copy_from_slice(&self.solana_program);
        bytes[106..138].copy_from_slice(&self.mint);
        bytes[138..170].copy_from_slice(&self.token_program);
        bytes[170] = self.source_network;
        bytes[171] = self.source_pool;
        bytes[172..176].copy_from_slice(&self.source_branch.to_le_bytes());
        bytes[176..180].copy_from_slice(&self.source_tx_version.to_le_bytes());
        bytes[180..212].copy_from_slice(&self.source_genesis);
        bytes[212..244].copy_from_slice(&self.receiver_policy);
        bytes[244..276].copy_from_slice(&self.pair);
        bytes[276..284].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[284..316].copy_from_slice(&self.rules_hash);
        bytes[316..324].copy_from_slice(&self.roster_version.to_le_bytes());
        bytes[324] = self.signature_scheme;
        Ok(DOMAIN_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, DOMAIN_LEN, b"KERBDM01")?;
        let domain = Self {
            schema_version: u16::from_le_bytes(read_array(bytes, 8)?),
            deployment: read_array(bytes, 10)?,
            solana_genesis: read_array(bytes, 42)?,
            solana_program: read_array(bytes, 74)?,
            mint: read_array(bytes, 106)?,
            token_program: read_array(bytes, 138)?,
            source_network: bytes[170],
            source_pool: bytes[171],
            source_branch: u32::from_le_bytes(read_array(bytes, 172)?),
            source_tx_version: u32::from_le_bytes(read_array(bytes, 176)?),
            source_genesis: read_array(bytes, 180)?,
            receiver_policy: read_array(bytes, 212)?,
            pair: read_array(bytes, 244)?,
            epoch: u64::from_le_bytes(read_array(bytes, 276)?),
            rules_hash: read_array(bytes, 284)?,
            roster_version: u64::from_le_bytes(read_array(bytes, 316)?),
            signature_scheme: bytes[324],
        };
        domain.validate()?;
        Ok(domain)
    }
}

pub(crate) fn check_frame(bytes: &[u8], len: usize, tag: &[u8; 8]) -> Result<(), ProtocolError> {
    if bytes.len() != len {
        return Err(ProtocolError::InvalidLength);
    }
    if &bytes[..8] != tag {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(())
}

pub(crate) fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProtocolError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProtocolError::InvalidLength)
}
