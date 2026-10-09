use std::{error::Error, fmt};

use primitive_types::U256;

/// Consensus money-range bound in zatoshis, not a quote or fee policy.
pub const MAX_SOURCE_AMOUNT: u64 = 21_000_000 * 100_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    Negative,
    SourceOutOfRange,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negative => f.write_str("source amount cannot be negative"),
            Self::SourceOutOfRange => {
                f.write_str("source amount exceeds the consensus money range")
            }
        }
    }
}

impl Error for AmountError {}

/// Checked source value in zatoshis. Zero is valid; allocation requires a
/// nonzero quote, while zero authenticated consideration is supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceAmount(u64);

impl SourceAmount {
    pub const fn new(value: u64) -> Result<Self, AmountError> {
        if value > MAX_SOURCE_AMOUNT {
            Err(AmountError::SourceOutOfRange)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SourceAmount {
    type Error = AmountError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<i64> for SourceAmount {
    type Error = AmountError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let unsigned = u64::try_from(value).map_err(|_| AmountError::Negative)?;
        Self::new(unsigned)
    }
}

/// Full-width destination-native value in wei. No token/address selector exists
/// in this native-only statement format. Zero is valid for allocation outputs,
/// but not for funding or a validated statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeAmount(U256);

impl NativeAmount {
    pub const fn new(value: U256) -> Self {
        Self(value)
    }

    pub const fn get(self) -> U256 {
        self.0
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        self.0.to_big_endian(&mut bytes);
        bytes
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(U256::from_big_endian(&bytes))
    }
}
