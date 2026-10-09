use std::{error::Error, fmt};

use primitive_types::{U256, U512};

use crate::{NativeAmount, SourceAmount};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub user: NativeAmount,
    pub solver: NativeAmount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationError {
    ZeroQuote,
    ZeroFunding,
    ExcessConsideration,
    ArithmeticOverflow,
}

impl fmt::Display for AllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroQuote => "quoted source consideration must be nonzero",
            Self::ZeroFunding => "funded native amount must be nonzero",
            Self::ExcessConsideration => "consideration exceeds the quoted source amount",
            Self::ArithmeticOverflow => "allocation exceeds the native amount range",
        })
    }
}

impl Error for AllocationError {}

/// Pure proportional arithmetic, not payment classification or financial
/// authorization: user=floor(funded*consideration/quoted), solver=funded-user.
/// Rounding dust stays with the solver; callers must authenticate consideration.
pub fn allocate(
    quoted: SourceAmount,
    funded: NativeAmount,
    consideration: SourceAmount,
) -> Result<Allocation, AllocationError> {
    if quoted.get() == 0 {
        return Err(AllocationError::ZeroQuote);
    }
    if funded.get().is_zero() {
        return Err(AllocationError::ZeroFunding);
    }
    if consideration > quoted {
        return Err(AllocationError::ExcessConsideration);
    }

    // Full multiplication retains all 512 bits. Since consideration <= quoted,
    // the quotient is <= funded and narrowing cannot discard high bits.
    let product = funded.get().full_mul(U256::from(consideration.get()));
    let quotient = product / U512::from(quoted.get());
    let user = U256::try_from(quotient).map_err(|_| AllocationError::ArithmeticOverflow)?;
    let solver = funded.get() - user;
    Ok(Allocation {
        user: NativeAmount::new(user),
        solver: NativeAmount::new(solver),
    })
}
