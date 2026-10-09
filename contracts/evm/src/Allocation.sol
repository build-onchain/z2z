// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

/// @notice Arithmetic only; callers must authenticate consideration before moving funds.
library Allocation {
    error InvalidAmounts();

    function split(uint256 funded, uint64 quoted, uint64 considered)
        internal pure returns (uint256 user, uint256 solver)
    {
        if (funded == 0 || quoted == 0 || considered > quoted) revert InvalidAmounts();

        // floor(D*C/A) without overflowing D*C. The remainder product fits uint128;
        // C <= A guarantees the quotient product and final allocation cannot exceed D.
        user = (funded / quoted) * considered
            + ((funded % quoted) * uint256(considered)) / quoted;
        solver = funded - user;
    }
}
