// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;
import {Allocation} from "../src/Allocation.sol";
contract AllocationSmoke {
    function run(uint256 funded, uint64 quoted, uint64 considered)
        external pure returns (uint256 userWei, uint256 solverWei)
    {
        return Allocation.split(funded, quoted, considered);
    }
}
