// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {Allocation} from "../src/Allocation.sol";

contract AllocationHarness {
    function split(uint256 funded, uint64 quoted, uint64 considered)
        external pure returns (uint256 user, uint256 solver)
    {
        return Allocation.split(funded, quoted, considered);
    }
}

contract AllocationTest {
    function testPartialConservesFundedAmount() public pure {
        (uint256 user, uint256 solver) = Allocation.split(10, 3, 1);
        require(user == 3 && solver == 7, "partial allocation");
        (user, solver) = Allocation.split(10, 3, 2);
        require(user == 6 && solver == 4, "rounding allocation");
    }

    function testBoundaryAllocations() public pure {
        (uint256 user, uint256 solver) = Allocation.split(10, 3, 0);
        require(user == 0 && solver == 10, "nonpayment allocation");
        (user, solver) = Allocation.split(10, 3, 3);
        require(user == 10 && solver == 0, "exact allocation");
    }

    function testFullWidthProductDoesNotOverflow() public pure {
        (uint256 user, uint256 solver) = Allocation.split(type(uint256).max, 3, 2);
        uint256 expected = (type(uint256).max / 3) * 2;
        require(user == expected, "full-width allocation");
        require(solver == type(uint256).max / 3, "full-width conservation");
        (user, solver) = Allocation.split(type(uint256).max, type(uint64).max, type(uint64).max);
        require(user == type(uint256).max && solver == 0, "maximum exact allocation");
    }

    function testInvalidAmountsRevert() public {
        AllocationHarness harness = new AllocationHarness();
        (bool success,) = address(harness).call(abi.encodeCall(harness.split, (10, 0, 0)));
        require(!success, "zero quote accepted");
        (success,) = address(harness).call(abi.encodeCall(harness.split, (10, 3, 4)));
        require(!success, "excess implicitly allocated");
        (success,) = address(harness).call(abi.encodeCall(harness.split, (0, 3, 1)));
        require(!success, "zero funding accepted");
    }

    function testFuzzSplitConservesAndRoundsDown(uint256 funded, uint64 quoted, uint64 considered) public pure {
        if (funded == 0 || quoted == 0 || considered > quoted) return;
        (uint256 user, uint256 solver) = Allocation.split(funded, quoted, considered);
        require(user <= funded && solver == funded - user, "conservation");
        if (funded <= type(uint128).max) {
            require(user == (funded * uint256(considered)) / quoted, "proportional rounding");
        }
        if (considered == quoted) require(user == funded, "full payment");
        if (considered == 0) require(user == 0, "zero payment");
    }
}
