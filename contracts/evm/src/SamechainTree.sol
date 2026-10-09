// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

/// @notice Depth-32 commitment-tree mathematics, not financial root admission.
/// @dev The authority owns deployment binding, historical roots and output data.
library SamechainTree {
    uint64 internal constant CAPACITY = uint64(1) << 32;

    struct State {
        uint32 treeId;
        uint64 count;
        bytes32[32] frontier;
        bytes32 root;
        bytes32[33] empty;
    }

    struct Insertion {
        uint32 treeId;
        uint32 index;
        uint64 count;
        bytes32 root;
    }

    error InvalidTree();
    error Full();
    error NotFull();
    error Exhausted();

    /// @dev Initialize once; preserves the caller's chosen initial treeId.
    function initialize(State storage state) internal {
        if (state.root != bytes32(0) || state.empty[0] != bytes32(0) || state.count != 0) {
            revert InvalidTree();
        }
        bytes32 current = sha256(abi.encodePacked("Z2Z_SAMECHAIN_MERKLE_EMPTY\x00", uint16(1)));
        state.empty[0] = current;
        for (uint256 height = 1; height <= 32; ++height) {
            current = node(current, current);
            state.empty[height] = current;
        }
        state.root = current;
    }

    function leaf(bytes32 deployment, uint32 treeId, uint32 index, bytes32 commitment)
        internal pure returns (bytes32)
    {
        return sha256(abi.encodePacked(
            "Z2Z_SAMECHAIN_MERKLE_LEAF\x00", uint16(1), deployment, treeId, index, commitment
        ));
    }

    function node(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("Z2Z_SAMECHAIN_MERKLE_NODE\x00", uint16(1), left, right));
    }

    /// @dev A full tree remains intact until the next append triggers rollover.
    /// The returned root is the intermediate root immediately after this note.
    function append(State storage state, bytes32 deployment, bytes32 commitment)
        internal returns (Insertion memory)
    {
        if (deployment == bytes32(0) || commitment == bytes32(0) || state.empty[0] == bytes32(0)) {
            revert InvalidTree();
        }
        if (state.count > CAPACITY) revert Full();
        if (state.count == CAPACITY) rollover(state);

        uint32 index = uint32(state.count);
        bytes32 current = leaf(deployment, state.treeId, index, commitment);
        for (uint256 height; height < 32; ++height) {
            if (((index >> height) & 1) == 0) {
                state.frontier[height] = current;
                current = node(current, state.empty[height]);
            } else {
                current = node(state.frontier[height], current);
            }
        }
        state.count += 1;
        state.root = current;
        return Insertion(state.treeId, index, state.count, current);
    }

    /// @dev Full-only and checked: the final tree identifier never wraps.
    function rollover(State storage state) internal {
        if (state.empty[0] == bytes32(0)) revert InvalidTree();
        if (state.count != CAPACITY) revert NotFull();
        if (state.treeId == type(uint32).max) revert Exhausted();
        state.treeId += 1;
        state.count = 0;
        delete state.frontier;
        state.root = state.empty[32];
    }
}
