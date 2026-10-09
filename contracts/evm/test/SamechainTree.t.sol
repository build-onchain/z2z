// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {SamechainTree} from "../src/SamechainTree.sol";

// Mathematics only: seeded collapsed subtrees are not admitted financial roots.
contract SamechainTreeHarness {
    SamechainTree.State private tree;

    constructor(uint32 treeId) {
        tree.treeId = treeId;
        SamechainTree.initialize(tree);
    }

    function append(bytes32 deployment, bytes32 commitment)
        external returns (SamechainTree.Insertion memory)
    {
        return SamechainTree.append(tree, deployment, commitment);
    }

    function appendPair(bytes32 deployment, bytes32 first, bytes32 second) external {
        SamechainTree.append(tree, deployment, first);
        SamechainTree.append(tree, deployment, second);
    }

    function rollover() external {
        SamechainTree.rollover(tree);
    }

    function initialize() external {
        SamechainTree.initialize(tree);
    }

    function state() external view returns (SamechainTree.State memory) {
        return tree;
    }

    function seed(SamechainTree.State calldata value) external {
        tree = value;
    }
}

contract SamechainTreeTest {
    bytes32 private constant DEPLOYMENT = hex"0707070707070707070707070707070707070707070707070707070707070707";
    uint32 private constant TREE_ID = 0x01020304;
    uint64 private constant CAPACITY = uint64(1) << 32;

    struct Block {
        uint64 start;
        uint8 height;
        bytes32 root;
    }

    function testSeventeenAppendsMatchActualRustRootsAndIndependentSparseSHA() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(TREE_ID);
        bytes32[33] memory empty = _empty();
        SamechainTree.State memory initial = harness.state();
        require(initial.count == 0 && initial.treeId == TREE_ID, "initial position");
        require(initial.root == hex"b35605a717176cf8a85e2eb0b6ac6f1acc369aaf4193c562f4882cd38cac6745", "Rust empty root");
        require(initial.empty[0] == hex"95130130023a494ac37bcffffccd548d9d349750ff722a0e8a5e41d69f1d8743", "Rust empty leaf");
        for (uint256 height; height <= 32; ++height) {
            require(initial.empty[height] == empty[height], "empty subtree SHA");
        }
        bytes32[17] memory roots = _rustRoots();
        Block[] memory blocks = new Block[](17);
        for (uint32 index; index < 17; ++index) {
            bytes32 commitment = _repeated(uint8(index + 1));
            blocks[index] = Block(index, 0, _leaf(DEPLOYMENT, TREE_ID, index, commitment));
            SamechainTree.Insertion memory insertion = harness.append(DEPLOYMENT, commitment);
            require(insertion.treeId == TREE_ID && insertion.index == index, "insertion position");
            require(insertion.count == uint64(index) + 1, "insertion count");
            require(insertion.root == roots[index], "Rust insertion root");
            require(insertion.root == _sparse(blocks, 0, 32, empty), "independent sparse root");
            SamechainTree.State memory current = harness.state();
            require(current.root == insertion.root && current.count == insertion.count, "stored insertion");
        }
    }

    function testLeafFramingBindsEveryContextAndNodeIsOrdered() public pure {
        bytes32 commitment = _repeated(9);
        uint32 index = 0x80400205;
        bytes32 expected = _leaf(DEPLOYMENT, TREE_ID, index, commitment);
        require(SamechainTree.leaf(DEPLOYMENT, TREE_ID, index, commitment) == expected, "leaf framing");
        require(SamechainTree.leaf(_repeated(8), TREE_ID, index, commitment) != expected, "deployment binding");
        require(SamechainTree.leaf(DEPLOYMENT, TREE_ID + 1, index, commitment) != expected, "tree binding");
        require(SamechainTree.leaf(DEPLOYMENT, TREE_ID, index ^ (uint32(1) << 31), commitment) != expected, "high index binding");
        require(SamechainTree.leaf(DEPLOYMENT, TREE_ID, index ^ 1, commitment) != expected, "low index binding");
        require(SamechainTree.leaf(DEPLOYMENT, TREE_ID, index, _repeated(10)) != expected, "commitment binding");
        require(SamechainTree.node(_repeated(1), _repeated(2)) == _node(_repeated(1), _repeated(2)), "node framing");
        require(SamechainTree.node(_repeated(1), _repeated(2)) != SamechainTree.node(_repeated(2), _repeated(1)), "node ordering");
        bytes32[33] memory empty = _empty();
        require(empty[0] != SamechainTree.leaf(bytes32(0), 0, 0, bytes32(0)), "empty domain");
    }

    function testMixedHighCarryMatchesIndependentCollapsedSubtrees() public {
        uint64[2] memory counts = [uint64(0x7fffffff), uint64(0x89abffff)];
        for (uint256 scenario; scenario < counts.length; ++scenario) {
            SamechainTreeHarness harness = new SamechainTreeHarness(9);
            Block[] memory blocks = _seed(harness, counts[scenario], 9);
            for (uint8 note = 1; note <= 3; ++note) {
                _appendAndCompare(harness, blocks, uint64(counts[scenario] + note - 1), 9, _repeated(note));
            }
        }
    }

    function testFinalIndexReachesU64CapacityAndNextAppendAutomaticallyRollsOver() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(9);
        Block[] memory blocks = _seed(harness, type(uint32).max, 9);
        SamechainTree.Insertion memory last = _appendAndCompare(harness, blocks, type(uint32).max, 9, _repeated(8));
        require(last.count == CAPACITY && last.index == type(uint32).max, "full u64 count");
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (DEPLOYMENT, bytes32(0))), SamechainTree.InvalidTree.selector);
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (bytes32(0), _repeated(9))), SamechainTree.InvalidTree.selector);
        SamechainTree.Insertion memory next = harness.append(DEPLOYMENT, _repeated(9));
        require(next.treeId == 10 && next.index == 0 && next.count == 1, "automatic rollover position");
        Block[] memory nextBlocks = new Block[](1);
        nextBlocks[0] = Block(0, 0, _leaf(DEPLOYMENT, 10, 0, _repeated(9)));
        require(next.root == _sparse(nextBlocks, 0, 32, _empty()), "rollover root");
        require(next.root != last.root, "tree context changed");
        SamechainTree.State memory current = harness.state();
        for (uint256 height; height < 32; ++height) {
            require(current.frontier[height] != bytes32(0), "new first frontier");
        }
        require(current.count == next.count && current.root == next.root, "rollover state");
    }

    function testExplicitRolloverClearsFrontierAndPreservesEmptyHashes() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(9);
        Block[] memory blocks = _seed(harness, type(uint32).max, 9);
        _appendAndCompare(harness, blocks, type(uint32).max, 9, _repeated(8));
        SamechainTree.State memory before = harness.state();
        harness.rollover();
        SamechainTree.State memory afterState = harness.state();
        require(afterState.treeId == 10 && afterState.count == 0, "explicit rollover position");
        require(afterState.root == before.empty[32], "explicit empty root");
        for (uint256 height; height < 32; ++height) {
            require(afterState.frontier[height] == bytes32(0), "frontier not cleared");
        }
        require(keccak256(abi.encode(afterState.empty)) == keccak256(abi.encode(before.empty)), "empty cache changed");
        SamechainTree.Insertion memory next = harness.append(DEPLOYMENT, _repeated(8));
        require(next.treeId == 10 && next.index == 0 && next.count == 1, "explicit next insertion");
    }

    function testFinalTreeAcceptsLastIndexThenExhaustionNeverWrapsOrMutates() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(type(uint32).max);
        Block[] memory blocks = _seed(harness, type(uint32).max, type(uint32).max);
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.rollover, ()), SamechainTree.NotFull.selector);
        SamechainTree.Insertion memory last = _appendAndCompare(harness, blocks, type(uint32).max, type(uint32).max, _repeated(11));
        require(last.treeId == type(uint32).max && last.count == CAPACITY, "final insertion");
        for (uint256 attempt; attempt < 2; ++attempt) {
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.rollover, ()), SamechainTree.Exhausted.selector);
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (DEPLOYMENT, _repeated(12))), SamechainTree.Exhausted.selector);
        }
    }

    function testSecondAppendExhaustionRollsBackFirstAppendInSameTransaction() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(type(uint32).max);
        _seed(harness, type(uint32).max, type(uint32).max);
        _assertRevertsUnchanged(
            harness,
            abi.encodeCall(harness.appendPair, (DEPLOYMENT, _repeated(11), _repeated(12))),
            SamechainTree.Exhausted.selector
        );
        SamechainTree.Insertion memory last = harness.append(DEPLOYMENT, _repeated(11));
        require(last.index == type(uint32).max && last.count == CAPACITY, "last slot lost after revert");
    }

    function testInvalidInputsPrematureRolloverAndReinitializationLeaveAllStateUnchanged() public {
        SamechainTreeHarness harness = new SamechainTreeHarness(TREE_ID);
        for (uint8 count; count < 3; ++count) {
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (DEPLOYMENT, bytes32(0))), SamechainTree.InvalidTree.selector);
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (bytes32(0), _repeated(1))), SamechainTree.InvalidTree.selector);
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.rollover, ()), SamechainTree.NotFull.selector);
            _assertRevertsUnchanged(harness, abi.encodeCall(harness.initialize, ()), SamechainTree.InvalidTree.selector);
            harness.append(DEPLOYMENT, _repeated(count + 1));
        }
        SamechainTree.State memory invalid;
        harness.seed(invalid);
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (DEPLOYMENT, _repeated(1))), SamechainTree.InvalidTree.selector);
        harness.initialize();
        invalid = harness.state();
        invalid.count = CAPACITY + 1;
        harness.seed(invalid);
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.append, (DEPLOYMENT, _repeated(1))), SamechainTree.Full.selector);
        _assertRevertsUnchanged(harness, abi.encodeCall(harness.rollover, ()), SamechainTree.NotFull.selector);
    }

    function _assertRevertsUnchanged(SamechainTreeHarness harness, bytes memory callData, bytes4 selector) private {
        bytes32 before = keccak256(abi.encode(harness.state()));
        (bool success, bytes memory reason) = address(harness).call(callData);
        require(!success && reason.length == 4 && bytes4(reason) == selector, "expected tree error");
        require(keccak256(abi.encode(harness.state())) == before, "failure changed tree");
    }

    function _seed(SamechainTreeHarness harness, uint64 count, uint32 treeId) private returns (Block[] memory blocks) {
        // Each set bit supplies one collapsed perfect subtree, not billions of notes.
        SamechainTree.State memory value = harness.state();
        value.count = count;
        value.treeId = treeId;
        blocks = new Block[](35);
        uint64 start;
        uint256 used;
        for (uint256 height = 32; height > 0;) {
            --height;
            if ((count & (uint64(1) << uint8(height))) == 0) continue;
            bytes32 digest = sha256(abi.encodePacked(_repeated(uint8(height + 1))));
            for (uint256 level; level < height; ++level) digest = _node(digest, digest);
            value.frontier[height] = digest;
            blocks[used++] = Block(start, uint8(height), digest);
            start += uint64(1) << uint8(height);
        }
        require(start == count, "collapsed fixture count");
        value.root = _sparse(blocks, 0, 32, value.empty);
        harness.seed(value);
    }

    function _appendAndCompare(SamechainTreeHarness harness, Block[] memory blocks, uint64 index, uint32 treeId, bytes32 commitment)
        private returns (SamechainTree.Insertion memory insertion)
    {
        uint256 free;
        while (blocks[free].root != bytes32(0)) ++free;
        blocks[free] = Block(index, 0, _leaf(DEPLOYMENT, treeId, uint32(index), commitment));
        bytes32 expected = _sparse(blocks, 0, 32, _empty());
        insertion = harness.append(DEPLOYMENT, commitment);
        require(insertion.treeId == treeId && insertion.index == uint32(index), "collapsed insertion position");
        require(insertion.count == index + 1 && insertion.root == expected, "collapsed insertion root");
        SamechainTree.State memory current = harness.state();
        require(current.count == insertion.count && current.root == expected, "collapsed stored root");
    }

    // Top-down recomputation deliberately does not use a frontier or append loop.
    function _sparse(Block[] memory blocks, uint64 start, uint8 height, bytes32[33] memory empty) private pure returns (bytes32) {
        bool occupied;
        uint64 end = start + (uint64(1) << height);
        for (uint256 i; i < blocks.length; ++i) {
            if (blocks[i].root == bytes32(0)) continue;
            if (blocks[i].start == start && blocks[i].height == height) return blocks[i].root;
            if (blocks[i].start >= start && blocks[i].start < end) occupied = true;
        }
        if (!occupied) return empty[height];
        require(height > 0, "missing fixture leaf");
        uint64 half = uint64(1) << (height - 1);
        return _node(_sparse(blocks, start, height - 1, empty), _sparse(blocks, start + half, height - 1, empty));
    }

    function _leaf(bytes32 deployment, uint32 treeId, uint32 index, bytes32 commitment) private pure returns (bytes32) {
        return sha256(bytes.concat(hex"5a325a5f53414d45434841494e5f4d45524b4c455f4c454146000001", deployment, bytes4(treeId), bytes4(index), commitment));
    }

    function _node(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return sha256(bytes.concat(hex"5a325a5f53414d45434841494e5f4d45524b4c455f4e4f4445000001", left, right));
    }

    function _empty() private pure returns (bytes32[33] memory empty) {
        empty[0] = sha256(hex"5a325a5f53414d45434841494e5f4d45524b4c455f454d505459000001");
        for (uint256 height = 1; height <= 32; ++height) empty[height] = _node(empty[height - 1], empty[height - 1]);
    }

    function _repeated(uint8 value) private pure returns (bytes32) {
        return bytes32((type(uint256).max / 255) * value);
    }

    // Literal roots from samechain-native-vectors.json, produced by actual Rust.
    function _rustRoots() private pure returns (bytes32[17] memory) {
        return [
            bytes32(hex"59b6a5e9c8511df8bab88698baeb9157ff8afbc15ee84b67b339b94b9203d000"),
            bytes32(hex"b1d93d6738a9ff653547ff3466fb5b87ed3d9eb3a2346f2b4407667a060bfdf9"),
            bytes32(hex"f9baefef0bd8dcfb8d20bad619c19f08f0506eddfaf8cb5c0eb94f3284e60b22"),
            bytes32(hex"5fe5d96b8cf4030138d116c4881ed60a0bc5dfa4ce21375c5344a585c6a0547c"),
            bytes32(hex"4469eb836340f84e15f2cb63e0c94b61fc4e5ae45c3c45150784d37195edf4fc"),
            bytes32(hex"d67d1e9b9321fb5d420264dee7a9983345ea944274889f8db767b1c47a034986"),
            bytes32(hex"d81d31df234cc1439e82fde245988208a2e3d8a103106e00d4c89301f530c816"),
            bytes32(hex"1fe09be705257d99af2176889d3e6fa7b88c2dfcf5fabb2143d55e3ec614ce64"),
            bytes32(hex"5472f2e7ecdb258c5971ff2f3468d2f05fb0b71873201adc49d485d7a5d76dcd"),
            bytes32(hex"d884dd1e7e69daa12dc9b6e24aa5a8c795df3a46cf5425cd07510b76ebddb17f"),
            bytes32(hex"b7c7d94d9f5eff8b91f04fb97a5dad810be333d0187918ad7a0ae326aae57e2b"),
            bytes32(hex"f541301f6c0ce76517068dd3be0e9761968d0031ccff57c05945aad27ee7d946"),
            bytes32(hex"bdd72896802fbffec9339cc32467a05bada0ae81333a7211d6557ae6e5ff0207"),
            bytes32(hex"5bab9c9cdd438da8aa731bf38fc206724279a52ec6e3123a3db8ee5cc3e0e43a"),
            bytes32(hex"cbbf2d56d2e2cc3388cdf77552dd50fcfbc8860993380d1e4c34b0a62bbee30a"),
            bytes32(hex"3f23eb271a6df8bd85a54684d3fc5b75e91ce31e0a3e28d41fdd386c316b1152"),
            bytes32(hex"aa133a837731d52ab89282e224ad25ac20b40322aa26150bd07170824875c9b7")
        ];
    }
}
