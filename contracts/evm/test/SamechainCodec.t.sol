// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;
import {SamechainCodec} from "../src/SamechainCodec.sol";
import {SamechainNativeVectors} from "./fixtures/SamechainNativeVectors.sol";
import {SamechainFill2Vectors} from "./fixtures/SamechainFill2Vectors.sol";

// Foundry-generated in-process math/codec helpers only; no asset authority or proof verifier.
interface SamechainCodecVm {
    function getCode(string calldata artifactPath) external view returns (bytes memory);
}

contract SamechainCodecHarness {
    function creation(bytes calldata bytes_) external pure returns (bytes memory, bytes32, bytes32) {
        SamechainCodec.Packet memory packet = SamechainCodec.decodeCreation(bytes_);
        return (SamechainCodec.creationJournal(packet), SamechainCodec.deploymentDigest(packet.deployment), packet.initialOrderId);
    }
    function decode(bytes calldata raw, uint8 mode) external pure returns (SamechainCodec.Packet memory) {
        return _decode(raw, mode);
    }
    function journal(bytes calldata raw, uint8 mode, uint8 journalMode, uint8 role, uint8 action)
        external pure returns (bytes memory)
    {
        SamechainCodec.Packet memory packet = _decode(raw, mode);
        if (journalMode == 0) return SamechainCodec.ownerJournal(packet, role, action);
        if (journalMode == 2) return SamechainCodec.withdrawalJournal(packet);
        if (journalMode == 3) return SamechainCodec.creationJournal(packet);
        revert SamechainCodec.InvalidPacket();
    }
    function deployment(SamechainCodec.Deployment calldata value) external pure returns (bytes32) {
        return SamechainCodec.deploymentDigest(value);
    }
    function _decode(bytes calldata raw, uint8 mode) private pure returns (SamechainCodec.Packet memory) {
        if (mode == 0) return SamechainCodec.decodeFill(raw);
        if (mode == 1) return SamechainCodec.decodeSingle(raw);
        if (mode == 2) return SamechainCodec.decodeWithdrawal(raw);
        if (mode == 3) return SamechainCodec.decodeCreation(raw);
        revert SamechainCodec.InvalidPacket();
    }
}

contract SamechainCodecVectors {
    function packet(uint256 index) external pure returns (bytes memory) {
        if (index == 0) return SamechainFill2Vectors.packet();
        return SamechainNativeVectors.packet(index);
    }

    function journal(uint256 index, bool roleB) external pure returns (bytes memory) {
        if (index == 0) return SamechainFill2Vectors.journal(roleB);
        return SamechainNativeVectors.journal(index, roleB);
    }

    function deploymentDigest() external pure returns (bytes32) {
        return SamechainNativeVectors.deploymentDigest();
    }
}

abstract contract SamechainCodecTestBase {
    SamechainCodecHarness internal codec;
    SamechainCodecVectors internal vectors;

    function setUp() public {
        codec = SamechainCodecHarness(_deployArtifact("SamechainCodec.t.sol:SamechainCodecHarness"));
        vectors = SamechainCodecVectors(_deployArtifact("SamechainCodec.t.sol:SamechainCodecVectors"));
    }

    function _deployArtifact(string memory name) private returns (address deployed) {
        SamechainCodecVm vm = SamechainCodecVm(address(uint160(uint256(keccak256("hevm cheat code")))));
        bytes memory code = vm.getCode(name);
        assembly ("memory-safe") { deployed := create(0, add(code, 32), mload(code)) }
        require(deployed != address(0), "test artifact deployment");
    }

    function _mode(uint256 vector) internal pure returns (uint8) {
        return vector == 0 ? 0 : vector < 3 ? 1 : vector < 5 ? 2 : 3;
    }

    function _header(uint8 mode) internal pure returns (uint256) {
        return mode < 2 ? 30 : mode == 2 ? 39 : 37;
    }

    function _outputStart(uint256 vector) internal pure returns (uint256) {
        if (vector == 0) return 536;
        if (vector < 3) return 356;
        if (vector < 5) return 325;
        return vector == 5 ? 322 : vector == 6 ? 342 : vector == 7 ? 354 : 374;
    }

    function _manifest(uint256 vector, bytes memory outputs, uint32 count) internal view returns (bytes memory) {
        bytes memory original = vectors.packet(vector);
        return bytes.concat(_range(original, 0, _outputStart(vector) - 4), abi.encodePacked(count), outputs,
            _range(original, original.length - 40, 40));
    }

    function _creationOutput(bytes memory original, uint256 start, bytes memory output) internal pure returns (bytes memory) {
        return bytes.concat(_range(original, 0, start), output, _range(original, original.length - 40, 40));
    }

    function _note(uint8 role, uint256 commitment, bytes memory ciphertext, uint16 version) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), role, bytes32(commitment), bytes32(uint256(900)), version, uint32(ciphertext.length), ciphertext);
    }

    function _payment(uint8 kind, uint8 role, address asset, address recipient, uint256 amount) internal pure returns (bytes memory) {
        bytes memory assetBytes = asset == address(0) ? abi.encodePacked(uint8(0)) : abi.encodePacked(uint8(1), asset);
        return abi.encodePacked(kind, role, assetBytes, recipient, amount);
    }

    function _range(bytes memory raw, uint256 start, uint256 length) internal pure returns (bytes memory result) {
        require(start <= raw.length && length <= raw.length - start, "test range");
        result = new bytes(length);
        assembly ("memory-safe") { mcopy(add(result, 32), add(add(raw, 32), start), length) }
    }

    function _replace(bytes memory raw, uint256 start, uint256 length, bytes memory replacement) internal pure returns (bytes memory) {
        return bytes.concat(_range(raw, 0, start), replacement, _range(raw, start + length, raw.length - start - length));
    }

    function _field(bytes memory raw, uint256 start, uint256 width, uint256 value) internal pure returns (bytes memory) {
        bytes memory replacement = new bytes(width);
        for (uint256 i; i < width; ++i) replacement[width - 1 - i] = bytes1(uint8(value >> (i * 8)));
        return _replace(raw, start, width, replacement);
    }

    function _number(bytes memory raw, uint256 start, uint256 width) internal pure returns (uint256 result) {
        for (uint256 i; i < width; ++i) result = (result << 8) | uint8(raw[start + i]);
    }

    function _assertOutputFields(SamechainCodec.Output memory output, bytes memory raw, uint256 offset) internal pure {
        if (output.kind == 0) {
            require(output.commitment == bytes32(_number(raw, offset + 2, 32)), "note commitment bytes");
            require(output.recoveryKeyCommitment == bytes32(_number(raw, offset + 34, 32)), "recovery commitment bytes");
            require(output.asset == address(0) && output.recipient == address(0) && output.amount == 0, "note unused payment fields");
        } else {
            bool token = raw[offset + 2] == bytes1(uint8(1));
            uint256 recipientOffset = offset + (token ? 23 : 3);
            address asset = token ? address(uint160(_number(raw, offset + 3, 20))) : address(0);
            require(output.asset == asset, "payment asset tag and address");
            require(output.recipient == address(uint160(_number(raw, recipientOffset, 20))), "payment recipient bytes");
            require(output.amount == _number(raw, recipientOffset + 20, 32), "complete payment integer");
            require(output.commitment == bytes32(0) && output.recoveryKeyCommitment == bytes32(0)
                && output.ciphertextVersion == 0 && output.ciphertext.length == 0, "payment unused note fields");
        }
    }

    function _assertSame(bytes memory actual, bytes memory expected) internal pure {
        require(actual.length == expected.length && sha256(actual) == sha256(expected), "complete journal SHA256");
        for (uint256 i; i < actual.length; ++i) require(actual[i] == expected[i], "complete canonical bytes");
    }

    function _reject(bytes memory raw, uint8 mode) internal view {
        (bool success, bytes memory error) = address(codec).staticcall(abi.encodeCall(codec.decode, (raw, mode)));
        require(!success && error.length == 4 && bytes4(error) == SamechainCodec.InvalidPacket.selector, "malformed packet must fail closed");
    }

    function _rejectJournal(bytes memory raw, uint8 mode, uint8 journalMode, uint8 role, uint8 action) internal view {
        (bool success, bytes memory error) = address(codec).staticcall(abi.encodeCall(codec.journal, (raw, mode, journalMode, role, action)));
        require(!success && error.length == 4 && bytes4(error) == SamechainCodec.InvalidPacket.selector, "wrong journal selection must fail closed");
    }
}

contract SamechainCodecTest is SamechainCodecTestBase {
    function testActualRustCreationOrdinaryAndInitialJournals() public view {
        uint256[4] memory lengths = [uint256(307), 327, 339, 359];
        for (uint256 i = 5; i < 9; ++i) {
            bytes memory raw = vectors.packet(i);
            (bytes memory journal_, bytes32 deployment_, bytes32 initialOrder) = codec.creation(raw);
            require(deployment_ == vectors.deploymentDigest(), "deployment digest");
            _assertSame(journal_, vectors.journal(i, false));
            require(journal_.length == lengths[i - 5], "creation journal length");
            require((initialOrder == bytes32(0)) == (i < 7), "optional initial order");
            SamechainCodec.Packet memory packet = codec.decode(raw, 3);
            require(packet.inputs.length == 0 && packet.outputs.length == 1, "one creation note");
            require(packet.outputs[0].kind == 0 && packet.outputs[0].role == packet.role, "creation role");
            require(packet.asset == ((i == 5 || i == 7) ? address(0) : packet.token), "creation asset");
        }
    }
    function testActualRustFillAndSingleOwnerJournals() public view {
        bytes memory fill = vectors.packet(0);
        _assertSame(codec.journal(fill, 0, 0, 0, 0), vectors.journal(0, false));
        _assertSame(codec.journal(fill, 0, 0, 1, 0), vectors.journal(0, true));
        bytes memory fillJournal = codec.journal(fill, 0, 0, 0, 0);
        require(fillJournal.length == 274 && _number(fillJournal, 28, 2) == 1
            && _number(fillJournal, 30, 2) == 2, "fill2 relation with unchanged outer frame");
        SamechainCodec.Packet memory packet = codec.decode(fill, 0);
        require(packet.inputs.length == 2 && packet.outputs.length == 5, "fill counts");
        require(packet.inputs[0].treeId == 9 && packet.inputs[1].treeId == 9, "tree integers");
        require(packet.inputs[0].index == 0 && packet.inputs[1].index == 1, "role input selection");
        require(packet.inputs[0].generation == 7 && packet.inputs[1].generation == 7, "generation integer");
        for (uint256 i = 1; i < 3; ++i) {
            bytes memory actual = codec.journal(vectors.packet(i), 1, 0, 0, uint8(i));
            require(actual.length == 274, "owner journal length");
            require(_number(actual, 28, 2) == 1 && _number(actual, 30, 2) == 1, "single relation remains one");
            _assertSame(actual, vectors.journal(i, false));
        }
        require(keccak256(vectors.packet(1)) == keccak256(vectors.packet(2)), "same single packet");
        require(keccak256(vectors.journal(1, false)) != keccak256(vectors.journal(2, false)), "action binding");
    }
    function testActualRustOrdinaryWithdrawalJournals() public view {
        for (uint256 i = 3; i < 5; ++i) {
            bytes memory raw = vectors.packet(i);
            bytes memory actual = codec.journal(raw, 2, 2, 0, 0);
            require(actual.length == 242, "withdrawal journal length");
            _assertSame(actual, vectors.journal(i, false));
            SamechainCodec.Packet memory packet = codec.decode(raw, 2);
            require(packet.inputs.length == 1, "ordinary input count");
            require(packet.inputs[0].orderId == bytes32(0) && packet.inputs[0].generation == 0, "ordinary has no order");
            for (uint256 j; j < packet.outputs.length; ++j) require(packet.outputs[j].role == 0, "ordinary role A");
        }
    }
    function testAllNineRustFullPacketDigestsAndCiphertexts() public view {
        bytes32[9] memory digests = [
            SamechainFill2Vectors.digest(),
            hex"334ec6d6a032cdb04c848530dc1f86d4dce973c188def9a78a7a409fda45cc8b",
            hex"334ec6d6a032cdb04c848530dc1f86d4dce973c188def9a78a7a409fda45cc8b",
            hex"22d6e988482a2e73e74c9b0af836e45492aa6b8b3e491adfdd0f0676137e4b50",
            hex"3d2a312cfd20ad4a60db2e650a3e36554a6f453ec1d40ada43756f22b14f87eb",
            hex"878b25f756b409c5722830f449002a26799e352dc56351da5aefbac7d7bb73f5",
            hex"a8f893b2de07e3c06caad86a5f786b154e2e031b8a5008b4ba74e0b5ba1fae78",
            hex"014d2f792797e6a4f6143e15abb15c8f6f9803b2b16805c969f65f14cd72b896",
            hex"25ae6f975051e30caff4dccd1c7142b49520c5ceceaedf2c6de4fbeb7bade04d"
        ];
        for (uint256 i; i < 9; ++i) {
            bytes memory raw = vectors.packet(i);
            SamechainCodec.Packet memory packet = codec.decode(raw, _mode(i));
            require(packet.packetDigest == digests[i] && sha256(raw) == digests[i], "Rust full packet SHA256");
            require(codec.deployment(packet.deployment) == vectors.deploymentDigest(), "Rust deployment SHA256");
            require(packet.expiry == _number(raw, raw.length - 40, 8), "complete expiry integer");
            require(packet.termsCommitment == bytes32(_number(raw, raw.length - 32, 32)), "complete terms bytes");
            uint256 offset = _outputStart(i);
            for (uint256 j; j < packet.outputs.length; ++j) {
                SamechainCodec.Output memory output = packet.outputs[j];
                require(output.kind == uint8(raw[offset]) && output.role == uint8(raw[offset + 1]), "manifest tags");
                _assertOutputFields(output, raw, offset);
                if (output.kind == 0) {
                    uint256 length = _number(raw, offset + 68, 4);
                    require(output.ciphertextVersion == _number(raw, offset + 66, 2), "ciphertext version");
                    _assertSame(output.ciphertext, _range(raw, offset + 72, length));
                    offset += 72 + length;
                } else {
                    offset += raw[offset + 2] == bytes1(0) ? 55 : 75;
                }
            }
            require(offset + 40 == raw.length, "complete manifest bytes");
        }
    }
    function testBigEndianFullWidthIntegersAndZeroTreePositions() public view {
        bytes memory raw = vectors.packet(1);
        raw = _field(raw, 30, 8, type(uint64).max);
        raw = _field(raw, 240, 4, 0x01020304);
        raw = _field(raw, 244, 4, 0x10203040);
        raw = _field(raw, 280, 8, type(uint64).max);
        raw = _field(raw, raw.length - 40, 8, type(uint64).max);
        SamechainCodec.Packet memory packet = codec.decode(raw, 1);
        require(packet.deployment.chainId == type(uint64).max && packet.expiry == type(uint64).max, "u64 not narrowed");
        require(packet.inputs[0].treeId == 0x01020304 && packet.inputs[0].index == 0x10203040, "u32 BE");
        require(packet.inputs[0].generation == type(uint64).max, "generation not narrowed");
        packet = codec.decode(_field(_field(raw, 240, 4, 0), 244, 4, 0), 1);
        require(packet.inputs[0].treeId == 0 && packet.inputs[0].index == 0, "zero tree positions permitted");
        packet = codec.decode(_field(_field(raw, 240, 4, type(uint32).max), 244, 4, type(uint32).max), 1);
        require(packet.inputs[0].treeId == type(uint32).max && packet.inputs[0].index == type(uint32).max, "u32 full width");
        raw = _field(vectors.packet(5), 289, 32, type(uint256).max);
        packet = codec.decode(raw, 3);
        require(packet.amount == type(uint256).max, "creation U256 BE");
        raw = _field(vectors.packet(4), 348, 32, type(uint256).max);
        packet = codec.decode(raw, 2);
        require(packet.outputs[0].amount == type(uint256).max, "payment U256 BE");
    }
    function testFullPacketHashBindsRecoveryVersionCiphertextExpiryAndTerms() public view {
        bytes memory original = vectors.packet(5);
        uint256[6] memory fields = [uint256(255), 356, 389, 394, original.length - 40, original.length - 32];
        for (uint256 i; i < fields.length; ++i) {
            bytes memory changed = _field(original, fields[i], 1, uint8(original[fields[i]]) ^ 128);
            SamechainCodec.Packet memory packet = codec.decode(changed, 3);
            require(packet.packetDigest == sha256(changed) && packet.packetDigest != sha256(original), "full recovery bytes binding");
        }
    }
}

contract SamechainCodecBoundaryTest is SamechainCodecTestBase {
    function testRejectsCrossModeDomainsAndMalformedHeaders() public view {
        for (uint256 i; i < 9; ++i) {
            bytes memory raw = vectors.packet(i);
            uint8 mode = _mode(i);
            for (uint8 other; other < 4; ++other) if (other != mode) _reject(raw, other);
            _reject(_field(raw, 0, 1, 0), mode);
            uint256 header = _header(mode);
            _reject(_field(raw, header - 3, 1, 1), mode); // Mandatory domain NUL.
            _reject(_field(raw, header - 2, 2, 0), mode);
            _reject(_field(raw, header - 2, 2, 2), mode);
            _reject(_field(raw, header - 2, 2, 0x0100), mode); // Not little-endian schema.
            _reject(_field(raw, header + 144, 2, 0), mode);
            _reject(_field(raw, header + 144, 2, 0x0100), mode);
        }
    }
    function testRejectsTruncationTrailingBytesAndOversize() public view {
        for (uint256 i; i < 9; ++i) {
            bytes memory raw = vectors.packet(i);
            uint8 mode = _mode(i);
            uint256 header = _header(mode);
            uint256[13] memory cuts = [uint256(0), header - 3, header - 1, header, header + 7,
                header + 27, header + 59, header + 79, header + 111, header + 145,
                _outputStart(i), raw.length - 40, raw.length - 1];
            for (uint256 j; j < cuts.length; ++j) _reject(_range(raw, 0, cuts[j]), mode);
            _reject(bytes.concat(raw, hex"00"), mode);
            _reject(bytes.concat(raw, new bytes(32)), mode);
            _reject(new bytes(65537), mode);
        }
    }
    function testFuzzEveryStrictPrefixRejects(uint8 vector, uint16 cut) public view {
        uint256 i = uint256(vector) % 9;
        bytes memory raw = vectors.packet(i);
        _reject(_range(raw, 0, uint256(cut) % raw.length), _mode(i));
    }
    function testRejectsInvalidCountsAndLittleEndianCounts() public view {
        bytes memory fill = vectors.packet(0);
        uint256[4] memory inputCounts = [uint256(0), 1, 3, type(uint32).max];
        for (uint256 i; i < inputCounts.length; ++i) _reject(_field(fill, 176, 4, inputCounts[i]), 0);
        _reject(_field(fill, 176, 4, 0x02000000), 0);
        uint256[3] memory vectorIds = [uint256(0), 1, 3];
        uint256[3] memory counts = [uint256(0), 9, type(uint32).max];
        for (uint256 i; i < vectorIds.length; ++i) {
            uint256 vector = vectorIds[i];
            bytes memory raw = vectors.packet(vector);
            for (uint256 j; j < counts.length; ++j) _reject(_field(raw, _outputStart(vector) - 4, 4, counts[j]), _mode(vector));
            _reject(_field(raw, _outputStart(vector) - 4, 4, 0x01000000), _mode(vector));
        }
    }
    function testRejectsZeroDeploymentAndInputIdentities() public view {
        bytes memory fill = vectors.packet(0);
        uint256[7] memory offsets = [uint256(30), 38, 58, 90, 110, 142, 174];
        uint256[7] memory widths = [uint256(8), 20, 32, 20, 32, 32, 2];
        for (uint256 i; i < offsets.length; ++i) _reject(_field(fill, offsets[i], widths[i], 0), 0);
        uint256[6] memory fields = [uint256(0), 32, 72, 104, 112, 144];
        for (uint256 input; input < 2; ++input) {
            for (uint256 i; i < fields.length; ++i) {
                _reject(_field(fill, 180 + input * 176 + fields[i], fields[i] == 104 ? 8 : 32, 0), 0);
            }
        }
        bytes memory ordinary = vectors.packet(4);
        uint256[4] memory ordinaryFields = [uint256(0), 32, 72, 104];
        for (uint256 i; i < ordinaryFields.length; ++i) _reject(_field(ordinary, 185 + ordinaryFields[i], 32, 0), 2);
    }
    function testRejectsZeroExpiryAndTermsAcrossAllModes() public view {
        for (uint256 i; i < 9; ++i) {
            bytes memory raw = vectors.packet(i);
            _reject(_field(raw, raw.length - 40, 8, 0), _mode(i));
            _reject(_field(raw, raw.length - 32, 32, 0), _mode(i));
        }
    }
    function testCreationRequiresCanonicalOptionalOrderAndExactlyOneNote() public view {
        bytes memory ordinary = vectors.packet(5);
        _reject(_field(ordinary, 321, 1, 2), 3);
        _reject(_field(ordinary, 321, 1, 255), 3);
        _reject(_replace(ordinary, 322, 0, new bytes(32)), 3); // None has no ID bytes.
        bytes memory initial = vectors.packet(7);
        _reject(_field(initial, 322, 32, 0), 3);
        _reject(_replace(initial, 322, 32, hex""), 3); // Some requires its whole ID.
        _reject(_creationOutput(ordinary, 322, _payment(1, 0, address(0), address(9), 1)), 3);
        _reject(_creationOutput(ordinary, 322, _payment(2, 0, address(0), address(9), 1)), 3);
        _reject(_creationOutput(ordinary, 322, bytes.concat(_note(0, 1, hex"01", 1), _note(0, 2, hex"02", 1))), 3);
        _reject(_field(ordinary, 323, 1, 1), 3); // Output must use creation's role.
        _reject(_field(ordinary, 287, 1, 2), 3);
        _reject(_field(ordinary, 288, 1, 2), 3);
        _reject(_field(ordinary, 183, 20, 0), 3);
        _reject(_field(ordinary, 203, 20, 0), 3);
        _reject(_field(ordinary, 223, 32, 0), 3);
        _reject(_field(ordinary, 255, 32, 0), 3);
        _reject(_field(ordinary, 289, 32, 0), 3);
        bytes memory token = vectors.packet(6);
        _reject(_field(token, 289, 20, 0), 3);
        _reject(_field(token, 289, 20, 1), 3); // Nonzero but not the fixed token.
    }
    function testRejectsOutputTagsRolesAssetsRecipientsAndZeroAmounts() public view {
        bytes memory ordinary = vectors.packet(4);
        _reject(_field(ordinary, 325, 1, 3), 2);
        _reject(_field(ordinary, 325, 1, 255), 2);
        _reject(_field(ordinary, 326, 1, 2), 2);
        _reject(_field(ordinary, 326, 1, 255), 2);
        _reject(_field(ordinary, 327, 1, 2), 2);
        _reject(_field(ordinary, 328, 20, 0), 2);
        _reject(_field(ordinary, 348, 32, 0), 2);
        bytes memory token = vectors.packet(3);
        _reject(_field(token, 328, 20, 0), 2);
        bytes memory note = vectors.packet(5);
        _reject(_field(note, 322, 1, 3), 3);
        _reject(_field(note, 323, 1, 2), 3);
        _reject(_field(note, 324, 32, 0), 3);
        _reject(_field(note, 356, 32, 0), 3);
        _reject(_field(note, 388, 2, 0), 3);
        bytes memory countedCreation = _replace(note, 322, 0, abi.encodePacked(uint32(1)));
        _reject(countedCreation, 3); // Creation has no output count field.
    }
}

contract SamechainCodecManifestTest is SamechainCodecTestBase {
    function testRejectsEveryFillInputOverlapAndMissingRole() public view {
        bytes memory raw = vectors.packet(0);
        uint256[4] memory fields = [uint256(0), 72, 112, 144];
        for (uint256 i; i < fields.length; ++i) {
            _reject(_replace(raw, 356 + fields[i], 32, _range(raw, 180 + fields[i], 32)), 0);
        }
        _reject(_replace(raw, 420, 8, _range(raw, 244, 8)), 0);
        _reject(_manifest(0, bytes.concat(_note(0, 1, hex"01", 1), _note(0, 2, hex"02", 1)), 2), 0);
        _reject(_manifest(0, bytes.concat(_note(1, 1, hex"01", 1), _note(1, 2, hex"02", 1)), 2), 0);
    }
    function testCiphertextAndManifestBounds() public view {
        bytes memory ordinary = vectors.packet(5);
        _reject(_field(ordinary, 390, 4, 0), 3);
        _reject(_field(ordinary, 390, 4, 4097), 3);
        _reject(_field(ordinary, 390, 4, type(uint32).max), 3);
        _reject(_field(ordinary, 390, 4, 0x07010000), 3); // Ciphertext count is BE, not LE.
        bytes memory raw = _creationOutput(ordinary, 322, _note(0, 1, hex"ab", type(uint16).max));
        SamechainCodec.Packet memory packet = codec.decode(raw, 3);
        require(packet.outputs[0].ciphertext.length == 1 && packet.outputs[0].ciphertextVersion == type(uint16).max, "nonzero descriptor version");
        bytes memory ciphertext = new bytes(4096);
        bytes memory manifest;
        for (uint256 i; i < 8; ++i) {
            ciphertext[0] = bytes1(uint8(i));
            manifest = bytes.concat(manifest, _note(uint8(i % 2), i + 1, ciphertext, 1));
        }
        packet = codec.decode(_manifest(0, manifest, 8), 0);
        require(packet.outputs.length == 8 && packet.outputs[7].ciphertext.length == 4096, "maximum bounded manifest");
        raw = _creationOutput(ordinary, 322, _note(0, 1, new bytes(4097), 1));
        _reject(raw, 3);
        raw = _manifest(1, _note(0, 1, hex"01", 1), 1);
        raw = _field(raw, 356 + 68, 4, 2);
        raw = _field(raw, raw.length - 40, 1, 128);
        _reject(raw, 1); // Length cannot consume an expiry byte and silently pad EOF.
    }

    function testEightPaymentLimitRejectsCompleteNinthPayment() public view {
        bytes memory manifest;
        for (uint256 i; i < 8; ++i) {
            uint8 role = i < 4 ? 0 : 1;
            manifest = bytes.concat(manifest,
                _payment(uint8(1 + i % 2), role, address(0), address(uint160(i + 1)), i + 1));
        }
        bytes memory eight = _manifest(0, manifest, 8);
        SamechainCodec.Packet memory packet = codec.decode(eight, 0);
        require(packet.outputs.length == 8 && packet.outputs[0].role == 0
            && packet.outputs[7].role == 1 && packet.outputs[7].amount == 8, "eight complete payments accepted");
        manifest = bytes.concat(manifest, _payment(1, 1, address(0), address(9), 9));
        bytes memory nine = _manifest(0, manifest, 9);
        require(nine.length == eight.length + 55, "complete ninth native payment");
        _reject(nine, 0); // Otherwise canonical, both roles, full EOF; no Note hash-array bounds mask.
    }
    function testRejectsDuplicateNoteCommitmentsCiphertextsAndConsumedCommitments() public view {
        _reject(_manifest(0, bytes.concat(_note(0, 1, hex"01", 1), _note(1, 1, hex"02", 1)), 2), 0);
        _reject(_manifest(0, bytes.concat(_note(0, 1, hex"abcd", 1), _note(1, 2, hex"abcd", 2)), 2), 0);
        bytes memory raw = vectors.packet(0);
        bytes memory manifest = bytes.concat(_note(0, 1, hex"01", 1), _note(1, 2, hex"02", 1));
        for (uint256 i; i < 2; ++i) {
            _reject(_manifest(0, _replace(manifest, 2, 32, _range(raw, 180 + i * 176, 32)), 2), 0);
        }
        bytes memory single = _manifest(1, _note(0, 1, hex"01", 1), 1);
        _reject(_replace(single, 358, 32, _range(single, 176, 32)), 1);
        bytes memory ordinary = _manifest(4, bytes.concat(_note(0, 1, hex"01", 1), _payment(1, 0, address(0), address(9), 1)), 2);
        _reject(_replace(ordinary, 327, 32, _range(ordinary, 185, 32)), 2);
    }
    function testCanonicalPaymentsOrderUsesRoleAssetTagAddressThenRecipient() public view {
        bytes memory manifest = bytes.concat(
            _payment(1, 0, address(0), address(255), 1),
            _note(1, 1, hex"01", 1),
            _payment(2, 0, address(1), address(1), 2),
            _payment(1, 0, address(2), address(1), 3),
            _payment(1, 0, address(2), address(2), 4),
            _payment(2, 1, address(0), address(1), 5)
        );
        SamechainCodec.Packet memory packet = codec.decode(_manifest(0, manifest, 6), 0);
        require(packet.outputs.length == 6, "strict canonical payment subsequence");
        _reject(_manifest(0, bytes.concat(_payment(1, 1, address(0), address(1), 1), _payment(1, 0, address(0), address(2), 2)), 2), 0);
        _reject(_manifest(0, bytes.concat(_payment(1, 0, address(2), address(1), 1), _payment(2, 0, address(1), address(2), 2), _note(1, 1, hex"01", 1)), 3), 0);
        _reject(_manifest(0, bytes.concat(_payment(1, 0, address(0), address(2), 1), _payment(2, 0, address(0), address(1), 2), _note(1, 1, hex"01", 1)), 3), 0);
        _reject(_manifest(0, bytes.concat(_payment(1, 0, address(1), address(9), 1), _note(1, 1, hex"01", 1), _payment(2, 0, address(1), address(9), 999)), 3), 0);
    }
    function testSingleSelectedRoleAndActionAndOrdinaryExitRequirement() public view {
        bytes memory raw = vectors.packet(1);
        uint256 payment = 356 + 72 + 263;
        bytes memory roleB = _field(_field(raw, 357, 1, 1), payment + 1, 1, 1);
        SamechainCodec.Packet memory packet = codec.decode(roleB, 1);
        require(packet.outputs[0].role == 1 && packet.outputs[1].role == 1, "single role B");
        bytes memory actual = codec.journal(roleB, 1, 0, 1, 1);
        require(actual.length == 274 && actual[32] == bytes1(uint8(1)) && actual[33] == bytes1(uint8(1)), "selected B cancel journal");
        actual = codec.journal(roleB, 1, 0, 1, 2);
        require(actual[32] == bytes1(uint8(2)) && actual[33] == bytes1(uint8(1)), "selected B exit journal");
        _reject(_field(raw, payment + 1, 1, 1), 1);
        _rejectJournal(raw, 1, 0, 1, 1);
        _rejectJournal(roleB, 1, 0, 0, 2);
        _rejectJournal(raw, 1, 0, 0, 0);
        _rejectJournal(raw, 1, 0, 2, 1);
        _rejectJournal(raw, 1, 0, 0, 3);
        _rejectJournal(vectors.packet(0), 0, 0, 0, 1);
        _rejectJournal(vectors.packet(0), 0, 0, 1, 2);
        _rejectJournal(vectors.packet(0), 0, 0, 2, 0);
        bytes memory noteOnly = _manifest(1, _note(0, 1, hex"01", 1), 1);
        require(codec.journal(noteOnly, 1, 0, 0, 1).length == 274, "cancel may return ordinary note");
        require(codec.journal(noteOnly, 1, 0, 0, 2).length == 274, "exit action does not invent transfer");
        _reject(_manifest(4, _note(0, 1, hex"01", 1), 1), 2);
        _reject(_manifest(4, _payment(2, 0, address(0), address(9), 1), 1), 2);
        _reject(_manifest(4, _payment(1, 1, address(0), address(9), 1), 1), 2);
        bytes memory received = vectors.packet(3);
        _reject(_field(received, 325 + 75 + 1, 1, 1), 2); // Every output, including ordinary change, is Role A.
    }
    function testRejectsJournalModeCrossing() public view {
        uint256[4] memory vectorIds = [uint256(0), 1, 4, 5];
        for (uint256 i; i < vectorIds.length; ++i) {
            uint256 vector = vectorIds[i];
            bytes memory raw = vectors.packet(vector);
            uint8 mode = _mode(vector);
            if (mode != 0 && mode != 1) _rejectJournal(raw, mode, 0, 0, 1);
            if (mode != 2) _rejectJournal(raw, mode, 2, 0, 0);
            if (mode != 3) _rejectJournal(raw, mode, 3, 0, 0);
        }
    }
}

