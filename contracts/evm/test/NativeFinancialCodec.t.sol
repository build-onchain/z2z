// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {NativeFinancialCodec} from "../src/NativeFinancialCodec.sol";
import {NativeFinancialVectors} from "./fixtures/NativeFinancialVectors.sol";

contract NativeFinancialCodecHarness {
    function decode(bytes calldata raw) external pure returns (NativeFinancialCodec.Statement memory) {
        return NativeFinancialCodec.decodeStatement(raw);
    }
    function boundary(bytes calldata raw) external pure returns (NativeFinancialCodec.SourceBoundary memory) {
        return NativeFinancialCodec.decodeBoundary(raw);
    }
    function origin(bytes calldata raw, bytes calldata rawBoundary) external pure returns (bytes memory) {
        NativeFinancialCodec.Statement memory statement = NativeFinancialCodec.decodeStatement(raw);
        return NativeFinancialCodec.originJournal(statement, NativeFinancialCodec.contextHash(raw),
            NativeFinancialCodec.decodeBoundary(rawBoundary));
    }
    function journals(bytes calldata raw, bytes calldata rawBoundary, uint8 outcome, uint64 cnet)
        external pure returns (bytes32, bytes memory, bytes memory, bytes memory)
    {
        NativeFinancialCodec.Statement memory statement = NativeFinancialCodec.decodeStatement(raw);
        NativeFinancialCodec.SourceBoundary memory source = NativeFinancialCodec.decodeBoundary(rawBoundary);
        bytes32 context = NativeFinancialCodec.contextHash(raw);
        return (context, NativeFinancialCodec.armJournal(statement, context, source),
            NativeFinancialCodec.resolveJournal(statement, context, source, outcome, cnet),
            NativeFinancialCodec.acceptanceJournal(statement, source));
    }
}

// Codec-only assertions do not authenticate a funded note, accepted source
// boundary, private route terms, source availability or target money rights.
contract NativeFinancialCodecTest {
    NativeFinancialCodecHarness private codec = new NativeFinancialCodecHarness();

    function testIndependentCanonicalStatementAndPurposeJournals() public view {
        bytes memory raw = NativeFinancialVectors.statement();
        NativeFinancialCodec.Statement memory statement = codec.decode(raw);
        require(raw.length == 638 && statement.schemaVersion == 1 && statement.sourcePool == 3, "statement frame");
        require(statement.sourceNetwork == 1 && statement.transactionVersion == 6
            && statement.consensusBranch == 0x37a5165b, "source cohort");
        require(statement.targetChainId == 84532 && statement.obligation == address(0x0505050505050505050505050505050505050505), "target scope");
        require(statement.deploymentDescriptor == NativeFinancialVectors.deploymentDescriptor(), "deployment digest");
        require(statement.payer == address(0x0909090909090909090909090909090909090909)
            && statement.uPayee == address(bytes20(hex"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"))
            && statement.sRefund == address(bytes20(hex"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")), "distinct explicit funding/beneficiaries");
        require(statement.a == 100000000 && statement.d == type(uint256).max
            && statement.jValue == 100020000 && statement.rReturn == 99990000, "exact economic values");
        require(statement.originProgram == bytes32(uint256(type(uint256).max / 255) * 20)
            && statement.jointBinding == NativeFinancialVectors.jointBinding(), "independent origin/funding binding");
        _same(codec.origin(raw, NativeFinancialVectors.boundary()), NativeFinancialVectors.originJournal());
        (bytes32 context, bytes memory arm, bytes memory resolve, bytes memory accepted) =
            codec.journals(raw, NativeFinancialVectors.boundary(), 1, 100000000);
        require(context == NativeFinancialVectors.contextHash(), "statement context digest");
        _same(arm, NativeFinancialVectors.armJournal());
        _same(resolve, NativeFinancialVectors.resolveCJournal());
        _same(accepted, NativeFinancialVectors.acceptanceJournal());
        (, , resolve,) = codec.journals(raw, NativeFinancialVectors.boundary(), 2, 0);
        _same(resolve, NativeFinancialVectors.resolveRJournal());
    }

    function testDeploymentDescriptorMatchesIndependentVector() public pure {
        NativeFinancialCodec.DeploymentDescriptor memory value = NativeFinancialCodec.DeploymentDescriptor({
            schemaVersion: 1, sourceNetwork: 1, sourcePool: 3, transactionVersion: 6,
            consensusBranch: 0x37a5165b, financialProgram: bytes32(uint256(type(uint256).max / 255)),
            originProgram: bytes32(uint256(type(uint256).max / 255) * 20),
            sourceAcceptanceProgram: bytes32(uint256(type(uint256).max / 255) * 2),
            sourcePolicyId: bytes32(uint256(type(uint256).max / 255) * 3), targetChainId: 84532,
            obligation: address(0x0505050505050505050505050505050505050505),
            obligationRuntimeCode: bytes32(uint256(type(uint256).max / 255) * 6),
            verifier: address(0x0707070707070707070707070707070707070707),
            verifierRuntimeCode: bytes32(uint256(type(uint256).max / 255) * 8)
        });
        require(NativeFinancialCodec.deploymentDigest(value) == NativeFinancialVectors.deploymentDescriptor(), "canonical actual deployment descriptor");
    }

    function testTruncationSuffixDomainAndEveryVersionFieldReject() public view {
        bytes memory raw = NativeFinancialVectors.statement();
        for (uint256 length; length < raw.length; ++length) _reject(_range(raw, 0, length));
        _reject(bytes.concat(raw, hex"00"));
        raw[0] ^= bytes1(uint8(1));
        _reject(raw);
        uint256[6] memory offsets = [uint256(27), 28, 29, 33, 37, 26];
        for (uint256 index; index < offsets.length; ++index) {
            raw = NativeFinancialVectors.statement();
            raw[offsets[index]] ^= bytes1(uint8(1));
            _reject(raw);
        }
    }

    function testMissingBindingsAndFinancialMismatchReject() public view {
        uint256[16] memory commitments = [uint256(38), 70, 102, 134, 166, 226, 446, 478, 510, 542, 574, 606, 206, 258, 278, 298];
        for (uint256 index; index < commitments.length; ++index) {
            bytes memory raw = NativeFinancialVectors.statement();
            uint256 width = index < 12 ? 32 : 20;
            for (uint256 byte_; byte_ < width; ++byte_) raw[commitments[index] + byte_] = 0;
            _reject(raw);
        }
        bytes memory wrong = NativeFinancialVectors.statement();
        for (uint256 i; i < 20; ++i) wrong[298 + i] = wrong[278 + i];
        _reject(wrong);
        _reject(_field(NativeFinancialVectors.statement(), 318, 8, 0));
        _reject(_field(NativeFinancialVectors.statement(), 358, 8, 100020001));
        _reject(_field(NativeFinancialVectors.statement(), 366, 8, 99990001));
        _reject(_field(NativeFinancialVectors.statement(), 430, 8, 19999));
        _reject(_field(NativeFinancialVectors.statement(), 386, 4, 4134020));
        _reject(_field(NativeFinancialVectors.statement(), 390, 4, 4465026));
        _reject(_field(NativeFinancialVectors.statement(), 374, 4, 4133999));
    }

    function testBoundaryStrictLengthAndMissingFactsReject() public view {
        bytes memory raw = NativeFinancialVectors.boundary();
        for (uint256 length; length < raw.length; ++length) _rejectBoundary(_range(raw, 0, length));
        _rejectBoundary(bytes.concat(raw, hex"00"));
        _rejectBoundary(_field(raw, 0, 4, 0));
        _rejectBoundary(_field(raw, 0, 4, 4465026));
        _rejectBoundary(_field(raw, 4, 32, 0));
        _rejectBoundary(_field(raw, 36, 32, 0));
        _rejectBoundary(_field(raw, 68, 32, 0));
    }

    function testUnknownOtherExcessAndRecoveryWithPaymentNeverResolve() public view {
        _rejectOutcome(0, 0);
        _rejectOutcome(3, 0);
        _rejectOutcome(255, 100000000);
        _rejectOutcome(1, 0);
        _rejectOutcome(1, 100000001);
        _rejectOutcome(2, 1);
        (, , bytes memory partialJournal,) = codec.journals(NativeFinancialVectors.statement(), NativeFinancialVectors.boundary(), 1, 1);
        require(partialJournal.length == 197 && sha256(partialJournal) != sha256(NativeFinancialVectors.resolveCJournal()), "partial exact consideration binding");
    }

    function _reject(bytes memory raw) private view {
        (bool success, bytes memory reason) = address(codec).staticcall(abi.encodeCall(codec.decode, (raw)));
        require(!success && bytes4(reason) == NativeFinancialCodec.InvalidStatement.selector, "malformed native statement accepted");
    }
    function _rejectBoundary(bytes memory raw) private view {
        (bool success, bytes memory reason) = address(codec).staticcall(abi.encodeCall(codec.boundary, (raw)));
        require(!success && bytes4(reason) == NativeFinancialCodec.InvalidBoundary.selector, "malformed source boundary accepted");
    }
    function _rejectOutcome(uint8 outcome, uint64 cnet) private view {
        (bool success, bytes memory reason) = address(codec).staticcall(abi.encodeCall(codec.journals,
            (NativeFinancialVectors.statement(), NativeFinancialVectors.boundary(), outcome, cnet)));
        require(!success && bytes4(reason) == NativeFinancialCodec.InvalidOutcome.selector, "unqualified outcome allocated");
    }
    function _same(bytes memory actual, bytes memory expected) private pure {
        require(actual.length == expected.length && keccak256(actual) == keccak256(expected), "independent complete canonical bytes");
    }
    function _range(bytes memory raw, uint256 start, uint256 length) private pure returns (bytes memory out) {
        out = new bytes(length);
        assembly ("memory-safe") { mcopy(add(out, 32), add(add(raw, 32), start), length) }
    }
    function _field(bytes memory raw, uint256 start, uint256 width, uint256 value) private pure returns (bytes memory) {
        for (uint256 i; i < width; ++i) raw[start + width - i - 1] = bytes1(uint8(value >> (8 * i)));
        return raw;
    }
}
