// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {NativeEthObligation} from "../src/NativeEthObligation.sol";
import {NativeFinancialCodec} from "../src/NativeFinancialCodec.sol";
import {NativeFinancialVectors} from "./fixtures/NativeFinancialVectors.sol";
import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";

interface NativeEthVm {
    function getCode(string calldata artifact) external returns (bytes memory);
    function getDeployedCode(string calldata artifact) external returns (bytes memory);
    function chainId(uint256 chain) external;
    function deal(address account, uint256 balance) external;
    function warp(uint256 timestamp) external;
}

// Real verifier rejection only. Test pins are not qualified programs/policies.
// No accepting mock, storage-seeded obligation or fake certificate supplies a
// positive money lifecycle. Genuine-proof transfer/retry acceptance is separate.
contract NativeEthObligationTest {
    NativeEthVm private constant VM = NativeEthVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant FINANCIAL_PROGRAM = bytes32(uint256(1));
    bytes32 private constant ORIGIN_PROGRAM = bytes32(uint256(4));
    bytes32 private constant SOURCE_PROGRAM = bytes32(uint256(2));
    bytes32 private constant POLICY = bytes32(uint256(3));
    bytes4 private constant PROOF_SELECTOR = 0x4388a21c;
    uint256 private constant VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352;
    uint256 private constant AMOUNT = 7;
    uint64 private constant QUOTED = 100000000;
    address private constant U_PAYEE = address(0xBEEF);
    address private constant S_REFUND = address(0xCAFE);

    function testConstructorDescriptorBindsActualRuntimeAndAllThreePrograms() public {
        NativeEthObligation obligation = _obligation();
        NativeFinancialCodec.DeploymentDescriptor memory actual = obligation.deployment();
        require(actual.schemaVersion == 1 && actual.sourceNetwork == 1 && actual.sourcePool == 3
            && actual.transactionVersion == 6 && actual.consensusBranch == 0x37a5165b, "source cohort");
        require(actual.financialProgram == FINANCIAL_PROGRAM && obligation.financialProgram() == FINANCIAL_PROGRAM, "financial pin");
        require(actual.originProgram == ORIGIN_PROGRAM && obligation.originProgram() == ORIGIN_PROGRAM, "origin pin");
        require(actual.sourceAcceptanceProgram == SOURCE_PROGRAM && obligation.sourceAcceptanceProgram() == SOURCE_PROGRAM, "acceptance pin");
        require(actual.sourcePolicyId == POLICY && obligation.sourcePolicyId() == POLICY, "policy pin");
        require(actual.targetChainId == block.chainid && obligation.chainId() == block.chainid, "chain pin");
        require(actual.obligation == address(obligation) && actual.obligationRuntimeCode == address(obligation).codehash, "post-construction runtime");
        require(actual.verifier == address(obligation.verifier()) && actual.verifierRuntimeCode == obligation.verifierCode(), "verifier pin");
        require(actual.verifierRuntimeCode == actual.verifier.codehash
            && actual.verifierRuntimeCode == keccak256(VM.getDeployedCode("SP1VerifierGroth16.sol:SP1Verifier")), "not vendored verifier");
        require(obligation.deploymentDigest() == _deploymentDigest(actual), "canonical deployment digest");
        _unchanged(obligation, sha256(_statement(obligation)), NativeFinancialVectors.stableJtag(), 0);
    }

    function testConstructorRejectsMissingPinsSchemaNetworkAndOutOfRangeChain() public {
        _rejectConstructor(bytes32(0), ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, bytes32(0), SOURCE_PROGRAM, POLICY, 1, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, bytes32(0), POLICY, 1, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, bytes32(0), 1, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 0, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 2, 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 0);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 2);
        uint256 chain = block.chainid;
        VM.chainId(0);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 1);
        VM.chainId(uint256(type(uint64).max) + 1);
        _rejectConstructor(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 1);
        VM.chainId(chain);
    }

    function testFundAndArmRequiresDeclaredPayerAndExactValue() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectArm(obligation, _field(_statement(obligation), 258, 20, uint160(address(0xABCD))), boundary,
            proof, proof, proof, AMOUNT, NativeEthObligation.InvalidPayer.selector);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, 0, NativeEthObligation.InvalidValue.selector);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT - 1, NativeEthObligation.InvalidValue.selector);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT + 1, NativeEthObligation.InvalidValue.selector);
    }

    function testFundAndArmPinsEveryProgramPolicyChainAndObligation() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        // Nonzero mutations stay structurally valid, so the live deployment gate
        // rather than codec shape or invalid pairing must reject them.
        uint256[7] memory offsets = [uint256(69), 101, 133, 165, 205, 225, 257];
        for (uint256 index; index < offsets.length; ++index) {
            bytes memory raw = _statement(obligation);
            raw[offsets[index]] ^= bytes1(uint8(0x80));
            _rejectArm(obligation, raw, NativeFinancialVectors.boundary(), proof, proof, proof,
                AMOUNT, NativeEthObligation.InvalidDeployment.selector);
        }
    }

    function testFundAndArmRejectsDescriptorWithWrongRuntimeCodeHashes() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        NativeFinancialCodec.DeploymentDescriptor memory actual = obligation.deployment();
        actual.obligationRuntimeCode ^= bytes32(uint256(1));
        _rejectArm(obligation, _field(_statement(obligation), 226, 32, uint256(_deploymentDigest(actual))),
            NativeFinancialVectors.boundary(), proof, proof, proof, AMOUNT, NativeEthObligation.InvalidDeployment.selector);
        actual = obligation.deployment();
        actual.verifierRuntimeCode ^= bytes32(uint256(1));
        _rejectArm(obligation, _field(_statement(obligation), 226, 32, uint256(_deploymentDigest(actual))),
            NativeFinancialVectors.boundary(), proof, proof, proof, AMOUNT, NativeEthObligation.InvalidDeployment.selector);
    }

    function testFundAndArmRejectsStatementDomainLengthAndSourceCohort() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        bytes memory raw = _statement(obligation);
        _rejectArm(obligation, _prefix(raw, raw.length - 1), NativeFinancialVectors.boundary(), proof, proof, proof,
            AMOUNT, NativeFinancialCodec.InvalidStatement.selector);
        _rejectArm(obligation, bytes.concat(raw, hex"00"), NativeFinancialVectors.boundary(), proof, proof, proof,
            AMOUNT, NativeFinancialCodec.InvalidStatement.selector);
        uint256[7] memory offsets = [uint256(0), 26, 27, 28, 29, 33, 37];
        for (uint256 index; index < offsets.length; ++index) {
            raw = _statement(obligation);
            raw[offsets[index]] ^= bytes1(uint8(1));
            _rejectArm(obligation, raw, NativeFinancialVectors.boundary(), proof, proof, proof,
                AMOUNT, NativeFinancialCodec.InvalidStatement.selector);
        }
    }

    function testFundAndArmRejectsMalformedOrMissingSourceBoundaryFacts() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectArm(obligation, raw, _prefix(boundary, 99), proof, proof, proof, AMOUNT, NativeFinancialCodec.InvalidBoundary.selector);
        _rejectArm(obligation, raw, bytes.concat(boundary, hex"00"), proof, proof, proof, AMOUNT, NativeFinancialCodec.InvalidBoundary.selector);
        _rejectArm(obligation, raw, _field(NativeFinancialVectors.boundary(), 0, 4, 0), proof, proof, proof, AMOUNT, NativeFinancialCodec.InvalidBoundary.selector);
        _rejectArm(obligation, raw, _field(NativeFinancialVectors.boundary(), 0, 4, 4465026), proof, proof, proof, AMOUNT, NativeFinancialCodec.InvalidBoundary.selector);
        uint256[3] memory offsets = [uint256(4), 36, 68];
        for (uint256 index; index < offsets.length; ++index) {
            _rejectArm(obligation, raw, _field(NativeFinancialVectors.boundary(), offsets[index], 32, 0),
                proof, proof, proof, AMOUNT, NativeFinancialCodec.InvalidBoundary.selector);
        }
    }

    function testFundAndArmStrictProofFrameAndRealVerifierRejectionPreserveBacking() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectArm(obligation, raw, boundary, new bytes(355), proof, proof, AMOUNT, NativeEthObligation.InvalidProofLength.selector);
        _rejectArm(obligation, raw, boundary, bytes.concat(proof, hex"00"), proof, proof, AMOUNT, NativeEthObligation.InvalidProofLength.selector);
        _rejectArm(obligation, raw, boundary, _proof(bytes4(0), 0, VK_ROOT), proof, proof, AMOUNT, SP1Verifier.WrongVerifierSelector.selector);
        _rejectArm(obligation, raw, boundary, _proof(PROOF_SELECTOR, 1, VK_ROOT), proof, proof, AMOUNT, SP1Verifier.InvalidExitCode.selector);
        _rejectArm(obligation, raw, boundary, _proof(PROOF_SELECTOR, 0, 0), proof, proof, AMOUNT, SP1Verifier.InvalidVkRoot.selector);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT, Verifier.ProofInvalid.selector);
        // Failed attempts must not leave the guard entered or reserve this J-tag.
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT, Verifier.ProofInvalid.selector);
    }

    function testAllPinnedProgramsRejectTheirCanonicalExpectedJournals() public {
        NativeEthObligation obligation = _obligation();
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        bytes32 context = sha256(raw);
        bytes32 tag = NativeFinancialVectors.stableJtag();
        _directReject(obligation, FINANCIAL_PROGRAM, abi.encodePacked("ziquid.native.arm.v1", context, tag, boundary), proof, Verifier.ProofInvalid.selector);
        _directReject(obligation, ORIGIN_PROGRAM, abi.encodePacked("ziquid.native.origin.v1", context, tag,
            NativeFinancialVectors.jointBinding(), boundary), proof, Verifier.ProofInvalid.selector);
        _directReject(obligation, SOURCE_PROGRAM, abi.encodePacked("ziquid.native.acceptance.v1", uint8(1), POLICY, boundary), proof, Verifier.ProofInvalid.selector);
        _directReject(obligation, FINANCIAL_PROGRAM, abi.encodePacked("ziquid.native.resolve.v1", context, tag, boundary,
            uint8(1), QUOTED), proof, Verifier.ProofInvalid.selector);
        _directReject(obligation, FINANCIAL_PROGRAM, abi.encodePacked("ziquid.native.resolve.v1", context, tag, boundary,
            uint8(2), uint64(0)), proof, Verifier.ProofInvalid.selector);
    }

    function testChangedValidSourceBoundaryStillRequiresAuthenticProof() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        uint256[4] memory offsets = [uint256(3), 35, 67, 99];
        for (uint256 index; index < offsets.length; ++index) {
            bytes memory boundary = NativeFinancialVectors.boundary();
            boundary[offsets[index]] ^= bytes1(uint8(1));
            _rejectArm(obligation, _statement(obligation), boundary, proof, proof, proof, AMOUNT, Verifier.ProofInvalid.selector);
        }
    }

    function testLiveChainMismatchRejectsBothMutatorsAndDeployment() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        uint256 chain = block.chainid;
        VM.chainId(chain + 1);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT, NativeEthObligation.InvalidDeployment.selector);
        _rejectResolve(obligation, raw, boundary, 1, QUOTED, proof, NativeEthObligation.InvalidDeployment.selector);
        (bool success, bytes memory reason) = address(obligation).staticcall(abi.encodeCall(obligation.deployment, ()));
        require(!success && bytes4(reason) == NativeEthObligation.InvalidDeployment.selector, "deployment hid chain mismatch");
        VM.chainId(chain);
        _rejectArm(obligation, raw, boundary, proof, proof, proof, AMOUNT, Verifier.ProofInvalid.selector);
    }

    function testResolveUnarmedPartialFullAndRefundCannotConsumeOrTransfer() public {
        NativeEthObligation obligation = _obligation();
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectResolve(obligation, raw, boundary, 1, 1, proof, NativeEthObligation.NotArmed.selector);
        _rejectResolve(obligation, raw, boundary, 1, QUOTED, proof, NativeEthObligation.NotArmed.selector);
        _rejectResolve(obligation, raw, boundary, 2, 0, proof, NativeEthObligation.NotArmed.selector);
    }

    function testResolveUnknownOtherExcessZeroPaymentAndPayingRefundReject() public {
        NativeEthObligation obligation = _obligation();
        bytes memory raw = _statement(obligation);
        bytes memory boundary = NativeFinancialVectors.boundary();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectResolve(obligation, raw, boundary, 0, 0, proof, NativeFinancialCodec.InvalidOutcome.selector);
        _rejectResolve(obligation, raw, boundary, 3, 0, proof, NativeFinancialCodec.InvalidOutcome.selector);
        _rejectResolve(obligation, raw, boundary, 255, QUOTED, proof, NativeFinancialCodec.InvalidOutcome.selector);
        _rejectResolve(obligation, raw, boundary, 1, 0, proof, NativeFinancialCodec.InvalidOutcome.selector);
        _rejectResolve(obligation, raw, boundary, 1, QUOTED + 1, proof, NativeFinancialCodec.InvalidOutcome.selector);
        _rejectResolve(obligation, raw, boundary, 2, 1, proof, NativeFinancialCodec.InvalidOutcome.selector);
    }

    function testNoReceiveFallbackTimerAdminCancelWithdrawOrUpgradeEntry() public {
        NativeEthObligation obligation = _obligation();
        VM.deal(address(this), 100);
        bytes memory raw = _statement(obligation);
        bytes32 context = sha256(raw);
        bytes32 tag = NativeFinancialVectors.stableJtag();
        _reject(obligation, "", 1, bytes4(0), context, tag);
        VM.warp(type(uint64).max);
        _reject(obligation, "", 0, bytes4(0), context, tag);
        _reject(obligation, hex"deadbeef", 0, bytes4(0), context, tag);
        _reject(obligation, abi.encodeWithSignature("cancel(bytes32)", context), 0, bytes4(0), context, tag);
        _reject(obligation, abi.encodeWithSignature("withdraw(bytes32)", context), 0, bytes4(0), context, tag);
        _reject(obligation, abi.encodeWithSignature("refund(bytes32)", context), 0, bytes4(0), context, tag);
        _reject(obligation, abi.encodeWithSignature("sweep(address)", address(this)), 0, bytes4(0), context, tag);
        _reject(obligation, abi.encodeWithSignature("upgradeTo(address)", address(this)), 0, bytes4(0), context, tag);
        _rejectResolve(obligation, raw, NativeFinancialVectors.boundary(), 2, 0,
            _proof(PROOF_SELECTOR, 0, VK_ROOT), NativeEthObligation.NotArmed.selector);
        // Source heights are not compared to the EVM clock, even after a huge
        // timestamp. A fresh arm still reaches the real pairing rejection.
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _rejectArm(obligation, raw, NativeFinancialVectors.boundary(), proof, proof, proof, AMOUNT, Verifier.ProofInvalid.selector);
    }

    function _statement(NativeEthObligation obligation) private view returns (bytes memory raw) {
        // Reuse the independently frozen economic/window/commitment vector;
        // only deployment, fixed program/policy, payer, payees and D are rebound.
        raw = NativeFinancialVectors.statement();
        _field(raw, 38, 32, uint256(FINANCIAL_PROGRAM));
        _field(raw, 70, 32, uint256(ORIGIN_PROGRAM));
        _field(raw, 102, 32, uint256(SOURCE_PROGRAM));
        _field(raw, 134, 32, uint256(POLICY));
        _field(raw, 198, 8, obligation.chainId());
        _field(raw, 206, 20, uint160(address(obligation)));
        _field(raw, 226, 32, uint256(_deploymentDigest(obligation.deployment())));
        _field(raw, 258, 20, uint160(address(this)));
        _field(raw, 278, 20, uint160(U_PAYEE));
        _field(raw, 298, 20, uint160(S_REFUND));
        _field(raw, 326, 32, AMOUNT);
    }

    function _deploymentDigest(NativeFinancialCodec.DeploymentDescriptor memory value) private pure returns (bytes32) {
        // Do not use the production codec to compute its own expected identity.
        return sha256(abi.encodePacked("ziquid.native.deployment.v1", value.schemaVersion, value.sourceNetwork,
            value.sourcePool, value.transactionVersion, value.consensusBranch, value.financialProgram,
            value.originProgram, value.sourceAcceptanceProgram, value.sourcePolicyId, value.targetChainId,
            value.obligation, value.obligationRuntimeCode, value.verifier, value.verifierRuntimeCode));
    }

    function _rejectArm(NativeEthObligation obligation, bytes memory raw, bytes memory boundary,
        bytes memory armProof, bytes memory originProof, bytes memory acceptanceProof, uint256 value, bytes4 expected)
        private
    {
        _reject(obligation, abi.encodeCall(obligation.fundAndArm, (raw, boundary, armProof, originProof, acceptanceProof)),
            value, expected, sha256(raw), NativeFinancialVectors.stableJtag());
    }

    function _rejectResolve(NativeEthObligation obligation, bytes memory raw, bytes memory boundary,
        uint8 outcome, uint64 cnet, bytes memory proof, bytes4 expected) private
    {
        _reject(obligation, abi.encodeCall(obligation.resolve, (raw, boundary, outcome, cnet, proof, proof)),
            0, expected, sha256(raw), NativeFinancialVectors.stableJtag());
    }

    function _reject(NativeEthObligation obligation, bytes memory callData, uint256 value, bytes4 expected,
        bytes32 context, bytes32 tag) private
    {
        uint256 balance = address(obligation).balance;
        uint256 payerBalance = address(this).balance;
        uint256 userBalance = U_PAYEE.balance;
        uint256 solverBalance = S_REFUND.balance;
        (bool success, bytes memory reason) = address(obligation).call{value: value}(callData);
        require(!success && bytes4(reason) == expected, "wrong native rejection boundary");
        require(address(this).balance == payerBalance && U_PAYEE.balance == userBalance
            && S_REFUND.balance == solverBalance, "rejection changed participant balance");
        _unchanged(obligation, context, tag, balance);
    }

    function _unchanged(NativeEthObligation obligation, bytes32 context, bytes32 tag, uint256 balance) private view {
        require(address(obligation).balance == balance && obligation.totalLiability() == 0, "rejection changed backing");
        require(obligation.contextForTag(tag) == bytes32(0), "rejection reserved J-tag");
        (uint256 d, uint64 a, address payer, address user, address solver, bytes32 storedTag, bool armed, bool consumed) =
            obligation.obligations(context);
        require(d == 0 && a == 0 && payer == address(0) && user == address(0) && solver == address(0)
            && storedTag == bytes32(0) && !armed && !consumed, "rejection created or consumed obligation");
    }

    function _prefix(bytes memory raw, uint256 length) private pure returns (bytes memory result) {
        result = new bytes(length);
        assembly ("memory-safe") { mcopy(add(result, 32), add(raw, 32), length) }
    }

    function _field(bytes memory raw, uint256 start, uint256 width, uint256 value) private pure returns (bytes memory) {
        for (uint256 index; index < width; ++index) raw[start + width - index - 1] = bytes1(uint8(value >> (8 * index)));
        return raw;
    }

    function _obligation() private returns (NativeEthObligation) {
        (address deployed,) = _construct(FINANCIAL_PROGRAM, ORIGIN_PROGRAM, SOURCE_PROGRAM, POLICY, 1, 1);
        require(deployed != address(0), "native obligation construction");
        return NativeEthObligation(deployed);
    }

    function _construct(bytes32 financial, bytes32 origin, bytes32 source, bytes32 policy, uint16 schema, uint8 network)
        private returns (address deployed, bytes memory reason)
    {
        bytes memory code = abi.encodePacked(VM.getCode("NativeEthObligation.sol:NativeEthObligation"),
            abi.encode(financial, origin, source, policy, schema, network));
        assembly ("memory-safe") {
            deployed := create(0, add(code, 0x20), mload(code))
            reason := mload(0x40)
            let size := returndatasize()
            mstore(reason, size)
            returndatacopy(add(reason, 0x20), 0, size)
            mstore(0x40, add(add(reason, 0x20), and(add(size, 0x1f), not(0x1f))))
        }
    }

    function _rejectConstructor(bytes32 financial, bytes32 origin, bytes32 source, bytes32 policy, uint16 schema, uint8 network) private {
        (address deployed, bytes memory reason) = _construct(financial, origin, source, policy, schema, network);
        require(deployed == address(0) && bytes4(reason) == NativeEthObligation.InvalidDeployment.selector, "invalid construction accepted");
    }

    function _proof(bytes4 selector, uint256 exitCode, uint256 root) private pure returns (bytes memory) {
        uint256[8] memory elements;
        // Infinity curve points reach the real pairing equation. This is an
        // invalid witness, never a forged accepting financial certificate.
        return abi.encodePacked(selector, abi.encode(exitCode, root, uint256(0), elements));
    }

    function _directReject(NativeEthObligation obligation, bytes32 program, bytes memory journal, bytes memory proof, bytes4 expected)
        private view
    {
        (bool success, bytes memory reason) = address(obligation.verifier()).staticcall(
            abi.encodeCall(ISP1Verifier.verifyProof, (program, journal, proof)));
        require(!success && bytes4(reason) == expected, "real verifier rejection");
        _unchanged(obligation, sha256(_statement(obligation)), NativeFinancialVectors.stableJtag(), 0);
    }
}
