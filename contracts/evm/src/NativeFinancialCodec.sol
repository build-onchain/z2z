// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

/// @notice Exact protocol::native public encoding; parsing supplies no source acceptance.
library NativeFinancialCodec {
    uint16 internal constant SCHEMA_VERSION = 1;
    uint8 internal constant SOURCE_NETWORK = 1;
    uint8 internal constant SOURCE_POOL = 3;
    uint32 internal constant TRANSACTION_VERSION = 6;
    uint32 internal constant CONSENSUS_BRANCH = 0x37a5165b;
    uint32 internal constant IRONWOOD_ACTIVATION = 4134000;
    uint32 internal constant NEXT_UPGRADE = 4465026;
    uint64 internal constant MAX_SOURCE_AMOUNT = 2100000000000000;

    error InvalidStatement();
    error InvalidBoundary();
    error InvalidOutcome();

    struct DeploymentDescriptor {
        uint16 schemaVersion;
        uint8 sourceNetwork;
        uint8 sourcePool;
        uint32 transactionVersion;
        uint32 consensusBranch;
        bytes32 financialProgram;
        bytes32 originProgram;
        bytes32 sourceAcceptanceProgram;
        bytes32 sourcePolicyId;
        uint64 targetChainId;
        address obligation;
        bytes32 obligationRuntimeCode;
        address verifier;
        bytes32 verifierRuntimeCode;
    }

    struct Statement {
        uint16 schemaVersion;
        uint8 sourceNetwork;
        uint8 sourcePool;
        uint32 transactionVersion;
        uint32 consensusBranch;
        bytes32 financialProgram;
        bytes32 originProgram;
        bytes32 sourceAcceptanceProgram;
        bytes32 sourcePolicyId;
        bytes32 windowPolicyCommitment;
        uint64 targetChainId;
        address obligation;
        bytes32 deploymentDescriptor;
        address payer;
        address uPayee;
        address sRefund;
        uint64 a;
        uint256 d;
        uint64 jValue;
        uint64 rReturn;
        uint32 fTarget;
        uint32 cTarget;
        uint32 rTarget;
        uint32 fExpiry;
        uint32 cExpiry;
        uint32 rExpiry;
        uint64 feeF;
        uint64 feeC;
        uint64 feeR;
        uint64 feeCapF;
        uint64 feeCapC;
        uint64 feeCapR;
        bytes32 quoteCommitment;
        bytes32 agreementCommitment;
        bytes32 groupGrantCommitment;
        bytes32 sourceTermsCommitment;
        bytes32 jointBinding;
        bytes32 stableJtag;
    }

    struct SourceBoundary {
        uint32 height;
        bytes32 blockHash;
        uint256 cumulativeWork;
        bytes32 ledgerJournalDigest;
    }

    function decodeStatement(bytes calldata raw) internal pure returns (Statement memory value) {
        if (raw.length != 638 || keccak256(raw[:26]) != keccak256("ziquid.native.statement.v1")) {
            revert InvalidStatement();
        }
        value.schemaVersion = uint16(_number(raw, 26, 2));
        value.sourceNetwork = uint8(_number(raw, 28, 1));
        value.sourcePool = uint8(_number(raw, 29, 1));
        value.transactionVersion = uint32(_number(raw, 30, 4));
        value.consensusBranch = uint32(_number(raw, 34, 4));
        value.financialProgram = bytes32(_number(raw, 38, 32));
        value.originProgram = bytes32(_number(raw, 70, 32));
        value.sourceAcceptanceProgram = bytes32(_number(raw, 102, 32));
        value.sourcePolicyId = bytes32(_number(raw, 134, 32));
        value.windowPolicyCommitment = bytes32(_number(raw, 166, 32));
        value.targetChainId = uint64(_number(raw, 198, 8));
        value.obligation = address(uint160(_number(raw, 206, 20)));
        value.deploymentDescriptor = bytes32(_number(raw, 226, 32));
        value.payer = address(uint160(_number(raw, 258, 20)));
        value.uPayee = address(uint160(_number(raw, 278, 20)));
        value.sRefund = address(uint160(_number(raw, 298, 20)));
        value.a = uint64(_number(raw, 318, 8));
        value.d = _number(raw, 326, 32);
        value.jValue = uint64(_number(raw, 358, 8));
        value.rReturn = uint64(_number(raw, 366, 8));
        value.fTarget = uint32(_number(raw, 374, 4));
        value.cTarget = uint32(_number(raw, 378, 4));
        value.rTarget = uint32(_number(raw, 382, 4));
        value.fExpiry = uint32(_number(raw, 386, 4));
        value.cExpiry = uint32(_number(raw, 390, 4));
        value.rExpiry = uint32(_number(raw, 394, 4));
        value.feeF = uint64(_number(raw, 398, 8));
        value.feeC = uint64(_number(raw, 406, 8));
        value.feeR = uint64(_number(raw, 414, 8));
        value.feeCapF = uint64(_number(raw, 422, 8));
        value.feeCapC = uint64(_number(raw, 430, 8));
        value.feeCapR = uint64(_number(raw, 438, 8));
        value.quoteCommitment = bytes32(_number(raw, 446, 32));
        value.agreementCommitment = bytes32(_number(raw, 478, 32));
        value.groupGrantCommitment = bytes32(_number(raw, 510, 32));
        value.sourceTermsCommitment = bytes32(_number(raw, 542, 32));
        value.jointBinding = bytes32(_number(raw, 574, 32));
        value.stableJtag = bytes32(_number(raw, 606, 32));
        _validStatement(value);
    }

    function decodeBoundary(bytes calldata raw) internal pure returns (SourceBoundary memory value) {
        if (raw.length != 100) revert InvalidBoundary();
        value.height = uint32(_number(raw, 0, 4));
        value.blockHash = bytes32(_number(raw, 4, 32));
        value.cumulativeWork = _number(raw, 36, 32);
        value.ledgerJournalDigest = bytes32(_number(raw, 68, 32));
        _validBoundary(value);
    }

    function contextHash(bytes calldata raw) internal pure returns (bytes32) {
        // Every consumer decodes the same strict canonical Statement first.
        return sha256(raw);
    }

    function deploymentDigest(DeploymentDescriptor memory value) internal pure returns (bytes32) {
        if (value.schemaVersion != SCHEMA_VERSION || value.sourceNetwork != SOURCE_NETWORK
            || value.sourcePool != SOURCE_POOL || value.transactionVersion != TRANSACTION_VERSION
            || value.consensusBranch != CONSENSUS_BRANCH || value.financialProgram == bytes32(0)
            || value.originProgram == bytes32(0) || value.sourceAcceptanceProgram == bytes32(0)
            || value.sourcePolicyId == bytes32(0) || value.targetChainId == 0 || value.obligation == address(0)
            || value.obligationRuntimeCode == bytes32(0) || value.verifier == address(0)
            || value.verifierRuntimeCode == bytes32(0)) revert InvalidStatement();
        return sha256(abi.encodePacked("ziquid.native.deployment.v1", value.schemaVersion, value.sourceNetwork,
            value.sourcePool, value.transactionVersion, value.consensusBranch, value.financialProgram,
            value.originProgram, value.sourceAcceptanceProgram, value.sourcePolicyId, value.targetChainId,
            value.obligation, value.obligationRuntimeCode, value.verifier, value.verifierRuntimeCode));
    }

    function originJournal(Statement memory statement, bytes32 context, SourceBoundary memory source)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked("ziquid.native.origin.v1", context, statement.stableJtag,
            statement.jointBinding, boundaryBytes(source));
    }

    function armJournal(Statement memory statement, bytes32 context, SourceBoundary memory source)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked("ziquid.native.arm.v1", context, statement.stableJtag, boundaryBytes(source));
    }

    function resolveJournal(Statement memory statement, bytes32 context, SourceBoundary memory source, uint8 outcome, uint64 cnet)
        internal pure returns (bytes memory)
    {
        // Other/Unknown is never zero consideration. The pinned actual relation
        // additionally restricts reachable C to its authentic, exact fixed effects.
        if ((outcome != 1 && outcome != 2) || (outcome == 1 && (cnet == 0 || cnet > statement.a))
            || (outcome == 2 && cnet != 0)) revert InvalidOutcome();
        return abi.encodePacked("ziquid.native.resolve.v1", context, statement.stableJtag,
            boundaryBytes(source), outcome, cnet);
    }

    function acceptanceJournal(Statement memory statement, SourceBoundary memory source)
        internal pure returns (bytes memory)
    {
        // The financial journal supplies context/tag; policy acceptance is
        // separately reusable only for this exact finite-validity boundary.
        return abi.encodePacked("ziquid.native.acceptance.v1", statement.sourceNetwork,
            statement.sourcePolicyId, boundaryBytes(source));
    }

    function boundaryBytes(SourceBoundary memory source) internal pure returns (bytes memory) {
        _validBoundary(source);
        return abi.encodePacked(source.height, source.blockHash, source.cumulativeWork, source.ledgerJournalDigest);
    }

    function _validStatement(Statement memory value) private pure {
        if (value.schemaVersion != SCHEMA_VERSION || value.sourceNetwork != SOURCE_NETWORK
            || value.sourcePool != SOURCE_POOL || value.transactionVersion != TRANSACTION_VERSION
            || value.consensusBranch != CONSENSUS_BRANCH || value.financialProgram == bytes32(0)
            || value.originProgram == bytes32(0) || value.sourceAcceptanceProgram == bytes32(0)
            || value.sourcePolicyId == bytes32(0) || value.windowPolicyCommitment == bytes32(0)
            || value.targetChainId == 0 || value.obligation == address(0) || value.deploymentDescriptor == bytes32(0)
            || value.payer == address(0) || value.uPayee == address(0) || value.sRefund == address(0)
            || value.uPayee == value.sRefund || value.quoteCommitment == bytes32(0)
            || value.agreementCommitment == bytes32(0) || value.groupGrantCommitment == bytes32(0)
            || value.sourceTermsCommitment == bytes32(0) || value.jointBinding == bytes32(0)
            || value.stableJtag == bytes32(0) || value.a == 0 || value.a > MAX_SOURCE_AMOUNT
            || value.d == 0 || value.jValue == 0 || value.jValue > MAX_SOURCE_AMOUNT
            || value.rReturn == 0 || value.rReturn > MAX_SOURCE_AMOUNT) revert InvalidStatement();
        if (!_validWindow(value.fTarget, value.fExpiry) || !_validWindow(value.cTarget, value.cExpiry)
            || !_validWindow(value.rTarget, value.rExpiry) || value.fExpiry >= value.cExpiry
            || value.fExpiry >= value.rExpiry || value.feeF > value.feeCapF || value.feeC > value.feeCapC
            || value.feeR > value.feeCapR || value.feeCapF > MAX_SOURCE_AMOUNT
            || value.feeCapC > MAX_SOURCE_AMOUNT || value.feeCapR > MAX_SOURCE_AMOUNT
            || value.jValue != value.a + value.feeC || value.jValue != value.rReturn + value.feeR) {
            revert InvalidStatement();
        }
    }

    function _validWindow(uint32 target, uint32 expiry) private pure returns (bool) {
        return target >= IRONWOOD_ACTIVATION && target <= expiry && expiry < NEXT_UPGRADE;
    }

    function _validBoundary(SourceBoundary memory source) private pure {
        if (source.height == 0 || source.height >= NEXT_UPGRADE || source.blockHash == bytes32(0)
            || source.cumulativeWork == 0 || source.ledgerJournalDigest == bytes32(0)) revert InvalidBoundary();
    }

    function _number(bytes calldata raw, uint256 offset, uint256 width) private pure returns (uint256 result) {
        // Exact frame lengths above dominate every fixed offset; widths<=32.
        assembly ("memory-safe") { result := shr(sub(256, mul(width, 8)), calldataload(add(raw.offset, offset))) }
    }
}
