// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {Allocation} from "./Allocation.sol";
import {NativeFinancialCodec} from "./NativeFinancialCodec.sol";
import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {SP1Verifier} from "./sp1/v6.1.0/SP1VerifierGroth16.sol";

/// @notice Immutable, proof-controlled native ETH backing for one exact native statement.
/// @dev Constructor pins identities; it does not qualify the source programs or their proofs.
contract NativeEthObligation {
    uint8 public constant SOURCE_POOL = 3;
    uint32 public constant TRANSACTION_VERSION = 6;
    uint32 public constant CONSENSUS_BRANCH = 0x37a5165b;
    uint256 private constant PROOF_BYTES = 356;

    bytes32 public immutable financialProgram;
    bytes32 public immutable originProgram;
    bytes32 public immutable sourceAcceptanceProgram;
    bytes32 public immutable sourcePolicyId;
    uint16 public immutable schemaVersion;
    uint8 public immutable sourceNetwork;
    uint64 public immutable chainId;
    SP1Verifier public immutable verifier;
    bytes32 public immutable verifierCode;

    struct Obligation {
        uint256 d;
        uint64 a;
        address payer;
        address uPayee;
        address sRefund;
        bytes32 stableJtag;
        bool armed;
        bool consumed;
    }

    mapping(bytes32 => Obligation) public obligations;
    mapping(bytes32 => bytes32) public contextForTag;
    uint256 public totalLiability;
    bool private entered;

    error InvalidDeployment();
    error InvalidPayer();
    error InvalidValue();
    error ExistingContext();
    error TagAlreadyReserved();
    error InvalidProofLength();
    error ReentrantCall();
    error NotArmed();
    error AlreadyConsumed();
    error NativeTransferFailed();

    event ObligationArmed(bytes32 indexed context, bytes32 indexed stableJtag, uint256 d, address payer);
    event ObligationResolved(bytes32 indexed context, uint8 outcome, uint64 cnet, uint256 userAmount, uint256 solverAmount);

    constructor(
        bytes32 fixedFinancialProgram,
        bytes32 fixedOriginProgram,
        bytes32 fixedSourceAcceptanceProgram,
        bytes32 fixedSourcePolicyId,
        uint16 fixedSchemaVersion,
        uint8 fixedSourceNetwork
    ) {
        if (
            fixedFinancialProgram == bytes32(0) || fixedOriginProgram == bytes32(0)
                || fixedSourceAcceptanceProgram == bytes32(0) || fixedSourcePolicyId == bytes32(0)
                || fixedSchemaVersion != NativeFinancialCodec.SCHEMA_VERSION
                || fixedSourceNetwork != NativeFinancialCodec.SOURCE_NETWORK
                || block.chainid == 0 || block.chainid > type(uint64).max
        ) revert InvalidDeployment();

        financialProgram = fixedFinancialProgram;
        originProgram = fixedOriginProgram;
        sourceAcceptanceProgram = fixedSourceAcceptanceProgram;
        sourcePolicyId = fixedSourcePolicyId;
        schemaVersion = fixedSchemaVersion;
        sourceNetwork = fixedSourceNetwork;
        chainId = uint64(block.chainid);

        SP1Verifier actualVerifier = new SP1Verifier();
        verifier = actualVerifier;
        verifierCode = address(actualVerifier).codehash;
    }

    modifier guarded() {
        if (entered) revert ReentrantCall();
        entered = true;
        _checkIdentity();
        _;
        _checkIdentity();
        entered = false;
    }

    function deployment() public view returns (NativeFinancialCodec.DeploymentDescriptor memory value) {
        _checkIdentity();
        value = NativeFinancialCodec.DeploymentDescriptor({
            schemaVersion: schemaVersion,
            sourceNetwork: sourceNetwork,
            sourcePool: SOURCE_POOL,
            transactionVersion: TRANSACTION_VERSION,
            consensusBranch: CONSENSUS_BRANCH,
            financialProgram: financialProgram,
            originProgram: originProgram,
            sourceAcceptanceProgram: sourceAcceptanceProgram,
            sourcePolicyId: sourcePolicyId,
            targetChainId: chainId,
            obligation: address(this),
            obligationRuntimeCode: address(this).codehash,
            verifier: address(verifier),
            verifierRuntimeCode: address(verifier).codehash
        });
    }

    function deploymentDigest() external view returns (bytes32) {
        return NativeFinancialCodec.deploymentDigest(deployment());
    }

    function fundAndArm(
        bytes calldata rawStatement,
        bytes calldata rawBoundary,
        bytes calldata armProof,
        bytes calldata originProof,
        bytes calldata acceptanceProof
    ) external payable guarded {
        NativeFinancialCodec.Statement memory statement = NativeFinancialCodec.decodeStatement(rawStatement);
        NativeFinancialCodec.SourceBoundary memory source = NativeFinancialCodec.decodeBoundary(rawBoundary);
        bytes32 context = _validateStatement(statement, rawStatement);

        if (statement.payer != msg.sender) revert InvalidPayer();
        if (msg.value != statement.d) revert InvalidValue();
        if (obligations[context].armed) revert ExistingContext();
        if (contextForTag[statement.stableJtag] != bytes32(0)) revert TagAlreadyReserved();

        _verify(financialProgram, NativeFinancialCodec.armJournal(statement, context, source), armProof);
        _verify(originProgram, NativeFinancialCodec.originJournal(statement, context, source), originProof);
        _verify(sourceAcceptanceProgram, NativeFinancialCodec.acceptanceJournal(statement, source), acceptanceProof);

        obligations[context] = Obligation({
            d: statement.d,
            a: statement.a,
            payer: statement.payer,
            uPayee: statement.uPayee,
            sRefund: statement.sRefund,
            stableJtag: statement.stableJtag,
            armed: true,
            consumed: false
        });
        contextForTag[statement.stableJtag] = context;
        totalLiability += statement.d;
        emit ObligationArmed(context, statement.stableJtag, statement.d, statement.payer);
    }

    function resolve(
        bytes calldata rawStatement,
        bytes calldata rawBoundary,
        uint8 outcome,
        uint64 cnet,
        bytes calldata financialProof,
        bytes calldata acceptanceProof
    ) external guarded {
        NativeFinancialCodec.Statement memory statement = NativeFinancialCodec.decodeStatement(rawStatement);
        NativeFinancialCodec.SourceBoundary memory source = NativeFinancialCodec.decodeBoundary(rawBoundary);
        bytes32 context = _validateStatement(statement, rawStatement);
        bytes memory journal = NativeFinancialCodec.resolveJournal(statement, context, source, outcome, cnet);
        bytes32 tagContext = contextForTag[statement.stableJtag];
        Obligation storage obligation = obligations[context];
        if (tagContext != context || !obligation.armed) revert NotArmed();
        if (obligation.consumed) revert AlreadyConsumed();
        if (obligation.d != statement.d || obligation.a != statement.a
            || obligation.payer != statement.payer || obligation.uPayee != statement.uPayee
            || obligation.sRefund != statement.sRefund) revert NotArmed();

        _verify(financialProgram, journal, financialProof);
        _verify(sourceAcceptanceProgram, NativeFinancialCodec.acceptanceJournal(statement, source), acceptanceProof);

        (uint256 userAmount, uint256 solverAmount) = Allocation.split(obligation.d, statement.a, cnet);
        obligation.consumed = true;
        totalLiability -= obligation.d;
        if (userAmount != 0) _transfer(obligation.uPayee, userAmount);
        if (solverAmount != 0) _transfer(obligation.sRefund, solverAmount);
        emit ObligationResolved(context, outcome, cnet, userAmount, solverAmount);
    }

    function _validateStatement(NativeFinancialCodec.Statement memory statement, bytes calldata rawStatement)
        private view returns (bytes32 context)
    {
        NativeFinancialCodec.DeploymentDescriptor memory actual = deployment();
        if (
            statement.schemaVersion != actual.schemaVersion || statement.sourceNetwork != actual.sourceNetwork
                || statement.sourcePool != actual.sourcePool || statement.transactionVersion != actual.transactionVersion
                || statement.consensusBranch != actual.consensusBranch || statement.financialProgram != actual.financialProgram
                || statement.originProgram != actual.originProgram
                || statement.sourceAcceptanceProgram != actual.sourceAcceptanceProgram
                || statement.sourcePolicyId != actual.sourcePolicyId || statement.targetChainId != actual.targetChainId
                || statement.obligation != actual.obligation
                || statement.deploymentDescriptor != NativeFinancialCodec.deploymentDigest(actual)
        ) revert InvalidDeployment();
        return NativeFinancialCodec.contextHash(rawStatement);
    }

    function _verify(bytes32 program, bytes memory journal, bytes calldata proof) private view {
        if (proof.length != PROOF_BYTES) revert InvalidProofLength();
        ISP1Verifier(address(verifier)).verifyProof(program, journal, proof);
    }

    function _transfer(address recipient, uint256 amount) private {
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert NativeTransferFailed();
    }

    function _checkIdentity() private view {
        if (
            block.chainid != chainId || address(verifier).codehash != verifierCode
                || address(this).codehash == bytes32(0)
        ) revert InvalidDeployment();
    }
}
