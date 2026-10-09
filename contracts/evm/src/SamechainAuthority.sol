// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {SamechainCodec} from "./SamechainCodec.sol";
import {SamechainTree} from "./SamechainTree.sol";
import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {SP1Verifier} from "./sp1/v6.1.0/SP1VerifierGroth16.sol";

/// @notice Immutable, proof-controlled custody for native and one qualified token.
/// @dev The constructor pin is not independent program/certificate qualification.
/// Supported tokens must be qualified vanilla, non-proxy, non-rebasing assets:
/// exact observed deltas do not promise issuer thaw or arbitrary hook safety.
contract SamechainAuthority {
    address public immutable token;
    bytes32 public immutable tokenCode;
    bytes32 public immutable ownerProgram;
    uint64 public immutable chainId;
    SP1Verifier public immutable verifier;
    bytes32 public immutable verifierCode;

    mapping(bytes32 => bool) public spent;
    mapping(bytes32 => bool) public seenCommitments;
    mapping(bytes32 => bool) public usedInitialOrders;
    mapping(address => mapping(bytes32 => bool)) public usedCreationNonce;
    mapping(uint32 => mapping(bytes32 => uint64)) public rootCounts;

    SamechainTree.State private tree;
    bool private entered;

    error InvalidDeployment();
    error InvalidOperation();
    error InvalidAsset();
    error InvalidRecipient();
    error InvalidPayer();
    error InvalidValue();
    error ExpiredPacket();
    error IneligibleInput();
    error AlreadySpent();
    error CommitmentAlreadySeen();
    error CreationNonceAlreadyUsed();
    error InitialOrderAlreadyUsed();
    error InvalidProofLength();
    error ReentrantCall();
    error NativeTransferFailed();
    error TokenCallFailed();
    error InvalidTokenReturn();
    error InvalidTokenBalance();
    error InvalidTokenDelta();

    event NoteAppended(
        bytes32 packetDigest, uint32 manifestIndex, uint8 role, uint32 treeId,
        uint32 index, uint64 count, bytes32 root, bytes32 commitment,
        bytes32 recoveryKeyCommitment, uint16 ciphertextVersion, bytes ciphertext
    );
    event NullifierConsumed(bytes32 packetDigest, bytes32 nullifier);
    event TreeRolledOver(uint32 prior, uint32 next);
    event NoteCreated(bytes32 packetDigest, address payer, bytes32 creationNonce, bytes32 initialOrderId, address asset, uint256 amount);
    event AssetTransferred(bytes32 packetDigest, uint32 manifestIndex, uint8 kind, uint8 role, address asset, address recipient, uint256 amount);
    event PacketExecuted(bytes32 packetDigest);

    constructor(address fixedToken, bytes32 fixedOwnerProgram) {
        if (fixedToken == address(0) || fixedToken == address(this) || fixedToken.code.length == 0
            || fixedOwnerProgram == bytes32(0) || block.chainid == 0 || block.chainid > type(uint64).max) {
            revert InvalidDeployment();
        }
        token = fixedToken;
        tokenCode = fixedToken.codehash;
        ownerProgram = fixedOwnerProgram;
        chainId = uint64(block.chainid);
        // Verbatim vendored implementation, never an injected verifier/gateway.
        SP1Verifier actualVerifier = new SP1Verifier();
        verifier = actualVerifier;
        verifierCode = address(actualVerifier).codehash;
        SamechainTree.initialize(tree);
    }

    modifier guarded() {
        if (entered) revert ReentrantCall();
        entered = true;
        _checkIdentity();
        _;
        _checkIdentity();
        entered = false;
    }

    /// @dev Self runtime identity must be derived after construction; embedding a
    /// precomputed self digest in that same runtime would be circular.
    function deployment() public view returns (SamechainCodec.Deployment memory) {
        _checkIdentity();
        return SamechainCodec.Deployment({
            chainId: chainId,
            authority: address(this),
            authorityCode: address(this).codehash,
            verifier: address(verifier),
            verifierCode: address(verifier).codehash,
            ownerProgram: ownerProgram,
            schema: 1
        });
    }

    function deploymentDigest() external view returns (bytes32) {
        return SamechainCodec.deploymentDigest(deployment());
    }

    function treeState() external view returns (uint32 treeId, uint64 count, bytes32 root) {
        return (tree.treeId, tree.count, tree.root);
    }

    function create(bytes calldata rawPacket, bytes calldata proof) external payable guarded {
        SamechainCodec.Packet memory packet = SamechainCodec.decodeCreation(rawPacket);
        bytes32 context = _validatePacket(packet);
        if (packet.token != token || (packet.asset != address(0) && packet.asset != token)) revert InvalidAsset();
        if (packet.payer != msg.sender) revert InvalidPayer();
        if (packet.asset == address(0) ? msg.value != packet.amount : msg.value != 0) revert InvalidValue();
        if (usedCreationNonce[packet.payer][packet.creationNonce]) revert CreationNonceAlreadyUsed();
        if (packet.initialOrderId != bytes32(0) && usedInitialOrders[packet.initialOrderId]) revert InitialOrderAlreadyUsed();

        _verify(SamechainCodec.creationJournal(packet), proof);
        if (packet.asset == token) _receiveToken(packet.payer, packet.amount);
        usedCreationNonce[packet.payer][packet.creationNonce] = true;
        if (packet.initialOrderId != bytes32(0)) usedInitialOrders[packet.initialOrderId] = true;
        _applyOutputs(packet, context);
        emit NoteCreated(packet.packetDigest, packet.payer, packet.creationNonce, packet.initialOrderId, packet.asset, packet.amount);
        emit PacketExecuted(packet.packetDigest);
    }

    function fill(bytes calldata rawPacket, bytes calldata proofA, bytes calldata proofB) external guarded {
        SamechainCodec.Packet memory packet = SamechainCodec.decodeFill(rawPacket);
        bytes32 context = _validatePacket(packet);
        _eligible(packet.inputs[0]);
        _eligible(packet.inputs[1]);
        // Both complete journals bind this same packet and salted common terms.
        // No rights or effects are consumed before the second real proof passes.
        _verify(SamechainCodec.ownerJournal(packet, 0, 0), proofA);
        _verify(SamechainCodec.ownerJournal(packet, 1, 0), proofB);
        _consume(packet.packetDigest, packet.inputs[0].nullifier);
        _consume(packet.packetDigest, packet.inputs[1].nullifier);
        _applyOutputs(packet, context);
        emit PacketExecuted(packet.packetDigest);
    }

    function cancelOrExit(bytes calldata rawPacket, uint8 role, uint8 action, bytes calldata proof) external guarded {
        if (role > 1 || (action != 1 && action != 2)) revert InvalidOperation();
        SamechainCodec.Packet memory packet = SamechainCodec.decodeSingle(rawPacket);
        for (uint256 i; i < packet.outputs.length; ++i) {
            if (packet.outputs[i].role != role) revert InvalidOperation();
        }
        bytes32 context = _validatePacket(packet);
        _eligible(packet.inputs[0]);
        _verify(SamechainCodec.ownerJournal(packet, role, action), proof);
        // The authenticated common N kills every F1/F2 of this generation.
        // Successors/order privacy are proven, not guessed from public notes;
        // initial IDs stay reserved forever, including after Cancel or Exit.
        _consume(packet.packetDigest, packet.inputs[0].nullifier);
        _applyOutputs(packet, context);
        emit PacketExecuted(packet.packetDigest);
    }

    function withdraw(bytes calldata rawPacket, bytes calldata proof) external guarded {
        SamechainCodec.Packet memory packet = SamechainCodec.decodeWithdrawal(rawPacket);
        bytes32 context = _validatePacket(packet);
        _eligible(packet.inputs[0]);
        _verify(SamechainCodec.withdrawalJournal(packet), proof);
        _consume(packet.packetDigest, packet.inputs[0].nullifier);
        _applyOutputs(packet, context);
        emit PacketExecuted(packet.packetDigest);
    }

    function _checkIdentity() private view {
        if (block.chainid != chainId || token.codehash != tokenCode
            || address(verifier).codehash != verifierCode) revert InvalidDeployment();
    }

    function _validatePacket(SamechainCodec.Packet memory packet) private view returns (bytes32) {
        SamechainCodec.Deployment memory actual = deployment();
        SamechainCodec.Deployment memory supplied = packet.deployment;
        if (supplied.chainId != actual.chainId || supplied.authority != actual.authority
            || supplied.authorityCode != actual.authorityCode || supplied.verifier != actual.verifier
            || supplied.verifierCode != actual.verifierCode || supplied.ownerProgram != actual.ownerProgram
            || supplied.schema != actual.schema) revert InvalidDeployment();
        if (block.timestamp > packet.expiry) revert ExpiredPacket();
        for (uint256 i; i < packet.outputs.length; ++i) {
            SamechainCodec.Output memory output = packet.outputs[i];
            if (output.kind == 0) {
                if (seenCommitments[output.commitment]) revert CommitmentAlreadySeen();
            } else {
                if (output.asset != address(0) && output.asset != token) revert InvalidAsset();
                if (output.recipient == address(0) || output.recipient == address(this)) revert InvalidRecipient();
            }
        }
        return SamechainCodec.deploymentDigest(actual);
    }

    function _eligible(SamechainCodec.Input memory input) private view {
        uint64 count = rootCounts[input.treeId][input.root];
        if (count == 0 || uint64(input.index) >= count) revert IneligibleInput();
        if (spent[input.nullifier]) revert AlreadySpent();
    }

    function _verify(bytes memory expectedJournal, bytes calldata proof) private view {
        // Upstream ABI decoding alone permits a suffix. This boundary requires
        // selector4 || ABI(exit, VK-root, nonce, eight actual pairing elements).
        if (proof.length != 356) revert InvalidProofLength();
        ISP1Verifier(address(verifier)).verifyProof(ownerProgram, expectedJournal, proof);
    }

    function _consume(bytes32 packetDigest, bytes32 nullifier) private {
        spent[nullifier] = true;
        emit NullifierConsumed(packetDigest, nullifier);
    }

    function _applyOutputs(SamechainCodec.Packet memory packet, bytes32 context) private {
        for (uint256 i; i < packet.outputs.length; ++i) {
            SamechainCodec.Output memory output = packet.outputs[i];
            if (output.kind == 0) {
                _appendNote(packet.packetDigest, uint32(i), output, context);
            } else {
                if (output.asset == address(0)) {
                    (bool success,) = output.recipient.call{value: output.amount}("");
                    if (!success) revert NativeTransferFailed();
                } else {
                    _sendToken(output.recipient, output.amount);
                }
                emit AssetTransferred(packet.packetDigest, uint32(i), output.kind, output.role, output.asset, output.recipient, output.amount);
            }
        }
    }

    function _appendNote(bytes32 packetDigest, uint32 manifestIndex, SamechainCodec.Output memory output, bytes32 context) private {
        if (seenCommitments[output.commitment]) revert CommitmentAlreadySeen();
        seenCommitments[output.commitment] = true;
        uint32 prior = tree.treeId;
        SamechainTree.Insertion memory insertion = SamechainTree.append(tree, context, output.commitment);
        if (insertion.treeId != prior) emit TreeRolledOver(prior, insertion.treeId);
        // Every intermediate append root is retained with its own index bound;
        // initialized/rollover empty roots are never admitted for spending.
        rootCounts[insertion.treeId][insertion.root] = insertion.count;
        emit NoteAppended(packetDigest, manifestIndex, output.role, insertion.treeId, insertion.index,
            insertion.count, insertion.root, output.commitment, output.recoveryKeyCommitment,
            output.ciphertextVersion, output.ciphertext);
    }

    function _receiveToken(address payer, uint256 amount) private {
        uint256 payerBefore = _tokenBalance(payer);
        uint256 authorityBefore = _tokenBalance(address(this));
        _tokenCall(abi.encodeWithSelector(bytes4(0x23b872dd), payer, address(this), amount));
        uint256 payerAfter = _tokenBalance(payer);
        uint256 authorityAfter = _tokenBalance(address(this));
        if (payerAfter > payerBefore || payerBefore - payerAfter != amount
            || authorityAfter < authorityBefore || authorityAfter - authorityBefore != amount) revert InvalidTokenDelta();
    }

    function _sendToken(address recipient, uint256 amount) private {
        uint256 authorityBefore = _tokenBalance(address(this));
        uint256 recipientBefore = _tokenBalance(recipient);
        _tokenCall(abi.encodeWithSelector(bytes4(0xa9059cbb), recipient, amount));
        uint256 authorityAfter = _tokenBalance(address(this));
        uint256 recipientAfter = _tokenBalance(recipient);
        if (authorityAfter > authorityBefore || authorityBefore - authorityAfter != amount
            || recipientAfter < recipientBefore || recipientAfter - recipientBefore != amount) revert InvalidTokenDelta();
    }

    function _tokenBalance(address account) private view returns (uint256) {
        (bool success, bytes memory result) = token.staticcall(abi.encodeWithSelector(bytes4(0x70a08231), account));
        if (!success || result.length != 32) revert InvalidTokenBalance();
        return abi.decode(result, (uint256));
    }

    function _tokenCall(bytes memory callData) private {
        if (token.codehash != tokenCode) revert InvalidDeployment();
        (bool success, bytes memory result) = token.call(callData);
        if (token.codehash != tokenCode) revert InvalidDeployment();
        if (!success) revert TokenCallFailed();
        if (result.length != 0 && (result.length != 32 || abi.decode(result, (uint256)) != 1)) revert InvalidTokenReturn();
    }
}
