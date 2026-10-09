// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

import {SamechainAuthority} from "../src/SamechainAuthority.sol";
import {SamechainCodec} from "../src/SamechainCodec.sol";
import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";

interface SamechainAuthorityVm {
    function getCode(string calldata artifact) external returns (bytes memory);
    function getDeployedCode(string calldata artifact) external returns (bytes memory);
    function chainId(uint256 chain) external;
    function deal(address account, uint256 balance) external;
    function warp(uint256 timestamp) external;
}

// Deliberately hostile, public VM fixture, not a qualified supported asset.
contract SamechainConstructionToken {
    error HostileReceipt();
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        revert HostileReceipt();
    }
    function transfer(address, uint256) external pure returns (bool) {
        revert HostileReceipt();
    }
}

// Codec-only journal construction; this exposes no financial state or verifier.
contract SamechainExpectedJournal {
    function journal(bytes calldata packet, uint8 mode, uint8 role, uint8 action)
        external pure returns (bytes memory)
    {
        if (mode == 0) return SamechainCodec.ownerJournal(SamechainCodec.decodeFill(packet), role, action);
        if (mode == 1) return SamechainCodec.ownerJournal(SamechainCodec.decodeSingle(packet), role, action);
        if (mode == 2) return SamechainCodec.withdrawalJournal(SamechainCodec.decodeWithdrawal(packet));
        if (mode == 3) return SamechainCodec.creationJournal(SamechainCodec.decodeCreation(packet));
        revert("unknown test journal mode");
    }
}

// Reject paths only. No genuine samechain certificate or independently qualified
// program key is available here. Funded lifecycle, second-proof rollback and
// transfer/receiver-failure acceptance remain NOT RUN; no storage-seeded rights.
contract SamechainAuthorityTest {
    SamechainAuthorityVm private constant VM = SamechainAuthorityVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant PROGRAM = bytes32(uint256(1)); // Unqualified test pin.
    bytes32 private constant C_A = bytes32(uint256(11));
    bytes32 private constant C_B = bytes32(uint256(12));
    bytes32 private constant C_OUT_A = bytes32(uint256(13));
    bytes32 private constant C_OUT_B = bytes32(uint256(14));
    bytes32 private constant N_A = bytes32(uint256(21));
    bytes32 private constant N_B = bytes32(uint256(22));
    bytes32 private constant ORDER_A = bytes32(uint256(31));
    bytes32 private constant ORDER_B = bytes32(uint256(32));
    bytes32 private constant NONCE = bytes32(uint256(41));
    bytes32 private constant ROOT = bytes32(uint256(51));
    bytes32 private constant TERMS = bytes32(uint256(61));
    bytes32 private constant EMPTY_ROOT = hex"b35605a717176cf8a85e2eb0b6ac6f1acc369aaf4193c562f4882cd38cac6745";
    uint256 private constant AMOUNT = 7;
    bytes4 private constant PROOF_SELECTOR = 0x4388a21c;
    uint256 private constant VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352;

    function testImmutableDescriptorUsesActualConstructedVerifier() public {
        SamechainAuthority authority = _authority();
        SamechainCodec.Deployment memory descriptor = authority.deployment();
        require(descriptor.authority == address(authority), "wrong authority");
        require(descriptor.authorityCode == address(authority).codehash, "constructor identity instead of runtime");
        require(descriptor.chainId == block.chainid && descriptor.chainId == authority.chainId(), "wrong chain scope");
        require(descriptor.ownerProgram == PROGRAM && authority.ownerProgram() == PROGRAM, "wrong program pin");
        require(descriptor.schema == 1, "wrong schema");
        require(descriptor.verifier == address(authority.verifier()), "wrong verifier address");
        require(descriptor.verifier.code.length != 0 && descriptor.verifierCode == descriptor.verifier.codehash, "unbacked verifier identity");
        require(descriptor.verifierCode == authority.verifierCode(), "wrong immutable verifier hash");
        require(descriptor.verifierCode == keccak256(VM.getDeployedCode("SP1VerifierGroth16.sol:SP1Verifier")), "not actual vendored verifier runtime");
        require(authority.tokenCode() == authority.token().codehash, "wrong fixed token hash");
        require(authority.deploymentDigest() == SamechainCodec.deploymentDigest(descriptor), "canonical descriptor digest");
        _unchanged(authority, 0);
    }

    function testSpendScopeAndExpiryRejectBeforeUnadmittedMembership() public {
        SamechainAuthority authority = _authority();
        VM.warp(1000);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        bytes memory packet = _fill(authority);
        packet[30 + 28] ^= bytes1(uint8(1));
        _reject(authority, abi.encodeCall(authority.fill, (packet, proof, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        packet = _fill(authority);
        _expiry(packet, 999);
        _reject(authority, abi.encodeCall(authority.fill, (packet, proof, proof)), 0, SamechainAuthority.ExpiredPacket.selector);
        packet = _single(authority, 1);
        packet[30 + 80] ^= bytes1(uint8(1));
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (packet, 1, 1, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        packet = _single(authority, 1);
        _expiry(packet, 999);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (packet, 1, 2, proof)), 0, SamechainAuthority.ExpiredPacket.selector);
        packet = _withdrawal(authority, address(0xBEEF), address(0));
        packet[39 + 112] ^= bytes1(uint8(1));
        _reject(authority, abi.encodeCall(authority.withdraw, (packet, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        packet = _withdrawal(authority, address(0xBEEF), address(0));
        _expiry(packet, 999);
        _reject(authority, abi.encodeCall(authority.withdraw, (packet, proof)), 0, SamechainAuthority.ExpiredPacket.selector);
    }

    function testConstructorRejectsMissingTokenProgramAndZeroChain() public {
        address token = address(new SamechainConstructionToken());
        (address deployed, bytes memory reason) = _construct("SamechainAuthority.sol:SamechainAuthority", abi.encode(address(0), PROGRAM));
        require(deployed == address(0) && _selector(reason) == SamechainAuthority.InvalidDeployment.selector, "zero token accepted");
        (deployed, reason) = _construct("SamechainAuthority.sol:SamechainAuthority", abi.encode(address(0xBEEF), PROGRAM));
        require(deployed == address(0) && _selector(reason) == SamechainAuthority.InvalidDeployment.selector, "code-less token accepted");
        (deployed, reason) = _construct("SamechainAuthority.sol:SamechainAuthority", abi.encode(token, bytes32(0)));
        require(deployed == address(0) && _selector(reason) == SamechainAuthority.InvalidDeployment.selector, "zero program accepted");
        uint256 chain = block.chainid;
        VM.chainId(0);
        (deployed, reason) = _construct("SamechainAuthority.sol:SamechainAuthority", abi.encode(token, PROGRAM));
        VM.chainId(chain);
        require(deployed == address(0) && _selector(reason) == SamechainAuthority.InvalidDeployment.selector, "zero chain accepted");
    }

    function testCreationRealInvalidPairingCannotMintOrInvokeHostileToken() public {
        SamechainAuthority authority = _authority();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        for (uint8 variant; variant < 4; ++variant) {
            bool tokenAsset = (variant & 1) != 0;
            bytes32 initial = variant < 2 ? bytes32(0) : (variant == 2 ? ORDER_A : ORDER_B);
            bytes memory packet = _creation(authority, tokenAsset, variant & 1, initial);
            _reject(authority, abi.encodeCall(authority.create, (packet, proof)), tokenAsset ? 0 : AMOUNT, Verifier.ProofInvalid.selector);
        }
    }

    function testCreationWrappedLengthSelectorExitAndRootAreStrict() public {
        SamechainAuthority authority = _authority();
        VM.deal(address(this), 100);
        bytes memory packet = _creation(authority, false, 0, bytes32(0));
        _reject(authority, abi.encodeCall(authority.create, (packet, new bytes(355))), AMOUNT, SamechainAuthority.InvalidProofLength.selector);
        _reject(authority, abi.encodeCall(authority.create, (packet, new bytes(357))), AMOUNT, SamechainAuthority.InvalidProofLength.selector);
        _reject(authority, abi.encodeCall(authority.create, (packet, _proof(bytes4(0), 0, VK_ROOT))), AMOUNT, SP1Verifier.WrongVerifierSelector.selector);
        _reject(authority, abi.encodeCall(authority.create, (packet, _proof(PROOF_SELECTOR, 1, VK_ROOT))), AMOUNT, SP1Verifier.InvalidExitCode.selector);
        _reject(authority, abi.encodeCall(authority.create, (packet, _proof(PROOF_SELECTOR, 0, 0))), AMOUNT, SP1Verifier.InvalidVkRoot.selector);
    }

    function testCreationAuthenticatesEveryDeploymentFieldAndFixedToken() public {
        SamechainAuthority authority = _authority();
        VM.deal(address(this), 100);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        uint256[6] memory offsets = [uint256(7), 8, 28, 60, 80, 112];
        for (uint256 index; index < offsets.length; ++index) {
            bytes memory packet = _creation(authority, false, 0, bytes32(0));
            packet[37 + offsets[index]] ^= bytes1(uint8(1));
            _reject(authority, abi.encodeCall(authority.create, (packet, proof)), AMOUNT, SamechainAuthority.InvalidDeployment.selector);
        }
        bytes memory wrongSchema = _creation(authority, false, 0, bytes32(0));
        wrongSchema[37 + 145] = bytes1(uint8(2));
        _reject(authority, abi.encodeCall(authority.create, (wrongSchema, proof)), AMOUNT, SamechainCodec.InvalidPacket.selector);
        bytes memory wrongToken = _creation(authority, false, 0, bytes32(0));
        wrongToken[37 + 146] ^= bytes1(uint8(1));
        _reject(authority, abi.encodeCall(authority.create, (wrongToken, proof)), AMOUNT, SamechainAuthority.InvalidAsset.selector);
    }

    function testCreationPayerExpiryAndExactValueRejectWithoutCredits() public {
        SamechainAuthority authority = _authority();
        VM.deal(address(this), 100);
        VM.warp(1000);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        bytes memory packet = _creation(authority, false, 0, bytes32(0));
        packet[37 + 166] ^= bytes1(uint8(1));
        _reject(authority, abi.encodeCall(authority.create, (packet, proof)), AMOUNT, SamechainAuthority.InvalidPayer.selector);
        packet = _creation(authority, false, 0, bytes32(0));
        _expiry(packet, 999);
        _reject(authority, abi.encodeCall(authority.create, (packet, proof)), AMOUNT, SamechainAuthority.ExpiredPacket.selector);
        packet = _creation(authority, false, 0, bytes32(0));
        _reject(authority, abi.encodeCall(authority.create, (packet, proof)), 0, SamechainAuthority.InvalidValue.selector);
        _reject(authority, abi.encodeCall(authority.create, (packet, proof)), AMOUNT + 1, SamechainAuthority.InvalidValue.selector);
        packet = _creation(authority, true, 1, bytes32(0));
        _reject(authority, abi.encodeCall(authority.create, (packet, proof)), 1, SamechainAuthority.InvalidValue.selector);
    }

    function testLiveChainPinRejectsEveryMutatorWithoutChangingRights() public {
        SamechainAuthority authority = _authority();
        bytes memory creation = _creation(authority, true, 0, bytes32(0));
        bytes memory fillPacket = _fill(authority);
        bytes memory single = _single(authority, 0);
        bytes memory withdrawal = _withdrawal(authority, address(0xBEEF), address(0));
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        uint256 chain = block.chainid;
        VM.chainId(chain + 1);
        _reject(authority, abi.encodeCall(authority.create, (creation, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        _reject(authority, abi.encodeCall(authority.fill, (fillPacket, proof, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (single, 0, 1, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        _reject(authority, abi.encodeCall(authority.withdraw, (withdrawal, proof)), 0, SamechainAuthority.InvalidDeployment.selector);
        (bool ok, bytes memory reason) = address(authority).staticcall(abi.encodeCall(authority.deployment, ()));
        VM.chainId(chain);
        require(!ok && _selector(reason) == SamechainAuthority.InvalidDeployment.selector, "getter hid live chain mismatch");
        _unchanged(authority, 0);
    }

    function testAllSpendModesRejectUnadmittedMembershipNotPretendProofAcceptance() public {
        SamechainAuthority authority = _authority();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        _reject(authority, abi.encodeCall(authority.fill, (_fill(authority), proof, proof)), 0, SamechainAuthority.IneligibleInput.selector);
        for (uint8 role; role < 2; ++role) {
            for (uint8 action = 1; action <= 2; ++action) {
                _reject(authority, abi.encodeCall(authority.cancelOrExit, (_single(authority, role), role, action, proof)), 0, SamechainAuthority.IneligibleInput.selector);
            }
        }
        _reject(authority, abi.encodeCall(authority.withdraw, (_withdrawal(authority, address(0xBEEF), address(0)), proof)), 0, SamechainAuthority.IneligibleInput.selector);
    }

    function testUnknownRoleActionDomainAndUnauthorizedEffectsFailBeforeConsumption() public {
        SamechainAuthority authority = _authority();
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        bytes memory single = _single(authority, 0);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (single, 2, 1, proof)), 0, SamechainAuthority.InvalidOperation.selector);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (single, 0, 0, proof)), 0, SamechainAuthority.InvalidOperation.selector);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (single, 0, 3, proof)), 0, SamechainAuthority.InvalidOperation.selector);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (single, 1, 1, proof)), 0, SamechainAuthority.InvalidOperation.selector);
        bytes memory creation = _creation(authority, true, 0, bytes32(0));
        _reject(authority, abi.encodeCall(authority.fill, (creation, proof, proof)), 0, SamechainCodec.InvalidPacket.selector);
        _reject(authority, abi.encodeCall(authority.cancelOrExit, (creation, 0, 1, proof)), 0, SamechainCodec.InvalidPacket.selector);
        _reject(authority, abi.encodeCall(authority.withdraw, (creation, proof)), 0, SamechainCodec.InvalidPacket.selector);
        _reject(authority, abi.encodeCall(authority.create, (_fill(authority), proof)), 0, SamechainCodec.InvalidPacket.selector);
        _reject(authority, abi.encodeCall(authority.withdraw, (_withdrawal(authority, address(authority), address(0)), proof)), 0, SamechainAuthority.InvalidRecipient.selector);
        _reject(authority, abi.encodeCall(authority.withdraw, (_withdrawal(authority, address(0xBEEF), address(0xCAFE)), proof)), 0, SamechainAuthority.InvalidAsset.selector);
    }

    function testActualConstructedVerifierRejectsExpectedJournalsForAllModesRolesAndActions() public {
        SamechainAuthority authority = _authority();
        (address helper,) = _construct("SamechainAuthority.t.sol:SamechainExpectedJournal", "");
        require(helper != address(0), "journal harness construction failed");
        SamechainExpectedJournal journals = SamechainExpectedJournal(helper);
        bytes memory proof = _proof(PROOF_SELECTOR, 0, VK_ROOT);
        for (uint8 role; role < 2; ++role) {
            _directReject(authority, journals.journal(_fill(authority), 0, role, 0), proof);
            for (uint8 action = 1; action <= 2; ++action) {
                _directReject(authority, journals.journal(_single(authority, role), 1, role, action), proof);
            }
        }
        _directReject(authority, journals.journal(_withdrawal(authority, address(0xBEEF), address(0)), 2, 0, 0), proof);
        for (uint8 variant; variant < 4; ++variant) {
            bytes32 initial = variant < 2 ? bytes32(0) : (variant == 2 ? ORDER_A : ORDER_B);
            _directReject(authority, journals.journal(_creation(authority, (variant & 1) != 0, variant & 1, initial), 3, 0, 0), proof);
        }
    }

    function testUnsolicitedNativeBalanceDoesNotAdmitNotesOrRoots() public {
        SamechainAuthority authority = _authority();
        // VM-injected unsolicited balance represents no authenticated receipt.
        VM.deal(address(authority), 9);
        _unchanged(authority, 9);
        _reject(authority, abi.encodeCall(authority.create, (_creation(authority, false, 0, bytes32(0)), _proof(PROOF_SELECTOR, 0, VK_ROOT))), 0, SamechainAuthority.InvalidValue.selector);
        (bool ok,) = address(authority).call("");
        require(!ok, "unguarded native receive");
        _unchanged(authority, 9);
    }

    function _authority() private returns (SamechainAuthority) {
        address token = address(new SamechainConstructionToken());
        (address deployed,) = _construct("SamechainAuthority.sol:SamechainAuthority", abi.encode(token, PROGRAM));
        require(deployed != address(0), "authority construction failed");
        return SamechainAuthority(deployed);
    }

    function _construct(string memory artifact, bytes memory args) private returns (address deployed, bytes memory reason) {
        bytes memory code = abi.encodePacked(VM.getCode(artifact), args);
        assembly ("memory-safe") {
            deployed := create(0, add(code, 0x20), mload(code))
            reason := mload(0x40)
            let size := returndatasize()
            mstore(reason, size)
            returndatacopy(add(reason, 0x20), 0, size)
            mstore(0x40, add(add(reason, 0x20), and(add(size, 0x1f), not(0x1f))))
        }
    }

    function _reject(SamechainAuthority authority, bytes memory callData, uint256 value, bytes4 expected) private {
        uint256 balance = address(authority).balance;
        uint256 payerBalance = address(this).balance;
        (bool ok, bytes memory reason) = address(authority).call{value: value}(callData);
        require(!ok && _selector(reason) == expected, "wrong authority rejection boundary");
        require(address(this).balance == payerBalance, "failed call debited payer");
        _unchanged(authority, balance);
    }

    function _directReject(SamechainAuthority authority, bytes memory journal, bytes memory proof) private view {
        (bool ok, bytes memory reason) = address(authority.verifier()).staticcall(abi.encodeCall(ISP1Verifier.verifyProof, (PROGRAM, journal, proof)));
        require(!ok && _selector(reason) == Verifier.ProofInvalid.selector, "actual verifier accepted hostile proof");
        _unchanged(authority, 0);
    }

    function _unchanged(SamechainAuthority authority, uint256 nativeBalance) private view {
        (uint32 treeId, uint64 count, bytes32 root) = authority.treeState();
        require(treeId == 0 && count == 0 && root == EMPTY_ROOT, "rejection admitted tree state");
        require(authority.rootCounts(0, ROOT) == 0 && authority.rootCounts(0, EMPTY_ROOT) == 0, "rejection admitted historical root");
        require(!authority.spent(N_A) && !authority.spent(N_B), "rejection consumed nullifier");
        require(!authority.seenCommitments(C_A) && !authority.seenCommitments(C_B), "rejection admitted input commitment");
        require(!authority.seenCommitments(C_OUT_A) && !authority.seenCommitments(C_OUT_B), "rejection admitted output commitment");
        require(!authority.usedInitialOrders(ORDER_A) && !authority.usedInitialOrders(ORDER_B), "rejection reserved initial order");
        require(!authority.usedCreationNonce(address(this), NONCE), "rejection consumed creation nonce");
        require(address(authority).balance == nativeBalance, "rejection changed authority native balance");
        SamechainConstructionToken token = SamechainConstructionToken(authority.token());
        require(token.balanceOf(address(authority)) == 0 && token.balanceOf(address(this)) == 0, "rejection changed token balance");
    }

    function _selector(bytes memory reason) private pure returns (bytes4 result) {
        if (reason.length >= 4) assembly ("memory-safe") { result := mload(add(reason, 0x20)) }
    }

    function _proof(bytes4 selector, uint256 exitCode, uint256 root) private pure returns (bytes memory) {
        uint256[8] memory proof;
        // Canonical curve-infinity encodings reach the actual pairing equation,
        // which rejects this invalid witness without off-curve gas exhaustion.
        return abi.encodePacked(selector, abi.encode(exitCode, root, uint256(0), proof));
    }

    function _deployment(SamechainAuthority authority) private view returns (bytes memory) {
        SamechainCodec.Deployment memory descriptor = authority.deployment();
        return abi.encodePacked(descriptor.chainId, descriptor.authority, descriptor.authorityCode,
            descriptor.verifier, descriptor.verifierCode, descriptor.ownerProgram, descriptor.schema);
    }

    function _asset(address asset) private pure returns (bytes memory) {
        return asset == address(0) ? abi.encodePacked(uint8(0)) : abi.encodePacked(uint8(1), asset);
    }

    function _note(bytes32 commitment, uint8 role) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), role, commitment, bytes32(uint256(71)), uint16(1), uint32(3), bytes1(0xaa), role, bytes1(0xbb));
    }

    function _orderInput(bool roleB) private pure returns (bytes memory) {
        return abi.encodePacked(roleB ? C_B : C_A, ROOT, uint32(0), uint32(roleB ? 1 : 0),
            roleB ? ORDER_B : ORDER_A, uint64(1), roleB ? N_B : N_A, bytes32(uint256(roleB ? 82 : 81)));
    }

    function _creation(SamechainAuthority authority, bool tokenAsset, uint8 role, bytes32 initial) private view returns (bytes memory) {
        bytes memory order = initial == bytes32(0) ? abi.encodePacked(uint8(0)) : abi.encodePacked(uint8(1), initial);
        return abi.encodePacked("Z2Z_SAMECHAIN_NOTE_CREATION_PACKET\x00", uint16(1), _deployment(authority),
            authority.token(), address(this), NONCE, bytes32(uint256(81)), role,
            _asset(tokenAsset ? authority.token() : address(0)), AMOUNT, order,
            _note(C_OUT_A, role), uint64(block.timestamp + 100), TERMS);
    }

    function _fill(SamechainAuthority authority) private view returns (bytes memory) {
        return abi.encodePacked("Z2Z_SAMECHAIN_PUBLIC_PACKET\x00", uint16(1), _deployment(authority),
            uint32(2), _orderInput(false), _orderInput(true), uint32(2),
            _note(C_OUT_A, 0), _note(C_OUT_B, 1), uint64(block.timestamp + 100), TERMS);
    }

    function _single(SamechainAuthority authority, uint8 role) private view returns (bytes memory) {
        return abi.encodePacked("Z2Z_SAMECHAIN_SINGLE_PACKET\x00", uint16(1), _deployment(authority),
            _orderInput(role == 1), uint32(1), _note(C_OUT_A, role), uint64(block.timestamp + 100), TERMS);
    }

    function _withdrawal(SamechainAuthority authority, address recipient, address asset) private view returns (bytes memory) {
        return abi.encodePacked("Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\x00", uint16(1), _deployment(authority),
            C_A, ROOT, uint32(0), uint32(0), N_A, bytes32(uint256(81)), uint32(1),
            uint8(1), uint8(0), _asset(asset), recipient, uint256(5), uint64(block.timestamp + 100), TERMS);
    }

    function _expiry(bytes memory packet, uint64 timestamp) private pure {
        uint256 offset = packet.length - 40;
        for (uint256 index; index < 8; ++index) packet[offset + index] = bytes1(uint8(timestamp >> (56 - index * 8)));
    }
}
