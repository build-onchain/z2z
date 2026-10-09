// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;

// Canonical public descriptions only. Decoding/hashing constructs no proof,
// authentic membership, asset receipt, spentness or financial permission.
library SamechainCodec {
    error InvalidPacket();

    struct Deployment {
        uint64 chainId;
        address authority;
        bytes32 authorityCode;
        address verifier;
        bytes32 verifierCode;
        bytes32 ownerProgram;
        uint16 schema;
    }

    struct Input {
        bytes32 commitment;
        bytes32 root;
        uint32 treeId;
        uint32 index;
        bytes32 orderId;
        uint64 generation;
        bytes32 nullifier;
        bytes32 ownerKey;
    }

    struct Output {
        uint8 kind;
        uint8 role;
        bytes32 commitment;
        bytes32 recoveryKeyCommitment;
        uint16 ciphertextVersion;
        bytes ciphertext;
        address asset;
        address recipient;
        uint256 amount;
    }

    struct Packet {
        Deployment deployment;
        Input[] inputs;
        Output[] outputs;
        uint64 expiry;
        bytes32 termsCommitment;
        bytes32 packetDigest;
        address token;
        address payer;
        bytes32 creationNonce;
        bytes32 ownerKey;
        uint8 role;
        address asset;
        uint256 amount;
        bytes32 initialOrderId;
    }

    struct Cursor { uint256 offset; }

    function decodeFill(bytes calldata raw) internal pure returns (Packet memory packet) {
        Cursor memory cursor = _header(raw, "Z2Z_SAMECHAIN_PUBLIC_PACKET\x00");
        packet.deployment = _deployment(raw, cursor);
        if (_number(raw, cursor, 4) != 2) revert InvalidPacket();
        packet.inputs = new Input[](2);
        packet.inputs[0] = _input(raw, cursor, true);
        packet.inputs[1] = _input(raw, cursor, true);
        Input memory a = packet.inputs[0];
        Input memory b = packet.inputs[1];
        if (a.commitment == b.commitment || a.nullifier == b.nullifier || a.ownerKey == b.ownerKey
            || a.orderId == b.orderId || (a.treeId == b.treeId && a.index == b.index)) revert InvalidPacket();
        packet.outputs = _outputs(raw, cursor, packet.inputs);
        uint8 roles;
        for (uint256 i; i < packet.outputs.length; ++i) roles |= uint8(1) << packet.outputs[i].role;
        if (roles != 3) revert InvalidPacket();
        _finish(raw, cursor, packet);
    }

    function decodeSingle(bytes calldata raw) internal pure returns (Packet memory packet) {
        Cursor memory cursor = _header(raw, "Z2Z_SAMECHAIN_SINGLE_PACKET\x00");
        packet.deployment = _deployment(raw, cursor);
        packet.inputs = new Input[](1);
        packet.inputs[0] = _input(raw, cursor, true);
        packet.outputs = _outputs(raw, cursor, packet.inputs);
        uint8 role = packet.outputs[0].role;
        for (uint256 i = 1; i < packet.outputs.length; ++i) {
            if (packet.outputs[i].role != role) revert InvalidPacket();
        }
        _finish(raw, cursor, packet);
    }

    function decodeWithdrawal(bytes calldata raw) internal pure returns (Packet memory packet) {
        Cursor memory cursor = _header(raw, "Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\x00");
        packet.deployment = _deployment(raw, cursor);
        packet.inputs = new Input[](1);
        packet.inputs[0] = _input(raw, cursor, false);
        packet.outputs = _outputs(raw, cursor, packet.inputs);
        bool hasExit;
        for (uint256 i; i < packet.outputs.length; ++i) {
            if (packet.outputs[i].role != 0) revert InvalidPacket();
            if (packet.outputs[i].kind == 1) hasExit = true;
        }
        if (!hasExit) revert InvalidPacket();
        _finish(raw, cursor, packet);
    }

    function decodeCreation(bytes calldata raw) internal pure returns (Packet memory packet) {
        Cursor memory cursor = _header(raw, "Z2Z_SAMECHAIN_NOTE_CREATION_PACKET\x00");
        packet.deployment = _deployment(raw, cursor);
        packet.token = address(uint160(_number(raw, cursor, 20)));
        packet.payer = address(uint160(_number(raw, cursor, 20)));
        packet.creationNonce = bytes32(_number(raw, cursor, 32));
        packet.ownerKey = bytes32(_number(raw, cursor, 32));
        packet.role = _role(raw, cursor);
        packet.asset = _asset(raw, cursor);
        packet.amount = _number(raw, cursor, 32);
        uint256 orderTag = _number(raw, cursor, 1);
        if (orderTag == 1) {
            packet.initialOrderId = bytes32(_number(raw, cursor, 32));
            if (packet.initialOrderId == bytes32(0)) revert InvalidPacket();
        } else if (orderTag != 0) {
            revert InvalidPacket();
        }
        packet.inputs = new Input[](0);
        packet.outputs = new Output[](1);
        packet.outputs[0] = _output(raw, cursor);
        if (packet.token == address(0) || packet.payer == address(0) || packet.creationNonce == bytes32(0)
            || packet.ownerKey == bytes32(0) || packet.amount == 0
            || (packet.asset != address(0) && packet.asset != packet.token)
            || packet.outputs[0].kind != 0 || packet.outputs[0].role != packet.role) revert InvalidPacket();
        _finish(raw, cursor, packet);
    }

    function deploymentDigest(Deployment memory value) internal pure returns (bytes32) {
        _validDeployment(value);
        return sha256(abi.encodePacked("Z2Z_SAMECHAIN_DEPLOYMENT\x00", uint16(1), value.chainId,
            value.authority, value.authorityCode, value.verifier, value.verifierCode, value.ownerProgram, value.schema));
    }

    function ownerJournal(Packet memory packet, uint8 role, uint8 action) internal pure returns (bytes memory) {
        if (role > 1 || action > 2) revert InvalidPacket();
        uint256 index;
        if (packet.inputs.length == 2) {
            if (action != 0) revert InvalidPacket();
            index = role;
        } else if (packet.inputs.length == 1) {
            if (action == 0 || packet.outputs.length == 0) revert InvalidPacket();
            for (uint256 i; i < packet.outputs.length; ++i) {
                if (packet.outputs[i].role != role) revert InvalidPacket();
            }
        } else {
            revert InvalidPacket();
        }
        Input memory input = packet.inputs[index];
        if (input.orderId == bytes32(0) || input.generation == 0) revert InvalidPacket();
        // Journal order is N, commitment; ordinary withdrawal reverses these.
        return abi.encodePacked("Z2Z_SAMECHAIN_OWNER_JOURNAL\x00", uint16(1), uint16(action == 0 ? 2 : 1),
            action, role, deploymentDigest(packet.deployment), packet.termsCommitment, packet.packetDigest,
            input.nullifier, input.commitment, input.root, input.treeId, input.index, input.orderId, input.generation);
    }

    function withdrawalJournal(Packet memory packet) internal pure returns (bytes memory) {
        if (packet.inputs.length != 1) revert InvalidPacket();
        Input memory input = packet.inputs[0];
        if (input.orderId != bytes32(0) || input.generation != 0) revert InvalidPacket();
        return abi.encodePacked("Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_JOURNAL\x00", uint16(1), uint16(1),
            deploymentDigest(packet.deployment), packet.termsCommitment, packet.packetDigest,
            input.commitment, input.nullifier, input.root, input.treeId, input.index);
    }

    function creationJournal(Packet memory packet) internal pure returns (bytes memory) {
        if (packet.inputs.length != 0 || packet.outputs.length != 1 || packet.outputs[0].kind != 0
            || packet.token == address(0)) revert InvalidPacket();
        // Creation binds packet before terms; it has no legacy action byte.
        bytes memory asset = packet.asset == address(0)
            ? abi.encodePacked(uint8(0)) : abi.encodePacked(uint8(1), packet.asset);
        bytes memory order = packet.initialOrderId == bytes32(0)
            ? abi.encodePacked(uint8(0)) : abi.encodePacked(uint8(1), packet.initialOrderId);
        return abi.encodePacked("Z2Z_SAMECHAIN_NOTE_CREATION_JOURNAL\x00", uint16(1), uint16(1),
            deploymentDigest(packet.deployment), packet.packetDigest, packet.termsCommitment, packet.creationNonce,
            packet.payer, packet.ownerKey, packet.token, packet.role, asset, packet.amount, order, packet.outputs[0].commitment);
    }

    function _header(bytes calldata raw, bytes memory domain) private pure returns (Cursor memory cursor) {
        if (raw.length > 65536 || raw.length < domain.length + 2) revert InvalidPacket();
        if (keccak256(raw[:domain.length]) != keccak256(domain)) revert InvalidPacket();
        cursor = Cursor(domain.length);
        if (_number(raw, cursor, 2) != 1) revert InvalidPacket();
    }

    function _deployment(bytes calldata raw, Cursor memory cursor) private pure returns (Deployment memory value) {
        value.chainId = uint64(_number(raw, cursor, 8));
        value.authority = address(uint160(_number(raw, cursor, 20)));
        value.authorityCode = bytes32(_number(raw, cursor, 32));
        value.verifier = address(uint160(_number(raw, cursor, 20)));
        value.verifierCode = bytes32(_number(raw, cursor, 32));
        value.ownerProgram = bytes32(_number(raw, cursor, 32));
        value.schema = uint16(_number(raw, cursor, 2));
        _validDeployment(value);
    }

    function _validDeployment(Deployment memory value) private pure {
        if (value.chainId == 0 || value.authority == address(0) || value.authorityCode == bytes32(0)
            || value.verifier == address(0) || value.verifierCode == bytes32(0)
            || value.ownerProgram == bytes32(0) || value.schema != 1) revert InvalidPacket();
    }

    function _input(bytes calldata raw, Cursor memory cursor, bool order) private pure returns (Input memory value) {
        value.commitment = bytes32(_number(raw, cursor, 32));
        value.root = bytes32(_number(raw, cursor, 32));
        value.treeId = uint32(_number(raw, cursor, 4));
        value.index = uint32(_number(raw, cursor, 4));
        if (order) {
            value.orderId = bytes32(_number(raw, cursor, 32));
            value.generation = uint64(_number(raw, cursor, 8));
            if (value.orderId == bytes32(0) || value.generation == 0) revert InvalidPacket();
        }
        value.nullifier = bytes32(_number(raw, cursor, 32));
        value.ownerKey = bytes32(_number(raw, cursor, 32));
        if (value.commitment == bytes32(0) || value.root == bytes32(0)
            || value.nullifier == bytes32(0) || value.ownerKey == bytes32(0)) revert InvalidPacket();
    }

    function _outputs(bytes calldata raw, Cursor memory cursor, Input[] memory inputs)
        private pure returns (Output[] memory values)
    {
        uint256 count = _number(raw, cursor, 4);
        if (count == 0 || count > 8) revert InvalidPacket();
        values = new Output[](count);
        // Bounded eight-note scan; cache each ciphertext hash once.
        bytes32[8] memory ciphertextHashes;
        uint256 previousPayment;
        bool hasPayment;
        for (uint256 i; i < count; ++i) {
            Output memory value = _output(raw, cursor);
            if (value.kind == 0) {
                bytes32 ciphertextHash = keccak256(value.ciphertext);
                for (uint256 j; j < i; ++j) {
                    if (values[j].kind == 0 && (value.commitment == values[j].commitment
                        || ciphertextHash == ciphertextHashes[j])) revert InvalidPacket();
                }
                for (uint256 j; j < inputs.length; ++j) {
                    if (value.commitment == inputs[j].commitment) revert InvalidPacket();
                }
                ciphertextHashes[i] = ciphertextHash;
            } else {
                if (hasPayment && !_paymentLess(values[previousPayment], value)) revert InvalidPacket();
                previousPayment = i;
                hasPayment = true;
            }
            values[i] = value;
        }
    }

    function _output(bytes calldata raw, Cursor memory cursor) private pure returns (Output memory value) {
        value.kind = uint8(_number(raw, cursor, 1));
        value.role = _role(raw, cursor);
        if (value.kind == 0) {
            value.commitment = bytes32(_number(raw, cursor, 32));
            value.recoveryKeyCommitment = bytes32(_number(raw, cursor, 32));
            value.ciphertextVersion = uint16(_number(raw, cursor, 2));
            uint256 length = _number(raw, cursor, 4);
            if (value.commitment == bytes32(0) || value.recoveryKeyCommitment == bytes32(0)
                || value.ciphertextVersion == 0 || length == 0 || length > 4096) revert InvalidPacket();
            uint256 start = _take(raw, cursor, length);
            value.ciphertext = raw[start:start + length];
        } else if (value.kind == 1 || value.kind == 2) {
            value.asset = _asset(raw, cursor);
            value.recipient = address(uint160(_number(raw, cursor, 20)));
            value.amount = _number(raw, cursor, 32);
            if (value.recipient == address(0) || value.amount == 0) revert InvalidPacket();
        } else {
            revert InvalidPacket();
        }
    }

    function _paymentLess(Output memory a, Output memory b) private pure returns (bool) {
        // address(0) represents Native, sorted before every nonzero Token.
        // Exit/Fee kind and amount are deliberately NOT part of the payment key.
        if (a.role != b.role) return a.role < b.role;
        if (a.asset != b.asset) return uint160(a.asset) < uint160(b.asset);
        return uint160(a.recipient) < uint160(b.recipient);
    }

    function _role(bytes calldata raw, Cursor memory cursor) private pure returns (uint8 role) {
        role = uint8(_number(raw, cursor, 1));
        if (role > 1) revert InvalidPacket();
    }

    function _asset(bytes calldata raw, Cursor memory cursor) private pure returns (address asset) {
        uint256 tag = _number(raw, cursor, 1);
        if (tag == 1) {
            asset = address(uint160(_number(raw, cursor, 20)));
            if (asset == address(0)) revert InvalidPacket();
        } else if (tag != 0) {
            revert InvalidPacket();
        }
    }

    function _finish(bytes calldata raw, Cursor memory cursor, Packet memory packet) private pure {
        packet.expiry = uint64(_number(raw, cursor, 8));
        packet.termsCommitment = bytes32(_number(raw, cursor, 32));
        if (packet.expiry == 0 || packet.termsCommitment == bytes32(0) || cursor.offset != raw.length) revert InvalidPacket();
        packet.packetDigest = sha256(raw);
    }

    function _take(bytes calldata raw, Cursor memory cursor, uint256 width) private pure returns (uint256 start) {
        start = cursor.offset;
        if (start > raw.length || width > raw.length - start) revert InvalidPacket();
        cursor.offset = start + width;
    }

    function _number(bytes calldata raw, Cursor memory cursor, uint256 width) private pure returns (uint256 value) {
        // Every caller uses a fixed width in 1..32. Bounds precede CALLDATALOAD;
        // the shift discards bytes outside that exact big-endian field.
        uint256 start = _take(raw, cursor, width);
        assembly ("memory-safe") {
            value := shr(mul(sub(32, width), 8), calldataload(add(raw.offset, start)))
        }
    }
}
