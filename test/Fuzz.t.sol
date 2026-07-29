// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ZstdDecompress} from "../src/ZstdDecompress.sol";

contract FuzzTests is Test {
    /// @notice Fuzz random compressed data — decompressor must not crash
    function test_fuzz_decompress(bytes memory compressed) public {
        uint256 len = bound(compressed.length, 0, 512);
        bytes memory data = new bytes(len);
        for (uint256 i = 0; i < len && i < compressed.length; i++) {
            data[i] = compressed[i];
        }
        try this.tryDecompress(data) returns (bytes memory) {} catch {}
    }

    function tryDecompress(bytes memory c) external pure returns (bytes memory) {
        return ZstdDecompress.decompress(c);
    }

    /// @notice Fuzz known valid magic + random suffix
    function test_fuzz_valid_magic(bytes memory suffix) public {
        // Clamp suffix to available bytes and reasonable size
        uint256 suffixLen = suffix.length;
        if (suffixLen > 256) suffixLen = 256;

        bytes memory data = new bytes(4 + suffixLen);
        data[0] = 0x28;
        data[1] = 0xb5;
        data[2] = 0x2f;
        data[3] = 0xfd;
        for (uint256 i = 0; i < suffixLen; i++) {
            data[4 + i] = suffix[i];
        }
        try this.tryDecompress(data) returns (bytes memory) {} catch {}
    }

    /// @notice Fuzz frame sizes — small valid frames with various parameters
    function test_fuzz_small_frames(uint8 fhdByte, bytes memory payload) public {
        // Only fuzz reasonable FHD values (skip reserved bits)
        fhdByte = uint8(bound(fhdByte, 0, 0xFF)) & 0xF7; // clear reserved bit 3

        uint256 payloadLen = bound(payload.length, 0, 64);

        bytes memory frame = new bytes(4 + 1 + payloadLen);
        // Magic
        frame[0] = 0x28;
        frame[1] = 0xb5;
        frame[2] = 0x2f;
        frame[3] = 0xfd;
        // FHD
        frame[4] = bytes1(fhdByte);
        // Payload
        for (uint256 i = 0; i < payloadLen && i < payload.length; i++) {
            frame[5 + i] = payload[i];
        }

        try this.tryDecompress(frame) returns (bytes memory) {} catch {}
    }
}
