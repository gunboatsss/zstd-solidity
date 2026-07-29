// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ZstdDecompress} from "../src/ZstdDecompress.sol";

contract GoldenTests is Test {
    function loadAndDecompress(string memory name) internal returns (bytes memory) {
        string memory path = string.concat("test/data/", name, ".zst");
        bytes memory compressed = vm.readFileBinary(path);
        return ZstdDecompress.decompress(compressed);
    }

    function test_empty_block() public {
        bytes memory r = loadAndDecompress("empty-block");
        assertEq(r.length, 0);
    }

    function test_block_128k() public {
        bytes memory r = loadAndDecompress("block-128k");
        assertEq(r.length, 131068);
        assertEq(r[0], bytes1(0x00));
        assertEq(r[131067], bytes1(0x00));
    }

    function test_rle_first_block() public {
        bytes memory r = loadAndDecompress("rle-first-block");
        assertEq(r.length, 1048576);
        assertEq(r[0], bytes1(0x00));
        assertEq(r[500000], bytes1(0x00));
    }
}
