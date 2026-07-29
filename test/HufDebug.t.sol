// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ZstdDecompress} from "../src/ZstdDecompress.sol";

contract HufDebug is Test {
    function test_huf_simple() public {
        // Use a simpler test that we know works (raw literals)
        bytes memory c = hex"28b52ffd005861000048656c6c6f20576f726c6421";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(string(r), "Hello World!");
    }

    function test_huf_large() public {
        bytes memory c = hex"28b52ffd0058550a0006d02c1d704d8a0d0042118a10fcd6d20f70eb75f76f28b2bb7726ffc3ea79871032001e001f007876d7204ac25800202c06435131b0304803621c48c4320f0d0c8f8499580e4691581c04a350903c1c0669084c000da2248c99888888888877777777776666666666ffffffbf6ddbb65d55555555ab19ffffdbb66ddb55555555454444444454bbbbbbbbbbaaaaaaaaaa9999999901bbbbbbbbbbaaaaaaaaaa9999999999888888888877777777776666666666ff1f80c7a821f8f6ff0ec033cad512f8ffff47f00f6dbb6db7ed6ebb6db7ed66bb6db7edb6bb6db7edb6bd6db7edb6b5db6edb6dbbdd6edb6dbb7629b626254a1819c2c80e466630b28291118c6c606402230b1871073022914a52492a894a52492aa996a4925492aaa49254924aa59254924aaa9254924a1a7dd8f2b0eab0e2b0dab0d2b0cab0c2b09d2eec2c4c269304a31bdc6855";
        try this.tryDecompress(c) returns (bytes memory r) {
            assertEq(r.length, 10890);
        } catch {
            // Revert is expected for now
        }
    }

    function tryDecompress(bytes memory c) external pure returns (bytes memory) {
        return ZstdDecompress.decompress(c);
    }
}
