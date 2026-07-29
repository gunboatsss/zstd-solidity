// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ZstdDecompress} from "../src/ZstdDecompress.sol";

/// @notice Zstd decompression test suite — 18 tests
contract ZstdTestSuite is Test {
    function test_raw_hello() public {
        bytes memory c = hex"28b52ffd005861000048656c6c6f20576f726c6421";
        assertEq(string(ZstdDecompress.decompress(c)), "Hello World!");
    }

    function test_raw_hello_comma() public {
        bytes memory c = hex"28b52ffd005869000048656c6c6f2c20576f726c6421";
        assertEq(string(ZstdDecompress.decompress(c)), "Hello, World!");
    }

    function test_raw_fox() public {
        bytes memory c =
            hex"28b52ffd005861010054686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e";
        assertEq(string(ZstdDecompress.decompress(c)), "The quick brown fox jumps over the lazy dog.");
    }

    function test_raw_numbers() public {
        bytes memory c = hex"28b52ffd005851000030313233343536373839";
        assertEq(string(ZstdDecompress.decompress(c)), "0123456789");
    }

    function test_raw_binary() public {
        bytes memory c =
            hex"28b52ffd0058010200000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        bytes memory expected =
            hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        assertEq(ZstdDecompress.decompress(c), expected);
    }

    function test_single_byte_A() public {
        bytes memory c = hex"28b52ffd005809000041";
        assertEq(string(ZstdDecompress.decompress(c)), "A");
    }

    function test_single_byte_B() public {
        bytes memory c = hex"28b52ffd005809000042";
        assertEq(string(ZstdDecompress.decompress(c)), "B");
    }

    function test_five_A_raw() public {
        bytes memory c = hex"28b52ffd00582900004141414141";
        assertEq(string(ZstdDecompress.decompress(c)), "AAAAA");
    }

    function test_empty_frame() public {
        bytes memory c = hex"28b52ffd2000010000";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 0);
    }

    function test_compressed_abcde_x8() public {
        bytes memory c = hex"28b52ffd00585d0000286162636465010040162d";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 40);
    }

    function test_compressed_abcde_x10() public {
        bytes memory c = hex"28b52ffd00585d00002861626364650100c22c5a";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 50);
    }

    function test_compressed_hello_x50() public {
        bytes memory c = hex"28b52ffd00588d00005048656c6c6f576f726c640100e7550b12";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 500);
    }

    function test_compressed_zeros() public {
        bytes memory c = hex"28b52ffd005845000010000001003f012c";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 100);
        for (uint256 i = 0; i < r.length; i++) {
            assertEq(r[i], bytes1(0x00));
        }
    }

    function test_compressed_A_x20() public {
        bytes memory c = hex"28b52ffd005845000010414101001ec002";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 20);
    }

    function test_compressed_A_x50() public {
        bytes memory c = hex"28b52ffd0058450000104141010045000b";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 50);
    }

    function test_compressed_level1() public {
        bytes memory c = hex"28b52ffd0048fd0000c0436f6d7072657373206d65206174206c6576656c20312120010014af3ac7";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 480);
    }

    function test_compressed_level19() public {
        bytes memory c = hex"28b52ffd0068150100d04d6178696d756d20636f6d7072657373696f6e207465737421200100beeb6a8e01";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 780);
    }

    function test_repetitive_45x20() public {
        bytes memory c =
            hex"28b52ffd0058b50100d40254686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e200100a50a2b5506";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 900);
    }

    function test_fuzz_counterexample_86() public {
        bytes memory c =
            hex"28b52ffd20560d0200a403000029d4c02a30c59d449bf1e6d0869c40dca3e4799100cf1ca65261c476654bae4fc905d241f77180b212ee3d5cfc2429057b859d3c8328d1ea01000cc002";
        bytes memory r = ZstdDecompress.decompress(c);
        assertEq(r.length, 86);
    }
}
