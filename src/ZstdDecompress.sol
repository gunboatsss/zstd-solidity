// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;

/// @title ZstdDecompress
/// @notice Zstandard (RFC 8478) decompression in Solidity inline assembly.
///         Handles raw, RLE, and compressed blocks with FSE sequences.
library ZstdDecompress {
    error Corrupt();

    function decompress(bytes memory srcData) internal pure returns (bytes memory dstData) {
        assembly ("memory-safe") {
            // ================================================================
            // BYTE READING HELPERS
            // ================================================================
            // CRITICAL: byte(0, mload(addr)) reads memory[addr] (first byte)
            // NOT and(mload(addr), 0xFF) which reads memory[addr+31] (last byte)!

            function read8(p) -> v { v := byte(0, mload(p)) }

            function readLE16(p) -> v {
                v := or(read8(p), shl(8, read8(add(p, 1))))
            }
            function readLE24(p) -> v {
                v := or(or(read8(p), shl(8, read8(add(p, 1)))), shl(16, read8(add(p, 2))))
            }
            function readLE32(p) -> v {
                v := or(
                    or(or(read8(p), shl(8, read8(add(p, 1)))), shl(16, read8(add(p, 2)))),
                    shl(24, read8(add(p, 3)))
                )
            }
            function readLE64(p) -> v {
                v := or(readLE32(p), shl(32, readLE32(add(p, 4))))
            }

            function memcpy(dst, src, len) {
                for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                    mstore8(add(dst, i), read8(add(src, i)))
                }
            }

            // ================================================================
            // BIT UTILITIES
            // ================================================================
            function highbit32(x) -> r {
                // Returns 0-based position of highest set bit (matches ZSTD_highbit32)
                if iszero(x) {
                    r := 0
                    leave
                }
                r := 0
                if gt(x, 0xFFFF) {
                    x := shr(16, x)
                    r := add(r, 16)
                }
                if gt(x, 0xFF) {
                    x := shr(8, x)
                    r := add(r, 8)
                }
                if gt(x, 0xF) {
                    x := shr(4, x)
                    r := add(r, 4)
                }
                if gt(x, 0x3) {
                    x := shr(2, x)
                    r := add(r, 2)
                }
                if gt(x, 0x1) { r := add(r, 1) }
            }
            function tzeros(x) -> r {
                if iszero(x) {
                    r := 32
                    leave
                }
                r := 0
                if iszero(and(x, 0xFFFF)) {
                    x := shr(16, x)
                    r := add(r, 16)
                }
                if iszero(and(x, 0xFF)) {
                    x := shr(8, x)
                    r := add(r, 8)
                }
                if iszero(and(x, 0xF)) {
                    x := shr(4, x)
                    r := add(r, 4)
                }
                if iszero(and(x, 0x3)) {
                    x := shr(2, x)
                    r := add(r, 2)
                }
                if iszero(and(x, 0x1)) { r := add(r, 1) }
            }

            // ================================================================
            // BITSTREAM (for compressed blocks — 64-bit LE accumulator)
            // ================================================================
            // 64-bit bitstream (MUST emulate 64-bit wraparound!)
            function bitRead(cont, cons, nb) -> val, nc {
                nc := add(cons, nb)
                // If already past 64 bits, return 0
                if gt(cons, 63) {
                    val := 0
                    leave
                }
                // Mask to 64-bit: shift left, mask, then extract
                let shifted := and(shl(cons, cont), 0xFFFFFFFFFFFFFFFF)
                val := and(shr(sub(64, nb), shifted), sub(shl(nb, 1), 1))
            }
            function bitReload(cont, cons, ptr, start, limit) -> c2, n2, p2 {
                // If overflowed, return same state (reads will return 0)
                if gt(cons, 64) {
                    c2 := cont
                    n2 := cons
                    p2 := ptr
                    leave
                }
                if iszero(lt(ptr, limit)) {
                    p2 := sub(ptr, div(cons, 8))
                    n2 := and(cons, 7)
                    c2 := readLE64(p2)
                    leave
                }
                if eq(ptr, start) {
                    c2 := cont
                    n2 := cons
                    p2 := ptr
                    leave
                }
                let nb := div(cons, 8)
                p2 := sub(ptr, nb)
                if lt(p2, start) {
                    p2 := start
                    nb := sub(ptr, start)
                }
                n2 := sub(cons, shl(3, nb))
                c2 := readLE64(p2)
            }

            // ================================================================
            // LL / OF / ML BASE VALUES AND EXTRA BITS
            // ================================================================
            function llBase(sym) -> v {
                if lt(sym, 16) {
                    v := sym
                    leave
                }
                if eq(sym, 16) {
                    v := 16
                    leave
                }
                if eq(sym, 17) {
                    v := 18
                    leave
                }
                if eq(sym, 18) {
                    v := 20
                    leave
                }
                if eq(sym, 19) {
                    v := 22
                    leave
                }
                if eq(sym, 20) {
                    v := 24
                    leave
                }
                if eq(sym, 21) {
                    v := 28
                    leave
                }
                if eq(sym, 22) {
                    v := 32
                    leave
                }
                if eq(sym, 23) {
                    v := 40
                    leave
                }
                if eq(sym, 24) {
                    v := 48
                    leave
                }
                if eq(sym, 25) {
                    v := 64
                    leave
                }
                if eq(sym, 26) {
                    v := 0x80
                    leave
                }
                if eq(sym, 27) {
                    v := 0x100
                    leave
                }
                if eq(sym, 28) {
                    v := 0x200
                    leave
                }
                if eq(sym, 29) {
                    v := 0x400
                    leave
                }
                if eq(sym, 30) {
                    v := 0x800
                    leave
                }
                if eq(sym, 31) {
                    v := 0x1000
                    leave
                }
                if eq(sym, 32) {
                    v := 0x2000
                    leave
                }
                if eq(sym, 33) {
                    v := 0x4000
                    leave
                }
                if eq(sym, 34) {
                    v := 0x8000
                    leave
                }
                if eq(sym, 35) {
                    v := 0x10000
                    leave
                }
            }
            function llBits(sym) -> b {
                if lt(sym, 16) {
                    b := 0
                    leave
                }
                if eq(sym, 16) {
                    b := 1
                    leave
                }
                if eq(sym, 17) {
                    b := 1
                    leave
                }
                if eq(sym, 18) {
                    b := 1
                    leave
                }
                if eq(sym, 19) {
                    b := 1
                    leave
                }
                if eq(sym, 20) {
                    b := 2
                    leave
                }
                if eq(sym, 21) {
                    b := 2
                    leave
                }
                if eq(sym, 22) {
                    b := 3
                    leave
                }
                if eq(sym, 23) {
                    b := 3
                    leave
                }
                if eq(sym, 24) {
                    b := 4
                    leave
                }
                if eq(sym, 25) {
                    b := 6
                    leave
                }
                if eq(sym, 26) {
                    b := 7
                    leave
                }
                if eq(sym, 27) {
                    b := 8
                    leave
                }
                if eq(sym, 28) {
                    b := 9
                    leave
                }
                if eq(sym, 29) {
                    b := 10
                    leave
                }
                if eq(sym, 30) {
                    b := 11
                    leave
                }
                if eq(sym, 31) {
                    b := 12
                    leave
                }
                if eq(sym, 32) {
                    b := 13
                    leave
                }
                if eq(sym, 33) {
                    b := 14
                    leave
                }
                if eq(sym, 34) {
                    b := 15
                    leave
                }
                if eq(sym, 35) {
                    b := 16
                    leave
                }
            }
            function ofBase(sym) -> v {
                if eq(sym, 0) {
                    v := 0
                    leave
                }
                if eq(sym, 1) {
                    v := 1
                    leave
                }
                if eq(sym, 2) {
                    v := 1
                    leave
                }
                v := sub(shl(sym, 1), 3)
            }
            function ofBits(sym) -> b {
                if eq(sym, 0) {
                    b := 0
                    leave
                }
                if eq(sym, 1) {
                    b := 1
                    leave
                }
                b := sub(sym, 1)
            }
            function mlBase(sym) -> v {
                if lt(sym, 32) {
                    v := add(sym, 3)
                    leave
                }
                if eq(sym, 32) {
                    v := 35
                    leave
                }
                if eq(sym, 33) {
                    v := 37
                    leave
                }
                if eq(sym, 34) {
                    v := 39
                    leave
                }
                if eq(sym, 35) {
                    v := 41
                    leave
                }
                if eq(sym, 36) {
                    v := 43
                    leave
                }
                if eq(sym, 37) {
                    v := 47
                    leave
                }
                if eq(sym, 38) {
                    v := 51
                    leave
                }
                if eq(sym, 39) {
                    v := 59
                    leave
                }
                if eq(sym, 40) {
                    v := 67
                    leave
                }
                if eq(sym, 41) {
                    v := 83
                    leave
                }
                if eq(sym, 42) {
                    v := 99
                    leave
                }
                if eq(sym, 43) {
                    v := 0x83
                    leave
                }
                if eq(sym, 44) {
                    v := 0x103
                    leave
                }
                if eq(sym, 45) {
                    v := 0x203
                    leave
                }
                if eq(sym, 46) {
                    v := 0x403
                    leave
                }
                if eq(sym, 47) {
                    v := 0x803
                    leave
                }
                if eq(sym, 48) {
                    v := 0x1003
                    leave
                }
                if eq(sym, 49) {
                    v := 0x2003
                    leave
                }
                if eq(sym, 50) {
                    v := 0x4003
                    leave
                }
                if eq(sym, 51) {
                    v := 0x8003
                    leave
                }
                if eq(sym, 52) {
                    v := 0x10003
                    leave
                }
            }
            function mlBits(sym) -> b {
                if lt(sym, 32) {
                    b := 0
                    leave
                }
                if eq(sym, 32) {
                    b := 1
                    leave
                }
                if eq(sym, 33) {
                    b := 1
                    leave
                }
                if eq(sym, 34) {
                    b := 1
                    leave
                }
                if eq(sym, 35) {
                    b := 1
                    leave
                }
                if eq(sym, 36) {
                    b := 2
                    leave
                }
                if eq(sym, 37) {
                    b := 2
                    leave
                }
                if eq(sym, 38) {
                    b := 3
                    leave
                }
                if eq(sym, 39) {
                    b := 3
                    leave
                }
                if eq(sym, 40) {
                    b := 4
                    leave
                }
                if eq(sym, 41) {
                    b := 4
                    leave
                }
                if eq(sym, 42) {
                    b := 5
                    leave
                }
                if eq(sym, 43) {
                    b := 7
                    leave
                }
                if eq(sym, 44) {
                    b := 8
                    leave
                }
                if eq(sym, 45) {
                    b := 9
                    leave
                }
                if eq(sym, 46) {
                    b := 10
                    leave
                }
                if eq(sym, 47) {
                    b := 11
                    leave
                }
                if eq(sym, 48) {
                    b := 12
                    leave
                }
                if eq(sym, 49) {
                    b := 13
                    leave
                }
                if eq(sym, 50) {
                    b := 14
                    leave
                }
                if eq(sym, 51) {
                    b := 15
                    leave
                }
                if eq(sym, 52) {
                    b := 16
                    leave
                }
            }

            // ================================================================
            // DEFAULT NORM WRITERS
            // ================================================================
            function writeOFNorm(p) {
                // OF_defaultNorm: 1,1,1,1,1,1,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,-1,-1,-1,-1,-1
                mstore(add(p, 0), 1)
                mstore(add(p, 32), 1)
                mstore(add(p, 64), 1)
                mstore(add(p, 96), 1)
                mstore(add(p, 128), 1)
                mstore(add(p, 160), 1)
                mstore(add(p, 192), 2)
                mstore(add(p, 224), 2)
                mstore(add(p, 256), 2)
                mstore(add(p, 288), 1)
                mstore(add(p, 320), 1)
                mstore(add(p, 352), 1)
                mstore(add(p, 384), 1)
                mstore(add(p, 416), 1)
                mstore(add(p, 448), 1)
                mstore(add(p, 480), 1)
                mstore(add(p, 512), 1)
                mstore(add(p, 544), 1)
                mstore(add(p, 576), 1)
                mstore(add(p, 608), 1)
                mstore(add(p, 640), 1)
                mstore(add(p, 672), 1)
                mstore(add(p, 704), 1)
                mstore(add(p, 736), 1)
                mstore(add(p, 768), 0xFFFFFFFFFFFF)
                mstore(add(p, 800), 0xFFFFFFFFFFFF)
                mstore(add(p, 832), 0xFFFFFFFFFFFF)
                mstore(add(p, 864), 0xFFFFFFFFFFFF)
                mstore(add(p, 896), 0xFFFFFFFFFFFF)
            }
            // ================================================================
            // FSE_READ_NCOUNT — decode normalized counts from FSE header
            // ================================================================
            function fseReadNCount(norm, maxS, sp, se) -> br, tlog, mo {
                if gt(add(sp, 3), se) { revert(0, 0) }
                let bs := readLE32(sp)
                let ip := add(sp, 4)
                let bc := 4
                tlog := add(and(bs, 0xF), 5)
                if gt(tlog, 15) { revert(0, 0) }
                bs := shr(4, bs)
                let remaining := add(shl(tlog, 1), 1)
                let threshold := shl(tlog, 1)
                let nbBits := add(tlog, 1)
                let cn := 0
                let maxV1 := add(maxS, 1)
                let p0 := 0
                for { let i := 0 } lt(i, maxV1) { i := add(i, 1) } {
                    mstore(add(norm, shl(5, i)), 0)
                }
                for {} 1 {} {
                    if p0 {
                        let rep := div(tzeros(or(not(bs), 0x80000000)), 2)
                        for {} iszero(lt(rep, 12)) {} {
                            cn := add(cn, 36)
                            ip := add(ip, 3)
                            bs := readLE32(ip)
                            rep := div(tzeros(or(not(bs), 0x80000000)), 2)
                        }
                        cn := add(cn, mul(3, rep))
                        bs := shr(mul(2, rep), bs)
                        bc := add(bc, mul(2, rep))
                        cn := add(cn, and(bs, 3))
                        bs := shr(2, bs)
                        bc := add(bc, 2)
                        if iszero(lt(cn, maxV1)) { break }
                        ip := add(ip, div(bc, 8))
                        bc := and(bc, 7)
                        bs := readLE32(ip)
                    }
                    {
                        let maxV := sub(sub(shl(nbBits, 1), 1), remaining)
                        let cnt := 0
                        let nbt := nbBits
                        if lt(and(bs, sub(threshold, 1)), maxV) {
                            cnt := and(bs, sub(threshold, 1))
                            nbt := sub(nbBits, 1)
                        }
                        if iszero(lt(and(bs, sub(threshold, 1)), maxV)) {
                            cnt := and(bs, sub(shl(nbBits, 1), 1))
                            if iszero(lt(cnt, threshold)) { cnt := sub(cnt, maxV) }
                        }
                        bs := shr(nbt, bs)
                        bc := add(bc, nbt)
                        cnt := sub(cnt, 1)
                        if iszero(lt(cnt, 0)) { remaining := sub(remaining, cnt) }
                        if lt(cnt, 0) { remaining := add(remaining, cnt) }
                        mstore(add(norm, shl(5, cn)), and(cnt, 0xFFFF))
                        cn := add(cn, 1)
                        p0 := iszero(cnt)
                        if iszero(lt(remaining, threshold)) {
                            if iszero(gt(remaining, 1)) { break }
                            nbBits := add(highbit32(remaining), 1)
                            threshold := shl(sub(nbBits, 1), 1)
                        }
                        if iszero(lt(cn, maxV1)) { break }
                        ip := add(ip, div(bc, 8))
                        bc := and(bc, 7)
                        bs := readLE32(ip)
                    }
                }
                if iszero(eq(remaining, 1)) { revert(0, 0) }
                if gt(cn, maxV1) { revert(0, 0) }
                mo := sub(cn, 1)
                ip := add(ip, div(add(bc, 7), 8))
                br := sub(ip, sp)
            }

            // ================================================================
            // FSE BUILD SEQ DECODE TABLE
            // ================================================================
            function fseBuildSeqDTable(dt, norm, msym, tlog, tabType, wk) {
                let tsize := shl(tlog, 1)
                let msv1 := add(msym, 1)
                // Temporary arrays placed AFTER all table space (at wk+0x4000)
                let sn := add(wk, 0x4000)
                let spread := add(sn, shl(5, 54))
                let hith := sub(tsize, 1)
                let largeL := shl(sub(tlog, 1), 1)
                let fm := 1
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    let c := and(mload(add(norm, shl(5, s))), 0xFFFF)
                    if eq(c, 0xFFFF) {
                        mstore(add(dt, add(32, shl(5, hith))), s)
                        mstore(add(sn, shl(5, s)), 1)
                        hith := sub(hith, 1)
                    }
                    if iszero(eq(c, 0xFFFF)) {
                        if iszero(lt(c, largeL)) { fm := 0 }
                        mstore(add(sn, shl(5, s)), c)
                    }
                }
                mstore(dt, or(fm, shl(32, tlog)))
                let td := add(dt, 32)
                let tmask := sub(tsize, 1)
                let step := add(add(div(tsize, 2), div(tsize, 8)), 3)
                let pos := 0
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    let n := and(mload(add(norm, shl(5, s))), 0xFFFF)
                    if eq(n, 0xFFFF) { continue }
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        mstore8(add(spread, pos), s)
                        pos := add(pos, 1)
                    }
                }
                pos := 0
                for { let u := 0 } lt(u, tsize) { u := add(u, 1) } {
                    mstore(add(td, shl(5, u)), and(mload(add(spread, pos)), 0xFF))
                    pos := and(add(pos, step), tmask)
                }
                let nc := add(wk, 0x5000)
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    mstore(add(nc, shl(5, s)), and(mload(add(sn, shl(5, s))), 0xFFFF))
                }
                for { let u := 0 } lt(u, tsize) { u := add(u, 1) } {
                    let sym := and(mload(add(td, shl(5, u))), 0xFF)
                    let nx := and(mload(add(nc, shl(5, sym))), 0xFFFF)
                    mstore(add(nc, shl(5, sym)), add(nx, 1))
                    let nb := sub(tlog, highbit32(nx))
                    if iszero(nx) { nb := tlog }
                    let nn := 0
                    if nb { nn := sub(shl(nx, nb), tsize) }
                    let nadd := seqNbAddBits(tabType, sym)
                    let bv := seqBaseValue(tabType, sym)
                    let entry := or(or(and(nn, 0xFFFF), shl(16, nadd)), shl(24, nb))
                    entry := or(entry, shl(32, bv))
                    mstore(add(td, shl(5, u)), entry)
                }
            }

            function seqNbAddBits(tabType, sym) -> b {
                if eq(tabType, 0) {
                    b := llBits(sym)
                    leave
                }
                if eq(tabType, 1) {
                    b := ofBits(sym)
                    leave
                }
                b := mlBits(sym)
            }
            function seqBaseValue(tabType, sym) -> v {
                if eq(tabType, 0) {
                    v := llBase(sym)
                    leave
                }
                if eq(tabType, 1) {
                    v := ofBase(sym)
                    leave
                }
                v := mlBase(sym)
            }

            // ================================================================
            // HARDCODED PREDEFINED FSE TABLES (from zstd spec)
            // ================================================================
            function writeLLTable(p) {
                mstore(add(p, 0), 0x0000000601010001)
                mstore(add(p, 32), 0x0000000004000000)
                mstore(add(p, 64), 0x0000000004000010)
                mstore(add(p, 96), 0x0000000105000020)
                mstore(add(p, 128), 0x0000000305000000)
                mstore(add(p, 160), 0x0000000405000000)
                mstore(add(p, 192), 0x0000000605000000)
                mstore(add(p, 224), 0x0000000705000000)
                mstore(add(p, 256), 0x0000000905000000)
                mstore(add(p, 288), 0x0000000a05000000)
                mstore(add(p, 320), 0x0000000c05000000)
                mstore(add(p, 352), 0x0000000e06000000)
                mstore(add(p, 384), 0x0000001005010000)
                mstore(add(p, 416), 0x0000001405010000)
                mstore(add(p, 448), 0x0000001605010000)
                mstore(add(p, 480), 0x0000001c05020000)
                mstore(add(p, 512), 0x0000002005030000)
                mstore(add(p, 544), 0x0000003005040000)
                mstore(add(p, 576), 0x0000004005060020)
                mstore(add(p, 608), 0x0000008005070000)
                mstore(add(p, 640), 0x0000010006080000)
                mstore(add(p, 672), 0x00000400060a0000)
                mstore(add(p, 704), 0x00001000060c0000)
                mstore(add(p, 736), 0x0000000004000020)
                mstore(add(p, 768), 0x0000000104000000)
                mstore(add(p, 800), 0x0000000205000000)
                mstore(add(p, 832), 0x0000000405000020)
                mstore(add(p, 864), 0x0000000505000000)
                mstore(add(p, 896), 0x0000000705000020)
                mstore(add(p, 928), 0x0000000805000000)
                mstore(add(p, 960), 0x0000000a05000020)
                mstore(add(p, 992), 0x0000000b05000000)
                mstore(add(p, 1024), 0x0000000d06000000)
                mstore(add(p, 1056), 0x0000001005010020)
                mstore(add(p, 1088), 0x0000001205010000)
                mstore(add(p, 1120), 0x0000001605010020)
                mstore(add(p, 1152), 0x0000001805020000)
                mstore(add(p, 1184), 0x0000002005030020)
                mstore(add(p, 1216), 0x0000002805030000)
                mstore(add(p, 1248), 0x0000004004060000)
                mstore(add(p, 1280), 0x0000004004060010)
                mstore(add(p, 1312), 0x0000008005070020)
                mstore(add(p, 1344), 0x0000020006090000)
                mstore(add(p, 1376), 0x00000800060b0000)
                mstore(add(p, 1408), 0x0000000004000030)
                mstore(add(p, 1440), 0x0000000104000010)
                mstore(add(p, 1472), 0x0000000205000020)
                mstore(add(p, 1504), 0x0000000305000020)
                mstore(add(p, 1536), 0x0000000505000020)
                mstore(add(p, 1568), 0x0000000605000020)
                mstore(add(p, 1600), 0x0000000805000020)
                mstore(add(p, 1632), 0x0000000905000020)
                mstore(add(p, 1664), 0x0000000b05000020)
                mstore(add(p, 1696), 0x0000000c05000020)
                mstore(add(p, 1728), 0x0000000f06000000)
                mstore(add(p, 1760), 0x0000001205010020)
                mstore(add(p, 1792), 0x0000001405010020)
                mstore(add(p, 1824), 0x0000001805020020)
                mstore(add(p, 1856), 0x0000001c05020020)
                mstore(add(p, 1888), 0x0000002805030020)
                mstore(add(p, 1920), 0x0000003005040020)
                mstore(add(p, 1952), 0x0001000006100000)
                mstore(add(p, 1984), 0x00008000060f0000)
                mstore(add(p, 2016), 0x00004000060e0000)
                mstore(add(p, 2048), 0x00002000060d0000)
            }
            function writeOFTable(p) {
                mstore(add(p, 0), 0x0000000501010001)
                mstore(add(p, 32), 0x0000000005000000)
                mstore(add(p, 64), 0x0000003d04060000)
                mstore(add(p, 96), 0x000001fd05090000)
                mstore(add(p, 128), 0x00007ffd050f0000)
                mstore(add(p, 160), 0x001ffffd05150000)
                mstore(add(p, 192), 0x0000000505030000)
                mstore(add(p, 224), 0x0000007d04070000)
                mstore(add(p, 256), 0x00000ffd050c0000)
                mstore(add(p, 288), 0x0003fffd05120000)
                mstore(add(p, 320), 0x007ffffd05170000)
                mstore(add(p, 352), 0x0000001d05050000)
                mstore(add(p, 384), 0x000000fd04080000)
                mstore(add(p, 416), 0x00003ffd050e0000)
                mstore(add(p, 448), 0x000ffffd05140000)
                mstore(add(p, 480), 0x0000000105020000)
                mstore(add(p, 512), 0x0000007d04070010)
                mstore(add(p, 544), 0x000007fd050b0000)
                mstore(add(p, 576), 0x0001fffd05110000)
                mstore(add(p, 608), 0x003ffffd05160000)
                mstore(add(p, 640), 0x0000000d05040000)
                mstore(add(p, 672), 0x000000fd04080010)
                mstore(add(p, 704), 0x00001ffd050d0000)
                mstore(add(p, 736), 0x0007fffd05130000)
                mstore(add(p, 768), 0x0000000105010000)
                mstore(add(p, 800), 0x0000003d04060010)
                mstore(add(p, 832), 0x000003fd050a0000)
                mstore(add(p, 864), 0x0000fffd05100000)
                mstore(add(p, 896), 0x0ffffffd051c0000)
                mstore(add(p, 928), 0x07fffffd051b0000)
                mstore(add(p, 960), 0x03fffffd051a0000)
                mstore(add(p, 992), 0x01fffffd05190000)
                mstore(add(p, 1024), 0x00fffffd05180000)
            }
            function writeMLTable(p) {
                mstore(add(p, 0), 0x0000000601010001)
                mstore(add(p, 32), 0x0000000306000000)
                mstore(add(p, 64), 0x0000000404000000)
                mstore(add(p, 96), 0x0000000505000020)
                mstore(add(p, 128), 0x0000000605000000)
                mstore(add(p, 160), 0x0000000805000000)
                mstore(add(p, 192), 0x0000000905000000)
                mstore(add(p, 224), 0x0000000b05000000)
                mstore(add(p, 256), 0x0000000d06000000)
                mstore(add(p, 288), 0x0000001006000000)
                mstore(add(p, 320), 0x0000001306000000)
                mstore(add(p, 352), 0x0000001606000000)
                mstore(add(p, 384), 0x0000001906000000)
                mstore(add(p, 416), 0x0000001c06000000)
                mstore(add(p, 448), 0x0000001f06000000)
                mstore(add(p, 480), 0x0000002206000000)
                mstore(add(p, 512), 0x0000002506010000)
                mstore(add(p, 544), 0x0000002906010000)
                mstore(add(p, 576), 0x0000002f06020000)
                mstore(add(p, 608), 0x0000003b06030000)
                mstore(add(p, 640), 0x0000005306040000)
                mstore(add(p, 672), 0x0000008306070000)
                mstore(add(p, 704), 0x0000020306090000)
                mstore(add(p, 736), 0x0000000404000010)
                mstore(add(p, 768), 0x0000000504000000)
                mstore(add(p, 800), 0x0000000605000020)
                mstore(add(p, 832), 0x0000000705000000)
                mstore(add(p, 864), 0x0000000905000020)
                mstore(add(p, 896), 0x0000000a05000000)
                mstore(add(p, 928), 0x0000000c06000000)
                mstore(add(p, 960), 0x0000000f06000000)
                mstore(add(p, 992), 0x0000001206000000)
                mstore(add(p, 1024), 0x0000001506000000)
                mstore(add(p, 1056), 0x0000001806000000)
                mstore(add(p, 1088), 0x0000001b06000000)
                mstore(add(p, 1120), 0x0000001e06000000)
                mstore(add(p, 1152), 0x0000002106000000)
                mstore(add(p, 1184), 0x0000002306010000)
                mstore(add(p, 1216), 0x0000002706010000)
                mstore(add(p, 1248), 0x0000002b06020000)
                mstore(add(p, 1280), 0x0000003306030000)
                mstore(add(p, 1312), 0x0000004306040000)
                mstore(add(p, 1344), 0x0000006306050000)
                mstore(add(p, 1376), 0x0000010306080000)
                mstore(add(p, 1408), 0x0000000404000020)
                mstore(add(p, 1440), 0x0000000404000030)
                mstore(add(p, 1472), 0x0000000504000010)
                mstore(add(p, 1504), 0x0000000705000020)
                mstore(add(p, 1536), 0x0000000805000020)
                mstore(add(p, 1568), 0x0000000a05000020)
                mstore(add(p, 1600), 0x0000000b05000020)
                mstore(add(p, 1632), 0x0000000e06000000)
                mstore(add(p, 1664), 0x0000001106000000)
                mstore(add(p, 1696), 0x0000001406000000)
                mstore(add(p, 1728), 0x0000001706000000)
                mstore(add(p, 1760), 0x0000001a06000000)
                mstore(add(p, 1792), 0x0000001d06000000)
                mstore(add(p, 1824), 0x0000002006000000)
                mstore(add(p, 1856), 0x0001000306100000)
                mstore(add(p, 1888), 0x00008003060f0000)
                mstore(add(p, 1920), 0x00004003060e0000)
                mstore(add(p, 1952), 0x00002003060d0000)
                mstore(add(p, 1984), 0x00001003060c0000)
                mstore(add(p, 2016), 0x00000803060b0000)
                mstore(add(p, 2048), 0x00000403060a0000)
            }

            // ================================================================
            // BUILD ONE SEQ TABLE (handles predefined / RLE / FSE / repeat)
            // ================================================================
            function buildSeqTable(sp, se, typ, maxS, maxL, dt, wk, tabType) -> np, tlog {
                np := sp
                if eq(typ, 0) {
                    if eq(tabType, 0) {
                        tlog := 6
                        writeLLTable(dt)
                    }
                    if eq(tabType, 1) {
                        tlog := 5
                        writeOFTable(dt)
                    }
                    if eq(tabType, 2) {
                        tlog := 6
                        writeMLTable(dt)
                    }
                    leave
                }
                if eq(typ, 1) {
                    let sym := read8(sp)
                    if gt(sym, maxS) { revert(0, 0) }
                    np := add(sp, 1)
                    tlog := 0
                    mstore(dt, 0)
                    let nadd := seqNbAddBits(tabType, sym)
                    let bv := seqBaseValue(tabType, sym)
                    mstore(add(dt, 32), or(shl(16, nadd), shl(32, bv)))
                    leave
                }
                if eq(typ, 2) {
                    let np2 := add(wk, 0x6000)
                    let br := 0
                    let mo := 0
                    br, tlog, mo := fseReadNCount(np2, maxS, sp, se)
                    if gt(tlog, maxL) { revert(0, 0) }
                    np := add(sp, br)
                    fseBuildSeqDTable(dt, np2, mo, tlog, tabType, wk)
                    leave
                }
                if eq(typ, 3) {
                    tlog := and(mload(dt), 0xFFFFFFFF)
                    leave
                }
            }

            // ================================================================
            // EXECUTE SEQUENCES (decode + execute FSE-encoded sequences)
            // ================================================================
            function execSequences(
                dstPos,
                dstEnd,
                litPtr,
                litSize,
                seqSrc,
                seqSrcSize,
                nbSeq,
                llTab,
                llLog,
                ofTab,
                ofLog,
                mlTab,
                mlLog,
                rep0,
                rep1,
                rep2
            ) -> nd, r0, r1, r2 {
                // Allocate 3 words for repeat offsets at a safe address
                let repBase := mload(0x40)
                mstore(0x40, add(repBase, 0x60))
                mstore(repBase, r0)
                mstore(add(repBase, 0x20), r1)
                mstore(add(repBase, 0x40), r2)

                // Init bitstream
                let srcEnd := add(seqSrc, seqSrcSize)
                let cont := 0
                let cons := 0
                let bp := 0
                let bs := seqSrc
                let bl := add(bs, 8)
                if iszero(lt(seqSrcSize, 8)) {
                    cont := readLE64(sub(srcEnd, 8))
                    cons := 0
                    bp := sub(srcEnd, 8)
                    let srcLast := read8(sub(srcEnd, 1))
                    if srcLast { cons := sub(8, highbit32(srcLast)) }
                }
                if lt(seqSrcSize, 8) {
                    bp := seqSrc
                    cont := read8(seqSrc)
                    if gt(seqSrcSize, 1) { cont := add(cont, shl(8, read8(add(seqSrc, 1)))) }
                    if gt(seqSrcSize, 2) { cont := add(cont, shl(16, read8(add(seqSrc, 2)))) }
                    if gt(seqSrcSize, 3) { cont := add(cont, shl(24, read8(add(seqSrc, 3)))) }
                    if gt(seqSrcSize, 4) { cont := add(cont, shl(32, read8(add(seqSrc, 4)))) }
                    if gt(seqSrcSize, 5) { cont := add(cont, shl(40, read8(add(seqSrc, 5)))) }
                    if gt(seqSrcSize, 6) { cont := add(cont, shl(48, read8(add(seqSrc, 6)))) }
                    let lastB := read8(sub(srcEnd, 1))
                    if lastB { cons := sub(8, highbit32(lastB)) }
                    cons := add(cons, shl(3, sub(8, seqSrcSize)))
                }

                let sLL := 0
                let sOF := 0
                let sML := 0
                if llLog { sLL, cons := bitRead(cont, cons, llLog) }
                cont, cons, bp := bitReload(cont, cons, bp, bs, bl)
                if ofLog { sOF, cons := bitRead(cont, cons, ofLog) }
                cont, cons, bp := bitReload(cont, cons, bp, bs, bl)
                if mlLog { sML, cons := bitRead(cont, cons, mlLog) }
                cont, cons, bp := bitReload(cont, cons, bp, bs, bl)

                let seqS := mload(0x40)
                mstore(0x40, add(seqS, mul(nbSeq, 0x60)))

                for { let i := 0 } lt(i, nbSeq) { i := add(i, 1) } {
                    let llEnt := mload(add(llTab, shl(5, add(sLL, 1))))
                    let llNxt := and(llEnt, 0xFFFF)
                    let llNA := and(shr(16, llEnt), 0xFF)
                    let llNB := and(shr(24, llEnt), 0xFF)
                    let llBV := shr(32, llEnt)

                    let ofEnt := mload(add(ofTab, shl(5, add(sOF, 1))))
                    let ofNxt := and(ofEnt, 0xFFFF)
                    let ofNA := and(shr(16, ofEnt), 0xFF)
                    let ofNB := and(shr(24, ofEnt), 0xFF)
                    let ofBV := shr(32, ofEnt)

                    let mlEnt := mload(add(mlTab, shl(5, add(sML, 1))))
                    let mlNxt := and(mlEnt, 0xFFFF)
                    let mlNA := and(shr(16, mlEnt), 0xFF)
                    let mlNB := and(shr(24, mlEnt), 0xFF)
                    let mlBV := shr(32, mlEnt)

                    let offset := 0
                    if gt(ofNA, 1) {
                        let ex := 0
                        ex, cons := bitRead(cont, cons, ofNA)
                        offset := add(ofBV, ex)
                        mstore(add(repBase, 0x40), mload(add(repBase, 0x20)))
                        mstore(add(repBase, 0x20), mload(repBase))
                        mstore(repBase, offset)
                    }
                    if iszero(gt(ofNA, 1)) {
                        if eq(ofNA, 0) {
                            if eq(ofBV, 0) {
                                offset := mload(add(repBase, 0x20))
                                mstore(add(repBase, 0x20), mload(repBase))
                                mstore(repBase, offset)
                            }
                            if iszero(eq(ofBV, 0)) { offset := mload(repBase) }
                        }
                        if eq(ofNA, 1) {
                            let aB := 0
                            aB, cons := bitRead(cont, cons, 1)
                            let code := add(ofBV, aB)
                            if eq(code, 0) {
                                offset := mload(add(repBase, 0x20))
                                mstore(add(repBase, 0x20), mload(repBase))
                                mstore(repBase, offset)
                            }
                            if eq(code, 1) {
                                offset := sub(mload(repBase), 1)
                                if iszero(offset) { offset := 0xFFFFFFFFFFFFFFFF }
                                mstore(add(repBase, 0x20), mload(repBase))
                                mstore(repBase, offset)
                            }
                            if eq(code, 2) {
                                offset := mload(add(repBase, 0x40))
                                mstore(add(repBase, 0x40), mload(add(repBase, 0x20)))
                                mstore(add(repBase, 0x20), mload(repBase))
                                mstore(repBase, offset)
                            }
                            if eq(code, 3) {
                                offset := sub(mload(repBase), 1)
                                if iszero(offset) { offset := 0xFFFFFFFFFFFFFFFF }
                                mstore(add(repBase, 0x40), mload(add(repBase, 0x20)))
                                mstore(add(repBase, 0x20), mload(repBase))
                                mstore(repBase, offset)
                            }
                        }
                    }

                    let mlSym := mlBV
                    if mlNA {
                        let ex := 0
                        ex, cons := bitRead(cont, cons, mlNA)
                        mlSym := add(mlBV, ex)
                    }
                    let llSym := llBV
                    if llNA {
                        let ex := 0
                        ex, cons := bitRead(cont, cons, llNA)
                        llSym := add(llBV, ex)
                    }

                    if llNB {
                        let lo := 0
                        lo, cons := bitRead(cont, cons, llNB)
                        sLL := add(llNxt, lo)
                    }
                    if iszero(llNB) { sLL := llNxt }

                    if mlNB {
                        let lo := 0
                        lo, cons := bitRead(cont, cons, mlNB)
                        sML := add(mlNxt, lo)
                    }
                    if iszero(mlNB) { sML := mlNxt }

                    if ofNB {
                        let lo := 0
                        lo, cons := bitRead(cont, cons, ofNB)
                        sOF := add(ofNxt, lo)
                    }
                    if iszero(ofNB) { sOF := ofNxt }

                    let s := add(seqS, mul(i, 0x60))
                    mstore(s, llSym)
                    mstore(add(s, 0x20), mlSym)
                    mstore(add(s, 0x40), offset)

                    if gt(cons, 40) {
                        cont, cons, bp := bitReload(cont, cons, bp, bs, bl)
                    }
                }

                let curD := dstPos
                let curL := litPtr
                let litE := add(litPtr, litSize)
                for { let i := 0 } lt(i, nbSeq) { i := add(i, 1) } {
                    let s := add(seqS, mul(i, 0x60))
                    let seqLL := mload(s)
                    let seqML := mload(add(s, 0x20))
                    let seqOff := mload(add(s, 0x40))
                    if gt(seqLL, 0) {
                        if gt(add(curL, seqLL), litE) { revert(0, 0) }
                        for { let j := 0 } lt(j, seqLL) { j := add(j, 1) } {
                            mstore8(add(curD, j), read8(add(curL, j)))
                        }
                        curD := add(curD, seqLL)
                        curL := add(curL, seqLL)
                    }
                    if gt(seqML, 0) {
                        let mSrc := sub(curD, seqOff)
                        for { let j := 0 } lt(j, seqML) { j := add(j, 1) } {
                            mstore8(add(curD, j), read8(add(mSrc, j)))
                        }
                        curD := add(curD, seqML)
                    }
                }
                let rem := sub(litE, curL)
                if gt(rem, 0) {
                    for { let j := 0 } lt(j, rem) { j := add(j, 1) } {
                        mstore8(add(curD, j), read8(add(curL, j)))
                    }
                    curD := add(curD, rem)
                }
                r0 := mload(repBase)
                r1 := mload(add(repBase, 0x20))
                r2 := mload(add(repBase, 0x40))
                nd := curD
            }

            // ================================================================
            // HUFFMAN DECODER
            // ================================================================

            // FSE build DTable for byte symbols (used for Huffman weights)
            // Entry format: [newState(16), symbol(8), nbBits(8)] — 4 bytes each
            function fseBuildDTableBytes(dt, norm, maxSV, tlog, wk) {
                let tsize := shl(tlog, 1)
                let msv1 := add(maxSV, 1)
                let sn := add(wk, 0x6000)
                let spread := add(sn, shl(5, msv1))
                let hith := sub(tsize, 1)
                // Init
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    let c := and(mload(add(norm, shl(5, s))), 0xFFFF)
                    if eq(c, 0xFFFF) {
                        mstore(add(dt, add(4, shl(2, hith))), s)
                        mstore(add(sn, shl(5, s)), 1)
                        hith := sub(hith, 1)
                    }
                    if iszero(eq(c, 0xFFFF)) {
                        mstore(add(sn, shl(5, s)), c)
                    }
                }
                // Header: tableLog in low 16 bits
                mstore(dt, tlog)
                let td := add(dt, 4)
                let tmask := sub(tsize, 1)
                let step := add(add(div(tsize, 2), div(tsize, 8)), 3)
                let pos := 0
                // Spread
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    let n := and(mload(add(norm, shl(5, s))), 0xFFFF)
                    if eq(n, 0xFFFF) { continue }
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        mstore8(add(spread, pos), s)
                        pos := add(pos, 1)
                    }
                }
                pos := 0
                for { let u := 0 } lt(u, tsize) { u := add(u, 1) } {
                    mstore(add(td, shl(2, u)), and(mload(add(spread, pos)), 0xFF))
                    pos := and(add(pos, step), tmask)
                }
                // Build entries
                let nc := add(wk, 0x7000)
                for { let s := 0 } lt(s, msv1) { s := add(s, 1) } {
                    mstore(add(nc, shl(5, s)), and(mload(add(sn, shl(5, s))), 0xFFFF))
                }
                for { let u := 0 } lt(u, tsize) { u := add(u, 1) } {
                    let sym := and(mload(add(td, shl(2, u))), 0xFF)
                    let nx := and(mload(add(nc, shl(5, sym))), 0xFFFF)
                    mstore(add(nc, shl(5, sym)), add(nx, 1))
                    let nb := sub(tlog, highbit32(nx))
                    if iszero(nx) { nb := tlog }
                    let nn := 0
                    if nb { nn := sub(shl(nx, nb), tsize) }
                    let entry := or(or(and(nn, 0xFFFF), shl(16, sym)), shl(24, nb))
                    mstore(add(td, shl(2, u)), entry)
                }
            }

            // FSE decode stream for bytes
            function fseDecodeBytes(dst, maxDst, src, srcSize, dtable, tlog) -> written {
                // Need at least 8 bytes for the bitstream
                if lt(srcSize, 8) { written := dst
                    leave }
                let end := add(src, srcSize)
                let cont := readLE64(sub(end, 8))
                let cons := 0
                let bp := sub(end, 8)
                let bs := src
                let bl := add(bs, 8)
                let lb := read8(sub(end, 1))
                if lb { cons := sub(8, highbit32(lb)) }

                let state := 0
                if tlog {
                    state, cons := bitRead(cont, cons, tlog)
                }

                let op := dst
                let oend := add(dst, maxDst)
                for { } lt(op, oend) { } {
                    if gt(cons, 56) {
                        cont, cons, bp := bitReload(cont, cons, bp, bs, bl)
                    }
                    let entry := mload(add(dtable, add(4, shl(2, state))))
                    let sym := and(shr(16, entry), 0xFF)
                    let nb := and(shr(24, entry), 0xFF)
                    let ns := and(entry, 0xFFFF)
                    if nb {
                        let lo := 0
                        lo, cons := bitRead(cont, cons, nb)
                        state := add(ns, lo)
                    }
                    if iszero(nb) { state := ns }
                    mstore8(op, sym)
                    op := add(op, 1)
                }
                written := sub(op, dst)
            }

            // Huffman decode: reads weights, builds table, decodes stream
            function hufDecompress(dst, dstSize, src, srcSize) {
                // Fill with zeros (placeholder until Huffman decode works)
                for { let i := 0 } lt(i, dstSize) { i := add(i, 1) } {
                    mstore8(add(dst, i), 0)
                }
            }

function hufBuildDTableFromWeights(dt, weights, numSyms) {
                // Rank stats
                let rankStats := mload(0x40)
                mstore(0x40, add(rankStats, 64))
                for { let i := 0 } lt(i, 13) { i := add(i, 1) } {
                    mstore(add(rankStats, shl(2, i)), 0)
                }
                let weightTotal := 0
                for { let n := 0 } lt(n, numSyms) { n := add(n, 1) } {
                    let w := and(mload(add(weights, n)), 0xFF)
                    if gt(w, 12) { continue }
                    if eq(w, 0) { continue }
                    let cnt := mload(add(rankStats, shl(2, w)))
                    mstore(add(rankStats, shl(2, w)), add(cnt, 1))
                    weightTotal := add(weightTotal, shl(sub(w, 1), 1))
                }
                if iszero(weightTotal) { revert(0, 0) }

                let tableLog := add(highbit32(weightTotal), 1)
                if gt(tableLog, 12) { revert(0, 0) }
                let total := shl(tableLog, 1)
                let rest := sub(total, weightTotal)
                let restHigh := highbit32(rest)
                if iszero(eq(shl(restHigh, 1), rest)) { revert(0, 0) }
                let lastWeight := add(restHigh, 1)
                mstore8(add(weights, numSyms), lastWeight)
                let lc := mload(add(rankStats, shl(2, lastWeight)))
                mstore(add(rankStats, shl(2, lastWeight)), add(lc, 1))
                numSyms := add(numSyms, 1)

                // Build sorted symbols
                let sorted := mload(0x40)
                mstore(0x40, add(sorted, shl(5, numSyms)))
                let pos := 0
                for { let w := 1 } lt(w, 13) { w := add(w, 1) } {
                    let cnt := mload(add(rankStats, shl(2, w)))
                    if iszero(cnt) { continue }
                    for { let i := 0 } lt(i, cnt) { i := add(i, 1) } {
                        // Find symbol with this weight (linear search)
                        for { let s := 0 } lt(s, numSyms) { s := add(s, 1) } {
                            let sw := and(mload(add(weights, s)), 0xFF)
                            if eq(sw, w) {
                                mstore(add(sorted, shl(5, pos)), s)
                                pos := add(pos, 1)
                                // Mark as used
                                mstore8(add(weights, s), 0xFF)
                                break
                            }
                        }
                    }
                }

                // Build canonical codes and decode table
                let tableSize := shl(tableLog, 1)
                let nextCode := 0
                for { let w := 1 } lt(w, 13) { w := add(w, 1) } {
                    let cnt := mload(add(rankStats, shl(2, w)))
                    if iszero(cnt) { nextCode := shl(1, nextCode)
                        continue }
                    let code := nextCode
                    for { let i := 0 } lt(i, cnt) { i := add(i, 1) } {
                        let sym := mload(add(sorted, shl(5, add(sub(pos, cnt), i))))
                        // Fill table entries
                        let step := shl(sub(tableLog, w), 1)
                        for { let j := 0 } lt(j, step) { j := add(j, 1) } {
                            let idx := add(code, j)
                            // Store [nbBits(8), symbol(8), 0(16)]
                            mstore(add(dt, add(4, shl(2, idx))), or(shl(16, sym), shl(24, w)))
                        }
                        code := add(code, step)
                    }
                    nextCode := shl(1, add(code, cnt))
                    nextCode := shr(1, nextCode)
                }
                mstore(dt, tableLog)
            }

            // Huffman bitstream decoder
            function hufDecodeStream(dst, dstSize, src, srcSize, dtable) {
                if lt(srcSize, 8) {
                    // Not enough data — copy raw as fallback
                    for { let i := 0 } lt(i, dstSize) { i := add(i, 1) } {
                        mstore8(add(dst, i), read8(add(src, i)))
                    }
                    leave
                }
                let tableLog := and(mload(dtable), 0xFF)
                let tableSize := shl(tableLog, 1)
                let tableMask := sub(tableSize, 1)

                // Init bitstream
                let end := add(src, srcSize)
                let cont := readLE64(sub(end, 8))
                let cons := 0
                let bp := sub(end, 8)
                let bs := src
                let bl := add(bs, 8)
                let lb := read8(sub(end, 1))
                if lb { cons := sub(8, highbit32(lb)) }

                let op := dst
                let oend := add(dst, dstSize)
                for { } lt(op, oend) { } {
                    if gt(cons, 56) {
                        cont, cons, bp := bitReload(cont, cons, bp, bs, bl)
                    }
                    // Read tableLog bits for lookup
                    let idx := 0
                    idx, cons := bitRead(cont, cons, tableLog)
                    // Read entry: [nbBits(8), symbol(8), 0(16)]
                    let entry := mload(add(dtable, add(4, shl(2, idx))))
                    let sym := and(shr(16, entry), 0xFF)
                    let nb := and(shr(24, entry), 0xFF)
                    // If nb > tableLog, consume extra bits and adjust index
                    if gt(nb, tableLog) {
                        let extra := sub(nb, tableLog)
                        let more := 0
                        more, cons := bitRead(cont, cons, extra)
                        // Adjust: idx = (idx >> (nb - tableLog)) | (more << (tableLog - (nb - tableLog)))
                        idx := add(shl(tableLog, more), shr(sub(nb, tableLog), idx))
                        entry := mload(add(dtable, add(4, shl(2, idx))))
                        sym := and(shr(16, entry), 0xFF)
                    }
                    // If nb < tableLog, put back unused bits
                    if lt(nb, tableLog) {
                        cons := sub(cons, sub(tableLog, nb))
                    }
                    mstore8(op, sym)
                    op := add(op, 1)
                }
            }

            function zstdDecompress(srcPtr, srcLen) -> resultPtr {
                if lt(srcLen, 5) { revert(0, 0) }
                let srcEnd := add(srcPtr, srcLen)
                let srcPos := srcPtr

                // Magic: LE 0xFD2FB528
                if iszero(eq(readLE32(srcPos), 0xFD2FB528)) { revert(0, 0) }
                srcPos := add(srcPos, 4)

                // Frame header descriptor
                let fhd := read8(srcPos)
                srcPos := add(srcPos, 1)
                if and(fhd, 8) { revert(0, 0) }
                let dictF := and(fhd, 3)
                let chk := and(shr(2, fhd), 1)
                let single := and(shr(5, fhd), 1)
                let fcsId := shr(6, fhd)

                // Window descriptor (skip — we rely on output buffer sizing)
                if iszero(single) {
                    let wd := read8(srcPos)
                    srcPos := add(srcPos, 1)
                    // windowSize parsed but unused in raw/RLE path
                }

                // Dict ID
                if eq(dictF, 1) { srcPos := add(srcPos, 1) }
                if eq(dictF, 2) { srcPos := add(srcPos, 2) }
                if eq(dictF, 3) { srcPos := add(srcPos, 4) }

                // Frame content size
                let fcSize := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                if eq(fcsId, 1) {
                    fcSize := add(readLE16(srcPos), 256)
                    srcPos := add(srcPos, 2)
                }
                if eq(fcsId, 2) {
                    fcSize := readLE32(srcPos)
                    srcPos := add(srcPos, 4)
                }
                if eq(fcsId, 3) {
                    fcSize := mload(srcPos)
                    srcPos := add(srcPos, 8)
                }
                // Single-segment + fcsId=0: FCS is 1 byte following the header
                if and(single, iszero(fcsId)) {
                    fcSize := read8(srcPos)
                    srcPos := add(srcPos, 1)
                }

                // Allocate output buffer
                let dstBase := mload(0x40)
                let dstCap := 0x20000 // 128KB default
                if iszero(eq(fcSize, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)) {
                    if gt(fcSize, dstCap) { dstCap := fcSize }
                }
                if lt(dstCap, 0x2000) { dstCap := 0x2000 }
                dstCap := add(dstCap, 0x10000)
                mstore(0x40, add(dstBase, dstCap))
                // Output layout: [len(32)][data...]
                let dstPos := add(dstBase, 0x20)

                // Workspace
                let wk := mload(0x40)
                mstore(0x40, add(wk, 0x8000))

                // State
                let rep0 := 1
                let rep1 := 4
                let rep2 := 8

                // ============================================================
                // BLOCK LOOP
                // ============================================================
                for {} 1 {} {
                    if gt(add(srcPos, 2), srcEnd) { revert(0, 0) }
                    let bh := readLE24(srcPos)
                    srcPos := add(srcPos, 3)
                    let lastBlock := and(bh, 1)
                    let blockType := and(shr(1, bh), 3)
                    let blockSize := shr(3, bh)
                    if gt(blockType, 2) { revert(0, 0) }
                    // blockEnd: for RLE (type 1), compressed size is just 1 byte
                    let blockEnd := add(srcPos, blockSize)
                    if eq(blockType, 1) { blockEnd := add(srcPos, 1) }
                    if gt(blockEnd, srcEnd) { revert(0, 0) }

                    // --- RAW ---
                    if eq(blockType, 0) {
                        for { let i := 0 } lt(i, blockSize) { i := add(i, 1) } {
                            mstore8(add(dstPos, i), read8(add(srcPos, i)))
                        }
                        dstPos := add(dstPos, blockSize)
                    }

                    // --- RLE ---
                    if eq(blockType, 1) {
                        let rleB := read8(srcPos)
                        srcPos := add(srcPos, 1)
                        for { let i := 0 } lt(i, blockSize) { i := add(i, 1) } {
                            mstore8(add(dstPos, i), rleB)
                        }
                        dstPos := add(dstPos, blockSize)
                    }

                    // --- COMPRESSED ---
                    if eq(blockType, 2) {
                        let blkPtr := srcPos
                        let litHdr0 := read8(blkPtr)
                        let litEnc := and(litHdr0, 3)
                        let litCode := and(shr(2, litHdr0), 3)

                        // Parse literal size (matching C reference: case 0/2 share path)
                        let lhSize := 0
                        let litSize := 0
                        let litCSize := 0
                        if eq(litCode, 0) {
                            lhSize := 1
                            litSize := shr(3, litHdr0)
                        }
                        if eq(litCode, 1) {
                            lhSize := 2
                            litSize := shr(4, readLE16(blkPtr))
                        }
                        if eq(litCode, 2) {
                            lhSize := 1
                            litSize := shr(3, litHdr0)
                        }
                        if eq(litCode, 3) {
                            lhSize := 3
                            litSize := shr(4, readLE24(blkPtr))
                        }

                        let litPtr := 0
                        let litRead := 0
                        let litDirect := 0

                        // Raw literals
                        if eq(litEnc, 0) {
                            litRead := add(lhSize, litSize)
                            litPtr := add(blkPtr, lhSize)
                            litDirect := 1
                        }
                        // RLE literals
                        if eq(litEnc, 1) {
                            litRead := add(lhSize, 1)
                            let rB := read8(add(blkPtr, lhSize))
                            litPtr := mload(0x40)
                            mstore(0x40, add(litPtr, add(litSize, 0x20)))
                            for { let i := 0 } lt(i, litSize) { i := add(i, 1) } {
                                mstore8(add(litPtr, i), rB)
                            }
                        }
                        // Compressed/Repeat literals
                        // Huffman-compressed literals: not yet supported, revert cleanly
                        if or(eq(litEnc, 2), eq(litEnc, 3)) {
                            revert(0, 0)
                        }

                        blkPtr := add(blkPtr, litRead)

                        // --- Sequences ---
                        let nbSeq := 0
                        if lt(blkPtr, blockEnd) {
                            let s0 := read8(blkPtr)
                            blkPtr := add(blkPtr, 1)
                            nbSeq := s0
                            if gt(s0, 0x7F) {
                                if eq(s0, 0xFF) {
                                    nbSeq := add(readLE16(blkPtr), 0x7F00)
                                    blkPtr := add(blkPtr, 2)
                                }
                                if lt(s0, 0xFF) {
                                    nbSeq := add(shl(8, sub(s0, 0x80)), read8(blkPtr))
                                    blkPtr := add(blkPtr, 1)
                                }
                            }
                        }

                        if nbSeq {
                            let seqDesc := read8(blkPtr)
                            blkPtr := add(blkPtr, 1)
                            if and(seqDesc, 3) { revert(0, 0) }
                            let LLt := shr(6, seqDesc)
                            let OFt := and(shr(4, seqDesc), 3)
                            let MLt := and(shr(2, seqDesc), 3)

                            let llTab := add(wk, 0x0000)
                            let ofTab := add(wk, 0x1200)
                            let mlTab := add(wk, 0x1A00)
                            let llLog := 0
                            let ofLog := 0
                            let mlLog := 0

                            blkPtr, llLog := buildSeqTable(blkPtr, blockEnd, LLt, 35, 9, llTab, wk, 0)
                            blkPtr, ofLog := buildSeqTable(blkPtr, blockEnd, OFt, 31, 8, ofTab, wk, 1)
                            blkPtr, mlLog := buildSeqTable(blkPtr, blockEnd, MLt, 52, 9, mlTab, wk, 2)

                            dstPos, rep0, rep1, rep2 :=
                                execSequences(
                                dstPos,
                                add(dstBase, dstCap),
                                litPtr,
                                litSize,
                                blkPtr,
                                sub(blockEnd, blkPtr),
                                nbSeq,
                                llTab,
                                llLog,
                                ofTab,
                                ofLog,
                                mlTab,
                                mlLog,
                                rep0,
                                rep1,
                                rep2
                            )
                        }
                        if iszero(nbSeq) {
                            if gt(add(dstPos, litSize), add(dstBase, dstCap)) {
                                mstore(0x40, add(add(dstPos, litSize), 0x10000))
                            }
                            if gt(litSize, 0) {
                                for { let i := 0 } lt(i, litSize) { i := add(i, 1) } {
                                    mstore8(add(dstPos, i), read8(add(litPtr, i)))
                                }
                                dstPos := add(dstPos, litSize)
                            }
                        }
                    }

                    srcPos := blockEnd
                    if lastBlock { break }
                }

                if chk { srcPos := add(srcPos, 4) }

                // Build result: [len][data...]
                let outLen := sub(dstPos, add(dstBase, 0x20))
                mstore(dstBase, outLen)
                mstore(0x40, add(dstBase, add(0x20, outLen)))
                resultPtr := dstBase
            }

            // ============================================================
            // EXECUTE — call the main decompressor
            // ============================================================
            dstData := zstdDecompress(add(srcData, 0x20), mload(srcData))
        }
    }
}
