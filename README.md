# Zstd Decompression in Solidity

Pure Yul inline-assembly Zstandard (RFC 8478) decompressor. No dependencies beyond Solidity ^0.8.20.

## Quickstart

```solidity
import {ZstdDecompress} from "src/ZstdDecompress.sol";

bytes memory decompressed = ZstdDecompress.decompress(hex"28b52ffd...");
```

## Features

| Feature | Status |
|---------|--------|
| Raw blocks | ✅ |
| RLE blocks | ✅ |
| Empty frames | ✅ |
| Compressed (FSE sequences) | ✅ |
| Predefined / FSE / RLE / Repeat tables | ✅ |
| Multiple blocks per frame | ✅ |
| Huffman-compressed literals | ⚠️ passthrough |

## Build

Requires `via_ir = true` in foundry.toml.

```bash
forge build
```

## Test

```bash
forge test          # 19 unit + 3 golden
forge test --fuzz-runs 256  # +3 fuzz suites
```

## Gas

| Test | Gas |
|------|-----|
| Single byte | 5,284 |
| Raw 50 bytes | 9,688 |
| Empty frame | 2,026 |
| Compressed 40 bytes | 134,660 |
| Compressed 900 bytes | 197,833 |
| 1 MB RLE | 64,076,240 |

## Credits

Based on the Zstandard reference implementation by Meta Platforms, Inc.
