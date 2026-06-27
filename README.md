# make_npdata-rs

Rust port of `make_npdata`, a GPL-3.0 EDAT/SDAT tool originally written in C/C++.

This version keeps the original command workflows instead of replacing them with Rust-only subcommands:

- `-d` EDAT/SDAT decryption/extraction
- `-e` EDAT/SDAT packing/encryption/forging
- `-b` dev_klic brute-force mode
- `make_npdata v1.3.4` positional CLI shape for encryption
- compatibility fallback for the older `v1.2` encryption argument order
- NPD + EDAT/SDAT header parsing and forging
- RAP -> RIF key conversion, plus direct `rifkey.bin` input
- AES-128 ECB/CBC, SHA1-HMAC and AES-CMAC helpers via RustCrypto
- EDAT/SDAT metadata/header hash verification and forging
- custom LZ decompressor used by compressed EDAT/SDAT blocks

## Build

```bash
cargo build --release
```

## Original-compatible usage, v1.3.4

```bash
make_npdata [-v] -e <input> <output> <format> <data> <version> <compression> <block> [license type contentID key_mode [rap|rifkey.bin]]
make_npdata [-v] -d <input> <output> <key_mode> [rap|rifkey.bin]
make_npdata [-v] -b <input> <source> [mode]
```

Encryption parameters:

```text
format:      0 = SDAT, 1 = EDAT
data:        0 = debug data, 1 = finalized data
version:     1, 2, 3, or 4
compression: 0 = disabled, 1 = enabled
block:       block size in KB: 1, 2, 4, 8, 16, or 32
```

Finalized EDAT only appends:

```text
license:   1 = network, 2 = local/RAP, 3 = free/klic
type:      hex value such as 00, 01, 20, 21, or 30
contentID: NPDRM content ID
key_mode:  klic/key mode
rap:       optional RAP path, or rifkey.bin to read a raw RIF key
```

The command below is now parsed as v1.3.4 SDAT debug data and the trailing finalized-EDAT parameters are ignored, matching the original behavior:

```bash
make_npdata.exe -e data_new.dat data.sdat 0 0 2 0 16 3 00 UP0000-BLJM74271_00-0000000000000000 1
```

Other examples:

```bash
cargo run -- -d input.edat output.bin 4
cargo run -- -v -d input.edat output.bin 2 key.rap
cargo run -- -e input.bin output.sdat 0 0 2 0 16
cargo run -- -e input.bin output.edat 1 1 3 0 16 3 00 XXYYYY-AAAABBBBB_CC-DDDDDDDDDDDDDDDD 4
cargo run -- -b input.edat source.bin 0
cargo run -- -v -b input.edat source.txt 1
cargo run -- -v -b input.edat source_utf16.txt 2
```

The key mode table is preserved:

```text
0 - No key
1 - NPDRM OMAC key 1 (free license key)
2 - NPDRM OMAC key 2
3 - NPDRM OMAC key 3
4 - PS3 key (klic_dec_key)
5 - PSX key (PSOne Classics)
6 - PSP key 1 (PSP Minis)
7 - PSP key 2 (PSP Remasters)
8 - Custom key (32 hex chars, or klic.bin)
```

Compatibility helper aliases are still available:

```bash
cargo run -- info input.edat
cargo run -- rap2rif key.rap
```

## Porting notes

The C/C++ repository is organized around `make_npdata.cpp`, `make_npdata.h`, `utils.cpp/.h`, `aes.cpp/.h`, `sha1.cpp/.h`, and `lz.cpp/.h`. The Rust version replaces the bundled AES/SHA1 implementations with RustCrypto crates and keeps EDAT/SDAT-specific logic in `src/npdata.rs`.

The original project is GPL-3.0; this port keeps the same license identifier.
