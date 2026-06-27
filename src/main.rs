use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use make_npdata_rs::constants::*;
use make_npdata_rs::crypto::aes_cmac_16;
use make_npdata_rs::npdata::{extract_data, pack_data, read_headers_from_path, rif_key_from_rap_file};
use make_npdata_rs::util::{bytes_to_hex, xor16};

fn print_usage() {
    println!("***************************************************************************\n");
    println!("make_npdata v1.3.4 - PS3 EDAT/SDAT file encrypter/decrypter/bruteforcer.");
    println!(" - Written by Hykem (C).\n");
    println!("***************************************************************************\n");
    println!("Usage: make_npdata [-v] -e <input> <output> <format> <data> <version> <compression> <block> [license type contentID key_mode [rap|rifkey.bin]]");
    println!("       make_npdata [-v] -d <input> <output> <key_mode> [rap|rifkey.bin]");
    println!("       make_npdata [-v] -b <input> <source> [mode]\n");
    println!("- Modes:");
    println!("[-v]: Verbose mode");
    println!("[-e]: Encryption mode");
    println!("[-d]: Decryption mode");
    println!("[-b]: Bruteforce mode\n");
    println!("- Encryption mode only:");
    println!("<format>:      0 - SDAT");
    println!("               1 - EDAT");
    println!("<data>:        0 - Debug data");
    println!("               1 - Finalized data");
    println!("<version>:     1 - EDAT version 1");
    println!("               2 - EDAT/SDAT version 2");
    println!("               3 - EDAT/SDAT version 3");
    println!("               4 - EDAT/SDAT version 4");
    println!("<compression>: 0 - Disable compression");
    println!("               1 - Enable compression");
    println!("<block>:       Block size in KB (1, 2, 4, 8, 16, 32)\n");
    println!("- Finalized EDAT only:");
    println!("<license>:     1 - Network license (not supported)");
    println!("               2 - Local license (uses RAP/RIF key)");
    println!("               3 - Free license (uses klic as key)");
    println!("<type>:        00 - Common");
    println!("               01 - PS2 EDAT");
    println!("               20 - PSP Remasters");
    println!("               21 - Modules (disc bind)");
    println!("               30 - Unknown");
    println!("<contentID>:   Content ID (XXYYYY-AAAABBBBB_CC-DDDDDDDDDDDDDDDD)\n");
    println!("- Encryption and decryption modes:");
    println!("<key_mode>:    0 - No key");
    println!("               1 - NPDRM OMAC key 1 (free license key)");
    println!("               2 - NPDRM OMAC key 2");
    println!("               3 - NPDRM OMAC key 3");
    println!("               4 - PS3 key (klic_dec_key)");
    println!("               5 - PSX key (PSOne Classics)");
    println!("               6 - PSP key 1 (PSP Minis)");
    println!("               7 - PSP key 2 (PSP Remasters)");
    println!("               8 - Custom key (32 hex chars, or klic.bin)");
    println!("[rap]:         RAP file for encryption/decryption or rifkey.bin (optional)\n");
    println!("- Bruteforce mode:");
    println!("<source>:      ELF file source for klic");
    println!("[mode]:        0 - Binary");
    println!("               1 - Text");
    println!("               2 - Unicode text");
}

fn parse_i32_arg(value: &str, name: &str) -> Result<i32> {
    value
        .parse::<i32>()
        .with_context(|| format!("ERROR: Invalid {name}: {value}"))
}

fn parse_hex_i32_arg(value: &str, name: &str) -> Result<i32> {
    i32::from_str_radix(value, 16).with_context(|| format!("ERROR: Invalid {name}: {value}"))
}

fn is_hex_32(value: &str) -> bool {
    value.len() == 32 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

fn hex_16(value: &str) -> Result<[u8; 16]> {
    if !is_hex_32(value) {
        bail!("ERROR: Invalid 16-byte hex key");
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn read_16_byte_file(path: &Path, context: &str) -> Result<[u8; 16]> {
    let mut file = File::open(path).with_context(|| format!("ERROR: {context}: {}", path.display()))?;
    let mut key = [0u8; 16];
    file.read_exact(&mut key).with_context(|| format!("ERROR: {} must contain at least 16 bytes", path.display()))?;
    Ok(key)
}

fn read_custom_klic() -> Result<[u8; 16]> {
    read_16_byte_file(Path::new("klic.bin"), "Please place your binary custom klic in a klic.bin file")
}

fn select_devklic(key_mode: i32) -> Result<[u8; 16]> {
    match key_mode {
        0 => Ok([0u8; 16]),
        1 => Ok(NPDRM_OMAC_KEY_1),
        2 => Ok(NPDRM_OMAC_KEY_2),
        3 => Ok(NPDRM_OMAC_KEY_3),
        4 => Ok(NPDRM_KLIC_KEY),
        5 => Ok(NPDRM_PSX_KEY),
        6 => Ok(NPDRM_PSP_KEY_1),
        7 => Ok(NPDRM_PSP_KEY_2),
        8 => read_custom_klic(),
        _ => bail!("ERROR: Invalid mode"),
    }
}

fn select_devklic_with_optional_hex(args: &[String], mode_index: usize, next_index: usize) -> Result<([u8; 16], bool)> {
    let key_mode = parse_i32_arg(&args[mode_index], "key mode")?;
    if key_mode == 8 {
        if let Some(raw) = args.get(next_index) {
            if is_hex_32(raw) {
                return Ok((hex_16(raw)?, true));
            }
        }
    }
    Ok((select_devklic(key_mode)?, false))
}

fn read_optional_rap_or_rif(args: &[String], key_index: usize) -> Result<[u8; 16]> {
    if let Some(key_path) = args.get(key_index) {
        let path = Path::new(key_path);
        if path.file_name().and_then(|name| name.to_str()) == Some("rifkey.bin") {
            read_16_byte_file(path, "Please place your binary RIF key in a rifkey.bin file")
        } else {
            rif_key_from_rap_file(path)
        }
    } else {
        Ok([0u8; 16])
    }
}

fn print_header_info(input: &Path) -> Result<()> {
    let headers = read_headers_from_path(input)?;
    println!("NPD HEADER");
    println!("NPD version: {}", headers.npd.version);
    println!("NPD license: {}", headers.npd.license);
    println!("NPD type: {}", headers.npd.npd_type);
    println!();
    if (headers.edat.flags & SDAT_FLAG) == SDAT_FLAG {
        println!("SDAT HEADER");
        println!("SDAT flags: 0x{:08X}", headers.edat.flags);
        println!("SDAT block size: 0x{:08X}", headers.edat.block_size);
        println!("SDAT file size: 0x{:08X}", headers.edat.file_size);
    } else {
        println!("EDAT HEADER");
        println!("EDAT flags: 0x{:08X}", headers.edat.flags);
        println!("EDAT block size: 0x{:08X}", headers.edat.block_size);
        println!("EDAT file size: 0x{:08X}", headers.edat.file_size);
    }
    Ok(())
}

fn run_decrypt(args: &[String], mode_index: usize, verbose: bool) -> Result<()> {
    if args.len() <= mode_index + 3 {
        print_usage();
        return Ok(());
    }

    let input = PathBuf::from(&args[mode_index + 1]);
    let output = PathBuf::from(&args[mode_index + 2]);
    let (devklic, consumed_hex) = select_devklic_with_optional_hex(args, mode_index + 3, mode_index + 4)?;
    let rifkey = read_optional_rap_or_rif(args, mode_index + 4 + (if consumed_hex { 1 } else { 0 }))?;

    extract_data(&input, &output, &devklic, &rifkey, verbose)
}

fn valid_v134_block(block: i32) -> bool {
    matches!(block, 1 | 2 | 4 | 8 | 16 | 32)
}

fn looks_like_v134_encrypt(args: &[String], mode_index: usize) -> bool {
    if args.len() <= mode_index + 7 {
        return false;
    }
    let parsed = (
        args[mode_index + 3].parse::<i32>(),
        args[mode_index + 4].parse::<i32>(),
        args[mode_index + 5].parse::<i32>(),
        args[mode_index + 6].parse::<i32>(),
        args[mode_index + 7].parse::<i32>(),
    );
    if let (Ok(format), Ok(data), Ok(version), Ok(compression), Ok(block)) = parsed {
        (0..=1).contains(&format)
            && (0..=1).contains(&data)
            && (1..=4).contains(&version)
            && (0..=1).contains(&compression)
            && valid_v134_block(block)
    } else {
        false
    }
}

fn run_encrypt_v134(args: &[String], mode_index: usize, verbose: bool) -> Result<()> {
    if args.len() <= mode_index + 7 {
        print_usage();
        return Ok(());
    }

    let input = PathBuf::from(&args[mode_index + 1]);
    let output = PathBuf::from(&args[mode_index + 2]);
    let format = parse_i32_arg(&args[mode_index + 3], "format")?;
    let data = parse_i32_arg(&args[mode_index + 4], "data")?;
    let version = parse_i32_arg(&args[mode_index + 5], "version")?;
    let compression = parse_i32_arg(&args[mode_index + 6], "compression")?;
    let block = parse_i32_arg(&args[mode_index + 7], "block")?;

    if !(0..=1).contains(&format)
        || !(0..=1).contains(&data)
        || !(1..=4).contains(&version)
        || !(0..=1).contains(&compression)
        || !valid_v134_block(block)
    {
        bail!("ERROR: Invalid parameters");
    }

    let mut license = 0i32;
    let mut npd_type = 0i32;
    let mut content_id = String::new();
    let mut devklic = [0u8; 16];
    let mut rifkey = [0u8; 16];

    let is_edat = format != 0;
    let is_finalized = data != 0;

    if is_edat && is_finalized {
        if args.len() <= mode_index + 11 {
            bail!("ERROR: Not enough parameters for finalized EDAT");
        }
        license = parse_i32_arg(&args[mode_index + 8], "license")?;
        npd_type = parse_hex_i32_arg(&args[mode_index + 9], "type")?;
        content_id = args[mode_index + 10].clone();
        if !(1..=3).contains(&license) || content_id.is_empty() || content_id.len() > 0x30 {
            bail!("ERROR: Invalid finalized EDAT parameters");
        }
        let (selected_klic, consumed_hex) = select_devklic_with_optional_hex(args, mode_index + 11, mode_index + 12)?;
        devklic = selected_klic;
        rifkey = read_optional_rap_or_rif(args, mode_index + 12 + (if consumed_hex { 1 } else { 0 }))?;
    }

    match pack_data(
        &input,
        &output,
        &args[mode_index + 2],
        &content_id,
        &devklic,
        &rifkey,
        version as u32,
        license as u32,
        npd_type as u32,
        block as u32,
        compression != 0,
        is_edat,
        is_finalized,
        verbose,
    ) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&output);
            Err(err)
        }
    }
}

fn validate_encrypt_args_v12(
    version: i32,
    license: i32,
    edat_format: i32,
    block: i32,
    compression: i32,
    content_id: &str,
) -> Result<()> {
    if !(1..=4).contains(&version)
        || !(0..=3).contains(&license)
        || !(0..=1).contains(&edat_format)
        || (block != 16 && block != 32)
        || !(0..=1).contains(&compression)
        || content_id.is_empty()
        || content_id.len() > 0x30
    {
        bail!("ERROR: Invalid parameters");
    }
    Ok(())
}

fn run_encrypt_v12(args: &[String], mode_index: usize, verbose: bool) -> Result<()> {
    if args.len() <= mode_index + 10 {
        print_usage();
        return Ok(());
    }

    let input = PathBuf::from(&args[mode_index + 1]);
    let output = PathBuf::from(&args[mode_index + 2]);
    let version = parse_i32_arg(&args[mode_index + 3], "version")?;
    let license = parse_i32_arg(&args[mode_index + 4], "license")?;
    let npd_type = parse_i32_arg(&args[mode_index + 5], "type")?;
    let edat_format = parse_i32_arg(&args[mode_index + 6], "format")?;
    let block = parse_i32_arg(&args[mode_index + 7], "block")?;
    let compression = parse_i32_arg(&args[mode_index + 8], "compression")?;
    let content_id = &args[mode_index + 9];
    validate_encrypt_args_v12(version, license, edat_format, block, compression, content_id)?;

    let key_mode = parse_i32_arg(&args[mode_index + 10], "key mode")?;
    let devklic = select_devklic(key_mode)?;
    let rifkey = read_optional_rap_or_rif(args, mode_index + 11)?;
    let is_edat = edat_format == 0;

    match pack_data(
        &input,
        &output,
        &args[mode_index + 2],
        content_id,
        &devklic,
        &rifkey,
        version as u32,
        license as u32,
        npd_type as u32,
        block as u32,
        compression != 0,
        is_edat,
        true,
        verbose,
    ) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&output);
            Err(err)
        }
    }
}

fn run_encrypt(args: &[String], mode_index: usize, verbose: bool) -> Result<()> {
    if looks_like_v134_encrypt(args, mode_index) {
        run_encrypt_v134(args, mode_index, verbose)
    } else {
        run_encrypt_v12(args, mode_index, verbose)
    }
}

fn read_be_u16(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

fn read_npd_for_bruteforce(input_path: &Path, verbose: bool) -> Result<([u8; 0x60], [u8; 0x10])> {
    let mut input = File::open(input_path).with_context(|| format!("opening {}", input_path.display()))?;
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    input.seek(SeekFrom::Start(0))?;

    if magic == [0x53, 0x43, 0x45, 0x00] {
        let mut sce_header = [0u8; 0x10];
        input.read_exact(&mut sce_header)?;
        let npd_offset = read_be_u16(&sce_header[0x0E..0x10]) as i64 - 0x60;
        if npd_offset < 0 {
            return Err(anyhow!("ERROR: Invalid NPD offset inside SCE"));
        }
        input.seek(SeekFrom::Start(npd_offset as u64))?;
        if verbose {
            println!("SCE file detected!");
            println!("NPD offset inside SCE: 0x{npd_offset:08X}");
        }
    }

    let mut npd_buf = [0u8; 0x60];
    let mut dev_hash = [0u8; 0x10];
    input.read_exact(&mut npd_buf).context("ERROR: Could not read NPD header")?;
    input.read_exact(&mut dev_hash).context("ERROR: Could not read NPD dev_hash")?;
    Ok((npd_buf, dev_hash))
}

fn try_bruteforce_candidate(npd_buf: &[u8; 0x60], dev_hash: &[u8; 0x10], klicensee: &[u8; 0x10]) -> bool {
    let key = xor16(klicensee, &NPDRM_OMAC_KEY_2);
    aes_cmac_16(&key, npd_buf) == *dev_hash
}

fn brute_force_binary(npd_buf: &[u8; 0x60], dev_hash: &[u8; 0x10], source: &[u8]) -> Option<[u8; 0x10]> {
    for window in source.windows(0x10) {
        let mut klicensee = [0u8; 0x10];
        klicensee.copy_from_slice(window);
        if try_bruteforce_candidate(npd_buf, dev_hash, &klicensee) {
            return Some(klicensee);
        }
    }
    None
}

fn parse_hex_window(window: &[u8]) -> Option<[u8; 0x10]> {
    if window.len() != 0x20 || !window.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let text = std::str::from_utf8(window).ok()?;
    let mut out = [0u8; 0x10];
    for i in 0..0x10 {
        out[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn brute_force_text(npd_buf: &[u8; 0x60], dev_hash: &[u8; 0x10], source: &[u8]) -> Option<[u8; 0x10]> {
    for window in source.windows(0x20) {
        if let Some(klicensee) = parse_hex_window(window) {
            if try_bruteforce_candidate(npd_buf, dev_hash, &klicensee) {
                return Some(klicensee);
            }
        }
    }
    None
}

fn brute_force_unicode_text(npd_buf: &[u8; 0x60], dev_hash: &[u8; 0x10], source: &[u8]) -> Option<[u8; 0x10]> {
    for window in source.windows(0x40) {
        let mut ascii = [0u8; 0x20];
        let mut ok = true;
        for i in 0..0x20 {
            let lo = window[i * 2];
            let hi = window[i * 2 + 1];
            if hi != 0 || !lo.is_ascii_hexdigit() {
                ok = false;
                break;
            }
            ascii[i] = lo;
        }
        if ok {
            if let Some(klicensee) = parse_hex_window(&ascii) {
                if try_bruteforce_candidate(npd_buf, dev_hash, &klicensee) {
                    return Some(klicensee);
                }
            }
        }
    }
    None
}

fn run_bruteforce(args: &[String], mode_index: usize, verbose: bool) -> Result<()> {
    if args.len() <= mode_index + 2 {
        print_usage();
        return Ok(());
    }

    let input = Path::new(&args[mode_index + 1]);
    let source = Path::new(&args[mode_index + 2]);
    let mode = if let Some(raw) = args.get(mode_index + 3) {
        parse_i32_arg(raw, "bruteforce mode")?
    } else {
        0
    };
    if !matches!(mode, 0 | 1 | 2) {
        bail!("ERROR: Invalid parameters");
    }

    let (npd_buf, dev_hash) = read_npd_for_bruteforce(input, verbose)?;
    let source_data = fs::read(source).with_context(|| format!("opening {}", source.display()))?;

    if verbose {
        let mode_text = match mode {
            1 => "Text",
            2 => "Unicode text",
            _ => "Binary",
        };
        println!("MODE: {mode_text}");
        println!("DEV HASH: {}\n", bytes_to_hex(&dev_hash));
    }

    println!("Bruteforcing klic...");
    let found = match mode {
        1 => brute_force_text(&npd_buf, &dev_hash, &source_data),
        2 => brute_force_unicode_text(&npd_buf, &dev_hash, &source_data),
        _ => brute_force_binary(&npd_buf, &dev_hash, &source_data),
    };

    if let Some(klicensee) = found {
        let mut out = File::create("klic.bin").context("creating klic.bin")?;
        out.write_all(&klicensee)?;
        println!("Found valid klic! Saved to klic.bin");
    } else {
        println!("Failed to bruteforce klic!");
    }
    Ok(())
}

fn run_compat_alias(args: &[String]) -> Result<bool> {
    match args.get(1).map(String::as_str) {
        Some("info") if args.len() == 3 => {
            print_header_info(Path::new(&args[2]))?;
            Ok(true)
        }
        Some("rap2rif") if args.len() == 3 => {
            let key = rif_key_from_rap_file(Path::new(&args[2]))?;
            println!("{}", bytes_to_hex(&key));
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    if run_compat_alias(&args)? {
        return Ok(());
    }

    let mut mode_index = 1usize;
    let verbose = args.get(mode_index).map(String::as_str) == Some("-v");
    if verbose {
        mode_index += 1;
    }

    match args.get(mode_index).map(String::as_str) {
        Some("-e") => run_encrypt(&args, mode_index, verbose),
        Some("-d") => run_decrypt(&args, mode_index, verbose),
        Some("-b") => run_bruteforce(&args, mode_index, verbose),
        Some("-h") | Some("--help") | None => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
