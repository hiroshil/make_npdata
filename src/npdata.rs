use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::constants::*;
use crate::crypto::{aes_cmac_16, aes_ecb128_encrypt_block, decrypt_and_verify, encrypt_and_hash, rap_to_rif_key};
use crate::lz;
use crate::util::{bytes_to_hex, prng_fill, read_be_u32, read_be_u64, xor16};

#[derive(Clone, Debug)]
pub struct NpdHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub license: u32,
    pub npd_type: u32,
    pub content_id: [u8; 0x30],
    pub digest: [u8; 0x10],
    pub title_hash: [u8; 0x10],
    pub dev_hash: [u8; 0x10],
    pub unk1: u64,
    pub unk2: u64,
}

#[derive(Clone, Debug)]
pub struct EdatHeader {
    pub flags: u32,
    pub block_size: u32,
    pub file_size: u64,
}

#[derive(Clone, Debug)]
pub struct HeaderPair {
    pub npd: NpdHeader,
    pub edat: EdatHeader,
}

pub fn parse_headers<R: Read>(reader: &mut R) -> Result<HeaderPair> {
    let mut npd_header = [0u8; 0x80];
    let mut edat_header = [0u8; 0x10];
    reader.read_exact(&mut npd_header).context("reading NPD header")?;
    reader.read_exact(&mut edat_header).context("reading EDAT/SDAT header")?;

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&npd_header[0..4]);
    if magic != [0x4E, 0x50, 0x44, 0x00] {
        return Err(anyhow!("file has invalid NPD header"));
    }

    let mut content_id = [0u8; 0x30];
    content_id.copy_from_slice(&npd_header[16..64]);
    let mut digest = [0u8; 0x10];
    digest.copy_from_slice(&npd_header[64..80]);
    let mut title_hash = [0u8; 0x10];
    title_hash.copy_from_slice(&npd_header[80..96]);
    let mut dev_hash = [0u8; 0x10];
    dev_hash.copy_from_slice(&npd_header[96..112]);

    Ok(HeaderPair {
        npd: NpdHeader {
            magic,
            version: read_be_u32(&npd_header[4..8]),
            license: read_be_u32(&npd_header[8..12]),
            npd_type: read_be_u32(&npd_header[12..16]),
            content_id,
            digest,
            title_hash,
            dev_hash,
            unk1: read_be_u64(&npd_header[112..120]),
            unk2: read_be_u64(&npd_header[120..128]),
        },
        edat: EdatHeader {
            flags: read_be_u32(&edat_header[0..4]),
            block_size: read_be_u32(&edat_header[4..8]),
            file_size: read_be_u64(&edat_header[8..16]),
        },
    })
}

pub fn read_headers_from_path(path: &Path) -> Result<HeaderPair> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    parse_headers(&mut f)
}

fn dec_section(metadata: &[u8; 0x20]) -> [u8; 0x10] {
    let mut dec = [0u8; 0x10];
    dec[0x00] = metadata[0x0C] ^ metadata[0x08] ^ metadata[0x10];
    dec[0x01] = metadata[0x0D] ^ metadata[0x09] ^ metadata[0x11];
    dec[0x02] = metadata[0x0E] ^ metadata[0x0A] ^ metadata[0x12];
    dec[0x03] = metadata[0x0F] ^ metadata[0x0B] ^ metadata[0x13];
    dec[0x04] = metadata[0x04] ^ metadata[0x08] ^ metadata[0x14];
    dec[0x05] = metadata[0x05] ^ metadata[0x09] ^ metadata[0x15];
    dec[0x06] = metadata[0x06] ^ metadata[0x0A] ^ metadata[0x16];
    dec[0x07] = metadata[0x07] ^ metadata[0x0B] ^ metadata[0x17];
    dec[0x08] = metadata[0x0C] ^ metadata[0x00] ^ metadata[0x18];
    dec[0x09] = metadata[0x0D] ^ metadata[0x01] ^ metadata[0x19];
    dec[0x0A] = metadata[0x0E] ^ metadata[0x02] ^ metadata[0x1A];
    dec[0x0B] = metadata[0x0F] ^ metadata[0x03] ^ metadata[0x1B];
    dec[0x0C] = metadata[0x04] ^ metadata[0x00] ^ metadata[0x1C];
    dec[0x0D] = metadata[0x05] ^ metadata[0x01] ^ metadata[0x1D];
    dec[0x0E] = metadata[0x06] ^ metadata[0x02] ^ metadata[0x1E];
    dec[0x0F] = metadata[0x07] ^ metadata[0x03] ^ metadata[0x1F];
    dec
}

fn get_block_key(block: u32, npd: &NpdHeader) -> [u8; 16] {
    let mut dest = [0u8; 16];
    if npd.version > 1 {
        dest[..0x0C].copy_from_slice(&npd.dev_hash[..0x0C]);
    }
    dest[0x0C] = ((block >> 24) & 0xFF) as u8;
    dest[0x0D] = ((block >> 16) & 0xFF) as u8;
    dest[0x0E] = ((block >> 8) & 0xFF) as u8;
    dest[0x0F] = (block & 0xFF) as u8;
    dest
}

fn block_count(edat: &EdatHeader) -> Result<u32> {
    if edat.block_size == 0 {
        return Err(anyhow!("EDAT block size is zero"));
    }
    Ok(((edat.file_size + edat.block_size as u64 - 1) / edat.block_size as u64) as u32)
}

fn metadata_section_size(edat: &EdatHeader) -> u64 {
    if (edat.flags & EDAT_COMPRESSED_FLAG) != 0 || (edat.flags & EDAT_FLAG_0X20) != 0 {
        0x20
    } else {
        0x10
    }
}

pub fn check_data<R: Read + Seek>(reader: &mut R, key: &[u8; 16], edat: &EdatHeader, npd: &NpdHeader, verbose: bool) -> Result<()> {
    match npd.version {
        0 | 1 => {
            if edat.flags & 0x7EFF_FFFE != 0 {
                return Err(anyhow!("bad header flags for NPD version {}", npd.version));
            }
        }
        2 => {
            if edat.flags & 0x7EFF_FFE0 != 0 {
                return Err(anyhow!("bad header flags for NPD version 2"));
            }
        }
        3 | 4 => {
            if edat.flags & 0x7EFF_FFC0 != 0 {
                return Err(anyhow!("bad header flags for NPD version {}", npd.version));
            }
        }
        _ => return Err(anyhow!("unknown NPD version {}", npd.version)),
    }

    reader.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 0xA0];
    reader.read_exact(&mut header)?;
    reader.seek(SeekFrom::Start(0x90))?;
    let mut metadata_hash = [0u8; 0x10];
    let mut header_hash = [0u8; 0x10];
    reader.read_exact(&mut metadata_hash)?;
    reader.read_exact(&mut header_hash)?;

    let crypto_mode = 0x01u32;
    let mut hash_mode = if (edat.flags & EDAT_ENCRYPTED_KEY_FLAG) == 0 { 0x0000_0002 } else { 0x1000_0002 };
    if (edat.flags & EDAT_DEBUG_DATA_FLAG) != 0 {
        if verbose {
            eprintln!("DEBUG data detected");
        }
        hash_mode |= 0x0100_0000;
    }
    let zero_key = [0u8; 16];
    let zero_iv = [0u8; 16];
    let (_, header_ok) = decrypt_and_verify(hash_mode, crypto_mode, npd.version == 4, &header, &zero_key, &zero_iv, key, &header_hash)?;
    if verbose && !header_ok {
        eprintln!("WARNING: header hash is invalid");
    }

    if (edat.flags & EDAT_COMPRESSED_FLAG) != 0 && verbose {
        eprintln!("COMPRESSED data detected");
    }
    let blocks = block_count(edat)?;
    let metadata_size = metadata_section_size(edat) as usize * blocks as usize;
    let mut metadata = vec![0u8; metadata_size];
    reader.seek(SeekFrom::Start(0x100))?;
    reader.read_exact(&mut metadata)?;
    let (_, metadata_ok) = decrypt_and_verify(hash_mode, crypto_mode, npd.version == 4, &metadata, &zero_key, &zero_iv, key, &metadata_hash)?;
    if verbose && !metadata_ok {
        eprintln!("WARNING: metadata section hash is invalid");
    }
    Ok(())
}

pub fn validate_npd_hashes(file_name: &str, klicensee: &[u8; 16], npd: &NpdHeader, verbose: bool) {
    let mut title_buf = Vec::with_capacity(0x30 + file_name.len());
    title_buf.extend_from_slice(&npd.content_id);
    title_buf.extend_from_slice(file_name.as_bytes());
    let title_ok = aes_cmac_16(&NPDRM_OMAC_KEY_3, &title_buf) == npd.title_hash;
    if verbose {
        if title_ok {
            eprintln!("NPD title hash is valid");
        } else {
            eprintln!("WARNING: NPD title hash is invalid");
        }
    }

    if klicensee.iter().all(|&b| b == 0) {
        if verbose {
            eprintln!("NPD dev hash is empty");
        }
        return;
    }

    let key = xor16(klicensee, &NPDRM_OMAC_KEY_2);
    let mut dev = Vec::with_capacity(0x60);
    dev.extend_from_slice(&npd.magic);
    dev.extend_from_slice(&npd.version.to_be_bytes());
    dev.extend_from_slice(&npd.license.to_be_bytes());
    dev.extend_from_slice(&npd.npd_type.to_be_bytes());
    dev.extend_from_slice(&npd.content_id);
    dev.extend_from_slice(&npd.digest);
    dev.extend_from_slice(&npd.title_hash);
    let dev_ok = aes_cmac_16(&key, &dev) == npd.dev_hash;
    if verbose {
        if dev_ok {
            eprintln!("NPD dev hash is valid");
        } else {
            eprintln!("WARNING: NPD dev hash is invalid");
        }
    }
}

pub fn decrypt_data<R: Read + Seek, W: Write>(reader: &mut R, writer: &mut W, edat: &mut EdatHeader, npd: &NpdHeader, crypt_key: &[u8; 16], verbose: bool) -> Result<()> {
    let blocks = block_count(edat)?;
    let meta_section = metadata_section_size(edat);
    let metadata_offset = 0x100u64;
    let empty_iv = [0u8; 16];

    for i in 0..blocks {
        reader.seek(SeekFrom::Start(metadata_offset + i as u64 * meta_section))?;
        let mut hash_result = [0u8; 0x14];
        let (offset, length, compression_end) = if (edat.flags & EDAT_COMPRESSED_FLAG) != 0 {
            let mut metadata = [0u8; 0x20];
            reader.read_exact(&mut metadata)?;
            let result = dec_section(&metadata);
            hash_result[..0x10].copy_from_slice(&metadata[..0x10]);
            (
                ((read_be_u32(&result[0..4]) as u64) << 4) | read_be_u32(&result[4..8]) as u64,
                read_be_u32(&result[8..12]) as usize,
                read_be_u32(&result[12..16]),
            )
        } else if (edat.flags & EDAT_FLAG_0X20) != 0 {
            let metadata_pos = metadata_offset + i as u64 * edat.block_size as u64 + i as u64 * meta_section;
            reader.seek(SeekFrom::Start(metadata_pos))?;
            let mut metadata = [0u8; 0x20];
            reader.read_exact(&mut metadata)?;
            for j in 0..0x10 {
                hash_result[j] = metadata[j] ^ metadata[j + 0x10];
            }
            let mut length = edat.block_size as usize;
            if i == blocks - 1 && edat.file_size % edat.block_size as u64 != 0 {
                length = (edat.file_size % edat.block_size as u64) as usize;
            }
            (
                metadata_offset + i as u64 * edat.block_size as u64 + (i as u64 + 1) * meta_section,
                length,
                0,
            )
        } else {
            reader.read_exact(&mut hash_result[..0x10])?;
            let mut length = edat.block_size as usize;
            if i == blocks - 1 && edat.file_size % edat.block_size as u64 != 0 {
                length = (edat.file_size % edat.block_size as u64) as usize;
            }
            (
                metadata_offset + i as u64 * edat.block_size as u64 + blocks as u64 * meta_section,
                length,
                0,
            )
        };

        let pad_length = length;
        let padded_length = (pad_length + 0x0F) & !0x0F;
        reader.seek(SeekFrom::Start(offset))?;
        let mut enc_data = vec![0u8; padded_length];
        reader.read_exact(&mut enc_data)?;

        let block_key = get_block_key(i, npd);
        let key_result = aes_ecb128_encrypt_block(crypt_key, &block_key);
        let hash = if (edat.flags & EDAT_FLAG_0X10) != 0 {
            aes_ecb128_encrypt_block(crypt_key, &key_result)
        } else {
            key_result
        };

        let mut crypto_mode = if (edat.flags & EDAT_FLAG_0X02) == 0 { 0x02 } else { 0x01 };
        let mut hash_mode = if (edat.flags & EDAT_FLAG_0X10) == 0 {
            0x02
        } else if (edat.flags & EDAT_FLAG_0X20) == 0 {
            0x04
        } else {
            0x01
        };
        if (edat.flags & EDAT_ENCRYPTED_KEY_FLAG) != 0 {
            crypto_mode |= 0x1000_0000;
            hash_mode |= 0x1000_0000;
        }

        let dec_data = if (edat.flags & EDAT_DEBUG_DATA_FLAG) != 0 {
            // Keep the original make_npdata behavior: reset the crypto/hash mode
            // flags for DEBUG data before copying the block without decryption.
            crypto_mode |= 0x0100_0000;
            hash_mode |= 0x0100_0000;
            let _reset_modes = (crypto_mode, hash_mode);
            enc_data.clone()
        } else {
            let iv_buf = if npd.version <= 1 { empty_iv } else { npd.digest };
            let (dec, ok) = decrypt_and_verify(hash_mode, crypto_mode, npd.version == 4, &enc_data, &key_result, &iv_buf, &hash, &hash_result)?;
            if verbose && !ok {
                eprintln!("WARNING: block at offset 0x{offset:08X} has invalid hash");
            }
            dec
        };

        if (edat.flags & EDAT_COMPRESSED_FLAG) != 0 && compression_end != 0 {
            let decomp_size = edat.file_size as usize;
            if verbose {
                eprintln!("Decompressing data...");
            }
            let decomp = lz::decompress(&dec_data, decomp_size)?;
            if verbose {
                eprintln!("Compressed block size: {pad_length}");
                eprintln!("Decompressed block size: {}", decomp.len());
            }
            writer.write_all(&decomp)?;
            edat.file_size = edat.file_size.saturating_sub(decomp.len() as u64);
            if edat.file_size == 0 && verbose {
                eprintln!("EDAT/SDAT successfully decompressed");
            }
        } else {
            writer.write_all(&dec_data[..pad_length])?;
        }
    }
    Ok(())
}

pub fn extract_data(input_path: &Path, output_path: &Path, devklic: &[u8; 16], rifkey: &[u8; 16], verbose: bool) -> Result<()> {
    let mut input = File::open(input_path).with_context(|| format!("opening {}", input_path.display()))?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .with_context(|| format!("creating {}", output_path.display()))?;
    let mut headers = parse_headers(&mut input)?;

    println!("NPD HEADER");
    println!("NPD version: {}", headers.npd.version);
    println!("NPD license: {}", headers.npd.license);
    println!("NPD type: {}", headers.npd.npd_type);
    println!();

    let mut key = [0u8; 16];
    if (headers.edat.flags & SDAT_FLAG) == SDAT_FLAG {
        println!("SDAT HEADER");
        println!("SDAT flags: 0x{:08X}", headers.edat.flags);
        println!("SDAT block size: 0x{:08X}", headers.edat.block_size);
        println!("SDAT file size: 0x{:08X}", headers.edat.file_size);
        println!();
        key = xor16(&headers.npd.dev_hash, &SDAT_KEY);
    } else {
        println!("EDAT HEADER");
        println!("EDAT flags: 0x{:08X}", headers.edat.flags);
        println!("EDAT block size: 0x{:08X}", headers.edat.block_size);
        println!("EDAT file size: 0x{:08X}", headers.edat.file_size);
        println!();

        let file_name = input_path.to_string_lossy();
        validate_npd_hashes(&file_name, devklic, &headers.npd, verbose);

        if (headers.npd.license & 0x03) == 0x03 {
            key = *devklic;
        } else if (headers.npd.license & 0x01) == 0x01 || (headers.npd.license & 0x02) == 0x02 {
            key = *rifkey;
            if key.iter().all(|&b| b == 0) {
                return Err(anyhow!("a valid RAP/RIF key is needed for this EDAT file"));
            }
        }
        if verbose {
            eprintln!("DEVKLIC: {}", bytes_to_hex(devklic));
            eprintln!("RIF KEY: {}", bytes_to_hex(rifkey));
        }
    }

    if verbose {
        eprintln!("DECRYPTION KEY: {}", bytes_to_hex(&key));
    }

    println!("Parsing data...");
    input.seek(SeekFrom::Start(0))?;
    match check_data(&mut input, &key, &headers.edat, &headers.npd, verbose) {
        Ok(()) => println!("File successfully parsed!"),
        Err(e) => println!("Parsing warning/error: {e}"),
    }
    println!();
    println!("Decrypting data...");
    input.seek(SeekFrom::Start(0))?;
    decrypt_data(&mut input, &mut output, &mut headers.edat, &headers.npd, &key, verbose)?;
    println!("File successfully decrypted!");
    Ok(())
}


fn footer_for(version: u32, is_sdat: bool) -> [u8; 16] {
    match (version, is_sdat) {
        (0 | 1, false) => *b"EDATA packager\0\0",
        (2, false) => *b"EDATA 2.4.0.W\0\0\0",
        (3, false) => *b"EDATA 3.3.0.W\0\0\0",
        (4, false) => *b"EDATA 4.0.0.W\0\0\0",
        (0 | 1, true) => *b"SDATA packager\0\0",
        (2, true) => *b"SDATA 2.4.0.W\0\0\0",
        (3, true) => *b"SDATA 3.3.0.W\0\0\0",
        (4, true) => *b"SDATA 4.0.0.W\0\0\0",
        (_, false) => *b"EDATA 4.0.0.W\0\0\0",
        (_, true) => *b"SDATA 4.0.0.W\0\0\0",
    }
}

fn content_id_48(content_id: &str) -> [u8; 0x30] {
    let mut out = [0u8; 0x30];
    let bytes = content_id.as_bytes();
    let n = bytes.len().min(0x30);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn npd_dev_buffer(npd: &NpdHeader) -> [u8; 0x60] {
    let mut dev = [0u8; 0x60];
    dev[0..4].copy_from_slice(&npd.magic);
    dev[4..8].copy_from_slice(&npd.version.to_be_bytes());
    dev[8..12].copy_from_slice(&npd.license.to_be_bytes());
    dev[12..16].copy_from_slice(&npd.npd_type.to_be_bytes());
    dev[16..64].copy_from_slice(&npd.content_id);
    dev[64..80].copy_from_slice(&npd.digest);
    dev[80..96].copy_from_slice(&npd.title_hash);
    dev
}

pub fn forge_npd_title_hash(file_name: &str, npd: &mut NpdHeader) {
    let mut buf = Vec::with_capacity(0x30 + file_name.len());
    buf.extend_from_slice(&npd.content_id);
    buf.extend_from_slice(file_name.as_bytes());
    npd.title_hash = aes_cmac_16(&NPDRM_OMAC_KEY_3, &buf);
}

pub fn forge_npd_dev_hash(klicensee: &[u8; 16], npd: &mut NpdHeader) {
    let key = xor16(klicensee, &NPDRM_OMAC_KEY_2);
    let dev = npd_dev_buffer(npd);
    npd.dev_hash = aes_cmac_16(&key, &dev);
}

fn write_npd_header<W: Write>(writer: &mut W, npd: &NpdHeader) -> Result<()> {
    writer.write_all(&npd.magic)?;
    writer.write_all(&npd.version.to_be_bytes())?;
    writer.write_all(&npd.license.to_be_bytes())?;
    writer.write_all(&npd.npd_type.to_be_bytes())?;
    writer.write_all(&npd.content_id)?;
    writer.write_all(&npd.digest)?;
    writer.write_all(&npd.title_hash)?;
    writer.write_all(&npd.dev_hash)?;
    writer.write_all(&npd.unk1.to_be_bytes())?;
    writer.write_all(&npd.unk2.to_be_bytes())?;
    Ok(())
}

fn write_edat_header<W: Write>(writer: &mut W, edat: &EdatHeader) -> Result<()> {
    writer.write_all(&edat.flags.to_be_bytes())?;
    writer.write_all(&edat.block_size.to_be_bytes())?;
    writer.write_all(&edat.file_size.to_be_bytes())?;
    Ok(())
}

pub fn encrypt_data<R: Read + Seek, W: Write + Seek>(reader: &mut R, writer: &mut W, edat: &EdatHeader, npd: &NpdHeader, crypt_key: &[u8; 16], verbose: bool) -> Result<()> {
    let blocks = block_count(edat)?;
    let metadata_offset = 0x100u64;
    let empty_iv = [0u8; 16];
    let is_sdat = (edat.flags & SDAT_FLAG) == SDAT_FLAG;
    let footer = footer_for(npd.version, is_sdat);

    for i in 0..blocks {
        let offset = i as u64 * edat.block_size as u64;
        let mut plain_len = edat.block_size as usize;
        if i == blocks - 1 && edat.file_size % edat.block_size as u64 != 0 {
            plain_len = (edat.file_size % edat.block_size as u64) as usize;
        }
        let padded_len = (plain_len + 0x0F) & !0x0F;
        reader.seek(SeekFrom::Start(offset))?;
        let mut dec_data = vec![0u8; padded_len];
        reader.read_exact(&mut dec_data[..plain_len])?;

        let block_key = get_block_key(i, npd);
        let key_result = aes_ecb128_encrypt_block(crypt_key, &block_key);
        let hash = if (edat.flags & EDAT_FLAG_0X10) != 0 {
            aes_ecb128_encrypt_block(crypt_key, &key_result)
        } else {
            key_result
        };

        let mut crypto_mode = if (edat.flags & EDAT_FLAG_0X02) == 0 { 0x02 } else { 0x01 };
        let mut hash_mode = if (edat.flags & EDAT_FLAG_0X10) == 0 {
            0x02
        } else if (edat.flags & EDAT_FLAG_0X20) == 0 {
            0x04
        } else {
            0x01
        };
        if (edat.flags & EDAT_ENCRYPTED_KEY_FLAG) != 0 {
            crypto_mode |= 0x1000_0000;
            hash_mode |= 0x1000_0000;
        }

        let (enc_data, hash_tag) = if (edat.flags & EDAT_DEBUG_DATA_FLAG) != 0 {
            crypto_mode |= 0x0100_0000;
            hash_mode |= 0x0100_0000;
            let _reset_modes = (crypto_mode, hash_mode);
            (dec_data, vec![0u8; 0x14])
        } else {
            let iv_buf = if npd.version <= 1 { empty_iv } else { npd.digest };
            let (enc, tag) = encrypt_and_hash(hash_mode, crypto_mode, npd.version == 4, &dec_data, &key_result, &iv_buf, &hash)?;
            (enc, tag)
        };

        if verbose {
            eprintln!("Encrypted block {} at input offset 0x{:08X}", i, offset);
        }

        if (edat.flags & EDAT_COMPRESSED_FLAG) != 0 {
            let data_offset = metadata_offset + i as u64 * edat.block_size as u64 + blocks as u64 * 0x20;
            let mut dec_metadata = [0u8; 0x20];
            let mut enc_metadata = [0u8; 0x20];
            dec_metadata[..0x10].copy_from_slice(&hash_tag[..0x10]);
            dec_metadata[0x10..0x18].copy_from_slice(&data_offset.to_be_bytes());
            dec_metadata[0x18..0x1C].copy_from_slice(&(plain_len as u32).to_be_bytes());
            dec_metadata[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes());
            if npd.version <= 1 {
                enc_metadata.copy_from_slice(&dec_metadata);
            } else {
                enc_metadata[..0x10].copy_from_slice(&dec_metadata[..0x10]);
                let sec = dec_section(&dec_metadata);
                enc_metadata[0x10..0x20].copy_from_slice(&sec);
            }

            if (edat.flags & EDAT_DEBUG_DATA_FLAG) == 0 {
                writer.seek(SeekFrom::Start(metadata_offset + i as u64 * 0x20))?;
                writer.write_all(&enc_metadata)?;
            }
            writer.seek(SeekFrom::Start(data_offset))?;
            writer.write_all(&enc_data)?;
        } else if (edat.flags & EDAT_FLAG_0X20) != 0 {
            let data_offset = metadata_offset + i as u64 * edat.block_size as u64 + (i as u64 + 1) * 0x20;
            let metadata_offset_i = metadata_offset + i as u64 * 0x20 + offset;
            let mut metadata = [0u8; 0x20];
            let mut xor_mask = [0u8; 0x10];
            prng_fill(&mut xor_mask);
            for j in 0..0x10 {
                metadata[j] = hash_tag[j] ^ xor_mask[j];
                metadata[j + 0x10] = xor_mask[j];
            }

            if (edat.flags & EDAT_DEBUG_DATA_FLAG) == 0 {
                writer.seek(SeekFrom::Start(metadata_offset_i))?;
                writer.write_all(&metadata)?;
            }
            writer.seek(SeekFrom::Start(data_offset))?;
            writer.write_all(&enc_data)?;
        } else {
            let data_offset = metadata_offset + i as u64 * edat.block_size as u64 + blocks as u64 * 0x10;
            if (edat.flags & EDAT_DEBUG_DATA_FLAG) == 0 {
                writer.seek(SeekFrom::Start(metadata_offset + i as u64 * 0x10))?;
                writer.write_all(&hash_tag[..0x10])?;
            }
            writer.seek(SeekFrom::Start(data_offset))?;
            writer.write_all(&enc_data)?;
        }
    }

    if edat.file_size == 0 {
        writer.seek(SeekFrom::Start(metadata_offset))?;
    }
    writer.write_all(&footer)?;
    Ok(())
}

pub fn forge_data<W: Read + Write + Seek>(writer: &mut W, key: &[u8; 16], edat: &EdatHeader, npd: &NpdHeader) -> Result<()> {
    let mut header = [0u8; 0xA0];
    let empty_header = [0u8; 0xA0];
    let mut signature = [0u8; 0x50];

    let crypto_mode = 0x01u32;
    let mut hash_mode = if (edat.flags & EDAT_ENCRYPTED_KEY_FLAG) == 0 { 0x0000_0002 } else { 0x1000_0002 };
    if (edat.flags & EDAT_DEBUG_DATA_FLAG) != 0 {
        hash_mode |= 0x0100_0000;
    }

    let blocks = block_count(edat)?;
    let metadata_size = metadata_section_size(edat) as usize * blocks as usize;
    let mut metadata = vec![0u8; metadata_size];
    let empty_metadata = vec![0u8; metadata_size];
    writer.seek(SeekFrom::Start(0x100))?;
    writer.read_exact(&mut metadata)?;

    let header_key = [0u8; 16];
    let header_iv = [0u8; 16];
    let (_, metadata_hash) = encrypt_and_hash(hash_mode, crypto_mode, npd.version == 4, &metadata, &header_key, &header_iv, key)?;
    let _ = empty_metadata;
    writer.seek(SeekFrom::Start(0x90))?;
    writer.write_all(&metadata_hash[..0x10])?;

    writer.seek(SeekFrom::Start(0))?;
    writer.read_exact(&mut header)?;
    let (_, header_hash) = encrypt_and_hash(hash_mode, crypto_mode, npd.version == 4, &header, &header_key, &header_iv, key)?;
    let _ = empty_header;
    writer.seek(SeekFrom::Start(0xA0))?;
    writer.write_all(&header_hash[..0x10])?;

    prng_fill(&mut signature);
    writer.seek(SeekFrom::Start(0xB0))?;
    writer.write_all(&signature)?;
    Ok(())
}

pub fn pack_data(input_path: &Path, output_path: &Path, output_name_for_hash: &str, content_id: &str, devklic: &[u8; 16], rifkey: &[u8; 16], version: u32, license: u32, npd_type: u32, block_kb: u32, use_compression: bool, is_edat: bool, is_finalized: bool, verbose: bool) -> Result<()> {
    let mut input = File::open(input_path).with_context(|| format!("opening {}", input_path.display()))?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .with_context(|| format!("creating {}", output_path.display()))?;
    let input_file_size = input.metadata()?.len();

    let npd_version = if version == 1 && !is_finalized { 0 } else { version };
    let mut npd = NpdHeader {
        magic: [0x4E, 0x50, 0x44, 0x00],
        version: npd_version,
        license: 0,
        npd_type: 0,
        content_id: [0u8; 0x30],
        digest: [0u8; 0x10],
        title_hash: [0u8; 0x10],
        dev_hash: [0u8; 0x10],
        unk1: 0,
        unk2: 0,
    };
    if is_finalized {
        npd.license = license;
        npd.npd_type = npd_type;
        npd.content_id = content_id_48(content_id);
        prng_fill(&mut npd.digest);
        let real_name = Path::new(output_name_for_hash)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(output_name_for_hash);
        forge_npd_title_hash(real_name, &mut npd);
        forge_npd_dev_hash(devklic, &mut npd);
    }

    let mut flags = if version == 1 {
        if !is_edat {
            return Err(anyhow!("ERROR: Invalid version for SDAT!"));
        }
        0x00
    } else if version == 2 {
        0x0C
    } else {
        0x3C
    };
    if use_compression {
        if version >= 3 {
            flags = 0x0C | EDAT_COMPRESSED_FLAG;
        } else {
            flags |= EDAT_COMPRESSED_FLAG;
        }
    }
    if !is_edat {
        flags |= SDAT_FLAG;
    }
    if !is_finalized {
        flags |= EDAT_DEBUG_DATA_FLAG;
    }
    let edat = EdatHeader {
        flags,
        block_size: block_kb * 1024,
        file_size: input_file_size,
    };

    println!("NPD HEADER");
    println!("NPD version: {}", npd.version);
    println!("NPD license: {}", npd.license);
    println!("NPD type: {}", npd.npd_type);
    println!();

    let key = if (edat.flags & SDAT_FLAG) == SDAT_FLAG {
        println!("SDAT HEADER");
        println!("SDAT flags: 0x{:08X}", edat.flags);
        println!("SDAT block size: 0x{:08X}", edat.block_size);
        println!("SDAT file size: 0x{:08X}", edat.file_size);
        println!();
        xor16(&npd.dev_hash, &SDAT_KEY)
    } else {
        println!("EDAT HEADER");
        println!("EDAT flags: 0x{:08X}", edat.flags);
        println!("EDAT block size: 0x{:08X}", edat.block_size);
        println!("EDAT file size: 0x{:08X}", edat.file_size);
        println!();
        let mut selected = [0u8; 16];
        if (npd.license & 0x03) == 0x03 {
            selected = *devklic;
        } else if (npd.license & 0x02) == 0x02 {
            selected = *rifkey;
            if selected.iter().all(|&b| b == 0) {
                return Err(anyhow!("ERROR: A valid RAP/RIF file is needed for this EDAT file!"));
            }
        } else if (npd.license & 0x01) == 0x01 {
            return Err(anyhow!("ERROR: Network license not supported!"));
        }
        if verbose {
            eprintln!("DEVKLIC: {}", bytes_to_hex(devklic));
            eprintln!("RIF KEY: {}", bytes_to_hex(rifkey));
        }
        selected
    };

    if verbose {
        eprintln!("ENCRYPTION KEY: {}", bytes_to_hex(&key));
        eprintln!();
    }

    write_npd_header(&mut output, &npd)?;
    write_edat_header(&mut output, &edat)?;

    println!("Encrypting data...");
    encrypt_data(&mut input, &mut output, &edat, &npd, &key, verbose)?;
    println!("File successfully encrypted!");
    println!();

    if is_finalized {
        println!("Forging data...");
        forge_data(&mut output, &key, &edat, &npd)?;
        println!("File successfully forged!");
    }
    Ok(())
}

pub fn rif_key_from_rap_file(path: &Path) -> Result<[u8; 16]> {
    let mut f = File::open(path).with_context(|| format!("opening RAP file {}", path.display()))?;
    let mut rap = [0u8; 16];
    f.read_exact(&mut rap).context("reading 16-byte RAP file")?;
    rap_to_rif_key(&rap)
}
