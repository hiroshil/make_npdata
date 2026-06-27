use anyhow::{anyhow, Result};

pub fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn read_be_u32(buf: &[u8]) -> u32 {
    u32::from_be_bytes(buf[0..4].try_into().expect("slice length checked by caller"))
}

pub fn read_be_u64(buf: &[u8]) -> u64 {
    u64::from_be_bytes(buf[0..8].try_into().expect("slice length checked by caller"))
}

pub fn parse_hex_16(s: &str) -> Result<[u8; 16]> {
    let trimmed = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if trimmed.len() != 32 || !trimmed.as_bytes().iter().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("expected exactly 32 hex characters"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02X}", b);
    }
    s
}


pub fn prng_fill(out: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA5A5_5A5A_D3C3_B4B4);
    let addr_mix = out.as_ptr() as usize as u64;
    let mut x = nanos ^ addr_mix.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15;

    for byte in out.iter_mut() {
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        *byte = (x & 0xFF) as u8;
        x = x.rotate_left(13).wrapping_add(0xA076_1D64_78BD_642F);
    }
}
