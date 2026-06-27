use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, Result};
use cmac::Cmac;
use digest::Mac;
use hmac::Hmac;
use sha1::Sha1;

use crate::constants::*;

pub fn aes_ecb128_encrypt_block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

pub fn aes_cbc128_decrypt(key: &[u8; 16], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>> {
    if input.len() % 16 != 0 {
        return Err(anyhow!("AES-CBC input length must be a multiple of 16"));
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        out.extend_from_slice(&block);
        prev.copy_from_slice(chunk);
    }
    Ok(out)
}

pub fn aes_cbc128_encrypt(key: &[u8; 16], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>> {
    if input.len() % 16 != 0 {
        return Err(anyhow!("AES-CBC input length must be a multiple of 16"));
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks_exact(16) {
        let mut tmp = [0u8; 16];
        for i in 0..16 {
            tmp[i] = chunk[i] ^ prev[i];
        }
        let mut block = GenericArray::clone_from_slice(&tmp);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev.copy_from_slice(&block);
    }
    Ok(out)
}

pub fn aes_cmac_16(key: &[u8; 16], input: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("AES-128 key length is fixed");
    mac.update(input);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    out
}

pub fn sha1_hmac(key: &[u8], input: &[u8]) -> [u8; 20] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag[..20]);
    out
}

pub fn generate_key(crypto_mode: u32, version4: bool, key: &[u8; 16], iv: &[u8; 16]) -> Result<([u8; 16], [u8; 16])> {
    match crypto_mode & 0xF000_0000 {
        0x1000_0000 => {
            let edat_key = if version4 { EDAT_KEY_1 } else { EDAT_KEY_0 };
            let dec = aes_cbc128_decrypt(&edat_key, &EDAT_IV, key)?;
            let mut key_final = [0u8; 16];
            key_final.copy_from_slice(&dec[..16]);
            Ok((key_final, *iv))
        }
        0x2000_0000 => Ok((if version4 { EDAT_KEY_1 } else { EDAT_KEY_0 }, EDAT_IV)),
        0x0000_0000 => Ok((*key, *iv)),
        mode => Err(anyhow!("unknown key mode 0x{mode:08X}")),
    }
}

pub fn generate_hash(hash_mode: u32, version4: bool, hash: &[u8; 16]) -> Result<[u8; 16]> {
    match hash_mode & 0xF000_0000 {
        0x1000_0000 => {
            let edat_key = if version4 { EDAT_KEY_1 } else { EDAT_KEY_0 };
            let dec = aes_cbc128_decrypt(&edat_key, &EDAT_IV, hash)?;
            let mut out = [0u8; 16];
            out.copy_from_slice(&dec[..16]);
            Ok(out)
        }
        0x2000_0000 => Ok(if version4 { EDAT_HASH_1 } else { EDAT_HASH_0 }),
        0x0000_0000 => Ok(*hash),
        mode => Err(anyhow!("unknown hash mode 0x{mode:08X}")),
    }
}

pub fn decrypt_and_verify(
    hash_mode: u32,
    crypto_mode: u32,
    version4: bool,
    input: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    hash: &[u8; 16],
    test_hash: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let (key_final, iv_final) = generate_key(crypto_mode, version4, key, iv)?;
    let hash_final = generate_hash(hash_mode, version4, hash)?;

    let output = match crypto_mode & 0xFF {
        0x01 => input.to_vec(),
        0x02 => aes_cbc128_decrypt(&key_final, &iv_final, input)?,
        v => return Err(anyhow!("unknown crypto algorithm 0x{v:02X}")),
    };

    let ok = match hash_mode & 0xFF {
        0x01 => {
            let mut hkey = [0u8; 20];
            hkey[..16].copy_from_slice(&hash_final);
            sha1_hmac(&hkey, input)[..16] == test_hash[..16]
        }
        0x02 => aes_cmac_16(&hash_final, input)[..16] == test_hash[..16],
        0x04 => sha1_hmac(&hash_final, input)[..16] == test_hash[..16],
        v => return Err(anyhow!("unknown hash algorithm 0x{v:02X}")),
    };

    Ok((output, ok))
}

pub fn encrypt_and_hash(
    hash_mode: u32,
    crypto_mode: u32,
    version4: bool,
    input: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    hash: &[u8; 16],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (key_final, iv_final) = generate_key(crypto_mode, version4, key, iv)?;
    let hash_final = generate_hash(hash_mode, version4, hash)?;
    let output = match crypto_mode & 0xFF {
        0x01 => input.to_vec(),
        0x02 => aes_cbc128_encrypt(&key_final, &iv_final, input)?,
        v => return Err(anyhow!("unknown crypto algorithm 0x{v:02X}")),
    };
    let tag = match hash_mode & 0xFF {
        0x01 => {
            let mut hkey = [0u8; 20];
            hkey[..16].copy_from_slice(&hash_final);
            sha1_hmac(&hkey, &output).to_vec()
        }
        0x02 => aes_cmac_16(&hash_final, &output).to_vec(),
        0x04 => sha1_hmac(&hash_final, &output)[..16].to_vec(),
        v => return Err(anyhow!("unknown hash algorithm 0x{v:02X}")),
    };
    Ok((output, tag))
}

pub fn rap_to_rif_key(rap: &[u8; 16]) -> Result<[u8; 16]> {
    let iv = [0u8; 16];
    let mut key = [0u8; 16];
    let dec = aes_cbc128_decrypt(&RAP_KEY, &iv, rap)?;
    key.copy_from_slice(&dec[..16]);

    for _ in 0..5 {
        for &p in &RAP_PBOX {
            key[p] ^= RAP_E1[p];
        }
        for i in (1..16).rev() {
            let p = RAP_PBOX[i];
            let pp = RAP_PBOX[i - 1];
            key[p] ^= key[pp];
        }
        let mut carry = 0u8;
        for &p in &RAP_PBOX {
            let kc = key[p].wrapping_sub(carry);
            let ec2 = RAP_E2[p];
            if carry != 1 || kc != 0xFF {
                carry = if kc < ec2 { 1 } else { 0 };
                key[p] = kc.wrapping_sub(ec2);
            } else if kc == 0xFF {
                key[p] = kc.wrapping_sub(ec2);
            } else {
                key[p] = kc;
            }
        }
    }
    Ok(key)
}
