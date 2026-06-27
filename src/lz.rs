use anyhow::{anyhow, Result};

struct RangeDecoder<'a> {
    src: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(src: &'a [u8]) -> Result<Self> {
        if src.len() < 5 {
            return Err(anyhow!("compressed stream is too short"));
        }
        let code = ((src[1] as u32) << 24) | ((src[2] as u32) << 16) | ((src[3] as u32) << 8) | src[4] as u32;
        Ok(Self { src, pos: 0, range: 0xFFFF_FFFF, code })
    }

    fn decode_range(&mut self) -> Result<()> {
        if (self.range >> 24) == 0 {
            let idx = self.pos + 5;
            if idx >= self.src.len() {
                return Err(anyhow!("compressed stream ended early"));
            }
            self.range <<= 8;
            self.code = (self.code << 8).wrapping_add(self.src[idx] as u32);
            self.pos += 1;
        }
        Ok(())
    }

    fn decode_bit(&mut self, tmp: &mut [u8], c_off: usize, mut index: Option<&mut i32>) -> Result<i32> {
        self.decode_range()?;
        let c = tmp[c_off];
        let val = (self.range >> 8).wrapping_mul(c as u32);
        tmp[c_off] = tmp[c_off].wrapping_sub(tmp[c_off] >> 3);
        if let Some(idx) = index.as_deref_mut() {
            *idx <<= 1;
        }
        if self.code < val {
            self.range = val;
            tmp[c_off] = tmp[c_off].wrapping_add(31);
            if let Some(idx) = index.as_deref_mut() {
                *idx += 1;
            }
            Ok(1)
        } else {
            self.code = self.code.wrapping_sub(val);
            self.range = self.range.wrapping_sub(val);
            Ok(0)
        }
    }
}

fn checked_tmp_offset(off: isize, tmp_len: usize) -> Result<usize> {
    if off < 0 || off as usize >= tmp_len {
        return Err(anyhow!("LZ model offset out of range"));
    }
    Ok(off as usize)
}

fn decode_number(tmp: &mut [u8], ptr: usize, mut index: i32, bit_flag: &mut i32, rd: &mut RangeDecoder<'_>) -> Result<i32> {
    let mut i = 1;
    if index >= 3 {
        rd.decode_bit(tmp, ptr + 0x18, Some(&mut i))?;
        if index >= 4 {
            rd.decode_bit(tmp, ptr + 0x18, Some(&mut i))?;
            if index >= 5 {
                rd.decode_range()?;
                while index >= 5 {
                    i <<= 1;
                    rd.range >>= 1;
                    if rd.code < rd.range {
                        i += 1;
                    } else {
                        rd.code = rd.code.wrapping_sub(rd.range);
                    }
                    index -= 1;
                }
            }
        }
    }

    *bit_flag = rd.decode_bit(tmp, ptr, Some(&mut i))?;
    if index >= 1 {
        rd.decode_bit(tmp, ptr + 0x8, Some(&mut i))?;
        if index >= 2 {
            rd.decode_bit(tmp, ptr + 0x10, Some(&mut i))?;
        }
    }
    Ok(i)
}

fn decode_word(tmp: &mut [u8], ptr: usize, mut index: i32, bit_flag: &mut i32, rd: &mut RangeDecoder<'_>) -> Result<i32> {
    let mut i = 1;
    index /= 8;
    if index >= 3 {
        rd.decode_bit(tmp, ptr + 4, Some(&mut i))?;
        if index >= 4 {
            rd.decode_bit(tmp, ptr + 4, Some(&mut i))?;
            if index >= 5 {
                rd.decode_range()?;
                while index >= 5 {
                    i <<= 1;
                    rd.range >>= 1;
                    if rd.code < rd.range {
                        i += 1;
                    } else {
                        rd.code = rd.code.wrapping_sub(rd.range);
                    }
                    index -= 1;
                }
            }
        }
    }

    *bit_flag = rd.decode_bit(tmp, ptr, Some(&mut i))?;
    if index >= 1 {
        rd.decode_bit(tmp, ptr + 1, Some(&mut i))?;
        if index >= 2 {
            rd.decode_bit(tmp, ptr + 2, Some(&mut i))?;
        }
    }
    Ok(i)
}

pub fn decompress(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if input.len() < 5 {
        return Err(anyhow!("compressed stream is too short"));
    }

    let mut tmp = vec![0u8; 0xCC8];
    for b in &mut tmp[..0xCA8] {
        *b = 0x80;
    }

    let mut rd = RangeDecoder::new(input)?;
    let mut out = vec![0u8; output_size];
    let mut start = 0usize;
    let end = output_size;
    let mut offset = 0i32;
    let mut bit_flag: i32;
    let mut prev = 0u8;
    let head = input[0];

    if (head as i8) < 0 {
        let code = rd.code as usize;
        if code <= output_size && input.len() >= code + 5 {
            out[..code].copy_from_slice(&input[5..5 + code]);
            out.truncate(code);
            return Ok(out);
        }
        return Err(anyhow!("invalid uncompressed LZ block"));
    }

    loop {
        let mut tmp_sect1 = (offset + 0xB68) as usize;
        if rd.decode_bit(&mut tmp, tmp_sect1, None)? == 0 {
            if offset > 0 {
                offset -= 1;
            }
            if start == end {
                out.truncate(start);
                return Ok(out);
            }
            let sect = ((((((start as i32) & 7) << 8) + prev as i32) >> head) & 7) * 0xFF - 1;
            let mut index = 1i32;
            loop {
                let off = checked_tmp_offset(sect as isize + index as isize, tmp.len())?;
                rd.decode_bit(&mut tmp, off, Some(&mut index))?;
                if (index >> 8) != 0 {
                    break;
                }
            }
            out[start] = index as u8;
            start += 1;
        } else {
            let mut index = -1i32;
            loop {
                tmp_sect1 += 8;
                bit_flag = rd.decode_bit(&mut tmp, tmp_sect1, None)?;
                index += bit_flag;
                if bit_flag == 0 || index >= 6 {
                    break;
                }
            }

            let mut b_size = 0x160i32;
            let mut tmp_sect2 = (index + 0x7F1) as usize;
            let data_length = if index >= 0 || bit_flag != 0 {
                let sect = (index << 5) | ((((start as i32) << index) & 3) << 3) | (offset & 7);
                let ptr = (0xBA8 + sect) as usize;
                let n = decode_number(&mut tmp, ptr, index, &mut bit_flag, &mut rd)?;
                if n == 0xFF {
                    out.truncate(start);
                    return Ok(out);
                }
                n
            } else {
                1
            };

            if data_length <= 2 {
                tmp_sect2 += 0xF8;
                b_size = 0x40;
            }

            let mut diff: i32;
            let mut shift = 1i32;
            loop {
                diff = (shift << 4) - b_size;
                let off = tmp_sect2 + ((shift << 3) as usize);
                bit_flag = rd.decode_bit(&mut tmp, off, Some(&mut shift))?;
                if diff >= 0 {
                    break;
                }
            }

            let data_offset = if diff > 0 || bit_flag != 0 {
                if bit_flag == 0 {
                    diff -= 8;
                }
                let ptr = (0x928 + diff) as usize;
                decode_word(&mut tmp, ptr, diff, &mut bit_flag, &mut rd)?
            } else {
                1
            };

            if data_offset <= 0 || data_length < 0 {
                return Err(anyhow!("invalid LZ back-reference"));
            }
            let buf_start = start.checked_sub(data_offset as usize).ok_or_else(|| anyhow!("LZ underflow"))?;
            let buf_end = start + data_length as usize + 1;
            if buf_end > end {
                return Err(anyhow!("LZ overflow"));
            }
            offset = (((buf_end as i32) + 1) & 1) + 6;
            let mut src = buf_start;
            while start < buf_end {
                out[start] = out[src];
                start += 1;
                src += 1;
            }
        }
        if start > 0 {
            prev = out[start - 1];
        }
    }
}
