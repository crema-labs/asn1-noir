
use crate::structs::BitStringResult;

fn parse_bit_string(bytes: [u8; 512], start: u32, end: u32, max_length: u32) -> BitStringResult {
    let unused_bits: u8 = bytes[start];
    assert(unused_bits <= 7);

    let bit_len: u32 = ((end - start - 1) * 8) - (unused_bits as u32);
    let mut bits: [bool; 512] = [false; 512];
    let mut bit_index: u32 = 0;

    for i in 0..512 {
        let in_lower_bound = i >= (start + 1);
        let in_upper_bound = i < end;
        let in_range = if in_lower_bound {
            if in_upper_bound {
                true
            } else {
                false
            }
        } else {
            false
        };

        let skip = if i == end - 1 { unused_bits } else { 0 };
        let bit_count = 8 - (skip as u32);

        if in_range {
            let byte: u8 = bytes[i];
            for k in 0..8 {
                let is_k_in_bounds = k < bit_count;
                let is_bit_index_in_bounds = bit_index < max_length;
                let should_write = if is_k_in_bounds {
                    if is_bit_index_in_bounds {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                if should_write {
                    let j: u8 = 7 - (k as u8);
                    let mask = 1 << j;
                    let result = (byte & mask) >> j;
                    bits[bit_index] = result == 1;
                    bit_index += 1;
                }
            }
        }
    }

    BitStringResult { size: bit_len, bits }
}
