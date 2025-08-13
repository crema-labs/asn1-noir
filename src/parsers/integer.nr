use crate::structs::{IntegerResult, TLV};

fn parse_integer(tlv: TLV) -> IntegerResult {
    let mut unsigned: u64 = 0;
    let mut is_negative = false;
    let mut bit_length: u32 = 0;

    if tlv.length > 0 {
        let first_byte = tlv.value[0];
        if (first_byte & 0x80) == 0x80 {
            is_negative = true;
        }

        for i in 0..8 {
            if i < tlv.length {
                unsigned = (unsigned << 8) | (tlv.value[i] as u64);
                bit_length += 8;
            }
        }
    }

    let signed_value: i64 = if is_negative {
        if bit_length == 64 {
            // avoid overflow: two's complement manually
            let unsigned_i64 = unsigned as i64;
            unsigned_i64
        } else {
            let two_pow_n = 1 as u64 << (bit_length as u8);
            ((unsigned as i64) - (two_pow_n as i64))
        }
    } else {
        unsigned as i64
    };

    IntegerResult { value: unsigned, signed_value, is_negative, bit_length }
}
