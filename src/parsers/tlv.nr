use crate::structs::TLV;
fn decode_tlv(bytes: [u8; 512], offset: u32) -> (TLV, u32) {
    let tag = bytes[offset];
    let length_byte = bytes[offset + 1];

    let mut length: u32 = 0;
    let mut len_size: u32 = 1;
    let mut val_offset: u32 = 0;

    if length_byte < 128 {
        // Short form
        length = length_byte as u32;
        val_offset = offset + 2;
    } else {
        // Long form
        let num_bytes = length_byte - 128;
        len_size = 1 + num_bytes as u32;
        length = 0;

        for i in 0..4 {
            if i < num_bytes {
                let byte_val = bytes[offset + 2 + i as u32];
                length = (length << 8) | (byte_val as u32);
            }
        }

        val_offset = offset + 2 + num_bytes as u32;
    }

    let mut value = [0 as u8; 512];
    for i in 0..512 {
        if i < length {
            value[i] = bytes[val_offset + i];
        }
    }

    let total_len = 1 + len_size + length;
    (TLV { tag, length, value }, offset + total_len)
}

fn decode_tlv_with_offset(bytes: [u8; 512], offset: u32) -> (TLV, u32, u32) {
    let tag = bytes[offset];
    let length_byte = bytes[offset + 1];

    let mut length: u32 = 0;
    let mut len_size: u32 = 1;
    let mut val_offset: u32 = 0;

    if length_byte < 128 {
        length = length_byte as u32;
        val_offset = offset + 2;
    } else {
        let num_bytes = length_byte - 128;
        len_size = 1 + num_bytes as u32;

        for i in 0..4 {
            if i < num_bytes {
                let byte_val = bytes[offset + 2 + i as u32];
                length = (length << 8) | (byte_val as u32);
            }
        }

        val_offset = offset + 2 + num_bytes as u32;
    }

    let mut value = [0 as u8; 512];
    for i in 0..512 {
        if i < length {
            value[i] = bytes[val_offset + i];
        }
    }

    let total_len = 1 + len_size + length;
    (TLV { tag, length, value }, offset + total_len, val_offset)
}
