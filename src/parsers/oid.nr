use crate::structs::TLV;

fn parse_oid(tlv: TLV) -> [u32; 64] {
    let mut oid: [u32; 64] = [0; 64];
    let first_byte: u8 = tlv.value[0];
    oid[0] = (first_byte / 40) as u32;
    oid[1] = (first_byte % 40) as u32;

    let mut index: u32 = 2;
    let mut value: u32 = 0;
    let mut parsing_done: bool = false;

    for i in 1..64 {
        let is_within_length = i < tlv.length;
        let read_byte = if is_within_length { tlv.value[i] } else { 0 };
        let is_last = (read_byte & 0x80) == 0;

        let should_process = if is_within_length {
            if !parsing_done {
                true
            } else {
                false
            }
        } else {
            false
        };

        let next_value = (value << 7) | ((read_byte & 0x7F) as u32);
        value = if should_process { next_value } else { value };

        let should_store = if should_process {
            if is_last {
                true
            } else {
                false
            }
        } else {
            false
        };

        for j in 0..64 {
            if should_store {
                if j == index {
                    oid[j] = value;
                }
            }
        }

        if should_store {
            index += 1;
            value = 0;
        }

        if i == (tlv.length - 1) {
            parsing_done = true;
        }
    }
    oid
}
