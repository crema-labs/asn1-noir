use crate::structs::{TLV, OctetStringResult};

fn parse_octet_string(tlv: TLV) -> OctetStringResult {
    let mut hex: [u8; 1024] = [0; 1024];
    let mut hex_index: u32 = 0;

    // for i in 0..512 {
    for i in 0..tlv.length {
        let byte: u8 = tlv.value[i];
        let high_nibble: u8 = (byte >> 4) & 0x0F;
        let low_nibble: u8 = byte & 0x0F;

        // Convert to ASCII hex ('0'..'9', 'a'..'f')
        hex[hex_index] = if high_nibble < 10 {
            48 + high_nibble
        } else {
            87 + high_nibble
        };
        hex[hex_index + 1] = if low_nibble < 10 {
            48 + low_nibble
        } else {
            87 + low_nibble
        };

        hex_index += 2;
    }
    // }

    OctetStringResult { size: hex_index, hex }
}
