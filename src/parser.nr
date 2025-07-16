struct TLV {
    tag: u8,
    length: u32,
    value: [u8; 512],
}

struct IntegerResult {
    value: u64,
    signed_value: i64, // Optional
    is_negative: bool,
    bit_length: u32,
}

// --------------------- Parsing Functions ---------------------

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



// --------------------- Tests ---------------------

//? ------------------ TLV Decoding Tests ---------------------
#[test]
fn test_decode_tlv_short_form() {
    // Tag = 0x02 (INTEGER), Length = 0x01, Value = 0x2A
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0x02; // INTEGER tag
    bytes[1] = 0x01; // Length = 1
    bytes[2] = 0x2A; // Value = 0x2A

    let (tlv, next_offset) = decode_tlv(bytes, 0);

    assert(tlv.tag == 0x02);
    assert(tlv.length == 1);
    assert(tlv.value[0] == 0x2A);
    assert(next_offset == 3); // tag + len + value = 3 bytes
}

#[test]
fn test_decode_tlv_long_form() {
    // Tag = 0x04 (OCTET STRING), Length = 0x82 0x01 0x00 (length = 256)
    // First 3 bytes: [0x04, 0x82, 0x01, 0x00]
    // Next 256 bytes = 0xAA repeated
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0x04; // Tag
    bytes[1] = 0x82; // Long form, next 2 bytes = length
    bytes[2] = 0x01;
    bytes[3] = 0x00; // length = 256

    for i in 0..256 {
        bytes[4 + i] = 0xAA;
    }

    let (tlv, next_offset) = decode_tlv(bytes, 0);

    assert(tlv.tag == 0x04);
    assert(tlv.length == 256);
    assert(tlv.value[0] == 0xAA);
    assert(tlv.value[255] == 0xAA);
    assert(next_offset == 4 + 256);
}

#[test]
fn test_decode_tlv_nested_tlv_inside_sequence() {
    let mut bytes: [u8; 512] = [0; 512];

    // Outer TLV
    bytes[0] = 0x30; // SEQUENCE tag
    bytes[1] = 0x03; // Length = 3

    // Inner TLV inside value
    bytes[2] = 0x02; // INTEGER tag
    bytes[3] = 0x01; // Length = 1
    bytes[4] = 0x01; // Value = 0x01

    let (outer_tlv, next_offset) = decode_tlv(bytes, 0);

    assert(outer_tlv.tag == 0x30);
    assert(outer_tlv.length == 3);
    assert(next_offset == 5);

    // Decoding the nested TLV from outer_tlv.value
    let (inner_tlv, inner_offset) = decode_tlv(outer_tlv.value, 0);

    assert(inner_tlv.tag == 0x02);
    assert(inner_tlv.length == 1);
    assert(inner_tlv.value[0] == 0x01);
    assert(inner_offset == 3);
}


//? ------------------ Integer Parsing Tests ---------------------

#[test]
fn test_parse_integer() {
    let tlv = TLV { tag: 0x02, length: 1, value: [0x2A; 512] };
    let result = parse_integer(tlv);
    assert(result.value == 42);
    assert(result.signed_value == 42);
    assert(result.is_negative == false);
    assert(result.bit_length == 8);
}
#[test]
fn test_parse_integer_neg1() {
    let tlv = TLV { tag: 0x02, length: 1, value: [0xFF; 512] };
    let result = parse_integer(tlv);
    assert(result.value == 255);
    assert(result.signed_value == -1);
    assert(result.is_negative == true);
    assert(result.bit_length == 8);
}