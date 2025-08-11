use crate::parsers::{bitstring::parse_bit_string, tlv::decode_tlv};
#[test]
fn test_no_unused_bits_full_byte() {
    // 00000000 -> all bits are 0
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0; // unused bits = 0
    bytes[1] = 0x00; // 8 bits: all false

    let result = parse_bit_string(bytes, 0, 2, 512);
    assert(result.size == 8);
    for i in 0..8 {
        assert(result.bits[i] == false);
    }
}

#[test]
fn test_no_unused_bits_mixed_bits() {
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0; // unused bits = 0
    bytes[1] = 170; // 0b10101010 in decimal, alternating bits

    let result = parse_bit_string(bytes, 0, 2, 512);
    assert(result.size == 8);
    assert(result.bits[0] == true);
    assert(result.bits[1] == false);
    assert(result.bits[2] == true);
    assert(result.bits[3] == false);
    assert(result.bits[4] == true);
    assert(result.bits[5] == false);
    assert(result.bits[6] == true);
    assert(result.bits[7] == false);
}

#[test]
fn test_with_unused_bits_at_end() {
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 3; // 3 unused bits => 5 bits only from last byte
    bytes[1] = 248; // only first 5 bits used: 11111

    let result = parse_bit_string(bytes, 0, 2, 512);
    assert(result.size == 5);
    for i in 0..5 {
        assert(result.bits[i] == true);
    }
}

#[test]
fn test_multiple_bytes_with_unused() {
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 2; // 2 unused bits in the last byte
    bytes[1] = 204;
    bytes[2] = 240; // only first 6 bits used: 111100 (0b11110000 = 240)

    let result = parse_bit_string(bytes, 0, 3, 512);
    assert(result.size == 14); // 8 (from first byte) + 6 = 14
    let expected = [
        true, true, false, false, true, true, false, false, // byte 1
        true, true, true, true, false, false, // byte 2 (6 bits)
    ];
    for i in 0..14 {
        assert(result.bits[i] == expected[i]);
    }
}

#[test]
fn test_all_ones_unused_zero() {
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0;
    bytes[1] = 0xFF;

    let result = parse_bit_string(bytes, 0, 2, 512);
    assert(result.size == 8);
    for i in 0..8 {
        assert(result.bits[i] == true);
    }
}

#[test]
fn test_empty_bit_string() {
    let mut bytes: [u8; 512] = [0; 512];
    bytes[0] = 0; // no unused bits

    let result = parse_bit_string(bytes, 0, 1, 512);
    assert(result.size == 0);
}

//? ------------------ Bit String Parsing Tests with TLV ---------------------
#[test]
fn test_no_unused_bits_full_byte_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];
    // TLV format: Tag (0x03), Length (0x02), Value: [unused = 0, byte = 0x00]
    bytes[0] = 0x03;
    bytes[1] = 0x02;
    bytes[2] = 0x00;
    bytes[3] = 0x00;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 8);
    for i in 0..8 {
        assert(result.bits[i] == false);
    }
}

#[test]
fn test_no_unused_bits_mixed_bits_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];
    // TLV: Tag, Length = 2, Value = [0 (unused), 0b10101010]
    bytes[0] = 0x03;
    bytes[1] = 0x02;
    bytes[2] = 0x00;
    bytes[3] = 170;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 8);
    let expected = [true, false, true, false, true, false, true, false];
    for i in 0..8 {
        assert(result.bits[i] == expected[i]);
    }
}

#[test]
fn test_with_unused_bits_at_end_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];

    bytes[0] = 0x03;
    bytes[1] = 0x02;
    bytes[2] = 3;
    bytes[3] = 248;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 5);
    for i in 0..5 {
        assert(result.bits[i] == true);
    }
}

#[test]
fn test_multiple_bytes_with_unused_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];

    bytes[0] = 0x03;
    bytes[1] = 0x03;
    bytes[2] = 2;
    bytes[3] = 204;
    bytes[4] = 240;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 14);
    let expected = [
        true, true, false, false, true, true, false, false, // byte 1
        true, true, true, true, false, false, // byte 2 (6 bits)
    ];
    for i in 0..14 {
        assert(result.bits[i] == expected[i]);
    }
}

#[test]
fn test_all_ones_unused_zero_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];
    // TLV: Length = 2, Value = [0, 0xFF]
    bytes[0] = 0x03;
    bytes[1] = 0x02;
    bytes[2] = 0;
    bytes[3] = 0xFF;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 8);
    for i in 0..8 {
        assert(result.bits[i] == true);
    }
}

#[test]
fn test_empty_bit_string_with_tlv() {
    let mut bytes: [u8; 512] = [0; 512];

    bytes[0] = 0x03;
    bytes[1] = 0x01;
    bytes[2] = 0;

    let (tlv, _) = decode_tlv(bytes, 0);
    let result = parse_bit_string(tlv.value, 0, tlv.length, 512);

    assert(result.size == 0);
}
