use crate::parsers::tlv::decode_tlv;
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