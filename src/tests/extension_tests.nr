use crate::parsers::{extension::parse_extensions, tlv::decode_tlv};
#[test]
fn test_parse_extensions_without_critical() {
    let values: [u8; 24] = [
        0x30, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x1D, 0x13, // OID 2.5.29.19
        0x04, 0x0D, // OCTET STRING
        0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x04, 0x01, 0x01, 0x00, 0x00,
    ];

    let mut data = [0; 512];
    for i in 0..24 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let (extensions, count) = parse_extensions(tlv);

    assert(count == 1);
    assert(extensions[0].oid[0] == 2);
    assert(extensions[0].oid[1] == 5);
    assert(extensions[0].oid[2] == 29);
    assert(extensions[0].oid[3] == 19);
    assert(extensions[0].critical == false);
    assert(extensions[0].value[0] == 0x30);
}

#[test]
fn test_parse_extensions_with_critical() {
    let values: [u8; 30] = [
        0x30, 0x1C, // SEQUENCE, length 28
        0x30, 0x1A, // Extension SEQUENCE
        0x06, 0x03, 0x55, 0x1D, 0x0F, // OID: 2.5.29.15
        0x01, 0x01, 0xFF, // BOOLEAN TRUE
        0x04, 0x0E, // OCTET STRING, length 14
        0x03, 0x0C, 0x00, // BIT STRING inside value
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00,
    ];

    let mut data = [0; 512];
    for i in 0..30 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let (extensions, count) = parse_extensions(tlv);

    assert(count == 1);
    assert(extensions[0].oid[0] == 2);
    assert(extensions[0].oid[1] == 5);
    assert(extensions[0].oid[2] == 29);
    assert(extensions[0].oid[3] == 15);
    assert(extensions[0].critical == true);
    assert(extensions[0].value[0] == 0x03);
}
