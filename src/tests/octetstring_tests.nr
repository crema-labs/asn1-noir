use crate::parsers::octetstring::parse_octet_string;
use crate::structs::TLV;
#[test]
fn test_parse_octet_string_single_byte() {
    let mut val = [0; 512];
    val[0] = 0x2A;

    let tlv = TLV { tag: 0x04, length: 1, value: val };
    let result = parse_octet_string(tlv);

    assert(result.size == 2);
    assert(result.hex[0] == 50 as u8);
    assert(result.hex[1] == 97 as u8);
}

#[test]
fn test_parse_octet_string_all_zero() {
    let mut val = [0; 512];
    for i in 0..4 {
        val[i] = 0x00;
    }

    let tlv = TLV { tag: 0x04, length: 4, value: val };
    let result = parse_octet_string(tlv);

    assert(result.size == 8);
    for i in 0..8 {
        assert(result.hex[i] == 48);
    }
}

#[test]
fn test_parse_octet_string_all_ff() {
    let mut val = [0; 512];
    for i in 0..3 {
        val[i] = 0xFF;
    }

    let tlv = TLV { tag: 0x04, length: 3, value: val };
    let result = parse_octet_string(tlv);

    assert(result.size == 6);
    for i in 0..3 {
        let hi = result.hex[i * 2];
        let lo = result.hex[i * 2 + 1];
        assert(hi == 102);
        assert(lo == 102);
    }
}

#[test]
fn test_parse_octet_string_mixed_bytes() {
    let mut val = [0; 512];
    val[0] = 0x00;
    val[1] = 0x10;
    val[2] = 0xA5;
    val[3] = 0xFF;

    let tlv = TLV { tag: 0x04, length: 4, value: val };
    let result = parse_octet_string(tlv);

    assert(result.size == 8);

    // Expected ASCII chars: "00", "10", "a5", "ff"
    let expected: [u8; 8] = [48, 48, 49, 48, 97, 53, 102, 102];

    for i in 0..8 {
        assert(result.hex[i] == expected[i]);
    }
}

#[test]
fn test_parse_octet_string_empty() {
    let val = [0; 512];
    let tlv = TLV { tag: 0x04, length: 0, value: val };
    let result = parse_octet_string(tlv);

    assert(result.size == 0);
    assert(result.hex[0] == 0);
}
