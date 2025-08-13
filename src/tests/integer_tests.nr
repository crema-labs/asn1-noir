use crate::parsers::integer::parse_integer;
use crate::structs::TLV;
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

#[test]
fn test_parse_integer_zero() {
    let mut val = [0 as u8; 512];
    val[0] = 0x00;
    let tlv = TLV { tag: 0x02, length: 1, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 0);
    assert(result.signed_value == 0);
    assert(result.is_negative == false);
    assert(result.bit_length == 8);
}

#[test]
fn test_parse_integer_positive_single_byte() {
    let mut val = [0 as u8; 512];
    val[0] = 0x2A; // 42
    let tlv = TLV { tag: 0x02, length: 1, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 42);
    assert(result.signed_value == 42);
    assert(result.is_negative == false);
    assert(result.bit_length == 8);
}

#[test]
fn test_parse_integer_positive_multi_byte() {
    // 0x01 0x00 = 256
    let mut val = [0 as u8; 512];
    val[0] = 0x01;
    val[1] = 0x00;
    let tlv = TLV { tag: 0x02, length: 2, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 256);
    assert(result.signed_value == 256);
    assert(result.is_negative == false);
    assert(result.bit_length == 16);
}

#[test]
fn test_parse_integer_negative_multi_byte() {
    // 0xFF 0x38 = -200 (65536 - 200 = 65336 = 0xFF38)
    let mut val = [0 as u8; 512];
    val[0] = 0xFF;
    val[1] = 0x38;
    let tlv = TLV { tag: 0x02, length: 2, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 0xFF38);
    assert(result.signed_value == -200);
    assert(result.is_negative == true);
    assert(result.bit_length == 16);
}

#[test]
fn test_parse_integer_max_8_bytes() {
    let mut val = [0 as u8; 512];
    // 0x0123456789ABCDEF
    val[0] = 0x01;
    val[1] = 0x23;
    val[2] = 0x45;
    val[3] = 0x67;
    val[4] = 0x89;
    val[5] = 0xAB;
    val[6] = 0xCD;
    val[7] = 0xEF;
    let tlv = TLV { tag: 0x02, length: 8, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 0x0123456789ABCDEF);
    assert(result.signed_value == 0x0123456789ABCDEF);
    assert(result.is_negative == false);
    assert(result.bit_length == 64);
}

#[test]
fn test_parse_integer_negative_8_bytes() {
    let mut val = [0xFF; 512];
    let tlv = TLV { tag: 0x02, length: 8, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 0xFFFFFFFFFFFFFFFF);
    assert(result.signed_value == -1);
    assert(result.is_negative == true);
    assert(result.bit_length == 64);
}

#[test]
fn test_parse_integer_empty() {
    let val = [0 as u8; 512];
    let tlv = TLV { tag: 0x02, length: 0, value: val };

    let result = parse_integer(tlv);
    assert(result.value == 0);
    assert(result.signed_value == 0);
    assert(result.is_negative == false);
    assert(result.bit_length == 0);
}
