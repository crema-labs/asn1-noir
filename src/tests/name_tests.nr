use crate::parsers::name::parse_attribute_type_and_value;
use crate::structs::TLV;
#[test]
fn test_parse_attribute_common_name() {
    // OID = 2.5.4.3 (Common Name), Value = "example"
    // Encoded:
    // 30 0D
    //    06 03 55 04 03       (OID)
    //    13 06 65 78 61 6D 70 6C (PrintableString "exampl")

    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x06;
    value[1] = 0x03;
    value[2] = 0x55;
    value[3] = 0x04;
    value[4] = 0x03;
    value[5] = 0x13;
    value[6] = 0x06;
    value[7] = 0x65; // 'e'
    value[8] = 0x78; // 'x'
    value[9] = 0x61; // 'a'
    value[10] = 0x6D; // 'm'
    value[11] = 0x70; // 'p'
    value[12] = 0x6C; // 'l'

    let tlv = TLV { tag: 0x30, length: 13, value };

    let result = parse_attribute_type_and_value(tlv);

    assert(result.oid[0] == 2); // 2.5.4.3
    assert(result.oid[1] == 5);
    assert(result.oid[2] == 4);
    assert(result.oid[3] == 3);
    assert(result.value[0] == 0x65); // 'e'
    assert(result.value[1] == 0x78); // 'x'
}

#[test]
fn test_parse_country_name() {
    // OID: 2.5.4.6 -> countryName (X.520 DN component)
    // Encoded TLV: 06 03 55 04 06 13 04 54 65 73 74 => "Test"
    let mut value: [u8; 512] = [0; 512];
    let arr: [u8; 11] = [
        0x06, 0x03, 0x55, 0x04, 0x06, // OBJECT IDENTIFIER (2.5.4.6)
        0x13, 0x04, 0x54, 0x65, 0x73, 0x74, // PrintableString "Test"
    ];
    for i in 0..11 {
        value[i] = arr[i];
    }

    let tlv = TLV { tag: 0x30, length: 12, value };

    let result = parse_attribute_type_and_value(tlv);
    assert(result.oid[0] == 2);
    assert(result.oid[1] == 5);
    assert(result.oid[2] == 4);
    assert(result.oid[3] == 6);
    assert(result.value[0] == 0x54); // 'T'
    assert(result.value[1] == 0x65); // 'e'
    assert(result.value[2] == 0x73); // 's'
    assert(result.value[3] == 0x74); // 't'
}

#[test]
fn test_parse_common_name() {
    // OID: 2.5.4.3 -> commonName (X.520 DN component)
    let mut value: [u8; 512] = [0; 512];
    let arr: [u8; 11] = [
        0x06, 0x03, 0x55, 0x04, 0x03, // OBJECT IDENTIFIER (2.5.4.3)
        0x13, 0x04, 0x54, 0x65, 0x73, 0x74, // "Test"
    ];
    for i in 0..11 {
        value[i] = arr[i];
    }

    let tlv = TLV { tag: 0x30, length: 12, value };

    let result = parse_attribute_type_and_value(tlv);
    assert(result.oid[3] == 3);
    assert(result.value[0] == 0x54);
}

#[test]
fn test_parse_organization_name() {
    // OID: 2.5.4.10 -> organizationName
    let mut value: [u8; 512] = [0; 512];
    let arr: [u8; 11] = [
        0x06, 0x03, 0x55, 0x04, 0x0a, // OBJECT IDENTIFIER (2.5.4.10)
        0x13, 0x04, 0x54, 0x65, 0x73, 0x74, // "Test"
    ];
    for i in 0..11 {
        value[i] = arr[i];
    }

    let tlv = TLV { tag: 0x30, length: 12, value };

    let result = parse_attribute_type_and_value(tlv);
    assert(result.oid[3] == 10);
}

#[test]
fn test_parse_jurisdiction_country() {
    // OID: 1.3.6.1.4.1.311.60.2.1.3 -> jurisdictionOfIncorporationC (Microsoft)
    let mut value: [u8; 512] = [0; 512];
    let arr: [u8; 19] = [
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03, // OID bytes
        0x13, 0x04, 0x54, 0x65, 0x73, 0x74, // "Test"
    ];
    for i in 0..19 {
        value[i] = arr[i];
    }

    let tlv = TLV { tag: 0x30, length: 19, value };

    let result = parse_attribute_type_and_value(tlv);
    assert(result.oid[0] == 1);
    assert(result.oid[1] == 3);
    assert(result.oid[2] == 6);
    assert(result.oid[3] == 1);
    assert(result.oid[4] == 4);
    assert(result.oid[5] == 1);
    assert(result.oid[6] == 311);
    assert(result.oid[7] == 60);
    assert(result.oid[8] == 2);
    assert(result.oid[9] == 1);
    assert(result.oid[10] == 3);
}
