use crate::parsers::oid::parse_oid;
use crate::structs::TLV;
#[test]
fn test_parse_oid_minimal() {
    // OID: 1.2
    // Encoded: 0x2a
    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x2a; // 1*40 + 2 = 42

    let tlv = TLV { tag: 6, length: 1, value };

    let result = parse_oid(tlv);

    assert(result[0] == 1);
    assert(result[1] == 2);
}

#[test]
fn test_parse_oid_rsa_encryption() {
    // OID: 1.2.840.113549
    // Root of RSA Data Security Inc. OID space (used in many RSA-related identifiers)
    // Encoded: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]

    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x2a;
    value[1] = 0x86;
    value[2] = 0x48;
    value[3] = 0x86;
    value[4] = 0xf7;
    value[5] = 0x0d;

    let tlv = TLV { tag: 6, length: 6, value };

    let result = parse_oid(tlv);

    assert(result[0] == 1);
    assert(result[1] == 2);
    assert(result[2] == 840);
    assert(result[3] == 113549);
}

#[test]
fn test_parse_oid_enterprise() {
    // OID: 1.3.6.1.4.1
    // Start of enterprise-specific OID namespace (IANA-registered private enterprise numbers)
    // Encoded: [0x2b, 0x06, 0x01, 0x04, 0x01]

    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x2b;
    value[1] = 0x06;
    value[2] = 0x01;
    value[3] = 0x04;
    value[4] = 0x01;

    let tlv = TLV { tag: 6, length: 5, value };

    let result = parse_oid(tlv);

    assert(result[0] == 1);
    assert(result[1] == 3);
    assert(result[2] == 6);
    assert(result[3] == 1);
    assert(result[4] == 4);
    assert(result[5] == 1);
}

#[test]
fn test_parse_oid_common_name() {
    // OID: 2.5.4.3
    // `commonName` (CN) in X.509 certificates
    // Encoded: [0x55, 0x04, 0x03]

    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x55;
    value[1] = 0x04;
    value[2] = 0x03;

    let tlv = TLV { tag: 6, length: 3, value };

    let result = parse_oid(tlv);

    assert(result[0] == 2);
    assert(result[1] == 5);
    assert(result[2] == 4);
    assert(result[3] == 3);
}

#[test]
fn test_parse_oid_ec_public_key() {
    // OID: 1.2.840.10045.2.1
    // ecPublicKey identifies an elliptic curve public key in X.509 SubjectPublicKeyInfo
    // Encoded: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]

    let mut value: [u8; 512] = [0; 512];
    value[0] = 0x2a;
    value[1] = 0x86;
    value[2] = 0x48;
    value[3] = 0xce;
    value[4] = 0x3d;
    value[5] = 0x02;
    value[6] = 0x01;

    let tlv = TLV { tag: 6, length: 7, value };

    let result = parse_oid(tlv);

    assert(result[0] == 1);
    assert(result[1] == 2);
    assert(result[2] == 840);
    assert(result[3] == 10045);
    assert(result[4] == 2);
    assert(result[5] == 1);
}
