use crate::parsers::{algorithm::parse_algorithm_identifier, tlv::decode_tlv};
use crate::structs::TLV;
#[test]
fn test_parse_algorithm_identifier_sha256_rsa() {
    // DER-encoded: SEQUENCE(OID + NULL)
    let encoded: [u8; 15] = [
        0x30, 0x0d, // SEQUENCE, length 13
        0x06, 0x09, // OID, length 9
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // 1.2.840.113549.1.1.11
        0x05, 0x00, // NULL
    ];

    let mut data: [u8; 512] = [0; 512];
    for i in 0..15 {
        data[i] = encoded[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let algo = parse_algorithm_identifier(tlv);

    assert(algo.oid[0] == 1);
    assert(algo.oid[1] == 2);
    assert(algo.oid[2] == 840);
    assert(algo.oid[3] == 113549);
    assert(algo.oid[4] == 1);
    assert(algo.oid[5] == 1);
    assert(algo.oid[6] == 11);

    // NULL parameter is encoded as tag=0x05, length=0
    assert(algo.parameters[0] == 0x05);
    assert(algo.parameters[1] == 0x00);
}

#[test]
fn test_algorithm_identifier_sha256_with_rsa() {
    // SEQUENCE of:
    //   OID: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    //   NULL
    let values: [u8; 15] = [
        0x30, 0x0D, // SEQUENCE, length 13
        0x06, 0x09, // OID, length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, // 1.2.840.113549.1.1.11
        0x05, 0x00, // NULL
    ];

    let mut data = [0; 512];
    for i in 0..15 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let algo = parse_algorithm_identifier(tlv);

    assert(algo.oid[0] == 1);
    assert(algo.oid[1] == 2);
    assert(algo.oid[2] == 840);
    assert(algo.oid[3] == 113549);
    assert(algo.oid[4] == 1);
    assert(algo.oid[5] == 1);
    assert(algo.oid[6] == 11);
    assert(algo.parameters[0] == 0x05); // NULL tag
    assert(algo.parameters[1] == 0x00); // NULL length
}

#[test]
fn test_algorithm_identifier_sha1_with_rsa() {
    // SEQUENCE of:
    //   OID: 1.2.840.113549.1.1.5 (sha1WithRSAEncryption)
    //   NULL
    let values: [u8; 15] = [
        0x30, 0x0D, // SEQUENCE
        0x06, 0x09, // OID
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, // 1.2.840.113549.1.1.5
        0x05, 0x00, // NULL
    ];

    let mut data = [0; 512];
    for i in 0..15 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let algo = parse_algorithm_identifier(tlv);

    assert(algo.oid[0] == 1);
    assert(algo.oid[1] == 2);
    assert(algo.oid[2] == 840);
    assert(algo.oid[3] == 113549);
    assert(algo.oid[4] == 1);
    assert(algo.oid[5] == 1);
    assert(algo.oid[6] == 5);
    assert(algo.parameters[0] == 0x05);
    assert(algo.parameters[1] == 0x00);
}

#[test]
fn test_algorithm_identifier_oid_only() {
    // SEQUENCE of:
    //   OID: 1.3.14.3.2.26 (sha1)
    // No NULL parameter
    let values: [u8; 11] = [
        0x30, 0x09, // SEQUENCE
        0x06, 0x05, // OID
        0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x00, 0x00, // 1.3.14.3.2.26 + padding
    ];

    let mut data = [0; 512];
    for i in 0..11 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let algo = parse_algorithm_identifier(tlv);

    assert(algo.oid[0] == 1);
    assert(algo.oid[1] == 3);
    assert(algo.oid[2] == 14);
    assert(algo.oid[3] == 3);
    assert(algo.oid[4] == 2);
    assert(algo.oid[5] == 26);
    assert(algo.parameters[0] == 0); // not present
}

#[test]
fn test_algorithm_identifier_truncated_oid() {
    // SEQUENCE of:
    //   OID: truncated, invalid
    let values: [u8; 7] = [
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, // OID, length 3
        0x2A, 0x86, 0x48, // 1.2.840 (incomplete)
    ];

    let mut data = [0; 512];
    for i in 0..7 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let algo = parse_algorithm_identifier(tlv);

    assert(algo.oid[0] == 1);
    assert(algo.oid[1] == 2);
    assert(algo.oid[2] == 840);
}
