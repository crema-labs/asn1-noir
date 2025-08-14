use crate::parsers::{tlv::decode_tlv, validity::parse_validity};
#[test]
fn test_parse_validity_utctime() {
    let values: [u8; 32] = [
        0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x36, 0x31, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x36, 0x31, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5A,
    ];

    let mut data = [0; 512];
    for i in 0..32 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let validity = parse_validity(tlv);

    assert(validity.not_before[0] == 0x32); // '2'
    assert(validity.not_before[1] == 0x33); // '3'
    assert(validity.not_before[11] == 0x30); // '0'
    assert(validity.not_before[12] == 0x5A); // 'Z'

    assert(validity.not_after[0] == 0x32); // '2'
    assert(validity.not_after[1] == 0x34); // '4'
    assert(validity.not_after[11] == 0x30); // '0'
    assert(validity.not_after[12] == 0x5A); // 'Z'
}
#[test]
fn test_parse_validity_min_date() {
    let values: [u8; 32] = [
        0x30, 0x1E, 0x17, 0x0D, // UTCTime
        0x30, 0x30, 0x30, 0x10, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, // "00001001000000Z"
        0x17, 0x0D, // UTCTime
        0x30, 0x30, 0x30, 0x12, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5A, // "00001201000000Z"
    ];

    let mut data = [0 as u8; 512];
    for i in 0..32 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let validity = parse_validity(tlv);

    assert(validity.not_before[0] == 0x30); // '0'
    assert(validity.not_before[1] == 0x30); // '0'
    assert(validity.not_before[12] == 0x5A); // 'Z'

    assert(validity.not_after[0] == 0x30); // '0'
    assert(validity.not_after[1] == 0x30); // '0'
    assert(validity.not_after[12] == 0x5A); // 'Z'
}

#[test]
fn test_parse_validity_future_date() {
    let values: [u8; 32] = [
        0x30, 0x1E, 0x17, 0x0D, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35,
        0x39, 0x5A, // "291231235959Z"
        0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5A, // "300101000000Z"
    ];

    let mut data = [0 as u8; 512];
    for i in 0..32 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let validity = parse_validity(tlv);

    assert(validity.not_before[0] == 0x32); // '2'
    assert(validity.not_before[1] == 0x39); // '9'
    assert(validity.not_before[12] == 0x5A); // 'Z'

    assert(validity.not_after[0] == 0x33); // '3'
    assert(validity.not_after[1] == 0x30); // '0'
    assert(validity.not_after[12] == 0x5A); // 'Z'
}

#[test]
fn test_parse_validity_diff_times() {
    // Validity:
    // not_before: "230101120000Z" => 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A
    // not_after:  "250101134567Z" => 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x5A

    let values: [u8; 32] = [
        0x30, 0x1E, // SEQUENCE, length 30
        0x17, 0x0D, // UTCTime (13 bytes)
        0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, // "230101120000Z"
        0x17, 0x0D, // UTCTime (13 bytes)
        0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x5A, // "250101134567Z"
    ];

    let mut data = [0 as u8; 512];
    for i in 0..32 {
        data[i] = values[i];
    }

    let (tlv, _) = decode_tlv(data, 0);
    let validity = parse_validity(tlv);

    // Check not_before == "230101120000Z"
    assert(validity.not_before[0] == 0x32); // '2'
    assert(validity.not_before[1] == 0x33); // '3'
    assert(validity.not_before[6] == 0x31); // '1'
    assert(validity.not_before[12] == 0x5A); // 'Z'

    // Check not_after == "250101134567Z"
    assert(validity.not_after[0] == 0x32); // '2'
    assert(validity.not_after[1] == 0x35); // '5'
    assert(validity.not_after[7] == 0x33); // '3'
    assert(validity.not_after[11] == 0x37); // '7'
    assert(validity.not_after[12] == 0x5A); // 'Z'
}



//? ------------------ Subject Public Key Info Parsing Tests ---------------------

// #[test]
// fn test_parse_subject_public_key_info_simple3() {
//     let values: [u8; 24] = [
//         0x30, 0x16,             // SEQUENCE (22 bytes)
//         0x30, 0x06,             // AlgorithmIdentifier
//         0x06, 0x01, 0x2A,       // OID = 1.2
//         0x05, 0x00,             // NULL
//         0x03, 0x0C,             // BIT STRING, length 12
//         0x00,                   // unused bits = 0
//         0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, // 6 bytes key
//         0x00, 0x00, 0x00, 0x00, // padding
//         0x00, 0x00
//     ];

//     let mut data = [0; 512];
//     for i in 0..24 {
//         data[i] = values[i];
//     }

//     let (tlv, _) = decode_tlv(data, 0);
//     let pubkey_info = parse_subject_public_key_info(tlv);

//     assert(pubkey_info.public_key[0] == true);
//     assert(pubkey_info.public_key[1] == false);
//     assert(pubkey_info.public_key[2] == true);
//     assert(pubkey_info.public_key[3] == false);
//     assert(pubkey_info.public_key[4] == true);
//     assert(pubkey_info.public_key[5] == false);
//     assert(pubkey_info.public_key[6] == true);
//     assert(pubkey_info.public_key[7] == false);
// }

// #[test]
// fn test_parse_subject_public_key_info_simple2() {
//     let values: [u8; 22] = [
//         0x30, 0x14,             // SEQUENCE
//         0x30, 0x06,             // AlgorithmIdentifier
//         0x06, 0x01, 0x2A,       // OID
//         0x05, 0x00,             // NULL
//         0x03, 0x08,             // BIT STRING, length 8
//         0x00,                   // unused bits = 0
//         0xAA, 0x55, 0xAA, 0x55, // 4 bytes data
//         0x00, 0x00, 0x00, 0x00, // padding
//         0x00, 0x00,             // padding
//     ];

//     let mut data = [0; 512];
//     for i in 0..22 {
//         data[i] = values[i];
//     }

//     let (tlv, _) = decode_tlv(data, 0);
//     let pubkey_info = parse_subject_public_key_info(tlv);

//     assert(pubkey_info.public_key[0] == true);
//     assert(pubkey_info.public_key[1] == false);
//     assert(pubkey_info.public_key[2] == true);
//     assert(pubkey_info.public_key[3] == false);
//     assert(pubkey_info.public_key[4] == true);
//     assert(pubkey_info.public_key[5] == false);
//     assert(pubkey_info.public_key[6] == true);
//     assert(pubkey_info.public_key[7] == false);
// }

