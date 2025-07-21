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

struct BitStringResult {
    size: u32,
    bits: [bool; 512],
}

struct OctetStringResult {
    size: u32,
    hex: [u8; 1024], // ASCII hex ('0'..'f')
}

// --------------------- Identity Fields ---------------------

struct AttributeTypeAndValue {
    oid: [u32; 64],
    value: [u8; 64],
}

struct RelativeDistinguishedName {
    set: [AttributeTypeAndValue; 8],
    count: u8,
}

struct Name {
    rdns: [RelativeDistinguishedName; 16],
    count: u8,
}

// --------------------- Signature & Public Key ---------------------

struct AlgorithmIdentifier {
    oid: [u32; 64],
    parameters: [u8; 64],
}

struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    public_key: [bool; 512],
}

struct Validity {
    not_before: [u8; 16],
    not_after: [u8; 16],
}

struct Extension {
    oid: [u32; 64],
    critical: bool,
    value: [u8; 256],
}

// --------------------- Final Certificate ---------------------

struct Certificate {
    version: u8,
    serial_number: [u8; 20],
    signature_algorithm: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    public_key_info: SubjectPublicKeyInfo,
    extensions: [Extension; 10],
    ext_count: u8,
    signature_algorithm2: AlgorithmIdentifier,
    signature: [u8; 256],
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

fn parse_bit_string(bytes: [u8; 512], start: u32, end: u32, max_length: u32) -> BitStringResult {
    let unused_bits: u8 = bytes[start];
    assert(unused_bits <= 7);

    let bit_len: u32 = ((end - start - 1) * 8) - (unused_bits as u32);
    let mut bits: [bool; 512] = [false; 512];
    let mut bit_index: u32 = 0;

    for i in 0..512 {
        let in_lower_bound = i >= (start + 1);
        let in_upper_bound = i < end;
        let in_range = if in_lower_bound {
            if in_upper_bound {
                true
            } else {
                false
            }
        } else {
            false
        };

        let skip = if i == end - 1 { unused_bits } else { 0 };
        let bit_count = 8 - (skip as u32);

        if in_range {
            let byte: u8 = bytes[i];
            for k in 0..8 {
                let is_k_in_bounds = k < bit_count;
                let is_bit_index_in_bounds = bit_index < max_length;
                let should_write = if is_k_in_bounds {
                    if is_bit_index_in_bounds {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                if should_write {
                    let j: u8 = 7 - (k as u8);
                    let mask = 1 << j;
                    let result = (byte & mask) >> j;
                    bits[bit_index] = result == 1;
                    bit_index += 1;
                }
            }
        }
    }

    BitStringResult { size: bit_len, bits }
}


fn parse_octet_string(tlv: TLV) -> OctetStringResult {
    let mut hex: [u8; 1024] = [0; 1024];
    let mut hex_index: u32 = 0;

    // for i in 0..512 {
    for i in 0..tlv.length {
        let byte: u8 = tlv.value[i];
        let high_nibble: u8 = (byte >> 4) & 0x0F;
        let low_nibble: u8 = byte & 0x0F;

        // Convert to ASCII hex ('0'..'9', 'a'..'f')
        hex[hex_index] = if high_nibble < 10 {
            48 + high_nibble
        } else {
            87 + high_nibble
        };
        hex[hex_index + 1] = if low_nibble < 10 {
            48 + low_nibble
        } else {
            87 + low_nibble
        };

        hex_index += 2;
    }
    // }

    OctetStringResult { size: hex_index, hex }
}


fn parse_oid(tlv: TLV) -> [u32; 64] {
    let mut oid: [u32; 64] = [0; 64];
    let first_byte: u8 = tlv.value[0];
    oid[0] = (first_byte / 40) as u32;
    oid[1] = (first_byte % 40) as u32;

    let mut index: u32 = 2;
    let mut value: u32 = 0;
    let mut parsing_done: bool = false;

    for i in 1..64 {
        let is_within_length = i < tlv.length;
        let read_byte = if is_within_length { tlv.value[i] } else { 0 };
        let is_last = (read_byte & 0x80) == 0;

        let should_process = if is_within_length {
            if !parsing_done {
                true
            } else {
                false
            }
        } else {
            false
        };

        let next_value = (value << 7) | ((read_byte & 0x7F) as u32);
        value = if should_process { next_value } else { value };

        let should_store = if should_process {
            if is_last {
                true
            } else {
                false
            }
        } else {
            false
        };

        for j in 0..64 {
            if should_store {
                if j == index {
                    oid[j] = value;
                }
            }
        }

        if should_store {
            index += 1;
            value = 0;
        }

        if i == (tlv.length - 1) {
            parsing_done = true;
        }
    }
    oid
}

fn parse_attribute_type_and_value(tlv: TLV) -> AttributeTypeAndValue {
    let (oid_tlv, offset) = decode_tlv(tlv.value, 0);
    let (value_tlv, _) = decode_tlv(tlv.value, offset);

    let parsed_oid: [u32; 64] = parse_oid(oid_tlv);

    let mut val_bytes: [u8; 64] = [0; 64];
    for i in 0..64 {
        if i < value_tlv.length {
            val_bytes[i] = value_tlv.value[i];
        }
    }

    AttributeTypeAndValue { oid: parsed_oid, value: val_bytes }
}


fn parse_algorithm_identifier(tlv: TLV) -> AlgorithmIdentifier {
    let (oid_tlv, offset) = decode_tlv(tlv.value, 0);
    let (params_tlv, _) = decode_tlv(tlv.value, offset);

    let parsed_oid: [u32; 64] = parse_oid(oid_tlv);

    let mut params_bytes: [u8; 64] = [0; 64];
    params_bytes[0] = params_tlv.tag;
    params_bytes[1] = params_tlv.length as u8;

    AlgorithmIdentifier { oid: parsed_oid, parameters: params_bytes }
}

fn parse_validity(tlv: TLV) -> Validity {
    let (not_before_tlv, offset) = decode_tlv(tlv.value, 0);
    let (not_after_tlv, _) = decode_tlv(tlv.value, offset);

    let mut not_before: [u8; 16] = [0; 16];
    let mut not_after: [u8; 16] = [0; 16];

    for i in 0..16 {
        if i < not_before_tlv.length {
            not_before[i] = not_before_tlv.value[i];
        }
        if i < not_after_tlv.length {
            not_after[i] = not_after_tlv.value[i];
        }
    }

    Validity { not_before, not_after }
}


fn parse_extensions(tlv: TLV) -> ([Extension; 10], u8) {
    let mut extensions: [Extension; 10] =
        [Extension { oid: [0; 64], critical: false, value: [0; 256] }; 10];
    let mut offset: u32 = 0;
    let mut count: u8 = 0;

    for i in 0..10 {
        let process = offset < tlv.length;

        if process {
            let (ext_tlv, new_offset) = decode_tlv(tlv.value, offset);
            let mut ext_offset: u32 = 0;

            let (oid_tlv, off1) = decode_tlv(ext_tlv.value, ext_offset);
            ext_offset = off1;

            let (critical_tlv, off2) = decode_tlv(ext_tlv.value, ext_offset);
            let mut critical = false;
            let mut is_critical_parsed = false;

            if critical_tlv.tag == 0x01 {
                critical = critical_tlv.value[0] == 0xff;
                ext_offset = off2;
                is_critical_parsed = true;
            }

            let decode_val = if is_critical_parsed {
                decode_tlv(ext_tlv.value, ext_offset)
            } else {
                (critical_tlv, off2)
            };

            let val_tlv = decode_val.0;

            let parsed_oid = parse_oid(oid_tlv);
            let mut ext_value = [0; 256];
            for j in 0..256 {
                if j < val_tlv.length {
                    ext_value[j] = val_tlv.value[j];
                }
            }

            extensions[i] = Extension { oid: parsed_oid, critical, value: ext_value };
            offset = new_offset;
            count += 1;
        }
    }

    (extensions, count)
}

fn decode_tlv_with_offset(bytes: [u8; 512], offset: u32) -> (TLV, u32, u32) {
    let tag = bytes[offset];
    let length_byte = bytes[offset + 1];

    let mut length: u32 = 0;
    let mut len_size: u32 = 1;
    let mut val_offset: u32 = 0;

    if length_byte < 128 {
        length = length_byte as u32;
        val_offset = offset + 2;
    } else {
        let num_bytes = length_byte - 128;
        len_size = 1 + num_bytes as u32;

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
    (TLV { tag, length, value }, offset + total_len, val_offset)
}

fn parse_subject_public_key_info(tlv: TLV) -> SubjectPublicKeyInfo {
    let (algo_tlv, algo_end_offset, _) = decode_tlv_with_offset(tlv.value, 0);
    let (bitstring_tlv, _, bit_val_start) = decode_tlv_with_offset(tlv.value, algo_end_offset);

    let algorithm = parse_algorithm_identifier(algo_tlv);

    let bit_result = parse_bit_string(
        tlv.value,
        bit_val_start,
        bit_val_start + bitstring_tlv.length,
        512,
    );

    SubjectPublicKeyInfo { algorithm, public_key: bit_result.bits }
}

unconstrained fn parse_name(tlv: TLV) -> Name {
    let mut rdns: [RelativeDistinguishedName; 16] = [
        RelativeDistinguishedName {
            set: [AttributeTypeAndValue { oid: [0; 64], value: [0; 64] }; 8],
            count: 0,
        }; 16
    ];
    let mut outer_offset: u32 = 0;
    let mut name_count: u8 = 0;

    for i in 0..16 {
        if outer_offset >= tlv.length {
            break;
        }

        // Decode one RDN (SET)
        let (rdn_tlv, next_outer_offset) = decode_tlv(tlv.value, outer_offset);
        outer_offset = next_outer_offset;

        let mut rdn = RelativeDistinguishedName {
            set: [AttributeTypeAndValue { oid: [0; 64], value: [0; 64] }; 8],
            count: 0,
        };

        let mut inner_offset: u32 = 0;
        for j in 0..8 {
            if inner_offset >= rdn_tlv.length {
                break;
            }

            // Decode one AttributeTypeAndValue (SEQUENCE inside SET)
            let (attr_tlv, next_inner_offset) = decode_tlv(rdn_tlv.value, inner_offset);
            rdn.set[j] = parse_attribute_type_and_value(attr_tlv);
            rdn.count += 1;
            inner_offset = next_inner_offset;
        }

        rdns[i] = rdn;
        name_count += 1;
    }

    Name { rdns, count: name_count }
}



fn parse_certificate(data: [u8; 512]) -> Certificate {
    let (cert_tlv, _) = decode_tlv(data, 0);
    let mut offset: u32 = 0;
    // 1. tbsCertificate (SEQUENCE)
    let (tbs_tlv, off1) = decode_tlv(cert_tlv.value, offset);
    offset = off1;

    // 2. signatureAlgorithm (AlgorithmIdentifier)
    let (sig_algo_tlv, off2) = decode_tlv(cert_tlv.value, offset);
    offset = off2;

    // 3. signatureValue (BIT STRING)
    let (sig_val_tlv, _, sig_val_start) = decode_tlv_with_offset(cert_tlv.value, offset);

    // 4. Parse tbsCertificate fields
    let mut inner_offset: u32 = 0;

    let (version_tlv, off_v) = decode_tlv(tbs_tlv.value, inner_offset);
    let version: u8 = if version_tlv.tag == 0xA0 {
        let (ver_int_tlv, _) = decode_tlv(version_tlv.value, 0);
        ver_int_tlv.value[ver_int_tlv.length - 1] // last byte
    } else {
        1 // default to v1
    };
    inner_offset = if version_tlv.tag == 0xA0 { off_v } else { 0 };

    // b. serialNumber
    let (serial_tlv, off_sn) = decode_tlv(tbs_tlv.value, inner_offset);
    let mut serial: [u8; 20] = [0; 20];
    for i in 0..20 {
        if i < serial_tlv.length {
            serial[i] = serial_tlv.value[i];
        }
    }
    inner_offset = off_sn;

    // c. signatureAlgorithm
    let (sig_algo1_tlv, off_sa1) = decode_tlv(tbs_tlv.value, inner_offset);
    let sig_algo1 = parse_algorithm_identifier(sig_algo1_tlv);
    inner_offset = off_sa1;

    // d. issuer
    let (issuer_tlv, off_issuer) = decode_tlv(tbs_tlv.value, inner_offset);
    let issuer = unsafe{ parse_name(issuer_tlv) }; // implement below
    inner_offset = off_issuer;

    // e. validity
    let (validity_tlv, off_validity) = decode_tlv(tbs_tlv.value, inner_offset);
    let validity = parse_validity(validity_tlv);
    inner_offset = off_validity;

    // f. subject
    let (subject_tlv, off_subject) = decode_tlv(tbs_tlv.value, inner_offset);
    let subject = unsafe { parse_name(subject_tlv) };
    inner_offset = off_subject;

    // g. subjectPublicKeyInfo
    let (spki_tlv, off_spki) = decode_tlv(tbs_tlv.value, inner_offset);
    let spki = parse_subject_public_key_info(spki_tlv);
    inner_offset = off_spki;

    let (ext_tlv, _) = decode_tlv(tbs_tlv.value, inner_offset);
    let (exts, ext_count): ([Extension; 10], u8) = if ext_tlv.tag == 0xA3 {
        let (seq_tlv, _) = decode_tlv(ext_tlv.value, 0);
        parse_extensions(seq_tlv)
    } else {
        ([Extension { oid: [0; 64], critical: false, value: [0; 256] }; 10], 0)
    };

    // i. signatureAlgorithm2
    let sig_algo2 = parse_algorithm_identifier(sig_algo_tlv);

    // j. signature
    let bit_result = parse_bit_string(
        cert_tlv.value,
        sig_val_start,
        sig_val_start + sig_val_tlv.length,
        256 * 8,
    );

    let mut signature: [u8; 256] = [0; 256];
    for i in 0..256 {
        let byte_index: u32 = i;
        if byte_index < (bit_result.size / 8) {
            let mut b: u8 = 0;
            for j in 0..8 {
                if (byte_index * 8 + j) < bit_result.size {
                    b = b | ((bit_result.bits[(byte_index * 8 + j)] as u8) << (7 - j) as u8);
                }
            }
            signature[i] = b;
        }
    }

    Certificate {
        version,
        serial_number: [0; 20],
        signature_algorithm: sig_algo1,
        issuer,
        validity,
        subject,
        public_key_info: spki,
        extensions: exts,
        ext_count,
        signature_algorithm2: sig_algo2,
        signature,
    }
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

//? ------------------ Bit String Parsing Tests with direct bytes ---------------------

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


//? ------------------ Octet String Parsing Tests with TLV ---------------------

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

//? ------------------ OID Parsing Tests ---------------------

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


//? ------------------ Attribute Type and Value Parsing Tests ---------------------
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



//? ------------------ Algorithm Identifier Parsing Tests ---------------------

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


//? ------------------ Validity Parsing Tests ---------------------

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


//? ------------------ Extensions Parsing Tests ---------------------

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



//? ------------------ Certificate Parsing Tests ---------------------

#[test]
fn test_parse_certificate() {
    let mut cert_bytes: [u8; 512] = [0 as u8; 512];
    let data: [u8; 377] = [
        0x30, 0x82, 0x01, 0x75, 0x30, 0x82, 0x01, 0x1f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x69, 0x2a, 0x11, 0x7e, 0x24, 0xfb, 0x5c, 0x8e, 0xc3, 0xac, 0x37, 0xc5, 0x32, 0xcc, 0x2d,
        0x44, 0x0a, 0x82, 0x9a, 0x25, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x36,
        0x32, 0x30, 0x31, 0x30, 0x31, 0x38, 0x35, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x36,
        0x32, 0x31, 0x31, 0x30, 0x31, 0x38, 0x35, 0x39, 0x5a, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x5c, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b,
        0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0xbd, 0x4d, 0xdd, 0x55, 0xc8, 0x86, 0x5b, 0xc9, 0x47,
        0x9c, 0x14, 0xde, 0x0e, 0xa8, 0x3b, 0x4d, 0x29, 0x9b, 0xc3, 0x1d, 0x10, 0x03, 0xa1, 0xfb,
        0xe1, 0x50, 0x2e, 0x23, 0xfb, 0xb1, 0x49, 0xe1, 0x7d, 0x6c, 0xb7, 0x17, 0xdd, 0xcc, 0x6c,
        0x83, 0x75, 0xbe, 0xf4, 0x1f, 0x32, 0x9c, 0x9d, 0x46, 0xe0, 0x49, 0xf0, 0xfa, 0xcb, 0x92,
        0x2d, 0xd8, 0xaf, 0x3b, 0x1e, 0x8c, 0x35, 0x40, 0x34, 0x03, 0x02, 0x03, 0x01, 0x00, 0x01,
        0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
        0x49, 0x15, 0x15, 0xac, 0xcf, 0xa7, 0x8b, 0x2e, 0x3e, 0x9c, 0xb9, 0xfa, 0x66, 0x34, 0xc2,
        0x3f, 0x06, 0x93, 0xd6, 0x79, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
        0x16, 0x80, 0x14, 0x49, 0x15, 0x15, 0xac, 0xcf, 0xa7, 0x8b, 0x2e, 0x3e, 0x9c, 0xb9, 0xfa,
        0x66, 0x34, 0xc2, 0x3f, 0x06, 0x93, 0xd6, 0x79, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
        0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x41, 0x00, 0x75, 0xef,
        0x3b, 0xe6, 0x3f, 0x2b, 0x7e, 0xac, 0x98, 0x67, 0x53, 0xcd, 0x9e, 0x0d, 0x3f, 0x60, 0x50,
        0x00, 0x11, 0x03, 0x6f, 0xa0, 0x09, 0x98, 0x3a, 0x28, 0xff, 0x7e, 0xf1, 0x2a, 0x91, 0x2d,
        0xc9, 0x69, 0xb7, 0xbc, 0xdf, 0xa3, 0x25, 0x63, 0x5a, 0x13, 0x58, 0xc2, 0xbd, 0x99, 0xb4,
        0xcc, 0x82, 0x39, 0x06, 0x96, 0xfd, 0x2b, 0x23, 0x5a, 0x2b, 0xfc, 0x31, 0x82, 0x16, 0x5f,
        0xc7, 0x5a,
    ];

    for i in 0..data.len() {
        cert_bytes[i] = data[i];
    }

    let cert = parse_certificate(cert_bytes);
    assert(cert.version == 2);

    let expected_oid: [u32; 9] = [1, 2, 840, 113549, 1, 1, 11, 0, 0];
    for i in 0..9 {
        assert(cert.signature_algorithm.oid[i] == expected_oid[i]);
    }

    // 1.2.840.113549.1.1.11
    assert(cert.issuer.rdns[0].set[0].oid[0] == 2);
    assert(cert.issuer.rdns[0].set[0].oid[1] == 5);
    assert(cert.issuer.rdns[0].set[0].oid[2] == 4);
    assert(cert.issuer.rdns[0].set[0].oid[3] == 3); // commonName
    // RDN's first AttributeTypeAndValue value field for issuer
    assert(cert.issuer.rdns[0].set[0].value[0] == 0x54); // 'T'
    assert(cert.issuer.rdns[0].set[0].value[1] == 0x65); // 'e'
    assert(cert.issuer.rdns[0].set[0].value[2] == 0x73); // 's'
    assert(cert.issuer.rdns[0].set[0].value[3] == 0x74); // 't'
    assert(cert.subject.rdns[0].set[0].oid[0] == 2);
    assert(cert.subject.rdns[0].set[0].oid[1] == 5);
    assert(cert.subject.rdns[0].set[0].oid[2] == 4);
    assert(cert.subject.rdns[0].set[0].oid[3] == 3); // commonName
    // RDN's first AttributeTypeAndValue value field for subject
    assert(cert.subject.rdns[0].set[0].value[0] == 0x54); // 'T'
    assert(cert.subject.rdns[0].set[0].value[1] == 0x65); // 'e'
    assert(cert.subject.rdns[0].set[0].value[2] == 0x73); // 's'
    assert(cert.subject.rdns[0].set[0].value[3] == 0x74); // 't'

    assert(
        cert.validity.not_before
            == [
                0x32, 0x35, 0x30, 0x36, 0x32, 0x30, 0x31, 0x30, 0x31, 0x38, 0x35, 0x39, 0x5A, 0x00,
                0x00, 0x00,
            ],
    );
    assert(
        cert.validity.not_after
            == [
                0x32, 0x35, 0x30, 0x36, 0x32, 0x31, 0x31, 0x30, 0x31, 0x38, 0x35, 0x39, 0x5A, 0x00,
                0x00, 0x00,
            ],
    );

    assert(cert.public_key_info.algorithm.oid[0] == 1);
    assert(cert.public_key_info.algorithm.oid[1] == 2);
    assert(cert.public_key_info.algorithm.oid[2] == 840);
    assert(cert.public_key_info.algorithm.oid[3] == 113549);
    assert(cert.public_key_info.algorithm.oid[4] == 1);
    assert(cert.public_key_info.algorithm.oid[5] == 1);
    assert(cert.public_key_info.algorithm.oid[6] == 1); // rsaEncryption
    // SubjectKeyIdentifier extension (OID: 2.5.29.14)
    let expected_oid: [u32; 4] = [2, 5, 29, 14];
    let expected_value: [u8; 20] = [
        0x49, 0x15, 0x15, 0xAC, 0xCF, 0xA7, 0x8B, 0x2E, 0x3E, 0x9C, 0xB9, 0xFA, 0x66, 0x34, 0xC2,
        0x3F, 0x06, 0x93, 0xD6, 0x79,
    ];

    let mut found = false;

    for i in 0..10 {
        let ext_in_bounds = i < cert.ext_count;
        let ext = cert.extensions[i];

        let is_oid_match = (ext.oid[0] == expected_oid[0])
            & (ext.oid[1] == expected_oid[1])
            & (ext.oid[2] == expected_oid[2])
            & (ext.oid[3] == expected_oid[3]);

        // Only run the assertions if:
        // - the current index is within ext_count
        // - the OID matches
        let should_check = ext_in_bounds & is_oid_match;

        if should_check {
            let val = ext.value;
            let offset = 2;
            for j in 0..20 {
                assert(val[offset + j] == expected_value[j]); // skip the 2-byte OCTET STRING header
            }

            found = true;
        }
    }

    assert(found);

    //  AuthorityKeyIdentifier extension (OID: 2.5.29.35)
    let mut found_aki = false;
    let expected_aki_oid: [u32; 4] = [2, 5, 29, 35];
    let expected_aki_value: [u8; 20] = [
        0x49, 0x15, 0x15, 0xAC, 0xCF, 0xA7, 0x8B, 0x2E, 0x3E, 0x9C, 0xB9, 0xFA, 0x66, 0x34, 0xC2,
        0x3F, 0x06, 0x93, 0xD6, 0x79,
    ];

    for i in 0..10 {
        let ext_in_bounds = i < cert.ext_count;
        let ext = cert.extensions[i];

        let is_oid_match = (ext.oid[0] == expected_aki_oid[0])
            & (ext.oid[1] == expected_aki_oid[1])
            & (ext.oid[2] == expected_aki_oid[2])
            & (ext.oid[3] == expected_aki_oid[3]);

        // Only run the assertions if:
        // - the current index is within ext_count
        // - the OID matches
        let should_check = ext_in_bounds & is_oid_match;

        if should_check {
            let val = ext.value;

            for j in 0..20 {
                assert(val[4 + j] == expected_aki_value[j]); // skip the 4-byte OCTET STRING header
            }

            found_aki = true;
        }
    }

    assert(found_aki);

    // BasicConstraints extension (OID: 2.5.29.19)
    let mut found_bc = false;
    let bc_oid: [u32; 4] = [2, 5, 29, 19];

    for i in 0..10 {
        let in_bounds = i < cert.ext_count;
        let ext = cert.extensions[i];

        let is_oid_match = (ext.oid[0] == bc_oid[0])
            & (ext.oid[1] == bc_oid[1])
            & (ext.oid[2] == bc_oid[2])
            & (ext.oid[3] == bc_oid[3]);

        // Only check if in bounds
        let should_check = in_bounds & is_oid_match;

        if should_check {
            found_bc = true;
        }
    }

    assert(found_bc);

    // --- Validate signature_algorithm2 ---
    // OID: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    let expected_oid2: [u32; 9] = [1, 2, 840, 113549, 1, 1, 11, 0, 0];

    for i in 0..9 {
        assert(cert.signature_algorithm2.oid[i] == expected_oid2[i]);
    }

    // --- Validate actual signature ---
    // Signature BIT STRING (64 bytes extracted from the certificate):
    // 75 EF 3B E6 3F 2B 7E AC 98 67 53 CD 9E 0D 3F 60
    // 50 00 11 03 6F A0 09 98 3A 28 FF 7E F1 2A 91 2D
    // C9 69 B7 BC DF A3 25 63 5A 13 58 C2 BD 99 B4 CC
    // 82 39 06 96 FD 2B 23 5A 2B FC 31 82 16 5F C7 5A

    let expected_signature: [u8; 64] = [
        0x75, 0xef, 0x3b, 0xe6, 0x3f, 0x2b, 0x7e, 0xac, 0x98, 0x67, 0x53, 0xcd, 0x9e, 0x0d, 0x3f,
        0x60, 0x50, 0x00, 0x11, 0x03, 0x6f, 0xa0, 0x09, 0x98, 0x3a, 0x28, 0xff, 0x7e, 0xf1, 0x2a,
        0x91, 0x2d, 0xc9, 0x69, 0xb7, 0xbc, 0xdf, 0xa3, 0x25, 0x63, 0x5a, 0x13, 0x58, 0xc2, 0xbd,
        0x99, 0xb4, 0xcc, 0x82, 0x39, 0x06, 0x96, 0xfd, 0x2b, 0x23, 0x5a, 0x2b, 0xfc, 0x31, 0x82,
        0x16, 0x5f, 0xc7, 0x5a,
    ];

    for i in 0..64 {
        assert(cert.signature[i] == expected_signature[i]);
    }
}

