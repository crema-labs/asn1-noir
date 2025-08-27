use crate::parsers::{
    algorithm::parse_algorithm_identifier,
    bitstring::parse_bit_string,
    extension::parse_extensions,
    name::parse_name,
    oid::parse_oid,
    tlv::{decode_tlv, decode_tlv_with_offset},
    validity::{parse_subject_public_key_info, parse_validity},
};

use crate::structs::{BitStringResult, Certificate, Extension, Name, SubjectPublicKeyInfo, TLV};

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
    let issuer = unsafe { parse_name(issuer_tlv) }; // implement below
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
    let bit_result: BitStringResult = parse_bit_string(
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
