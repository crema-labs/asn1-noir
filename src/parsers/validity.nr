use crate::parsers::{
    algorithm::parse_algorithm_identifier,
    bitstring::parse_bit_string,
    tlv::{decode_tlv, decode_tlv_with_offset},
};

use crate::structs::{SubjectPublicKeyInfo, TLV, Validity};

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
