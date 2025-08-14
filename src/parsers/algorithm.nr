use crate::parsers::{oid::parse_oid, tlv::decode_tlv};
use crate::structs::{AlgorithmIdentifier, SubjectPublicKeyInfo, TLV};

fn parse_algorithm_identifier(tlv: TLV) -> AlgorithmIdentifier {
    let (oid_tlv, offset) = decode_tlv(tlv.value, 0);
    let (params_tlv, _) = decode_tlv(tlv.value, offset);

    let parsed_oid: [u32; 64] = parse_oid(oid_tlv);

    let mut params_bytes: [u8; 64] = [0; 64];
    params_bytes[0] = params_tlv.tag;
    params_bytes[1] = params_tlv.length as u8;

    AlgorithmIdentifier { oid: parsed_oid, parameters: params_bytes }
}
