use crate::parsers::{oid::parse_oid, tlv::decode_tlv};
use crate::structs::{AttributeTypeAndValue, Name, RelativeDistinguishedName, TLV};

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
