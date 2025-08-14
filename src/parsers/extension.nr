use crate::parsers::{oid::parse_oid, tlv::decode_tlv};
use crate::structs::{Extension, TLV};

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
