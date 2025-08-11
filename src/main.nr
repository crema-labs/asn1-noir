mod parsers;
mod structs;
mod tests;
use parsers::{bitstring::parse_bit_string, certificate};

pub fn main(cert_bytes: [u8; 512], expected_subject_cn: [u8; 4]) {
    let cert = unsafe { parser::parse_certificate(cert_bytes) };

    let actual_cn = cert.subject.rdns[0].set[0].value;

    for i in 0..4 {
        assert(actual_cn[i] == expected_subject_cn[i]);
    }
}