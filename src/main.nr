pub mod parser;
pub fn main(cert_bytes: [u8; 512], expected_subject_cn: [u8; 4]) {
    let cert = unsafe { parser::parse_certificate(cert_bytes) };

    // Extract subject CN: usually in subject.rdns[0].set[0].value
    let actual_cn = cert.subject.rdns[0].set[0].value;

    // Compare with expected
    for i in 0..4 {
        assert(actual_cn[i] == expected_subject_cn[i]);
    }
}