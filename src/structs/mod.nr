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
