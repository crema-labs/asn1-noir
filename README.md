# ASN.1 Noir Parser

A fully functional ASN.1 parser written in **[Noir](https://noir-lang.org/)** for use in zero-knowledge circuits. This parser decodes DER-encoded binary structures such as X.509 certificates and extracts components like OIDs, UTF8 strings, UTC times, bit strings, octet strings, and signatures.

> Built for ZK use-cases such as proving certificate validity without revealing the entire document.

## Features

- Built entirely in Noir  
- Works with ASN.1 DER structures  
- Type-Length-Value (TLV) parser circuit  
- Extracts:  
  - **UTF8String**  
  - **UTC Time**  
  - **Object Identifiers (OIDs)**  
  - **Bit Strings**  
  - **Octet Strings**  
  - **Signature & Integer Values**
  many more...
## Test Coverage

Run tests using:

```bash
nargo test
```

### Current Test Coverage  
The implementation currently passes **53 test cases**, including:

```

[asn] Running 53 test functions
[asn] Testing test_main ... ok
[asn] Testing parser::test_decode_tlv_long_form ... ok
[asn] Testing parser::test_decode_tlv_nested_tlv_inside_sequence ... ok
[asn] Testing parser::test_decode_tlv_short_form ... ok
[asn] Testing parser::test_algorithm_identifier_oid_only ... ok
[asn] Testing parser::test_algorithm_identifier_truncated_oid ... ok
[asn] Testing parser::test_algorithm_identifier_sha256_with_rsa ... ok
[asn] Testing parser::test_all_ones_unused_zero ... ok
[asn] Testing parser::test_algorithm_identifier_sha1_with_rsa ... ok
[asn] Testing parser::test_empty_bit_string ... ok
[asn] Testing parser::test_all_ones_unused_zero_with_tlv ... ok
[asn] Testing parser::test_empty_bit_string_with_tlv ... ok
[asn] Testing parser::test_multiple_bytes_with_unused ... ok
[asn] Testing parser::test_no_unused_bits_mixed_bits ... ok
[asn] Testing parser::test_no_unused_bits_full_byte ... ok
[asn] Testing parser::test_parse_algorithm_identifier_sha256_rsa ... ok
[asn] Testing parser::test_multiple_bytes_with_unused_with_tlv ... ok
[asn] Testing parser::test_no_unused_bits_full_byte_with_tlv ... ok
[asn] Testing parser::test_parse_attribute_common_name ... ok
[asn] Testing parser::test_parse_integer ... ok
[asn] Testing parser::test_parse_integer_empty ... ok
[asn] Testing parser::test_parse_common_name ... ok
[asn] Testing parser::test_parse_integer_max_8_bytes ... ok
[asn] Testing parser::test_no_unused_bits_mixed_bits_with_tlv ... ok
[asn] Testing parser::test_parse_integer_neg1 ... ok
[asn] Testing parser::test_parse_integer_negative_8_bytes ... ok
[asn] Testing parser::test_parse_integer_negative_multi_byte ... ok
[asn] Testing parser::test_parse_integer_positive_multi_byte ... ok
[asn] Testing parser::test_parse_integer_positive_single_byte ... ok
[asn] Testing parser::test_parse_integer_zero ... ok
[asn] Testing parser::test_parse_octet_string_all_ff ... ok
[asn] Testing parser::test_parse_octet_string_all_zero ... ok
[asn] Testing parser::test_parse_octet_string_empty ... ok
[asn] Testing parser::test_parse_octet_string_mixed_bytes ... ok
[asn] Testing parser::test_parse_country_name ... ok
[asn] Testing parser::test_parse_octet_string_single_byte ... ok
[asn] Testing parser::test_parse_jurisdiction_country ... ok
[asn] Testing parser::test_parse_oid_ec_public_key ... ok
[asn] Testing parser::test_parse_oid_common_name ... ok
[asn] Testing parser::test_parse_oid_enterprise ... ok
[asn] Testing parser::test_parse_validity_diff_times ... ok
[asn] Testing parser::test_parse_oid_minimal ... ok
[asn] Testing parser::test_parse_oid_rsa_encryption ... ok
[asn] Testing parser::test_parse_validity_future_date ... ok
[asn] Testing parser::test_parse_organization_name ... ok
[asn] Testing parser::test_parse_validity_min_date ... ok
[asn] Testing parser::test_parse_validity_utctime ... ok
[asn] Testing parser::test_with_unused_bits_at_end ... ok
[asn] Testing parser::test_with_unused_bits_at_end_with_tlv ... ok
```

## Use Cases

These circuits enable ZK applications like:

- Proving a certificate contains a specific issuer  
- Verifying a signature algorithm used is a valid OID  
- Showing date ranges (validity period) without exposing exact timestamps  
- Extracting organization or country from certs in zero-knowledge  

## Project Milestones

### Phase 1 - ASN.1 Parser in Noir ✅

- Decode DER structure in-circuit  
- Extract issuer, subject, public key, signature algorithm, and validity

### Phase 2 - ZK Proof System _(In Progress)_

- Generate ZK proof over fields like issuer or validity  
- Verify document is signed by a known organization without revealing entire certificate

## Example ASN.1 Structures Parsed

- `INTEGER`: 0x02, followed by 1-byte or multi-byte integers  
- `OBJECT_IDENTIFIER`: 0x06, decoded using base-128 encoding  
- `SEQUENCE`: 0x30, with nested TLV data  
- `BIT_STRING`: 0x03, used for `subjectPublicKey`  
- `OCTET_STRING`: 0x04, used for signature or content hash  
- `UTF8String`: 0x0C, issuer/subject names  
- `UTCTime`: 0x17, validity periods  


## ASN.1 Type-Length-Value (TLV) Encoding:

```jsx
+----------+----------+----------+-- 
| Type (T) | Length (L) | Value (V) |
+----------+----------+----------+-- 
```

ASN.1 encoding follows the Type-Length-Value (TLV) format, where:

1. **Type (T)**: The tag that identifies the data type.
2. **Length (L)**: The length of the value field, encoded in a compact form.
3. **Value (V)**: The actual data value, encoded according to the specific data type and encoding rules.

Every value, an octet is an eight- bit unsigned integer. Bit 8 of the octet is the most significant and bit 1 is the least significant.

### Type - ASN1Tag

Every ASN1 Tag is octet. ASN1 Tag Representation

```mathematica
| 7 6 | 5 | 4 3 2 1 0 |
|-----|---|-----------|
| Class | C | Number |

- Bits 7-6 (Class): Represent the tag class.
- Bit 5 (C): Indicates if the tag is constructed.
- Bits 4-0 (Number): Represent the tag number.
```

## ASN.1 Tag Classes and Numbers

Here is a list of all universal class types which includes all these types.

| Tag Class  | Tag Number | Tag Name |
| --- | --- | --- |
| Universal  | 0x00 | EOC |
| Universal | 0x01 | BOOLEAN |
| Universal | 0x02 | INTEGER |
| Universal | 0x03 | BIT_STRING |
| Universal | 0x04 | OCTET_STRING |
| Universal | 0x05 | NULL |
| Universal | 0x06 | OBJECT_IDENTIFIER |
| Universal | 0x07 | ObjectDescriptor |
| Universal | 0x08 | EXTERNAL |
| Universal | 0x09 | REAL |
| Universal | 0x0A | ENUMERATED |
| Universal | 0x0B | EMBEDDED_PDV |
| Universal | 0x0C | UTF8String |
| Universal | 0x0D | RELATIVE_OID |
| Universal | 0x10 | SEQUENCE |
| Universal | 0x11 | SET |
| Universal | 0x12 | NumericString |
| Universal | 0x13 | PrintableString |
| Universal | 0x14 | TeletexString |
| Universal | 0x15 | VideotexString |
| Universal | 0x16 | IA5String |
| Universal | 0x17 | UTCTime |
| Universal | 0x18 | GeneralizedTime |
| Universal | 0x19 | GraphicString |
| Universal | 0x1A | VisibleString |
| Universal | 0x1B | GeneralString |
| Universal | 0x1C | UniversalString |
| Universal | 0x1E | BMPString |

Since we want to extract ASN1Tag from bytesArray:

- Generally, since it follows T-L-V, the tag will be the first byte of the ASN structure.
- We need to determine other things from class, form, and number.

![                              ASNTag Representation](https://hackmd.io/_uploads/rJG-CL2rA.png)

                              ASNTag Representation

## ASN.1 Length Decoding Algorithm

1. **Read the Length Byte**: 
    1. The second byte in ASN.1 indicates the length.
2. **Check the Most Significant Bit (MSB)**:
    - If the MSB is 0, the byte represents the length directly (short form).
    - If the MSB is 1, the byte indicates the number of subsequent bytes that encode the length (long form).
3. **Short Form Encoding**:
    - If the MSB is 0, return the value of the byte as the length.
4. **Long Form Encoding**:
    - If the MSB is 1, mask out the MSB to get the number of subsequent bytes.
    - Read the subsequent bytes and combine them to get the length.
    

## ASN.1 Example

Extraction of TLV (Type Length, Values)

```jsx
const simpleASN1 = [30 ,82 ,2A ,74, ....more];
```

**1. Decoding the Type**

- The first byte `0x30` represents the Tag value.
- The Tag value `0x30` corresponds to the SEQUENCE type in the universal class. This is a constructed type, meaning it can contain nested TLV triplets.
1. **Decode the Length**
    - The second byte `0x82` has the most significant bit set to 1, indicating a long-form length encoding.
    - The remaining 7 bits `0x02` indicate that the Length value is encoded in the next `2 bytes`.
2. **Decode the Value**
    - The next 2 bytes are `0x2A, 0x74`, which represent the Length value 10,868 (0x2A74 in hexadecimal) when combined.
- Since SEQUENCE indicates how many values it consists of in this constructed type, we can iterate through the next bytes, starting to check the type and extract values from it.

Let's analyze how to parse the next few bytes of the ASN.1 structure following the same approach:

1. Get the first byte and find the tag type.
2. Get the length of the bytes.
3. Get the values.



```jsx
[30,82,2A,74,  06 ,09 ,2A, 86, 48, 86, F7, 0D, 01, 07, 02, ...asn2];
|-parent asn-||-----------child asn1---------------------|--child2-|
```

From the previous example, we know that there are two ASN.1 structures in the stream. We can move the offset by +4 and get ASN.1 and calculate TLV values for it:

```jsx
const asn1 = [06 ,09 ,2A, 86, 48, 86, F7, 0D, 01, 07, 02]
```

- **Determine the Type (T)**:
    - The first byte `06` represents the Type (T) or the tag value.
    - This byte value `0x06` corresponds to the OBJECT_IDENTIFIER data type in the universal class.
- **Determine the Length (L)**:
    - The second byte `09` represents the Length (L) of the Value field.
    - Since the most significant bit (0x80) is not set, this is a short-form length encoding.
    - The value `0x09` (decimal 9) indicates that the length of the Value field is 9 bytes.
- **Determine the Value (V)**:
    - The remaining 9 bytes `2A 86 48 86 F7 0D 01 07 02` represent the Value (V) field for the OBJECT_IDENTIFIER data type.
    - OBJECT_IDENTIFIER values are encoded using a specific set of rules:
        - The value is represented as a sequence of variable-length numbers.
        - The first two numbers are encoded in the first byte, and subsequent numbers are encoded in subsequent bytes.
        - Each number is encoded in base 128, with the most significant bit indicating whether more bytes follow for that number.
    
      


### Example Parsing for X.509 certificate:

```typescript
const input = [
  0x30, 0x82, 0x04, 0x9F,
  0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
  0xA0, 0x82, 0x04, 0x90,
  0x30, 0x82, 0x04, 0x8C,
  0x02, 0x01, 0x01,
  // ... (more bytes would follow in a complete certificate)
];
```

Now, let's walk through how the parsing algorithm would process the first 5 elements of this input:

1. `30 82 04 9F`
   - Tag: `30` (SEQUENCE)
   - Length: `82 04 9F` (long form, 1183 bytes)
   - Algorithm: 
     - Recognizes `30` as SEQUENCE
     - Identifies long form length (0x82)
     - Calculates total length (0x049F = 1183)
     - Pushes `[30, 82, 04, 9F]` to ASN_ARRAY
   - Index moves to: 4

2. `06 09 2A 86 48 86 F7 0D 01 07 02`
   - Tag: `06` (OBJECT IDENTIFIER)
   - Length: `09` (9 bytes)
   - Value: `2A 86 48 86 F7 0D 01 07 02`
   - Algorithm:
     - Identifies `06` as OBJECT IDENTIFIER
     - Reads length `09`
     - Pushes entire line `[06, 09, 2A, 86, 48, 86, F7, 0D, 01, 07, 02]` to ASN_ARRAY
   - Index moves to: 15

3. `A0 82 04 90`
   - Tag: `A0` (CONTEXT SPECIFIC)
   - Length: `82 04 90` (long form, 1168 bytes)
   - Algorithm:
     - Recognizes `A0` as CONTEXT SPECIFIC
     - Identifies long form length (0x82)
     - Calculates total length (0x0490 = 1168)
     - Pushes `[A0, 82, 04, 90]` to ASN_ARRAY
   - Index moves to: 19

4. `30 82 04 8C`
   - Tag: `30` (SEQUENCE)
   - Length: `82 04 8C` (long form, 1164 bytes)
   - Algorithm:
     - Recognizes `30` as SEQUENCE
     - Identifies long form length (0x82)
     - Calculates total length (0x048C = 1164)
     - Pushes `[30, 82, 04, 8C]` to ASN_ARRAY
   - Index moves to: 23

5. `02 01 01`
   - Tag: `02` (INTEGER)
   - Length: `01` (1 byte)
   - Value: `01`
   - Algorithm:
     - Identifies `02` as INTEGER
     - Reads length `01`
     - Pushes entire line `[02, 01, 01]` to ASN_ARRAY
   - Index moves to: 26


we can look at first bytes of each array and determine its tag class and decode according to get value.
## Resources

- ASN.1 TLV Format – [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)  
- OID Reference – [oid-info.com](http://oid-info.com/)  
- ASN.1 Playground – [lapo.it/asn1js](https://lapo.it/asn1js/)  

## Built With

- [Noir](https://noir-lang.org/)  
- [Nargo](https://github.com/noir-lang/noir)  

