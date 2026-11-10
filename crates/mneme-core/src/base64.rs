//! Strict standard Base64 for the tagged JSON transport.
//!
//! The codec requires padding, rejects embedded whitespace and URL-safe
//! alphabet characters, and rejects non-zero trailing bits, so one byte string
//! has exactly one accepted textual form in transport documents.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard Base64 with padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output
            .push(ALPHABET[(((first & 0b11) << 4) | (second.unwrap_or(0) >> 4)) as usize] as char);
        match second {
            Some(second) => {
                output.push(
                    ALPHABET[(((second & 0b1111) << 2) | (third.unwrap_or(0) >> 6)) as usize]
                        as char,
                );
            }
            None => output.push('='),
        }
        match third {
            Some(third) => output.push(ALPHABET[(third & 0b11_1111) as usize] as char),
            None => output.push('='),
        }
    }
    output
}

/// Decode strict standard Base64 with required padding.
pub fn decode(text: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of four");
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (index, group) in bytes.chunks(4).enumerate() {
        let last = index + 1 == groups;
        let padding = group.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 {
            return Err("base64 padding exceeds two characters");
        }
        if padding > 0 && !last {
            return Err("base64 padding is only permitted at the end");
        }
        let decoded = [
            decode_char(group[0])?,
            decode_char(group[1])?,
            if padding >= 2 {
                0
            } else {
                decode_char(group[2])?
            },
            if padding >= 1 {
                0
            } else {
                decode_char(group[3])?
            },
        ];
        output.push((decoded[0] << 2) | (decoded[1] >> 4));
        if padding < 2 {
            output.push(((decoded[1] & 0b1111) << 4) | (decoded[2] >> 2));
        } else if decoded[1] & 0b1111 != 0 {
            return Err("base64 trailing bits must be zero");
        }
        if padding < 1 {
            output.push(((decoded[2] & 0b11) << 6) | decoded[3]);
        } else if decoded[2] & 0b11 != 0 {
            return Err("base64 trailing bits must be zero");
        }
    }
    Ok(output)
}

fn decode_char(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Err("padding is not valid here"),
        _ => Err("invalid base64 character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_known_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).expect("valid vector"), plain.as_bytes());
        }
    }

    #[test]
    fn rejects_noncanonical_or_malformed_input() {
        for input in [
            "Zg=", "Zg===", "Zg==Zg==", "Z g==", "Zg==\n", "-w==", "Zg?!",
        ] {
            assert!(decode(input).is_err(), "{input} must be rejected");
        }
        // Non-zero trailing bits are not an alternative spelling of the same bytes.
        assert!(decode("Zh==").is_err());
    }
}
