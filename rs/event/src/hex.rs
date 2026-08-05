// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! lowercase hex — hand-written so the tracker wasm skips the `hex` crate's
//! generic decode-iterator machinery. parity with the crate is pinned by
//! tests behind the `json` feature (native builds).

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xf) as usize] as char);
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// decode; accepts upper or lower case, requires even length.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::*;

    #[test]
    fn encode_parity_with_the_crate() {
        let cases: Vec<Vec<u8>> = vec![vec![], vec![0], vec![255], (0u8..=255).collect()];
        for c in cases {
            assert_eq!(encode(&c), ::hex::encode(&c), "case {c:?}");
        }
    }

    #[test]
    fn decode_roundtrip_and_case_insensitive() {
        let data: Vec<u8> = (0u8..=255).collect();
        let enc = encode(&data);
        assert_eq!(decode(&enc).unwrap(), data);
        assert_eq!(decode(&enc.to_uppercase()).unwrap(), data);
        assert_eq!(::hex::decode(&enc).unwrap(), data);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode("abc").is_none()); // odd length
        assert!(decode("zz").is_none()); // non-hex digit
    }
}
