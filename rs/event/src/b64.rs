// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! standard base64 (RFC 4648, with padding) — hand-written so the tracker
//! wasm carries ~40 lines instead of the full base64 crate. parity with the
//! crate is pinned by tests behind the `json` feature (native builds).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// encode with standard alphabet and `=` padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

fn value_of(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// decode standard base64; padding required for the final quantum, strict
/// (no whitespace, no url-safe alphabet).
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pads = chunk.iter().filter(|&&c| c == b'=').count();
        if pads > 2 || (!last && pads > 0) {
            return None;
        }
        // padding only at the tail positions
        if pads >= 1 && chunk[3] != b'=' {
            return None;
        }
        if pads == 2 && chunk[2] != b'=' {
            return None;
        }
        let v0 = value_of(chunk[0])?;
        let v1 = value_of(chunk[1])?;
        let v2 = if pads == 2 { 0 } else { value_of(chunk[2])? };
        let v3 = if pads >= 1 { 0 } else { value_of(chunk[3])? };
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push((n >> 16) as u8);
        if pads < 2 {
            out.push((n >> 8) as u8);
        }
        if pads < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::*;
    use base64::Engine;

    const ORACLE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    #[test]
    fn encode_parity_with_the_crate() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![255],
            vec![1, 2],
            vec![1, 2, 3],
            vec![1, 2, 3, 4],
            (0u8..=255).collect(),
            vec![7u8; 33],
            vec![42u8; 64],
        ];
        for c in cases {
            assert_eq!(encode(&c), ORACLE.encode(&c), "case {c:?}");
        }
    }

    #[test]
    fn decode_roundtrip_and_parity() {
        let data: Vec<u8> = (0u8..=255).collect();
        let enc = encode(&data);
        assert_eq!(decode(&enc).unwrap(), data);
        assert_eq!(ORACLE.decode(&enc).unwrap(), data);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode("abc").is_none()); // bad length
        assert!(decode("ab=c").is_none()); // pad in the middle
        assert!(decode("a bc").is_none()); // whitespace
        assert!(decode("ab-_").is_none()); // url-safe alphabet
    }
}
