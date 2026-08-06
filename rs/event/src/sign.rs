// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! ADR-036 signing — the mudra bridge signature shape.
//!
//! the signed document is the Cosmos offline StdSignDoc wrapping the
//! canonical body bytes as `sign/MsgSignData`. the doc shape, and the
//! sign/verify over it, are `mudra::claim::sign_arbitrary`/`verify_arbitrary`
//! now — this module is the lytics-specific wire format (base64 in/out,
//! `SignError`) around that shared primitive.

use k256::ecdsa::SigningKey;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("base64: {0}")]
    Base64(String),
    #[error("pubkey: {0}")]
    Pubkey(String),
    #[error("signature invalid")]
    Invalid,
    #[error("signer mismatch: neuron field differs from pubkey")]
    SignerMismatch,
}

/// standard base64 — shared so the wasm core encodes pubkeys identically.
pub fn b64_encode(bytes: &[u8]) -> String {
    crate::b64::encode(bytes)
}

/// sign canonical body bytes; returns (base64 pubkey, base64 signature).
pub fn sign_body(
    key: &SigningKey,
    body_bytes: &[u8],
    signer_bech32: &str,
) -> (String, String) {
    let sig = mudra::claim::sign_arbitrary(key, signer_bech32, body_bytes);
    let pubkey = key.verifying_key().to_encoded_point(true);
    (crate::b64::encode(pubkey.as_bytes()), crate::b64::encode(&sig))
}

/// verify a wire event's signature: pubkey must hash to the neuron field,
/// and the signature must cover the ADR-036 doc of the body bytes.
pub fn verify(
    body_bytes: &[u8],
    neuron_bech32: &str,
    pubkey_b64: &str,
    signature_b64: &str,
    hrp: &str,
) -> Result<(), SignError> {
    let pubkey_bytes =
        crate::b64::decode(pubkey_b64).ok_or_else(|| SignError::Base64("pubkey".into()))?;
    let pubkey: [u8; 33] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignError::Pubkey("expected 33 bytes".into()))?;
    if mudra::cosmos::address(&pubkey, hrp).map_err(|e| SignError::Pubkey(e.to_string()))?
        != neuron_bech32
    {
        return Err(SignError::SignerMismatch);
    }
    let sig_bytes =
        crate::b64::decode(signature_b64).ok_or_else(|| SignError::Base64("signature".into()))?;
    let signature: [u8; 64] =
        sig_bytes.as_slice().try_into().map_err(|_| SignError::Invalid)?;
    if mudra::claim::verify_arbitrary(&pubkey, neuron_bech32, body_bytes, &signature) {
        Ok(())
    } else {
        Err(SignError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seed;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn sign_verify_roundtrip() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let n = seed.neuron("example.com", "lytics").unwrap();
        let body = br#"{"hello":"world"}"#;
        let (pubkey, sig) = sign_body(n.signing_key(), body, &n.bech32);
        verify(body, &n.bech32, &pubkey, &sig, "lytics").unwrap();
    }

    #[test]
    fn tampered_body_fails() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let n = seed.neuron("example.com", "lytics").unwrap();
        let (pubkey, sig) = sign_body(n.signing_key(), b"real", &n.bech32);
        assert!(verify(b"fake", &n.bech32, &pubkey, &sig, "lytics").is_err());
    }

    #[test]
    fn wrong_neuron_field_fails() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let n = seed.neuron("example.com", "lytics").unwrap();
        let other = seed.neuron("other.org", "lytics").unwrap();
        let (pubkey, sig) = sign_body(n.signing_key(), b"data", &n.bech32);
        assert!(matches!(
            verify(b"data", &other.bech32, &pubkey, &sig, "lytics"),
            Err(SignError::SignerMismatch)
        ));
    }
}
