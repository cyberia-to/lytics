// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! ADR-036 signing — the mudra bridge signature shape.
//!
//! the signed document is the Cosmos offline StdSignDoc wrapping the
//! canonical body bytes as `sign/MsgSignData`. digest = sha256(doc),
//! signature = secp256k1 compact (64 B).

use base64::Engine;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::keys::bech32_of_pubkey;

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

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// standard base64 — shared so the wasm core encodes pubkeys identically.
pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// the ADR-036 sign doc for a body, canonical-encoded. hand-written so the
/// signing path never links serde_json; keys are already in sorted order at
/// every level, matching serde_json's canonical output byte-for-byte (a
/// parity test pins this).
fn sign_doc(body_bytes: &[u8], signer_bech32: &str) -> Vec<u8> {
    let mut s = String::from(
        r#"{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"#,
    );
    crate::canonical::escape_into(&mut s, &B64.encode(body_bytes));
    s.push_str(r#","signer":"#);
    crate::canonical::escape_into(&mut s, signer_bech32);
    s.push_str(r#"}}],"sequence":"0"}"#);
    s.into_bytes()
}

/// sign canonical body bytes; returns (base64 pubkey, base64 signature).
pub fn sign_body(
    key: &SigningKey,
    body_bytes: &[u8],
    signer_bech32: &str,
) -> (String, String) {
    let doc = sign_doc(body_bytes, signer_bech32);
    let digest = Sha256::digest(&doc);
    let sig: Signature = key.sign_prehash(&digest).expect("sign");
    let pubkey = key.verifying_key().to_encoded_point(true);
    (B64.encode(pubkey.as_bytes()), B64.encode(sig.to_bytes()))
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
    let pubkey_bytes = B64
        .decode(pubkey_b64)
        .map_err(|e| SignError::Base64(e.to_string()))?;
    let pubkey: [u8; 33] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignError::Pubkey("expected 33 bytes".into()))?;
    if bech32_of_pubkey(&pubkey, hrp) != neuron_bech32 {
        return Err(SignError::SignerMismatch);
    }
    let vk = VerifyingKey::from_sec1_bytes(&pubkey)
        .map_err(|e| SignError::Pubkey(e.to_string()))?;
    let sig_bytes = B64
        .decode(signature_b64)
        .map_err(|e| SignError::Base64(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| SignError::Invalid)?;
    let doc = sign_doc(body_bytes, neuron_bech32);
    let digest = Sha256::digest(&doc);
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(&digest, &sig).map_err(|_| SignError::Invalid)
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
