// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! identity pipeline — 32-byte entropy → BIP32 `m/0'/0'/account'/0/0` → secp256k1.
//!
//! zero-based path: cyber starts its registries at zero. the account level
//! carries the domain (`account' = u31(Hemera(domain))`) because hardening
//! is the unlinkability. spec: lytics/specs/README.md, identity pipeline.
//!
//! the secret is 32 bytes of entropy fed straight to BIP32 — no BIP39
//! PBKDF2 stretch on the signing path, so the 2048-word list never enters
//! the tracker wasm. the mnemonic is a display/backup encoding of that
//! entropy, behind the `mnemonic` feature, loaded lazily only for
//! import/export. spec: identity pipeline.

use bip32::{DerivationPath, XPrv};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("mnemonic: {0}")]
    Mnemonic(String),
    #[error("derivation: {0}")]
    Derivation(String),
    #[error("entropy: {0}")]
    Entropy(String),
}

/// a master seed — the visitor's root identity across all domains: 32 bytes
/// of entropy, fed directly to BIP32.
pub struct Seed {
    entropy: [u8; 32],
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// a per-domain neuron: the derived key and its wire identities.
pub struct Neuron {
    signing: k256::ecdsa::SigningKey,
    /// SEC1-compressed pubkey, 33 bytes
    pub pubkey: [u8; 33],
    /// bech32 wire form
    pub bech32: String,
    /// native id — Hemera(compressed pubkey)
    pub native: [u8; 32],
}

impl std::fmt::Debug for Neuron {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Neuron").field("bech32", &self.bech32).finish()
    }
}

/// `u31(Hemera(domain))` — the hardened account index for a domain.
/// `domain` must already be the registrable domain (eTLD+1).
pub fn domain_account(domain: &str) -> u32 {
    let h = hemera::hash(domain.as_bytes());
    let b = h.as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff
}

impl Seed {
    /// a fresh identity from OS entropy — no wordlist, no PBKDF2.
    pub fn generate() -> Self {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).expect("os entropy");
        Self { entropy }
    }

    /// adopt existing 32-byte entropy (e.g. a decoded backup).
    pub fn from_entropy(entropy: [u8; 32]) -> Self {
        Self { entropy }
    }

    /// the raw entropy — the value a backup encodes.
    pub fn entropy(&self) -> [u8; 32] {
        self.entropy
    }

    /// import a BIP39 mnemonic as entropy. behind `mnemonic` — the wordlist
    /// is only linked where import/export actually happens.
    #[cfg(feature = "mnemonic")]
    pub fn from_mnemonic(phrase: &str) -> Result<Self, KeyError> {
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
            .map_err(|e| KeyError::Mnemonic(e.to_string()))?;
        let (entropy, len) = mnemonic.to_entropy_array();
        if len != 32 {
            return Err(KeyError::Entropy(format!("expected 24 words (32 B), got {len} B")));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&entropy[..32]);
        Ok(Self { entropy: e })
    }

    /// encode the entropy as a 24-word backup phrase. behind `mnemonic`.
    #[cfg(feature = "mnemonic")]
    pub fn to_mnemonic(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.entropy).expect("32 B entropy").to_string()
    }

    /// derive the neuron a given domain observes.
    pub fn neuron(&self, domain: &str, hrp: &str) -> Result<Neuron, KeyError> {
        let account = domain_account(domain);
        let path: DerivationPath = format!("m/0'/0'/{account}'/0/0")
            .parse()
            .map_err(|e: bip32::Error| KeyError::Derivation(e.to_string()))?;
        let xprv = XPrv::derive_from_path(self.entropy, &path)
            .map_err(|e| KeyError::Derivation(e.to_string()))?;
        let signing = k256::ecdsa::SigningKey::from(xprv.private_key().clone());
        Ok(Neuron::from_signing(signing, hrp))
    }
}

impl Neuron {
    fn from_signing(signing: k256::ecdsa::SigningKey, hrp: &str) -> Self {
        let pubkey_point = signing.verifying_key().to_encoded_point(true);
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(pubkey_point.as_bytes());
        let bech = bech32_of_pubkey(&pubkey, hrp);
        let native = *hemera::hash(&pubkey).as_bytes();
        Self { signing, pubkey, bech32: bech, native }
    }

    pub fn signing_key(&self) -> &k256::ecdsa::SigningKey {
        &self.signing
    }
}

/// `bech32(hrp, ripemd160(sha256(pubkey)))` — the wire form.
pub fn bech32_of_pubkey(pubkey: &[u8; 33], hrp: &str) -> String {
    let sha = Sha256::digest(pubkey);
    let account_id = Ripemd160::digest(sha);
    let hrp = bech32::Hrp::parse(hrp).expect("valid hrp");
    bech32::encode::<bech32::Bech32>(hrp, &account_id).expect("bech32 encode")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn same_domain_same_neuron() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let a = seed.neuron("example.com", "lytics").unwrap();
        let b = seed.neuron("example.com", "lytics").unwrap();
        assert_eq!(a.bech32, b.bech32);
        assert_eq!(a.native, b.native);
    }

    #[test]
    fn different_domains_different_neurons() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let a = seed.neuron("example.com", "lytics").unwrap();
        let b = seed.neuron("cyber.page", "lytics").unwrap();
        assert_ne!(a.bech32, b.bech32);
    }

    #[test]
    fn account_index_is_u31() {
        assert!(domain_account("example.com") < (1 << 31));
        assert!(domain_account("cyber.page") < (1 << 31));
    }

    #[test]
    fn generated_entropy_roundtrips_through_mnemonic() {
        let seed = Seed::generate();
        let phrase = seed.to_mnemonic();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let restored = Seed::from_mnemonic(&phrase).unwrap();
        assert_eq!(seed.entropy(), restored.entropy());
        let a = seed.neuron("example.com", "lytics").unwrap();
        let b = restored.neuron("example.com", "lytics").unwrap();
        assert_eq!(a.bech32, b.bech32);
    }

    #[test]
    fn mnemonic_encoding_matches_the_standard() {
        // 32 zero bytes → the canonical all-zeros BIP39 phrase; the browser's
        // words.js must produce the identical string for export/import parity.
        let seed = Seed::from_entropy([0u8; 32]);
        assert_eq!(seed.to_mnemonic(), PHRASE);
    }

    #[test]
    fn entropy_is_the_seed() {
        let e = [7u8; 32];
        let a = Seed::from_entropy(e).neuron("example.com", "lytics").unwrap();
        let b = Seed::from_entropy(e).neuron("example.com", "lytics").unwrap();
        assert_eq!(a.bech32, b.bech32);
    }

    #[test]
    fn bech32_uses_hrp() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let n = seed.neuron("example.com", "lytics").unwrap();
        assert!(n.bech32.starts_with("lytics1"));
    }
}
