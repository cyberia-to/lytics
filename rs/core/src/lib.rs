// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! lytics wasm tracker core — the same crypto spine the agent uses, in the
//! browser. keygen, per-domain derivation, signing, PoW; the attention
//! sensor and transport live in loader.js, which drives this module.
//!
//! the loader owns the DOM, IndexedDB and network; this core is pure
//! compute over strings and bytes so it stays testable off-browser.

use lytics_event::{
    canonical_json, event_hash, sign_body, solve, Actor, AgentDecl, Attention, Event, EventBody,
    Kind, Navigation, Pow, Seed,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// a per-domain tracker bound to one neuron. constructed from stored
/// entropy (hex, persisted by the loader) plus the site domain.
#[wasm_bindgen]
pub struct Tracker {
    seed: Seed,
    domain: String,
    hrp: String,
    bech32: String,
    pubkey_b64: String,
}

/// generate a fresh identity — returns 32 bytes of entropy as hex for the
/// loader to store. no wordlist is touched: the human-readable 24-word
/// backup is derived lazily by the export module only when the visitor asks.
/// the secret never leaves the browser.
#[wasm_bindgen]
pub fn generate_entropy() -> String {
    hex::encode(Seed::generate().entropy())
}

#[wasm_bindgen]
impl Tracker {
    /// bind stored entropy (32-byte hex) to a domain.
    #[wasm_bindgen(constructor)]
    pub fn new(entropy_hex: &str, domain: &str, hrp: &str) -> Result<Tracker, String> {
        let bytes = hex::decode(entropy_hex).map_err(|e| e.to_string())?;
        let entropy: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "entropy must be 32 bytes")?;
        let seed = Seed::from_entropy(entropy);
        let neuron = seed.neuron(domain, hrp).map_err(|e| e.to_string())?;
        Ok(Tracker {
            bech32: neuron.bech32.clone(),
            pubkey_b64: base64_std(&neuron.pubkey),
            seed,
            domain: domain.to_string(),
            hrp: hrp.to_string(),
        })
    }

    /// the neuron this site observes.
    #[wasm_bindgen(getter)]
    pub fn neuron(&self) -> String {
        self.bech32.clone()
    }

    /// build a signed, pow-carrying event, ready to POST. `spec_json` is the
    /// loader's event description; `target` is the server's current target.
    #[wasm_bindgen]
    pub fn build_event(&self, spec_json: &str, target: u64) -> Result<String, String> {
        let spec: EventSpec = serde_json::from_str(spec_json).map_err(|e| e.to_string())?;
        let neuron = self.seed.neuron(&self.domain, &self.hrp).map_err(|e| e.to_string())?;
        let body = spec.into_body(&self.bech32, &self.domain)?;
        let bytes = canonical_json(&body).map_err(|e| e.to_string())?;
        let hash = event_hash(&bytes);
        let nonce = solve(&hash, target);
        let (pubkey, signature) = sign_body(neuron.signing_key(), &bytes, &self.bech32);
        debug_assert_eq!(pubkey, self.pubkey_b64);
        let event = Event { body, pow: Pow { nonce, difficulty: target }, pubkey, signature };
        serde_json::to_string(&event).map_err(|e| e.to_string())
    }
}

/// the loader's view of an event before signing.
#[derive(serde::Deserialize)]
struct EventSpec {
    kind: String,
    #[serde(default)]
    pathname: String,
    #[serde(default)]
    navigation: Option<String>,
    #[serde(default)]
    referrer: Option<String>,
    #[serde(default)]
    attention_ms: Option<u64>,
    #[serde(default)]
    scroll_depth: Option<u8>,
    #[serde(default)]
    agent: Option<AgentSpec>,
    #[serde(default)]
    timestamp: u64,
}

#[derive(serde::Deserialize)]
struct AgentSpec {
    name: String,
    operator: String,
}

impl EventSpec {
    fn into_body(self, neuron: &str, domain: &str) -> Result<EventBody, String> {
        let kind = match self.kind.as_str() {
            "pageview" => Kind::Pageview,
            "attention" => Kind::Attention,
            other => Kind::Custom(other.to_string()),
        };
        let navigation = match self.navigation.as_deref() {
            Some("external") => Some(Navigation::External),
            Some("direct") => Some(Navigation::Direct),
            Some("internal") => Some(Navigation::Internal),
            _ => None,
        };
        let attention = self.attention_ms.map(|ms| Attention {
            ms,
            scroll_depth: self.scroll_depth.unwrap_or(0),
        });
        let agent = self.agent.map(|a| AgentDecl { name: a.name, operator: a.operator });
        Ok(EventBody {
            neuron: neuron.to_string(),
            actor: if agent.is_some() { Actor::Agent } else { Actor::Human },
            agent,
            kind,
            navigation,
            hostname: domain.to_string(),
            pathname: self.pathname,
            referrer: self.referrer,
            utm: None,
            attention,
            props: None,
            revenue: None,
            timestamp: self.timestamp,
        })
    }
}

fn base64_std(bytes: &[u8]) -> String {
    lytics_event::b64_encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &str = "0000000000000000000000000000000000000000000000000000000000000007";

    #[test]
    fn builds_a_verifiable_event() {
        let t = Tracker::new(ENTROPY, "cyber.page", "lytics").unwrap();
        let spec = r#"{"kind":"pageview","pathname":"/","navigation":"external","timestamp":1}"#;
        let json = t.build_event(spec, lytics_event::target_from_difficulty(8)).unwrap();
        let event: Event = serde_json::from_str(&json).unwrap();
        let bytes = event.body_bytes().unwrap();
        // signature verifies and the neuron field matches the derived key
        lytics_event::sig_verify(&bytes, &event.body.neuron, &event.pubkey, &event.signature, "lytics").unwrap();
        assert_eq!(event.body.neuron, t.neuron());
    }

    #[test]
    fn generate_is_importable() {
        let e = generate_entropy();
        assert_eq!(e.len(), 64); // 32 bytes hex
        // deriving twice from the same entropy agrees
        let a = Tracker::new(&e, "x.com", "lytics").unwrap();
        let b = Tracker::new(&e, "x.com", "lytics").unwrap();
        assert_eq!(a.neuron(), b.neuron());
    }
}
