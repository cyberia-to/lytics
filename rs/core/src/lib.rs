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
    encode_body, event_hash, sign_body, solve, Actor, AgentDecl, Attention, EventBody, Kind,
    Navigation, Seed,
};
use wasm_bindgen::prelude::*;

// single-threaded wasm → the tiny free-list allocator replaces dlmalloc.
// the tracker allocates small short-lived strings; fragmentation is a
// non-issue at this scale.
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: lol_alloc::AssumeSingleThreaded<lol_alloc::FreeListAllocator> =
    unsafe { lol_alloc::AssumeSingleThreaded::new(lol_alloc::FreeListAllocator::new()) };

// no panic hook: the production build panics with `immediate-abort` (a bare
// trap, no formatting machinery) — a panic in the tracker is a bug surfaced
// as RuntimeError in the console, and the native test suite carries the
// readable messages.

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
    lytics_event::hex::encode(&Seed::generate().entropy())
}

#[wasm_bindgen]
impl Tracker {
    /// bind stored entropy (32-byte hex) to a domain.
    #[wasm_bindgen(constructor)]
    pub fn new(entropy_hex: &str, domain: &str, hrp: &str) -> Result<Tracker, String> {
        let bytes = lytics_event::hex::decode(entropy_hex).ok_or("entropy hex")?;
        let entropy: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "entropy must be 32 bytes")?;
        let seed = Seed::from_entropy(entropy);
        let neuron = seed.neuron(domain, hrp).map_err(|_| "derivation")?;
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

    /// build a signed, pow-carrying event as a ready-to-POST JSON string.
    /// fields come as explicit args (no JSON parse in the wasm); the wire
    /// JSON is hand-assembled from the canonical body (no serde_json). the
    /// loader owns the field values, so it could equally assemble the POST
    /// itself — returning the full JSON keeps u64 nonce/difficulty exact.
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn build_event(
        &self,
        kind: &str,
        pathname: &str,
        navigation: Option<String>,
        referrer: Option<String>,
        attention_ms: Option<f64>,
        scroll_depth: Option<u32>,
        agent_name: Option<String>,
        agent_operator: Option<String>,
        timestamp: f64,
        target: u64,
    ) -> Result<String, String> {
        let neuron = self.seed.neuron(&self.domain, &self.hrp).map_err(|_| "derivation")?;
        let kind = match kind {
            "pageview" => Kind::Pageview,
            "attention" => Kind::Attention,
            other => Kind::Custom(other.to_string()),
        };
        let navigation = match navigation.as_deref() {
            Some("external") => Some(Navigation::External),
            Some("direct") => Some(Navigation::Direct),
            Some("internal") => Some(Navigation::Internal),
            _ => None,
        };
        let attention = attention_ms.map(|ms| Attention {
            ms: ms as u64,
            scroll_depth: scroll_depth.unwrap_or(0) as u8,
        });
        let agent = match (agent_name, agent_operator) {
            (Some(name), Some(operator)) => Some(AgentDecl { name, operator }),
            _ => None,
        };
        let body = EventBody {
            neuron: self.bech32.clone(),
            actor: if agent.is_some() { Actor::Agent } else { Actor::Human },
            agent,
            kind,
            navigation,
            hostname: self.domain.clone(),
            pathname: pathname.to_string(),
            referrer,
            utm: None,
            attention,
            props: None,
            revenue: None,
            timestamp: timestamp as u64,
        };

        let bytes = encode_body(&body);
        let hash = event_hash(&bytes);
        let nonce = solve(&hash, target);
        let (pubkey, signature) = sign_body(neuron.signing_key(), &bytes, &self.bech32);
        debug_assert_eq!(pubkey, self.pubkey_b64);

        // wire event = canonical body object + pow + pubkey + signature.
        // pubkey/signature are base64 (JSON-safe alphabet), nonce/difficulty
        // written as integer literals so u64 stays exact across the boundary.
        let mut wire = String::from_utf8(bytes).map_err(|_| "utf8")?;
        wire.pop(); // drop the closing brace of the body object
        wire.push_str(r#","pow":{"difficulty":"#);
        lytics_event::push_u64_dec(&mut wire, target);
        wire.push_str(r#","nonce":"#);
        lytics_event::push_u64_dec(&mut wire, nonce);
        wire.push_str(r#"},"pubkey":""#);
        wire.push_str(&pubkey);
        wire.push_str(r#"","signature":""#);
        wire.push_str(&signature);
        wire.push_str("\"}");
        Ok(wire)
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
        let json = t
            .build_event(
                "pageview", "/", Some("external".into()), None, None, None, None, None, 1.0,
                lytics_event::target_from_difficulty(8),
            )
            .unwrap();
        // the wasm ships without serde_json; the test parses via a dev-dep to
        // confirm the hand-built wire JSON is well-formed and verifiable
        let event: lytics_event::Event = serde_json::from_str(&json).unwrap();
        let bytes = event.body_bytes();
        // signature verifies and the neuron field matches the derived key
        lytics_event::sig_verify(&bytes, &event.body.neuron, &event.pubkey, &event.signature, "lytics").unwrap();
        assert_eq!(event.body.neuron, t.neuron());
        assert_eq!(event.body.kind, lytics_event::Kind::Pageview);
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
