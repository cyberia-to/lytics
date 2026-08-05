// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! lytics event core — the shared crypto spine of tracker, agent and ingest.
//!
//! canonical encoding → hemera event hash → pow → adr-036 signature.
//! spec: lytics/specs/README.md.

pub mod canonical;
pub mod event;
pub mod keys;
pub mod pow;
pub mod sign;

pub use canonical::{encode_body, CanonicalError};
#[cfg(feature = "json")]
pub use canonical::canonical_json;
pub use event::{Actor, AgentDecl, Attention, Event, EventBody, Kind, Navigation, Pow, Prop, Revenue};
pub use keys::{Neuron, Seed};
pub use pow::{solve, verify as pow_verify, target_from_difficulty};
pub use sign::{b64_encode, sign_body, verify as sig_verify, SignError};

/// 32-byte particle hash — the event's identity in the cybergraph.
pub type Particle = [u8; 32];

/// Hemera hash of the canonical body bytes. Doubles as the particle hash
/// and the idempotency key.
pub fn event_hash(body_bytes: &[u8]) -> Particle {
    *hemera::hash(body_bytes).as_bytes()
}
