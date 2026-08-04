// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! the event schema — client body, pow, signature.
//!
//! `EventBody` holds exactly the client-known fields: the signed bytes are
//! canonical(body), the event hash is Hemera over those bytes, pow and
//! signature ride outside the body. server enrichment (source, channel,
//! geo, device) is server-attested and never part of the signature.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    Human,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Pageview,
    Attention,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Navigation {
    External,
    Direct,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDecl {
    pub name: String,
    pub operator: String,
}

/// attention integrated on-device: ms integer, scroll_depth percent 0-100.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Attention {
    pub ms: u64,
    pub scroll_depth: u8,
}

/// amount integer, minor units.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revenue {
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Utm {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// the client-signed body. field order is irrelevant — canonical encoding
/// sorts keys — but names are the wire contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBody {
    /// per-domain visitor neuron, bech32
    pub neuron: String,
    pub actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentDecl>,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub navigation: Option<Navigation>,
    pub hostname: String,
    pub pathname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utm: Option<Utm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attention: Option<Attention>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub props: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revenue: Option<Revenue>,
    /// unix milliseconds
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Pow {
    pub nonce: u64,
    /// the target the client solved — a record, never an acceptance input
    pub difficulty: u64,
}

/// the full wire event: body + pow + pubkey + signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    #[serde(flatten)]
    pub body: EventBody,
    pub pow: Pow,
    /// base64 SEC1-compressed secp256k1 pubkey (33 B) — verification needs
    /// it; the bech32 neuron is its hash and cannot be inverted
    pub pubkey: String,
    /// base64 64-byte compact secp256k1 signature over the adr-036 doc
    pub signature: String,
}

impl Event {
    pub fn body_bytes(&self) -> Result<Vec<u8>, crate::CanonicalError> {
        crate::canonical_json(&self.body)
    }
}
