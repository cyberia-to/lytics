// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! canonical JSON — sorted keys, no whitespace, integers only.
//!
//! `encode_body` is a hand-written encoder for `EventBody` that produces
//! byte-for-byte the same output serde_json would for the same value, so the
//! signing path never links serde_json (the biggest slice of the tracker
//! wasm). the `json` feature keeps a generic serde_json canonicalizer for
//! tests (byte-parity oracle) and any native caller that wants it.

use crate::event::{Attention, EventBody, Prop, Revenue, Utm};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CanonicalError {
    #[error("floats are forbidden in canonical encoding: {0}")]
    Float(String),
    #[error("json: {0}")]
    Json(String),
}

/// the canonical bytes of an event body — sorted keys, no whitespace,
/// integers only, serde_json-identical string escaping.
pub fn encode_body(body: &EventBody) -> Vec<u8> {
    let mut o = ObjectWriter::new();
    o.str("actor", match body.actor {
        crate::event::Actor::Human => "human",
        crate::event::Actor::Agent => "agent",
    });
    if let Some(a) = &body.agent {
        o.raw("agent", &{
            let mut w = ObjectWriter::new();
            w.str("name", &a.name);
            w.str("operator", &a.operator);
            w.finish()
        });
    }
    if let Some(a) = &body.attention {
        o.raw("attention", &encode_attention(a));
    }
    o.str("hostname", &body.hostname);
    o.str("kind", &kind_str(&body.kind));
    if let Some(n) = &body.navigation {
        o.str("navigation", match n {
            crate::event::Navigation::External => "external",
            crate::event::Navigation::Direct => "direct",
            crate::event::Navigation::Internal => "internal",
        });
    }
    o.str("neuron", &body.neuron);
    o.str("pathname", &body.pathname);
    if let Some(props) = &body.props {
        o.raw("props", &encode_props(props));
    }
    if let Some(r) = &body.referrer {
        o.str("referrer", r);
    }
    if let Some(r) = &body.revenue {
        o.raw("revenue", &encode_revenue(r));
    }
    o.int("timestamp", body.timestamp as i64);
    if let Some(u) = &body.utm {
        o.raw("utm", &encode_utm(u));
    }
    o.finish().into_bytes()
}

fn kind_str(kind: &crate::event::Kind) -> String {
    use crate::event::Kind;
    match kind {
        Kind::Pageview => "pageview".to_string(),
        Kind::Attention => "attention".to_string(),
        Kind::Custom(s) => s.clone(),
    }
}

fn encode_attention(a: &Attention) -> String {
    let mut w = ObjectWriter::new();
    w.int("ms", a.ms as i64);
    w.int("scroll_depth", a.scroll_depth as i64);
    w.finish()
}

fn encode_revenue(r: &Revenue) -> String {
    let mut w = ObjectWriter::new();
    w.int("amount", r.amount);
    w.str("currency", &r.currency);
    w.finish()
}

fn encode_utm(u: &Utm) -> String {
    // serde sorts by key: campaign, content, medium, source, term
    let mut w = ObjectWriter::new();
    if let Some(x) = &u.campaign { w.str("campaign", x); }
    if let Some(x) = &u.content { w.str("content", x); }
    if let Some(x) = &u.medium { w.str("medium", x); }
    if let Some(x) = &u.source { w.str("source", x); }
    if let Some(x) = &u.term { w.str("term", x); }
    w.finish()
}

fn encode_props(props: &std::collections::BTreeMap<String, Prop>) -> String {
    // BTreeMap already iterates in sorted key order
    let mut w = ObjectWriter::new();
    for (k, v) in props {
        match v {
            Prop::Str(s) => w.str(k, s),
            Prop::Int(i) => w.int(k, *i),
            Prop::Bool(b) => w.raw(k, if *b { "true" } else { "false" }),
        }
    }
    w.finish()
}

/// builds `{"k":v,...}`; keys are appended in the order given, which callers
/// keep sorted to match serde_json's BTreeMap output.
struct ObjectWriter {
    buf: String,
    first: bool,
}

impl ObjectWriter {
    fn new() -> Self {
        Self { buf: String::from("{"), first: true }
    }
    fn key(&mut self, k: &str) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
        escape_into(&mut self.buf, k);
        self.buf.push(':');
    }
    fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        escape_into(&mut self.buf, v);
    }
    fn int(&mut self, k: &str, v: i64) {
        self.key(k);
        self.buf.push_str(&v.to_string());
    }
    /// value already encoded as a JSON fragment (object / literal)
    fn raw(&mut self, k: &str, v: &str) {
        self.key(k);
        self.buf.push_str(v);
    }
    fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// JSON string escaping matching serde_json exactly: quote `"` and `\`, the
/// named short escapes, `\u00XX` for other control bytes, everything else
/// (including non-ASCII and `/`) verbatim.
pub(crate) fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// generic serde_json canonicalizer — parity oracle for tests, and a
/// convenience for native callers. behind `json` so the wasm core omits it.
#[cfg(feature = "json")]
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Json(e.to_string()))?;
    reject_floats(&v, "$")?;
    Ok(serde_json::to_string(&v)
        .map_err(|e| CanonicalError::Json(e.to_string()))?
        .into_bytes())
}

#[cfg(feature = "json")]
fn reject_floats(v: &serde_json::Value, path: &str) -> Result<(), CanonicalError> {
    use serde_json::Value;
    match v {
        Value::Number(n) if n.is_f64() => Err(CanonicalError::Float(path.to_string())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                reject_floats(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, item) in map {
                reject_floats(item, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::*;
    use crate::event::{Actor, AgentDecl, Kind, Navigation};
    use std::collections::BTreeMap;

    fn base() -> EventBody {
        EventBody {
            neuron: "lytics1abc".into(),
            actor: Actor::Human,
            agent: None,
            kind: Kind::Pageview,
            navigation: Some(Navigation::External),
            hostname: "cyber.page".into(),
            pathname: "/".into(),
            referrer: None,
            utm: None,
            attention: None,
            props: None,
            revenue: None,
            timestamp: 42,
        }
    }

    /// the encoder must match serde_json byte-for-byte — this is the contract
    /// that keeps signatures verifiable across the wasm/server boundary.
    fn assert_parity(b: &EventBody) {
        assert_eq!(encode_body(b), canonical_json(b).unwrap(), "mismatch for {b:?}");
    }

    #[test]
    fn parity_minimal() {
        assert_parity(&base());
    }

    #[test]
    fn parity_full() {
        let mut props = BTreeMap::new();
        props.insert("plan".to_string(), Prop::Str("pro".into()));
        props.insert("seats".to_string(), Prop::Int(5));
        props.insert("trial".to_string(), Prop::Bool(true));
        let b = EventBody {
            agent: Some(AgentDecl { name: "claude".into(), operator: "anthropic".into() }),
            kind: Kind::Custom("signup".into()),
            navigation: Some(Navigation::Internal),
            referrer: Some("https://x.com/a?b=1".into()),
            utm: Some(Utm {
                source: Some("nl".into()),
                medium: Some("email".into()),
                campaign: None,
                term: None,
                content: Some("hero".into()),
            }),
            attention: Some(Attention { ms: 30000, scroll_depth: 60 }),
            props: Some(props),
            revenue: Some(Revenue { amount: 1999, currency: "USD".into() }),
            actor: Actor::Agent,
            ..base()
        };
        assert_parity(&b);
    }

    #[test]
    fn parity_escaping() {
        let b = EventBody {
            pathname: "/a\"b\\c\n\t/d".into(),
            referrer: Some("π/über\u{01}".into()),
            ..base()
        };
        assert_parity(&b);
    }

    #[test]
    fn parity_kind_variants() {
        for k in [Kind::Pageview, Kind::Attention, Kind::Custom("x".into())] {
            assert_parity(&EventBody { kind: k, ..base() });
        }
    }
}
