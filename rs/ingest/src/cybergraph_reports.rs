// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! the `/cybergraph` dashboard's report layer — the semantic layer bbg
//! itself does not carry: per-neuron signal chains (step/prev/hash,
//! equivocation-checked) and the actual cyberlinks each signal bundled
//! (from/to/token/amount/valence), read straight from
//! `Cybergraph.chains: BTreeMap<NeuronId, SignalChain>`.
//!
//! this is Rust, not inf, on purpose: a signal chain is not a `bbg`
//! dimension — it is cybergraph's own per-node bookkeeping for ordering and
//! equivocation detection (`foculus::chain::SignalChain`), never committed
//! to `BbgState` itself. there is nothing for `inf` to query it *through* —
//! building a shadow `LocalSource` from it here would be exactly the
//! pattern this session spent an afternoon removing from the event-report
//! layer. reading a Rust struct's own fields to render it is not that
//! pattern; recomputing a business answer with a hand-rolled loop over data
//! `inf` could already answer is.
//!
//! also renders the `network` label every signal carries
//! (`cybergraph::private_network`) — honestly: today it is vestigial.
//! `BbgState::insert` does not partition by it (confirmed directly against
//! the evaluator's source, not assumed), so every distinct label in this
//! breakdown lands in the same shared particles/axons/neurons state. this
//! view exists to make that visible, not to imply isolation that is not
//! there yet.

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Json};
use axum::http::StatusCode;
use cybergraph::Cybergraph;
use serde_json::json;
use std::collections::BTreeMap;

use crate::Shared;

pub async fn dash() -> Html<&'static str> {
    Html(include_str!("../static/cybergraph_dash.html"))
}

/// the `/cybergraph` dashboard's data — the semantic layer bbg itself does
/// not carry: per-neuron signal chains and the cyberlinks each one bundled.
pub async fn get_report(
    State(state): State<Shared>,
    Path(name): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let app = state.lock().expect("lock");
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20usize);
    let out = match name.as_str() {
        "overview" => overview(&app.cell),
        "chains" => chains(&app.cell, limit),
        "recent_signals" => recent_signals(&app.cell, limit),
        "networks" => networks(&app.cell, limit),
        _ => return (StatusCode::NOT_FOUND, "unknown report").into_response(),
    };
    Json(out).into_response()
}

/// neurons with a chain, total signals across all chains, and how many
/// distinct network labels have been declared (see module doc: distinct
/// labels sharing one physical state today, not a partition).
pub fn overview(cell: &Cybergraph) -> serde_json::Value {
    let neurons_with_chains = cell.chains.len();
    let total_signals: usize = cell.chains.values().map(|c| c.entries.len()).sum();
    let networks: std::collections::BTreeSet<[u8; 32]> = cell
        .chains
        .values()
        .flat_map(|c| c.entries.values().map(|s| s.network))
        .collect();
    json!({
        "neurons_with_chains": neurons_with_chains,
        "total_signals": total_signals,
        "distinct_networks": networks.len(),
    })
}

/// one row per neuron with a chain: its length and the tip (latest step,
/// height, hash) — sorted by chain length, the most active visitors first.
pub fn chains(cell: &Cybergraph, limit: usize) -> serde_json::Value {
    let mut rows: Vec<(String, usize, u64, u64, String)> = cell
        .chains
        .iter()
        .filter_map(|(neuron, chain)| {
            let (&step, tip) = chain.entries.iter().next_back()?;
            Some((hex::encode(neuron), chain.entries.len(), step, tip.height, hex::encode(tip.hash())))
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows
        .into_iter()
        .map(|(neuron, length, tip_step, tip_height, tip_hash)| json!({
            "neuron": neuron, "length": length, "tip_step": tip_step,
            "tip_height": tip_height, "tip_hash": tip_hash,
        }))
        .collect::<Vec<_>>())
}

/// the most recent signals across every chain, links unrolled — the actual
/// cyberlinks (from/to/token/amount/valence) each signal bundled, not just
/// bbg's post-aggregation view of them.
pub fn recent_signals(cell: &Cybergraph, limit: usize) -> serde_json::Value {
    let mut rows: Vec<serde_json::Value> = cell
        .chains
        .iter()
        .flat_map(|(neuron, chain)| {
            chain.entries.values().map(move |s| {
                let links: Vec<_> = s
                    .links
                    .iter()
                    .map(|l| {
                        json!({
                            "from": hex::encode(l.from),
                            "to": hex::encode(l.to),
                            "token": hex::encode(l.token),
                            "amount": l.amount,
                            "valence": l.valence,
                        })
                    })
                    .collect();
                json!({
                    "neuron": hex::encode(neuron),
                    "step": s.step,
                    "height": s.height,
                    "network": hex::encode(s.network),
                    "prev": hex::encode(s.prev),
                    "hash": hex::encode(s.hash()),
                    "link_count": s.links.len(),
                    "links": links,
                })
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b["height"].as_u64().cmp(&a["height"].as_u64()).then(b["step"].as_u64().cmp(&a["step"].as_u64()))
    });
    rows.truncate(limit);
    json!(rows)
}

/// signals grouped by declared network label — see module doc: many
/// distinct labels, one shared physical state, shown honestly.
pub fn networks(cell: &Cybergraph, limit: usize) -> serde_json::Value {
    let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for chain in cell.chains.values() {
        for s in chain.entries.values() {
            *counts.entry(hex::encode(s.network)).or_default() += 1;
        }
    }
    let mut rows: Vec<(String, u64)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows.into_iter().map(|(network, signals)| json!({"network": network, "signals": signals})).collect::<Vec<_>>())
}
