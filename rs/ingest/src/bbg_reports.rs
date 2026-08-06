// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! the `/bbg` dashboard's report layer — real inf datalog over the actually
//! committed `bbg::state::BbgState`, via `inf_source::BbgSource`, not a
//! shadow copy. this is the proof that casting into cybergraph produces
//! something a query can read back: every number here comes from the same
//! state `Chains::cast` (`graph.rs`) writes into on every accepted event.
//!
//! covers every dimension `BbgSource` exposes (`inf/rs/source/src/bbg.rs`):
//! `particles`, `axons_out`/`axons_in`, `neurons`, `signals`, `balances`,
//! `locations`, `coins`, `cards`, `files`, `time`. nothing is hidden because
//! it happens to be empty — an empty dimension is itself the honest answer
//! to "is cybergraph using this yet" (see `neurons`: lytics casts cyberlinks
//! but never mints a `NeuronRecord`, so this reports 0 rows, correctly,
//! not a bug in the dashboard).
//!
//! `commitments`/`nullifiers`/`intents`/`axon_edges` are not `BbgSource`
//! relations (privacy dims / not yet in the query surface) — their counts
//! come from direct field access on `BbgState`, not a query, since inf has
//! no door onto them yet.

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Json};
use axum::http::StatusCode;
use inf_eval::{eval, Ctx, EvalError, Output};
use inf_parse::parse;
use inf_plan::plan;
use inf_source::BbgSource;
use inf_value::Value;
use serde_json::json;
use std::collections::BTreeMap;

use crate::Shared;

pub async fn dash() -> Html<&'static str> {
    Html(include_str!("../static/bbg_dash.html"))
}

/// the `/bbg` dashboard's data — real inf datalog over the actually
/// committed `bbg::state::BbgState`, not a shadow copy.
pub async fn get_report(
    State(state): State<Shared>,
    Path(name): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let app = state.lock().expect("lock");
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20usize);
    let bbg_state = &app.cell.bbg.state;
    let out = match name.as_str() {
        "overview" => overview(bbg_state),
        "particles" => particles(bbg_state, limit),
        "axons" => axons(bbg_state, limit),
        "neurons" => neurons(bbg_state, limit),
        "signals" => signals(bbg_state, limit),
        "balances" => balances(bbg_state, limit),
        "other_dims" => other_dims(bbg_state),
        _ => return (StatusCode::NOT_FOUND, "unknown report").into_response(),
    };
    Json(out).into_response()
}

fn q(src: &BbgSource, script: &str) -> Result<Output, String> {
    let prog = parse(script).map_err(|e| format!("parse: {} @ {}:{}", e.msg, e.line, e.col))?;
    let ir = plan(&prog).map_err(|e| format!("plan: {}", e.msg))?;
    eval(&ir, src, &Ctx::default()).map_err(|e: EvalError| format!("eval: {}", e.msg))
}

fn as_word(v: &Value) -> u64 {
    match v {
        Value::Word(w) => *w,
        Value::Int(i) => (*i).max(0) as u64,
        _ => 0,
    }
}

fn as_hash_hex(v: &Value) -> String {
    match v {
        Value::Hash(h) => hex::encode(h),
        other => format!("{other:?}"),
    }
}

fn scalar(src: &BbgSource, script: &str) -> u64 {
    match q(src, script) {
        Ok(out) if !out.rows.is_empty() => as_word(&out.rows[0][0]),
        _ => 0,
    }
}

/// dimension counts + the current committed snapshot — the front page.
pub fn overview(state: &bbg::state::BbgState) -> serde_json::Value {
    let src = BbgSource::new(state);
    let count = |rel: &str, col: &str| scalar(&src, &format!("?[count({col})] := {rel}{{{col}}}"));
    let particles = count("particles", "id");
    let axons = count("axons", "from");
    let neurons = count("neurons", "id");
    let signals = count("signals", "step");
    let balances = count("balances", "key");
    let locations = count("locations", "id");
    let coins = count("coins", "denom");
    let cards = count("cards", "card");
    let files = count("files", "particle");
    let time_rows = q(&src, "?[height, root] := time{height, root}").map(|o| o.rows).unwrap_or_default();
    let (height, root) = time_rows
        .iter()
        .max_by_key(|r| as_word(&r[0]))
        .map(|r| (as_word(&r[0]), as_hash_hex(&r[1])))
        .unwrap_or((0, String::new()));
    json!({
        "particles": particles, "axons": axons, "neurons": neurons,
        "signals": signals, "balances": balances, "locations": locations,
        "coins": coins, "cards": cards, "files": files,
        "height": height, "root": root,
        // not BbgSource relations — direct field counts (see module doc).
        "commitments": state.commitments.len(),
        "nullifiers": state.nullifiers.len(),
        "intents": state.intents.len(),
    })
}

/// top particles by energy (total staked conviction received) and by
/// weight (total conviction on the axon addressed to them).
pub fn particles(state: &bbg::state::BbgState, limit: usize) -> serde_json::Value {
    let src = BbgSource::new(state);
    let mut rows: Vec<(String, u64, u64, u64, u64, u64, u64)> = q(
        &src,
        "?[id, energy, pi_star, weight, s_yes, s_no, meta_score] := particles{id, energy, pi_star, weight, s_yes, s_no, meta_score}",
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| {
                (
                    as_hash_hex(&r[0]),
                    as_word(&r[1]),
                    as_word(&r[2]),
                    as_word(&r[3]),
                    as_word(&r[4]),
                    as_word(&r[5]),
                    as_word(&r[6]),
                )
            })
            .collect()
    })
    .unwrap_or_default();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(b.3.cmp(&a.3)).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows
        .into_iter()
        .map(|(id, energy, pi_star, weight, s_yes, s_no, meta_score)| json!({
            "particle": id, "energy": energy, "pi_star": pi_star, "weight": weight,
            "s_yes": s_yes, "s_no": s_no, "meta_score": meta_score,
        }))
        .collect::<Vec<_>>())
}

/// top particles by out-degree and in-degree — the most-linked-from and
/// most-linked-to particles in the committed axon graph.
pub fn axons(state: &bbg::state::BbgState, limit: usize) -> serde_json::Value {
    let src = BbgSource::new(state);
    let top = |rel: &str, key_col: &str, other_col: &str| -> Vec<serde_json::Value> {
        let script = format!("?[{key_col}, count({other_col})] := {rel}{{{key_col}, {other_col}}}");
        let mut rows: Vec<(String, u64)> = q(&src, &script)
            .map(|out| out.rows.iter().map(|r| (as_hash_hex(&r[0]), as_word(&r[1]))).collect())
            .unwrap_or_default();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows.into_iter().map(|(p, n)| json!({"particle": p, "degree": n})).collect()
    };
    json!({
        "out_degree": top("axons_out", "from", "to"),
        "in_degree": top("axons_in", "to", "from"),
    })
}

/// every minted `NeuronRecord` — focus/karma/stake. empty today (see module
/// doc): lytics casts cyberlinks but never mints a neuron record, so this
/// is the honest live confirmation of that gap, not a placeholder.
pub fn neurons(state: &bbg::state::BbgState, limit: usize) -> serde_json::Value {
    let src = BbgSource::new(state);
    let mut rows: Vec<(String, u64, u64, u64)> = q(
        &src,
        "?[id, focus, karma, stake] := neurons{id, focus, karma, stake}",
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| (as_hash_hex(&r[0]), as_word(&r[1]), as_word(&r[2]), as_word(&r[3])))
            .collect()
    })
    .unwrap_or_default();
    rows.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows
        .into_iter()
        .map(|(id, focus, karma, stake)| json!({"neuron": id, "focus": focus, "karma": karma, "stake": stake}))
        .collect::<Vec<_>>())
}

/// most recent signals (highest block_height first) — the raw append log
/// bbg actually committed, one row per signal header.
pub fn signals(state: &bbg::state::BbgState, limit: usize) -> serde_json::Value {
    let src = BbgSource::new(state);
    let mut rows: Vec<(u64, String, u64, u64, String)> = q(
        &src,
        "?[step, neuron, link_count, block_height, proof_hash] := signals{step, neuron, link_count, block_height, proof_hash}",
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| {
                (
                    as_word(&r[0]),
                    as_hash_hex(&r[1]),
                    as_word(&r[2]),
                    as_word(&r[3]),
                    as_hash_hex(&r[4]),
                )
            })
            .collect()
    })
    .unwrap_or_default();
    rows.sort_by(|a, b| b.3.cmp(&a.3).then(b.0.cmp(&a.0)));
    rows.truncate(limit);
    json!(rows
        .into_iter()
        .map(|(step, neuron, link_count, block_height, proof_hash)| json!({
            "step": step, "neuron": neuron, "link_count": link_count,
            "block_height": block_height, "proof_hash": proof_hash,
        }))
        .collect::<Vec<_>>())
}

/// top nonzero balances — `H(owner ‖ token)` keyed, so a key does not
/// decode back to a readable owner/token pair without the preimage.
pub fn balances(state: &bbg::state::BbgState, limit: usize) -> serde_json::Value {
    let src = BbgSource::new(state);
    let mut rows: Vec<(String, u64)> = q(&src, "?[key, amount] := balances{key, amount}")
        .map(|out| out.rows.iter().map(|r| (as_hash_hex(&r[0]), as_word(&r[1]))).collect())
        .unwrap_or_default();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows.into_iter().map(|(key, amount)| json!({"key": key, "amount": amount})).collect::<Vec<_>>())
}

/// the remaining committed dimensions lytics does not populate — reported
/// as counts, not hidden. an empty list here is the honest answer, not a
/// missing feature: nothing in lytics's cast path ever writes a location,
/// a coin, a card, or a file record.
pub fn other_dims(state: &bbg::state::BbgState) -> serde_json::Value {
    let src = BbgSource::new(state);
    let rows = |rel: &str, cols: &[&str]| -> Vec<serde_json::Value> {
        let binds = cols.join(", ");
        q(&src, &format!("?[{binds}] := {rel}{{{binds}}}"))
            .map(|out| {
                out.rows
                    .iter()
                    .map(|r| {
                        json!(r.iter().map(as_hash_hex_or_word).collect::<Vec<_>>())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    json!({
        "locations": rows("locations", &["id", "lat", "lon"]),
        "coins": rows("coins", &["denom", "total_supply"]),
        "cards": rows("cards", &["card", "owner", "particle"]),
        "files": rows("files", &["particle", "available", "chunk_count"]),
    })
}

fn as_hash_hex_or_word(v: &Value) -> serde_json::Value {
    match v {
        Value::Hash(h) => json!(hex::encode(h)),
        Value::Word(w) => json!(w),
        Value::Int(i) => json!(i),
        Value::Bool(b) => json!(b),
        other => json!(format!("{other:?}")),
    }
}
