// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! the report layer answered by real inf datalog, not hand-written loops.
//!
//! bbg's canonical dims carry no lytics event fields (pathname, attention,
//! actor, geo, device) — an event is not a particle, axon, or signal in bbg's
//! schema. so this builds a fresh `inf_source::LocalSource` per report call
//! from the same `&[&Stored]` slice `reports.rs`'s Rust functions take, and
//! answers each report with `parse → plan → eval` — the exact three calls
//! `cybergraph::Cybergraph::query()` already makes against a bbg-backed
//! source, here against a local one built from the payload log.
//!
//! every report is answered by inf now — there is no report left that runs
//! as a hand-written Rust loop over the event stream in the release binary.
//! `reports.rs` still holds a Rust implementation of each one, but every
//! function there is `#[cfg(test)]`: it exists only to be compared against
//! in this file's differential tests, and does not exist in a release build.
//!
//! the harder half of that is passage grouping (`sources`, `channels`,
//! `passages`/`passages_report`, `overview`'s visit-derived fields). a
//! passage is the run of a neuron's events from one arrival to the next —
//! grouping into passages looks like it needs an ordered scan carrying state
//! between consecutive events (inf has no window/`lag` primitive, and
//! `:sort` only orders final output, confirmed directly against the
//! evaluator). but a passage *boundary* is expressible without one: the
//! passage id of an event is just the count of that neuron's arrivals
//! strictly after its first-ever event and at-or-before this event's own
//! timestamp — an inequality self-join + count, the same running-count
//! trick `retention`/`returns` already used for cohort/offset math. see
//! `passage_ids` for the derivation and `/tmp/infcheck3` (scratch, not
//! committed) for where it was verified before being written here. `funnel`
//! turned out to need no new trick at all: "does an increasing-timestamp
//! subsequence exist" is what a chain of ordered existential joins already
//! answers, and that is provably equivalent to the greedy single-pass scan
//! the Rust reference used.
//!
//! relation schema built per call:
//!
//! - `events{neuron, pathname, ts, kind, ms, actor, agent_name, arrival}` —
//!   one row per `Stored` event, always. `kind` is the wire kind string
//!   ("pageview"/"attention"/a custom name); `ms` is the attention
//!   milliseconds (0 for non-attention events); `agent_name` is the
//!   declared name or empty bytes; `arrival` is "1"/"0" — a pageview whose
//!   navigation is external/direct, or that carries utm.
//! - `attrib_ev{neuron, ts, source, channel}` — one row per event, its own
//!   attribution. `sources`/`channels` look this up by a passage's earliest
//!   event, never by the passage's own key (there isn't one — a passage is
//!   `(neuron, passage_id)`, not a row).
//! - `geo_ev{neuron, country}`, `browser_ev{neuron, browser}`,
//!   `os_ev{neuron, os}`, `class_ev{neuron, class}` — one row per event
//!   that actually carries that optional field; events missing it are
//!   skipped when the relation is built (in Rust, not in datalog), so no
//!   query needs a null-check primitive.
//! - `pid{neuron, ts, passage_id}`, `ev2{neuron, ts, kind, pathname, ms}` —
//!   built by `passage_source` for every passage-grouped report: `pid` is
//!   `passage_ids`' output, gap-filled to 0 for events with no qualifying
//!   arrival; `ev2` restates `events` at the arity the `RULE_*` passage
//!   rollup rules need to join back against.

use crate::reports::Stored;
use inf_eval::{Ctx, EvalError, Output, eval};
use inf_parse::parse;
use inf_plan::plan;
use inf_source::LocalSource;
use inf_value::{Tuple, Value};
use lytics_event::Kind;
use serde_json::json;
use std::collections::BTreeMap;

fn kind_str(k: &Kind) -> String {
    match k {
        Kind::Pageview => "pageview".to_string(),
        Kind::Attention => "attention".to_string(),
        Kind::Custom(s) => s.clone(),
    }
}

/// run one query string against a source; panics-as-error on any stage
/// failure — a bad query here is a programming bug in this module, not a
/// runtime condition callers should handle.
fn q(src: &LocalSource, script: &str) -> Result<Output, String> {
    let prog = parse(script).map_err(|e| format!("parse: {} @ {}:{}", e.msg, e.line, e.col))?;
    let ir = plan(&prog).map_err(|e| format!("plan: {}", e.msg))?;
    eval(&ir, src, &Ctx::default()).map_err(|e: EvalError| format!("eval: {}", e.msg))
}

fn as_str(v: &Value) -> String {
    match v {
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        other => format!("{other:?}"),
    }
}
fn as_i64(v: &Value) -> i64 {
    match v {
        Value::Int(i) => *i,
        _ => 0,
    }
}
fn as_u64(v: &Value) -> u64 {
    as_i64(v).max(0) as u64
}

/// datalog string-literal escaping matching `inf-lex`'s reader exactly
/// (`\` starts an escape, any following byte is taken literally except `n`
/// and `t`) — needed wherever a value that did not originate in this
/// module (a pathname from a query param, in `funnel`) is interpolated into
/// a script string, or a crafted `"..).\n...` payload could inject clauses
/// into the query it is meant to be mere data for.
fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// build the base `events` relation from the event slice.
fn events_source(events: &[&Stored]) -> LocalSource {
    let mut s = LocalSource::new();
    let rows: Vec<Tuple> = events
        .iter()
        .map(|e| {
            let ms = e.attention_ms() as i64;
            let agent_name = e.body.agent.as_ref().map(|a| a.name.as_str()).unwrap_or("");
            vec![
                Value::str(&e.body.neuron),
                Value::str(&e.body.pathname),
                Value::int(e.body.timestamp as i64),
                Value::str(&kind_str(&e.body.kind)),
                Value::int(ms),
                Value::str(match e.body.actor {
                    lytics_event::Actor::Human => "human",
                    lytics_event::Actor::Agent => "agent",
                }),
                Value::str(agent_name),
                // arrival: a pageview whose navigation is external/direct, or
                // that carries utm — the boundary a passage opens on. this is
                // a per-event field derivation (same class as `kind`/`actor`
                // above), not aggregation, so precomputing it in Rust from
                // `Stored::is_arrival()` stays honest to "the query is inf's
                // job" — the grouping/counting inf does with this column is
                // the part that used to be a hand-rolled Rust loop.
                Value::str(if e.is_arrival() { "1" } else { "0" }),
            ]
        })
        .collect();
    s.add(
        "events",
        &[
            "neuron",
            "pathname",
            "ts",
            "kind",
            "ms",
            "actor",
            "agent_name",
            "arrival",
        ],
        rows,
    );

    // one row per event (never filtered) carrying its own attribution — the
    // key event of a passage (its earliest event) is looked up against this
    // by (neuron, ts) to source a passage's `sources`/`channels` key. `ts`
    // disambiguates for the same dedup-on-insert reason as the relations
    // below.
    let attrib_rows: Vec<Tuple> = events
        .iter()
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
                Value::str(e.attribution.source.as_deref().unwrap_or("direct")),
                Value::str(&format!("{:?}", e.attribution.channel).to_lowercase()),
            ]
        })
        .collect();
    s.add(
        "attrib_ev",
        &["neuron", "ts", "source", "channel"],
        attrib_rows,
    );

    // every filtered relation below carries `ts` even though most queries
    // never bind it — WITHOUT it, two real events from the same neuron with
    // the same (country|browser|os|class) would produce byte-identical
    // tuples, and `LocalSource::add`'s relation is a `BTreeSet` that
    // deduplicates ON INSERT, before any query runs — silently losing a real
    // event, not just a query-time projection artifact. `ts` makes every row
    // as distinct as the source event actually is, matching how `events`
    // itself (built with full arity) stays safe under narrow queries.
    let geo_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let c = e.geo.as_ref()?.country.as_ref()?;
            Some(vec![
                Value::str(&e.body.neuron),
                Value::str(c),
                Value::int(e.body.timestamp as i64),
            ])
        })
        .collect();
    s.add("geo_ev", &["neuron", "country", "ts"], geo_rows);

    let browser_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let b = e.device.browser.as_ref()?;
            Some(vec![
                Value::str(&e.body.neuron),
                Value::str(b),
                Value::int(e.body.timestamp as i64),
            ])
        })
        .collect();
    s.add("browser_ev", &["neuron", "browser", "ts"], browser_rows);

    let os_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let o = e.device.os.as_ref()?;
            Some(vec![
                Value::str(&e.body.neuron),
                Value::str(o),
                Value::int(e.body.timestamp as i64),
            ])
        })
        .collect();
    s.add("os_ev", &["neuron", "os", "ts"], os_rows);

    let class_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let c = e.device.device.as_ref()?;
            Some(vec![
                Value::str(&e.body.neuron),
                Value::str(c),
                Value::int(e.body.timestamp as i64),
            ])
        })
        .collect();
    s.add("class_ev", &["neuron", "class", "ts"], class_rows);

    s
}

/// per-event passage id, within a neuron. a passage opens on every arrival
/// except the stream's very first event (arrival or not).
///
/// first version of this function: a running-count self-join, `count of
/// arrivals strictly after the neuron's first-ever event and at-or-before
/// this event's own timestamp`. correct, and the natural translation of "no
/// window/lag primitive" into a count — but it materializes the FULL cross product of
/// a neuron's own events against its own arrivals before the `gt`/`le`
/// filters can prune it (`eval_body` computes one atom fully before the
/// next runs; filter pushdown only affects which atom filters early, not
/// whether the preceding join step's output existed in memory first). live
/// production data has one neuron — a crawler that never persists a client
/// key, so every page it ever hits looks like a fresh direct visit — with
/// 3123 events, all 3123 of them arrivals. the self-join for that one
/// neuron alone was ~3123×3123 ≈ 9.75M intermediate bindings: 6.4s and a
/// multi-GB spike per call, OOM-killing production under real traffic.
///
/// replaced with the primitive that actually exists for this: `running_*` +
/// `:order`, added to inf between the two versions of this function. rank
/// each neuron's own arrivals by timestamp in one sorted pass —
/// `?[neuron, ts, running_count(ts)] := arrival_ev{neuron, ts} :order ts` —
/// O(k log k) per neuron instead of O(k²); the identical 3123-arrival
/// neuron ranks in ~4ms, not 6.4s (measured, `/tmp/runcheck`, not
/// committed). every event that is not itself an arrival still needs a
/// passage id: carry the most recent preceding arrival's rank forward,
/// event by event in timestamp order — a single O(n) merge over two
/// already-sorted, already-computed sequences, done in Rust because it is
/// bookkeeping (like the gap-fill-to-0 pattern already used elsewhere in
/// this file), not a second aggregation.
///
/// numbering note: this carry-forward passage id is off by a constant +1
/// from the self-join version, *only* for a neuron whose very first event
/// is itself an arrival (that arrival now ranks 1 instead of being excluded
/// as the non-boundary-triggering first event). passage id is never in a
/// report's output — every consumer here only tests equality between two
/// events' ids, to decide whether they are the same passage — so a uniform
/// shift changes no grouping and no downstream count. the differential
/// tests below assert this: every report using passage grouping still
/// matches the Rust reference's output exactly.
fn passage_ids(events: &[&Stored]) -> BTreeMap<(String, i64), i64> {
    let mut src = LocalSource::new();
    let arr_rows: Vec<Tuple> = events
        .iter()
        .filter(|e| e.is_arrival())
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
            ]
        })
        .collect();
    src.add("arrival_ev", &["neuron", "ts"], arr_rows);

    let ranks: BTreeMap<(String, i64), i64> = match q(
        &src,
        "?[neuron, ts, running_count(ts)] := arrival_ev{neuron, ts} :order ts",
    ) {
        Ok(out) => out
            .rows
            .iter()
            .map(|r| ((as_str(&r[0]), as_i64(&r[1])), as_i64(&r[2])))
            .collect(),
        Err(_) => BTreeMap::new(),
    };

    let mut per_neuron: BTreeMap<&str, std::collections::BTreeSet<i64>> = BTreeMap::new();
    for e in events {
        per_neuron
            .entry(e.body.neuron.as_str())
            .or_default()
            .insert(e.body.timestamp as i64);
    }

    let mut out = BTreeMap::new();
    for (neuron, ts_set) in per_neuron {
        let mut current = 0i64;
        for ts in ts_set {
            if let Some(r) = ranks.get(&(neuron.to_string(), ts)) {
                current = *r;
            }
            out.insert((neuron.to_string(), ts), current);
        }
    }
    out
}

/// build the passage-scoped source for a report call: `pid{neuron, ts,
/// passage_id}` (every event, gap-filled to 0 — see `passage_ids`),
/// `ev2{neuron, ts, kind, pathname, ms}` (every event again, full arity so
/// the join back never loses a row), and `attrib_ev` carried over unchanged.
/// every entry/exit/rollup query below joins against these three, never
/// against raw Rust structures.
fn passage_source(events: &[&Stored]) -> LocalSource {
    let ids = passage_ids(events);

    let mut s = LocalSource::new();
    let mut seen: std::collections::BTreeSet<(String, i64)> = std::collections::BTreeSet::new();
    let mut pid_rows: Vec<Tuple> = Vec::new();
    for e in events {
        let key = (e.body.neuron.clone(), e.body.timestamp as i64);
        if seen.insert(key.clone()) {
            let pid = ids.get(&key).copied().unwrap_or(0);
            pid_rows.push(vec![Value::str(&key.0), Value::int(key.1), Value::int(pid)]);
        }
    }
    s.add("pid", &["neuron", "ts", "passage_id"], pid_rows);

    let ev2_rows: Vec<Tuple> = events
        .iter()
        .map(|e| {
            let ms = e.attention_ms() as i64;
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
                Value::str(&kind_str(&e.body.kind)),
                Value::str(&e.body.pathname),
                Value::int(ms),
            ]
        })
        .collect();
    s.add("ev2", &["neuron", "ts", "kind", "pathname", "ms"], ev2_rows);

    let attrib_rows: Vec<Tuple> = events
        .iter()
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
                Value::str(e.attribution.source.as_deref().unwrap_or("direct")),
                Value::str(&format!("{:?}", e.attribution.channel).to_lowercase()),
            ]
        })
        .collect();
    s.add(
        "attrib_ev",
        &["neuron", "ts", "source", "channel"],
        attrib_rows,
    );

    s
}

/// passage-rollup rules, each usable alone — `q()` parses a fresh script per
/// call, so named rules never carry over between calls (same as
/// `retention`'s two-stage shape), and the evaluator has no dead-rule
/// elimination: every named rule in a script gets fully computed even if
/// the final `?` never reaches it. `PASSAGE_RULES` used to be one 9-rule
/// blob every query below sent regardless of which of these it actually
/// needed — measured at 21s for a single `sources()` call on 1600 events,
/// most of it recomputing rules the query never touched. each query below
/// now composes only the pieces its own final `?` head reaches.
///
/// - `RULE_VPQ`/`RULE_APQ` — views/attention summed per passage.
/// - `RULE_EPATH`/`RULE_XPATH` — the pathname of a passage's earliest/latest
///   pageview (entry/exit).
/// - `RULE_KT` + `RULE_KSRC`/`RULE_KCHAN` — the source/channel of a
///   passage's earliest event (the "key event" — see `visit_breakdown`'s
///   docstring for why that is always the passage's first event, never a
///   later one). `RULE_KT` alone is cheap (no join against `ev2`); callers
///   needing a passage's key source/channel always pair it with one of
///   `RULE_KSRC`/`RULE_KCHAN`.
const RULE_VPQ: &str = "vpq[neuron, passage_id, count(pathname)] := pid{neuron, ts, passage_id}, ev2{neuron, ts, kind: \"pageview\", pathname}\n";
const RULE_APQ: &str = "apq[neuron, passage_id, sum(ms)] := pid{neuron, ts, passage_id}, ev2{neuron, ts, kind: \"attention\", ms}\n";
const RULE_EPATH: &str = "et[neuron, passage_id, min(ts)] := pid{neuron, ts, passage_id}, ev2{neuron, ts, kind: \"pageview\"}\nepath[neuron, passage_id, pathname] := et[neuron, passage_id, entry_ts], ev2{neuron, ts: entry_ts, pathname}\n";
const RULE_XPATH: &str = "xt[neuron, passage_id, max(ts)] := pid{neuron, ts, passage_id}, ev2{neuron, ts, kind: \"pageview\"}\nxpath[neuron, passage_id, pathname] := xt[neuron, passage_id, exit_ts], ev2{neuron, ts: exit_ts, pathname}\n";
const RULE_KT: &str = "kt[neuron, passage_id, min(ts)] := pid{neuron, ts, passage_id}\n";
const RULE_KSRC: &str = "ksrc[neuron, passage_id, source] := kt[neuron, passage_id, key_ts], attrib_ev{neuron, ts: key_ts, source}\n";
const RULE_KCHAN: &str = "kchan[neuron, passage_id, channel] := kt[neuron, passage_id, key_ts], attrib_ev{neuron, ts: key_ts, channel}\n";

/// total passage count and total views-across-all-passages (the latter is
/// just the overall pageview count restated, but computed the same way as
/// everything else here: a query, not a field carried over from the caller).
fn passages_totals(src: &LocalSource) -> (u64, u64) {
    let total = scalar(
        src,
        "dpid[neuron, passage_id] := pid{neuron, ts, passage_id}\n?[count(passage_id)] := dpid[neuron, passage_id]",
    ) as u64;
    let views_total = scalar(
        src,
        r#"?[count(pathname)] := ev2{kind: "pageview", pathname}"#,
    ) as u64;
    (total, views_total)
}

/// visit-derived counters for `overview`:
/// - visits (= total passages)
/// - depth = views/visit (milli)
/// - dwell = attention/visit
/// - attention/neuron — mean looking time per unique key (the juice)
///
/// single-page / bounce is intentionally absent: it confuses bots with
/// humans and does not answer "what happened".
fn visit_metrics(
    events: &[&Stored],
    views: u64,
    attention_ms: u64,
    neurons: u64,
) -> serde_json::Value {
    let src = passage_source(events);
    let (visits, _) = passages_totals(&src);
    let views_per_visit_milli = views
        .checked_mul(1000)
        .and_then(|v| v.checked_div(visits))
        .unwrap_or(0);
    let attention_ms_per_visit = attention_ms.checked_div(visits).unwrap_or(0);
    let attention_ms_per_neuron = attention_ms.checked_div(neurons).unwrap_or(0);
    json!({
        "visits": visits,
        "views_per_visit_milli": views_per_visit_milli,
        "attention_ms_per_visit": attention_ms_per_visit,
        "attention_ms_per_neuron": attention_ms_per_neuron,
    })
}

/// entries/exits by pathname (top-N) plus passage/view totals — the
/// `passages` report.
///
/// Each row carries:
/// - `passages` — how many visits opened/closed on this path
/// - `neurons`  — distinct visitors who ever opened/closed on this path
///
/// The juice is neurons: one neuron bouncing home ten times is one neuron,
/// not ten "unique landings".
pub fn passages_report(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = passage_source(events);
    let (total, views_total) = passages_totals(&src);

    // visits count + distinct-neuron count, merged and sorted by neurons.
    let top_by_pathname = |rules: &str, rel: &str| -> Vec<serde_json::Value> {
        let visits: BTreeMap<String, u64> = q(
            &src,
            &format!(
                "{rules}?[pathname, count(passage_id)] := {rel}[neuron, passage_id, pathname]"
            ),
        )
        .map(|out| {
            out.rows
                .iter()
                .map(|r| (as_str(&r[0]), as_u64(&r[1])))
                .collect()
        })
        .unwrap_or_default();
        // project (pathname, neuron) first so count(neuron) is distinct neurons
        let neurons: BTreeMap<String, u64> = q(
            &src,
            &format!(
                "{rules}dn[pathname, neuron] := {rel}[neuron, passage_id, pathname]\n?[pathname, count(neuron)] := dn[pathname, neuron]"
            ),
        )
        .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
        .unwrap_or_default();

        let mut rows: Vec<_> = visits
            .into_iter()
            .map(|(path, passages)| {
                let neurons = neurons.get(&path).copied().unwrap_or(0);
                (path, passages, neurons)
            })
            .collect();
        // primary sort: unique neurons (the juice), then visits, then path
        rows.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows.into_iter()
            .map(|(pathname, passages, neurons)| {
                json!({
                    "pathname": pathname,
                    "passages": passages,
                    "neurons": neurons,
                })
            })
            .collect()
    };
    let entries = top_by_pathname(RULE_EPATH, "epath");
    let exits = top_by_pathname(RULE_XPATH, "xpath");

    json!({
        "passages": total,
        "views_total": views_total,
        "entries": entries,
        "exits": exits,
    })
}

/// visits grouped by a passage's key-event source or channel, with views +
/// attention rolled up per group. `rel`/`col` select `ksrc`/"source" or
/// `kchan`/"channel"; visits/views/attention are three independent queries
/// (not one three-way join) because a passage missing from `vpq` (no
/// pageview) or `apq` (no attention) must contribute 0, not drop out of an
/// inner join — same reasoning `timeseries` already applies by merging three
/// separate bucketed queries in Rust instead of one.
fn visit_breakdown(src: &LocalSource, rel: &str, col: &str, limit: usize) -> serde_json::Value {
    let key_rule = if rel == "ksrc" { RULE_KSRC } else { RULE_KCHAN };
    let visits: BTreeMap<String, u64> = q(
        src,
        &format!(
            "{RULE_KT}{key_rule}?[{col}, count(passage_id)] := {rel}[neuron, passage_id, {col}]"
        ),
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| (as_str(&r[0]), as_u64(&r[1])))
            .collect()
    })
    .unwrap_or_default();
    let views: BTreeMap<String, u64> = q(
        src,
        &format!(
            "{RULE_KT}{key_rule}{RULE_VPQ}?[{col}, sum(views)] := {rel}[neuron, passage_id, {col}], vpq[neuron, passage_id, views]"
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();
    let attn: BTreeMap<String, u64> = q(
        src,
        &format!(
            "{RULE_KT}{key_rule}{RULE_APQ}?[{col}, sum(ms)] := {rel}[neuron, passage_id, {col}], apq[neuron, passage_id, ms]"
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    // distinct neurons under this source/channel
    let neurons: BTreeMap<String, u64> = q(
        src,
        &format!(
            "{RULE_KT}{key_rule}dn[{col}, neuron] := {rel}[neuron, passage_id, {col}]\n?[{col}, count(neuron)] := dn[{col}, neuron]"
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    let mut rows: Vec<_> = visits
        .iter()
        .map(|(k, v)| {
            let views = views.get(k).copied().unwrap_or(0);
            let att = attn.get(k).copied().unwrap_or(0);
            let neurons = neurons.get(k).copied().unwrap_or(0);
            let vpv_milli = views
                .checked_mul(1000)
                .and_then(|x| x.checked_div(*v))
                .unwrap_or(0);
            let att_pv = att.checked_div(*v).unwrap_or(0);
            let att_pn = att.checked_div(neurons).unwrap_or(0);
            (
                k.clone(),
                neurons,
                *v,
                views,
                att,
                vpv_milli,
                att_pv,
                att_pn,
            )
        })
        .collect();
    // juice: unique neurons first, then visits
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(
        rows.into_iter()
            .map(
                |(k, neurons, visits, views, att, vpv_milli, att_pv, att_pn)| json!({
                    "key": k,
                    "source": k,
                    "channel": k,
                    "neurons": neurons,
                    "visits": visits,
                    "views": views,
                    "attention_ms": att,
                    "views_per_visit_milli": vpv_milli,
                    "attention_ms_per_visit": att_pv,
                    "attention_ms_per_neuron": att_pn,
                })
            )
            .collect::<Vec<_>>()
    )
}

pub fn sources(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = passage_source(events);
    visit_breakdown(&src, "ksrc", "source", limit)
}

pub fn channels(events: &[&Stored]) -> serde_json::Value {
    let src = passage_source(events);
    visit_breakdown(&src, "kchan", "channel", 32)
}

/// ordered funnel: neurons reaching each prefix of `steps`, in order.
/// existence of an increasing-timestamp assignment to a chain of ordered
/// existential joins is equivalent to the greedy single-pass subsequence
/// scan the Rust reference used — a passing greedy scan always exists
/// exactly when a matching (not-necessarily-greedy) subsequence exists, so
/// `sK[neuron, tK] := s(K-1)[..], events{pathname: "<stepK>", ...}, gt(tK,
/// t(K-1))` chained K times reproduces it exactly.
///
/// step pathnames come straight from a query param — `escape_str` is load-
/// bearing here, not decoration: without it a pathname containing `"` could
/// close the string literal and inject clauses into the script text.
pub fn funnel(events: &[&Stored], steps: &[String]) -> serde_json::Value {
    if steps.is_empty() {
        return json!([]);
    }
    let src = events_source(events);
    let mut prefix = String::new();
    let mut counts = Vec::with_capacity(steps.len());
    for (i, step) in steps.iter().enumerate() {
        let rel = format!("s{i}");
        let esc = escape_str(step);
        if i == 0 {
            prefix.push_str(&format!(
                "{rel}[neuron, t{i}] := events{{kind: \"pageview\", pathname: \"{esc}\", neuron, ts: t{i}}}\n"
            ));
        } else {
            let prev = format!("s{}", i - 1);
            prefix.push_str(&format!(
                "{rel}[neuron, t{i}] := {prev}[neuron, t{}], events{{kind: \"pageview\", pathname: \"{esc}\", neuron, ts: t{i}}}, gt(t{i}, t{})\n",
                i - 1,
                i - 1
            ));
        }
        let script =
            format!("{prefix}dn[neuron] := {rel}[neuron, t{i}]\n?[count(neuron)] := dn[neuron]");
        counts.push(scalar(&src, &script) as u64);
    }
    json!(
        steps
            .iter()
            .zip(counts)
            .map(|(s, n)| json!({"step": s, "neurons": n}))
            .collect::<Vec<_>>()
    )
}

/// scalar helper: run a query expected to return exactly one row, one column.
fn scalar(src: &LocalSource, script: &str) -> i64 {
    match q(src, script) {
        Ok(out) if !out.rows.is_empty() => as_i64(&out.rows[0][0]),
        _ => 0,
    }
}

/// counts + sums that inf answers today: neurons, views, attention_ms,
/// agent_neurons. visit-derived fields are layered on by the caller
/// (`reports::overview`), which still needs `passages()`.
pub fn overview_counts(events: &[&Stored]) -> serde_json::Value {
    let src = events_source(events);
    let neurons = scalar(
        &src,
        "dn[neuron] := events{neuron}\n?[count(neuron)] := dn[neuron]",
    );
    let views = scalar(
        &src,
        r#"?[count(pathname)] := events{kind: "pageview", pathname}"#,
    );
    let attention = scalar(&src, r#"?[sum(ms)] := events{kind: "attention", ms}"#);
    let agent_neurons = scalar(
        &src,
        r#"dn[neuron] := events{actor: "agent", neuron}
?[count(neuron)] := dn[neuron]"#,
    );
    json!({
        "neurons": neurons,
        "views": views,
        "attention_ms": attention,
        "agent_neurons": agent_neurons,
    })
}

/// the full `overview` report: plain counts plus visit-derived fields, both
/// answered by inf — see `visit_metrics` for why the passage-grouping half
/// of this needed its own relation pipeline rather than a filter on `events`.
pub fn overview(events: &[&Stored]) -> serde_json::Value {
    let mut o = overview_counts(events);
    let views = o["views"].as_u64().unwrap_or(0);
    let attention = o["attention_ms"].as_u64().unwrap_or(0);
    let neurons = o["neurons"].as_u64().unwrap_or(0);
    let derived = visit_metrics(events, views, attention, neurons);
    if let (Some(obj), Some(v)) = (o.as_object_mut(), derived.as_object()) {
        for (k, val) in v {
            obj.insert(k.clone(), val.clone());
        }
    }
    o
}

/// bucket ms: e.g. 3_600_000 (hour) or 86_400_000 (day).
pub fn timeseries(events: &[&Stored], bucket_ms: u64) -> serde_json::Value {
    let src = events_source(events);
    let bm = bucket_ms as i64;

    let mut by_bucket: BTreeMap<i64, (u64, u64, u64)> = BTreeMap::new(); // neurons, views, attn

    if let Ok(out) = q(
        &src,
        &format!(
            "db[neuron, bucket] := events{{neuron, ts}}, bucket = div(ts, {bm})\n?[bucket, count(neuron)] := db[neuron, bucket]"
        ),
    ) {
        for r in out.rows {
            by_bucket.entry(as_i64(&r[0])).or_default().0 = as_u64(&r[1]);
        }
    }
    if let Ok(out) = q(
        &src,
        &format!(
            r#"?[bucket, count(pathname)] := events{{kind: "pageview", pathname, ts}}, bucket = div(ts, {bm})"#
        ),
    ) {
        for r in out.rows {
            by_bucket.entry(as_i64(&r[0])).or_default().1 = as_u64(&r[1]);
        }
    }
    if let Ok(out) = q(
        &src,
        &format!(
            r#"?[bucket, sum(ms)] := events{{kind: "attention", ms, ts}}, bucket = div(ts, {bm})"#
        ),
    ) {
        for r in out.rows {
            by_bucket.entry(as_i64(&r[0])).or_default().2 = as_u64(&r[1]);
        }
    }

    let rows: Vec<_> = by_bucket
        .into_iter()
        .map(|(bucket, (n, pv, att))| {
            json!({"t": bucket * bm, "neurons": n, "views": pv, "attention_ms": att})
        })
        .collect();
    json!(rows)
}

/// top particles — funnel: neurons / visits (arrivals on path) / views + attention.
pub fn particles(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    let mut attention: BTreeMap<String, u64> = BTreeMap::new();
    if let Ok(out) = q(
        &src,
        r#"?[pathname, sum(ms)] := events{kind: "attention", pathname, ms}"#,
    ) {
        for r in out.rows {
            attention.insert(as_str(&r[0]), as_u64(&r[1]));
        }
    }
    let views: BTreeMap<String, u64> = q(
        &src,
        r#"?[pathname, count(ts)] := events{kind: "pageview", pathname, ts}"#,
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| (as_str(&r[0]), as_u64(&r[1])))
            .collect()
    })
    .unwrap_or_default();
    let neurons: BTreeMap<String, u64> = q(
        &src,
        r#"dn[pathname, neuron] := events{kind: "pageview", pathname, neuron}
?[pathname, count(neuron)] := dn[pathname, neuron]"#,
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| (as_str(&r[0]), as_u64(&r[1])))
            .collect()
    })
    .unwrap_or_default();
    let visits: BTreeMap<String, u64> = q(
        &src,
        r#"?[pathname, count(ts)] := events{kind: "pageview", pathname, ts, arrival: "1"}"#,
    )
    .map(|out| {
        out.rows
            .iter()
            .map(|r| (as_str(&r[0]), as_u64(&r[1])))
            .collect()
    })
    .unwrap_or_default();

    let mut rows: Vec<_> = views
        .into_iter()
        .map(|(path, pv)| {
            let n = neurons.get(&path).copied().unwrap_or(0);
            let v = visits.get(&path).copied().unwrap_or(0);
            (path, n, v, pv)
        })
        .collect();
    rows.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.cmp(&a.2))
            .then(b.3.cmp(&a.3))
            .then(a.0.cmp(&b.0))
    });
    rows.truncate(limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(path, neurons, visits, pv)| {
            let att = attention.get(&path).copied().unwrap_or(0);
            let vpv_milli = pv
                .checked_mul(1000)
                .and_then(|x| x.checked_div(visits))
                .unwrap_or(0);
            let att_pv = att.checked_div(visits).unwrap_or(0);
            let att_pn = att.checked_div(neurons).unwrap_or(0);
            json!({
                "pathname": path,
                "neurons": neurons,
                "visits": visits,
                "views": pv,
                "attention_ms": att,
                "views_per_visit_milli": vpv_milli,
                "attention_ms_per_visit": att_pv,
                "attention_ms_per_neuron": att_pn,
            })
        })
        .collect();
    json!(out)
}

pub fn actors(events: &[&Stored]) -> serde_json::Value {
    let src = events_source(events);

    let human_neurons = scalar(
        &src,
        r#"dn[neuron] := events{actor: "human", neuron}
?[count(neuron)] := dn[neuron]"#,
    );
    let human_views = scalar(
        &src,
        r#"?[count(pathname)] := events{actor: "human", kind: "pageview", pathname}"#,
    );
    let human_attn = scalar(
        &src,
        r#"?[sum(ms)] := events{actor: "human", kind: "attention", ms}"#,
    );

    let agent_neurons = scalar(
        &src,
        r#"dn[neuron] := events{actor: "agent", neuron}
?[count(neuron)] := dn[neuron]"#,
    );
    let agent_views = scalar(
        &src,
        r#"?[count(pathname)] := events{actor: "agent", kind: "pageview", pathname}"#,
    );

    // declared: per agent name, count of ALL that name's events (matches the
    // existing Rust behavior precisely — it is not view-gated either).
    let declared: Vec<_> = q(
        &src,
        r#"?[agent_name, count(neuron)] := events{actor: "agent", agent_name, neuron}"#,
    )
    .map(|out| {
        let mut rows: Vec<(String, u64)> = out
            .rows
            .iter()
            .map(|r| (as_str(&r[0]), as_u64(&r[1])))
            .collect();
        rows.retain(|(name, _)| !name.is_empty());
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(16);
        rows.into_iter()
            .map(|(n, c)| json!({"name": n, "views": c}))
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    json!({
        "human": {"neurons": human_neurons, "views": human_views, "attention_ms": human_attn},
        "agent": {"neurons": agent_neurons, "views": agent_views, "declared": declared},
    })
}

/// Funnel for a per-event dimension relation `{neuron, <col>, ts}`:
/// neurons (unique), visits (arrivals), views (pageviews).
/// Prefer this shape over raw event counts in every cut.
fn dim_funnel(src: &LocalSource, rel: &str, col: &str, limit: usize) -> Vec<serde_json::Value> {
    // distinct neurons that ever had an event with this dim value
    let neurons: BTreeMap<String, u64> = q(
        src,
        &format!(
            "dn[{col}, neuron] := {rel}{{{col}, neuron, ts}}\n?[{col}, count(neuron)] := dn[{col}, neuron]"
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    // pageviews tagged with this dim (join on neuron+ts)
    let views: BTreeMap<String, u64> = q(
        src,
        &format!(
            r#"?[{col}, count(ts)] := {rel}{{{col}, neuron, ts}}, events{{neuron, ts, kind: "pageview"}}"#
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    // arrivals (= visits that opened with this dim on the arrival event)
    let visits: BTreeMap<String, u64> = q(
        src,
        &format!(
            r#"?[{col}, count(ts)] := {rel}{{{col}, neuron, ts}}, events{{neuron, ts, kind: "pageview", arrival: "1"}}"#
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    // attention ms tagged with this dim
    let attn: BTreeMap<String, u64> = q(
        src,
        &format!(
            r#"?[{col}, sum(ms)] := {rel}{{{col}, neuron, ts}}, events{{neuron, ts, kind: "attention", ms}}"#
        ),
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();

    let mut rows: Vec<_> = neurons
        .into_iter()
        .map(|(k, n)| {
            let visits = visits.get(&k).copied().unwrap_or(0);
            let views = views.get(&k).copied().unwrap_or(0);
            let att = attn.get(&k).copied().unwrap_or(0);
            (k, n, visits, views, att)
        })
        .collect();
    // juice order: unique people, then visits, then views
    rows.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.cmp(&a.2))
            .then(b.3.cmp(&a.3))
            .then(a.0.cmp(&b.0))
    });
    rows.truncate(limit);
    rows.into_iter()
        .map(|(k, neurons, visits, views, att)| {
            let vpv_milli = views
                .checked_mul(1000)
                .and_then(|x| x.checked_div(visits))
                .unwrap_or(0);
            let att_pv = att.checked_div(visits).unwrap_or(0);
            let att_pn = att.checked_div(neurons).unwrap_or(0);
            json!({
                col: k,
                "neurons": neurons,
                "visits": visits,
                "views": views,
                "attention_ms": att,
                "views_per_visit_milli": vpv_milli,
                "attention_ms_per_visit": att_pv,
                "attention_ms_per_neuron": att_pn,
            })
        })
        .collect()
}

pub fn countries(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    // rows use "country" key via dim_funnel col name
    let rows = dim_funnel(&src, "geo_ev", "country", limit);
    json!(rows)
}

pub fn devices(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    json!({
        "browsers": dim_funnel(&src, "browser_ev", "browser", limit),
        "os": dim_funnel(&src, "os_ev", "os", limit),
        "classes": dim_funnel(&src, "class_ev", "class", limit),
    })
}

const WEEK_MS: i64 = 7 * 24 * 3600 * 1000;

/// retention matrix over ALL events (cohorts need full history): cohort week
/// (first-seen) × week offset → distinct neurons active. the dedup-then-count
/// pattern: an intermediate rule projects to (neuron, cohort, offset), which
/// datalog set semantics collapse to one row per neuron per cell before the
/// final rule counts — counting neurons in the cell, not events in it.
pub fn retention(events: &[Stored], weeks: usize) -> serde_json::Value {
    let refs: Vec<&Stored> = events.iter().collect();
    let src = events_source(&refs);

    let fs = match q(&src, "?[neuron, min(ts)] := events{neuron, ts}") {
        Ok(out) => out,
        Err(_) => return json!([]),
    };
    // first-seen becomes its own source relation, then a second query joins
    // events against it for the cohort/offset cell — the dedup-then-count
    // pattern verified live: projecting to (neuron, cohort, offset) collapses
    // a neuron's same-cell events to one row before the final count.
    let mut fs_src = LocalSource::new();
    let fs_rows: Vec<Tuple> = fs
        .rows
        .iter()
        .map(|r| vec![r[0].clone(), r[1].clone()])
        .collect();
    fs_src.add("fs", &["neuron", "first"], fs_rows);
    // events also needed in the same source for the join
    let ev_rows: Vec<Tuple> = refs
        .iter()
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
            ]
        })
        .collect();
    fs_src.add("ev", &["neuron", "ts"], ev_rows);

    let script = format!(
        "cell[neuron, cohort, offset] := fs{{neuron, first}}, ev{{neuron, ts}}, cohort = div(first, {WEEK_MS}), offset = div(ts, {WEEK_MS}) - cohort\n?[cohort, offset, count(neuron)] := cell[neuron, cohort, offset]"
    );
    let cells = match q(&fs_src, &script) {
        Ok(out) => out,
        Err(_) => return json!([]),
    };

    let mut matrix: BTreeMap<i64, BTreeMap<i64, u64>> = BTreeMap::new();
    for r in cells.rows {
        let cohort = as_i64(&r[0]);
        let offset = as_i64(&r[1]);
        if offset >= 0 && (offset as usize) < weeks {
            matrix
                .entry(cohort)
                .or_default()
                .insert(offset, as_u64(&r[2]));
        }
    }
    let rows: Vec<_> = matrix
        .into_iter()
        .map(|(cohort, offsets)| {
            let size = offsets.get(&0).copied().unwrap_or(0);
            let cells: Vec<u64> =
                (0..weeks as i64).map(|o| offsets.get(&o).copied().unwrap_or(0)).collect();
            json!({"cohort_week": cohort, "cohort_start_ms": cohort * WEEK_MS, "size": size, "weeks": cells})
        })
        .collect();
    json!(rows)
}

/// return probability: of neurons first seen in [from, to), how many came
/// back within `horizon_ms` after their first event.
pub fn returns(events: &[Stored], from: u64, to: u64, horizon_ms: u64) -> serde_json::Value {
    let refs: Vec<&Stored> = events.iter().collect();
    let mut src = LocalSource::new();
    let ev_rows: Vec<Tuple> = refs
        .iter()
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
            ]
        })
        .collect();
    src.add("ev", &["neuron", "ts"], ev_rows);

    let cohort_script = format!(
        "fs[neuron, min(ts)] := ev{{neuron, ts}}\n?[neuron, first] := fs[neuron, first], ge(first, {from}), lt(first, {to})",
    );
    let cohort = match q(&src, &cohort_script) {
        Ok(out) => out,
        Err(_) => return json!({"cohort": 0, "returned": 0, "horizon_ms": horizon_ms}),
    };
    let cohort_count = cohort.rows.len();

    // second source: the cohort's (neuron, first) as facts, joined against
    // every event for a later-timestamp-within-horizon match.
    let mut src2 = LocalSource::new();
    src2.add(
        "fs",
        &["neuron", "first"],
        cohort
            .rows
            .iter()
            .map(|r| vec![r[0].clone(), r[1].clone()])
            .collect(),
    );
    let ev_rows2: Vec<Tuple> = refs
        .iter()
        .map(|e| {
            vec![
                Value::str(&e.body.neuron),
                Value::int(e.body.timestamp as i64),
            ]
        })
        .collect();
    src2.add("ev", &["neuron", "ts"], ev_rows2);

    let returns_script = format!(
        "rn[neuron] := fs{{neuron, first}}, ev{{neuron, ts}}, gt(ts, first), edge = first + {horizon_ms}, le(ts, edge)\n?[count(neuron)] := rn[neuron]",
    );
    let returned = scalar(&src2, &returns_script) as u64;

    json!({"cohort": cohort_count, "returned": returned, "horizon_ms": horizon_ms})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{Attribution, Channel, Device};
    use crate::geo::Geo;
    use lytics_event::event::AgentDecl;
    use lytics_event::{Actor, EventBody, Navigation};

    #[allow(clippy::too_many_arguments)]
    fn ev(
        neuron: &str,
        path: &str,
        ts: u64,
        kind: Kind,
        nav: Option<Navigation>,
        att: u64,
        actor: Actor,
        agent_name: Option<&str>,
    ) -> Stored {
        Stored {
            body: EventBody {
                neuron: neuron.into(),
                actor,
                agent: agent_name.map(|n| AgentDecl {
                    name: n.into(),
                    operator: "op".into(),
                }),
                kind: kind.clone(),
                navigation: nav,
                hostname: "cyber.page".into(),
                pathname: path.into(),
                referrer: None,
                utm: None,
                attention: (att > 0).then_some(lytics_event::Attention {
                    ms: att,
                    scroll_depth: 0,
                }),
                props: None,
                revenue: None,
                timestamp: ts,
            },
            event_hash: format!("{neuron}-{path}-{ts}-{kind:?}"),
            attribution: Attribution {
                source: None,
                channel: Channel::Direct,
            },
            device: Device {
                browser: None,
                browser_version: None,
                os: None,
                device: None,
            },
            geo: None,
            received_at: ts,
        }
    }

    fn pv(neuron: &str, path: &str, ts: u64) -> Stored {
        ev(
            neuron,
            path,
            ts,
            Kind::Pageview,
            Some(Navigation::External),
            0,
            Actor::Human,
            None,
        )
    }
    /// an internal-navigation pageview — not an arrival, stays inside the
    /// current passage.
    fn pv_internal(neuron: &str, path: &str, ts: u64) -> Stored {
        ev(
            neuron,
            path,
            ts,
            Kind::Pageview,
            Some(Navigation::Internal),
            0,
            Actor::Human,
            None,
        )
    }
    fn attn(neuron: &str, path: &str, ts: u64, ms: u64) -> Stored {
        ev(
            neuron,
            path,
            ts,
            Kind::Attention,
            None,
            ms,
            Actor::Human,
            None,
        )
    }
    fn with_attrib(mut s: Stored, source: Option<&str>, channel: Channel) -> Stored {
        s.attribution = Attribution {
            source: source.map(String::from),
            channel,
        };
        s
    }
    fn with_geo(mut s: Stored, country: &str) -> Stored {
        s.geo = Some(Geo {
            country: Some(country.into()),
            region: None,
            city: None,
        });
        s
    }
    fn with_device(mut s: Stored, browser: &str, os: &str, class: &str) -> Stored {
        s.device = Device {
            browser: Some(browser.into()),
            browser_version: None,
            os: Some(os.into()),
            device: Some(class.into()),
        };
        s
    }

    fn refs(events: &[Stored]) -> Vec<&Stored> {
        events.iter().collect()
    }

    #[test]
    fn overview_counts_matches_reference_on_empty() {
        let events: Vec<Stored> = vec![];
        let r = refs(&events);
        let inf = overview_counts(&r);
        assert_eq!(inf["neurons"], 0);
        assert_eq!(inf["views"], 0);
        assert_eq!(inf["attention_ms"], 0);
        assert_eq!(inf["agent_neurons"], 0);
    }

    #[test]
    fn overview_counts_matches_reference() {
        let events = [
            pv("n1", "/a", 1000),
            attn("n1", "/a", 1100, 5000),
            pv("n2", "/b", 1200),
            ev(
                "n3",
                "/c",
                1300,
                Kind::Pageview,
                Some(Navigation::External),
                0,
                Actor::Agent,
                Some("bot"),
            ),
        ];
        let r = refs(&events);
        // the reference `overview()` computes the same four counts plus
        // visit-derived fields this module does not touch; compare only the
        // fields inf_reports::overview_counts is responsible for.
        let reference = crate::reports::overview(&r);
        let inf = overview_counts(&r);
        assert_eq!(inf["views"], reference["views"]);
        assert_eq!(inf["neurons"], reference["neurons"]);
        assert_eq!(inf["attention_ms"], reference["attention_ms"]);
        assert_eq!(inf["agent_neurons"], reference["agent_neurons"]);
        assert_eq!(inf["neurons"], 3);
        assert_eq!(inf["views"], 3);
        assert_eq!(inf["attention_ms"], 5000);
        assert_eq!(inf["agent_neurons"], 1);
    }

    fn sort_by_pathname(v: &mut serde_json::Value) {
        v.as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["pathname"].as_str().cmp(&b["pathname"].as_str()));
    }

    #[test]
    fn particles_matches_reference() {
        let events = [
            pv("n1", "/a", 1000),
            pv("n2", "/a", 1100),
            pv("n1", "/b", 1200),
            attn("n1", "/a", 1300, 4000),
            attn("n2", "/a", 1400, 1000),
        ];
        let r = refs(&events);
        let mut reference = crate::reports::particles(&r, 10);
        let mut inf = particles(&r, 10);
        sort_by_pathname(&mut reference);
        sort_by_pathname(&mut inf);
        assert_eq!(inf, reference);
        // /a: 2 views, 5000ms attention; /b: 1 view, 0ms
        let arr = inf.as_array().unwrap();
        let a = arr.iter().find(|r| r["pathname"] == "/a").unwrap();
        assert_eq!(a["views"], 2);
        assert_eq!(a["attention_ms"], 5000);
    }

    #[test]
    fn particles_respects_limit_and_tie_order() {
        // three pathnames tied at 1 view each — reference breaks ties by
        // pathname ascending; inf must match exactly, not just the counts.
        let events = [pv("n1", "/z", 1), pv("n1", "/a", 2), pv("n1", "/m", 3)];
        let r = refs(&events);
        let reference = crate::reports::particles(&r, 2);
        let inf = particles(&r, 2);
        assert_eq!(inf, reference);
        let arr = inf.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["pathname"], "/a");
        assert_eq!(arr[1]["pathname"], "/m");
    }

    #[test]
    fn actors_matches_reference() {
        let events = [
            pv("n1", "/a", 1000),
            attn("n1", "/a", 1100, 2000),
            ev(
                "n2",
                "/b",
                1200,
                Kind::Pageview,
                Some(Navigation::External),
                0,
                Actor::Agent,
                Some("claude"),
            ),
            ev(
                "n2",
                "/c",
                1300,
                Kind::Pageview,
                Some(Navigation::External),
                0,
                Actor::Agent,
                Some("claude"),
            ),
            ev(
                "n3",
                "/d",
                1400,
                Kind::Pageview,
                Some(Navigation::External),
                0,
                Actor::Agent,
                Some("perplexity"),
            ),
        ];
        let r = refs(&events);
        let reference = crate::reports::actors(&r);
        let inf = actors(&r);
        assert_eq!(inf, reference);
        assert_eq!(inf["human"]["neurons"], 1);
        assert_eq!(inf["agent"]["neurons"], 2);
    }

    #[test]
    fn countries_matches_reference() {
        let events = [
            with_geo(pv("n1", "/a", 1000), "US"),
            with_geo(pv("n1", "/b", 1100), "US"),
            with_geo(pv("n2", "/a", 1200), "US"),
            with_geo(pv("n3", "/a", 1300), "DE"),
            pv("n4", "/a", 1400), // no geo — must not appear
        ];
        let r = refs(&events);
        let reference = crate::reports::countries(&r, 10);
        let inf = countries(&r, 10);
        assert_eq!(inf, reference);
        let arr = inf.as_array().unwrap();
        let us = arr.iter().find(|r| r["country"] == "US").unwrap();
        assert_eq!(us["neurons"], 2);
        assert_eq!(us["views"], 3); // 3 pageviews in US
        assert_eq!(us["visits"], 3); // all three are arrivals
        assert!(us.get("attention_ms_per_neuron").is_some());
    }

    #[test]
    fn devices_matches_reference() {
        let events = [
            with_device(pv("n1", "/a", 1000), "Chrome", "macOS", "pc"),
            with_device(pv("n2", "/b", 1100), "Chrome", "Windows", "pc"),
            with_device(pv("n3", "/c", 1200), "Safari", "iOS", "mobile"),
            pv("n4", "/d", 1300), // no device fields — must not appear
        ];
        let r = refs(&events);
        let reference = crate::reports::devices(&r, 10);
        let inf = devices(&r, 10);
        assert_eq!(inf, reference);
    }

    fn sort_by_t(v: &mut serde_json::Value) {
        v.as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["t"].as_u64().cmp(&b["t"].as_u64()));
    }

    #[test]
    fn timeseries_matches_reference() {
        const DAY: u64 = 86_400_000;
        let events = [
            pv("n1", "/a", 1000),
            attn("n1", "/a", 2000, 3000),
            pv("n2", "/b", DAY + 1000),
            pv("n1", "/c", DAY + 2000),
        ];
        let r = refs(&events);
        let mut reference = crate::reports::timeseries(&r, DAY);
        let mut inf = timeseries(&r, DAY);
        sort_by_t(&mut reference);
        sort_by_t(&mut inf);
        assert_eq!(inf, reference);
    }

    #[test]
    fn retention_matches_reference_with_same_cell_multi_event_neuron() {
        let w = 7 * 24 * 3600 * 1000u64;
        let events = vec![
            pv("n1", "/", 0),
            // same neuron, same cohort/offset cell (week 0), a second event —
            // this is exactly the case that would silently overcount if the
            // dedup-via-projection trick were done wrong (count(neuron) over
            // raw events instead of over the deduped (neuron,cohort,offset)
            // relation would count 2 here instead of 1).
            pv("n1", "/x", 3600 * 1000),
            pv("n1", "/", w + 10), // returns week 1
            pv("n2", "/", 5),      // never returns
        ];
        let reference = crate::reports::retention(&events, 4);
        let inf = retention(&events, 4);
        assert_eq!(inf, reference);
        let rows = inf.as_array().unwrap();
        assert_eq!(rows[0]["size"], 2);
        assert_eq!(rows[0]["weeks"][0], 2); // n1, n2 — NOT 3
        assert_eq!(rows[0]["weeks"][1], 1);
    }

    #[test]
    fn retention_matches_reference_on_empty() {
        let events: Vec<Stored> = vec![];
        let reference = crate::reports::retention(&events, 4);
        let inf = retention(&events, 4);
        assert_eq!(inf, reference);
        assert_eq!(inf.as_array().unwrap().len(), 0);
    }

    #[test]
    fn returns_matches_reference() {
        let events = vec![
            pv("n1", "/", 100),
            pv("n1", "/", 200), // n1 returns within horizon
            pv("n2", "/", 150), // n2 never returns
        ];
        let reference = crate::reports::returns(&events, 0, 1000, 1000);
        let inf = returns(&events, 0, 1000, 1000);
        assert_eq!(inf, reference);
        assert_eq!(inf["cohort"], 2);
        assert_eq!(inf["returned"], 1);
    }

    #[test]
    fn returns_matches_reference_outside_horizon() {
        let events = vec![
            pv("n1", "/", 100),
            pv("n1", "/", 5000), // far outside a 500ms horizon — must not count
        ];
        let reference = crate::reports::returns(&events, 0, 1000, 500);
        let inf = returns(&events, 0, 1000, 500);
        assert_eq!(inf, reference);
        assert_eq!(inf["returned"], 0);
    }

    #[test]
    fn passage_ids_groups_correctly_across_a_boundary_regardless_of_label() {
        // n1: arrival /a, internal /b (same passage as /a), arrival /c
        // (new passage), internal /d (same passage as /c). n2: internal /x
        // as the very first event ever — never an arrival, stays one
        // passage.
        //
        // the carry-forward version ranks n1's own first event (an arrival)
        // starting at 1, not 0 — a uniform +1 label shift from the old
        // self-join version, present only because n1's stream opens on an
        // arrival. this asserts what actually matters: /a and /b share an
        // id, /c and /d share a *different* id, and n2's single event has
        // its own id — the grouping, not the specific numbers.
        let events = vec![
            pv("n1", "/a", 0),
            pv_internal("n1", "/b", 200),
            pv("n1", "/c", 300),
            pv_internal("n1", "/d", 400),
            pv_internal("n2", "/x", 50),
        ];
        let r = refs(&events);
        let ids = passage_ids(&r);
        let a = ids[&("n1".to_string(), 0)];
        let b = ids[&("n1".to_string(), 200)];
        let c = ids[&("n1".to_string(), 300)];
        let d = ids[&("n1".to_string(), 400)];
        let x = ids[&("n2".to_string(), 50)];
        assert_eq!(a, b, "/a and /b are the same passage");
        assert_eq!(c, d, "/c and /d are the same passage");
        assert_ne!(a, c, "the arrival at /c opens a new passage");
        assert_eq!(x, 0, "n2's stream opens on a non-arrival, unshifted");
    }

    #[test]
    fn passage_ids_stays_fast_for_one_neuron_with_thousands_of_arrivals() {
        // the exact shape that OOM-killed production: a single neuron (a
        // crawler that never persists a client key, so every page it hits
        // looks like a fresh direct visit) with thousands of events, every
        // one an arrival. the self-join version of this function did
        // ~events×arrivals work for this one neuron alone — 3123×3123 ≈
        // 9.75M intermediate bindings, 6.4s and several GB, measured
        // against the real production dataset before this function was
        // rewritten. this reproduces the shape (smaller, so the test suite
        // stays fast) and asserts a wall-clock ceiling a quadratic
        // implementation would blow through.
        let events: Vec<Stored> = (0..4000u64).map(|i| pv("bot", "/p", i)).collect();
        let r = refs(&events);
        let t0 = std::time::Instant::now();
        let ids = passage_ids(&r);
        let elapsed = t0.elapsed();
        assert!(
            elapsed.as_millis() < 2000,
            "passage_ids took {elapsed:?} for one neuron's 4000 arrivals — quadratic regression?"
        );
        assert_eq!(ids.len(), 4000);
        // every event is its own arrival and its own passage — 4000 distinct ids
        let distinct: std::collections::BTreeSet<i64> = ids.values().copied().collect();
        assert_eq!(distinct.len(), 4000);
    }

    #[test]
    fn passages_report_matches_reference() {
        let events = vec![
            pv("n1", "/a", 1000),
            pv_internal("n1", "/b", 1000 + 6 * 3600 * 1000), // six-hour pause, same passage
            pv("n1", "/c", 1000 + 7 * 3600 * 1000),          // new arrival, new passage
            pv("n2", "/a", 500),
        ];
        let r = refs(&events);
        let reference = crate::reports::passages_report(&r, 10);
        let inf = passages_report(&r, 10);
        assert_eq!(inf, reference);
        assert_eq!(inf["passages"], 3); // n1: 2 passages, n2: 1
        assert_eq!(inf["views_total"], 4);
    }

    #[test]
    fn sources_matches_reference() {
        let events = vec![
            with_attrib(pv("n1", "/a", 1000), Some("google"), Channel::Search),
            pv_internal("n1", "/b", 1100), // same passage — key stays google/search
            attn("n1", "/a", 1150, 2000),
            with_attrib(pv("n2", "/a", 1200), Some("google"), Channel::Search),
            with_attrib(pv("n3", "/a", 1300), None, Channel::Direct),
        ];
        let r = refs(&events);
        let reference = crate::reports::sources(&r, 10);
        let inf = sources(&r, 10);
        assert_eq!(inf, reference);
        let arr = inf.as_array().unwrap();
        let google = arr.iter().find(|row| row["source"] == "google").unwrap();
        assert_eq!(google["visits"], 2);
        assert_eq!(google["views"], 3); // n1's passage has 2 views, n2's has 1
        assert_eq!(google["attention_ms"], 2000);
        let direct = arr.iter().find(|row| row["source"] == "direct").unwrap();
        assert_eq!(direct["visits"], 1);
    }

    #[test]
    fn channels_matches_reference() {
        let events = vec![
            with_attrib(pv("n1", "/a", 1000), Some("google"), Channel::Search),
            with_attrib(pv("n2", "/a", 1100), None, Channel::Direct),
            with_attrib(pv("n3", "/a", 1200), None, Channel::Direct),
        ];
        let r = refs(&events);
        let reference = crate::reports::channels(&r);
        let inf = channels(&r);
        assert_eq!(inf, reference);
        let arr = inf.as_array().unwrap();
        let direct = arr.iter().find(|row| row["channel"] == "direct").unwrap();
        assert_eq!(direct["visits"], 2);
    }

    #[test]
    fn funnel_matches_reference() {
        let events = vec![
            pv("n1", "/a", 1),
            pv_internal("n1", "/b", 2),
            pv("n2", "/a", 1),
            pv("n3", "/b", 1), // out of order: /b before /a — never reaches step 1
        ];
        let r = refs(&events);
        let steps = vec!["/a".to_string(), "/b".to_string()];
        let reference = crate::reports::funnel(&r, &steps);
        let inf = funnel(&r, &steps);
        assert_eq!(inf, reference);
        let rows = inf.as_array().unwrap();
        assert_eq!(rows[0]["neurons"], 2); // n1, n2
        assert_eq!(rows[1]["neurons"], 1); // only n1
    }

    #[test]
    fn funnel_escapes_quotes_in_step_pathnames() {
        // a pathname carrying a `"` must not be able to close the string
        // literal and inject a clause — if it did, this would either panic,
        // error, or (worse) silently match every pageview.
        let events = vec![pv("n1", "/normal", 1)];
        let r = refs(&events);
        let steps = vec![r#"/a" }, events{ts: 1} #"#.to_string()];
        let out = funnel(&r, &steps);
        assert_eq!(out[0]["neurons"], 0);
    }

    #[test]
    fn overview_matches_reference() {
        let events = vec![
            pv("n1", "/a", 1000),
            attn("n1", "/a", 1100, 5000),
            pv_internal("n1", "/b", 1200), // same passage as /a
            pv("n2", "/a", 1300),          // single-page visit
            ev(
                "n3",
                "/c",
                1400,
                Kind::Pageview,
                Some(Navigation::External),
                0,
                Actor::Agent,
                Some("bot"),
            ),
        ];
        let r = refs(&events);
        let reference = crate::reports::overview(&r);
        let inf = overview(&r);
        assert_eq!(inf, reference);
        assert_eq!(inf["visits"], 3); // n1: 1 passage, n2: 1, n3: 1
        assert!(inf.get("single_page_visits").is_none()); // bounce metric retired
        assert!(inf["attention_ms_per_neuron"].as_u64().is_some());
    }

    #[test]
    fn overview_matches_reference_on_empty() {
        let events: Vec<Stored> = vec![];
        let r = refs(&events);
        let reference = crate::reports::overview(&r);
        let inf = overview(&r);
        assert_eq!(inf, reference);
        assert_eq!(inf["visits"], 0);
    }
}
