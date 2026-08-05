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
//! what migrated and what stays Rust, honestly:
//!
//! - `overview`/`timeseries`/`particles`/`countries`/`devices`/`actors`/
//!   `retention`/`returns` — every metric that is a plain count, sum, or
//!   min/max over the raw event stream — run through inf below.
//! - `overview`'s visit-derived fields (`visits`, `views_per_visit_milli`,
//!   `attention_ms_per_visit`, `single_page_visits`) still come from
//!   `reports::passages` — a visit IS a passage, and grouping events into
//!   passages needs an ordered scan carrying state between consecutive
//!   events (open a new group when an arrival breaks the run). inf's
//!   language has no window/`lag` primitive today — `:sort` only orders
//!   final output, it cannot feed a rule body — so passage-grouping cannot
//!   be expressed as a datalog rule. this is a language gap, verified
//!   directly against the evaluator, not a shortcut.
//! - `sources`/`channels` stay Rust for the same reason: they roll up
//!   views/attention per *visit* (`visit_breakdown` groups by passage, then
//!   sums each passage's events) — downstream of the same passage
//!   computation inf cannot express.
//! - `passages`/`passages_report`/`funnel` are unchanged, already documented
//!   in `reports.rs` as inf-inexpressible (ordered scan; dynamic-arity
//!   ordered sequence match).
//!
//! relation schema built per call:
//!
//! - `events{neuron, pathname, ts, kind, ms, actor, agent_name}` — one row
//!   per `Stored` event, always. `kind` is the wire kind string
//!   ("pageview"/"attention"/a custom name); `ms` is the attention
//!   milliseconds (0 for non-attention events); `agent_name` is the
//!   declared name or empty bytes.
//! - `geo_ev{neuron, country}`, `browser_ev{neuron, browser}`,
//!   `os_ev{neuron, os}`, `class_ev{neuron, class}` — one row per event
//!   that actually carries that optional field; events missing it are
//!   skipped when the relation is built (in Rust, not in datalog), so no
//!   query needs a null-check primitive.

use crate::reports::Stored;
use inf_eval::{eval, Ctx, EvalError, Output};
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

/// build the base `events` relation from the event slice.
fn events_source(events: &[&Stored]) -> LocalSource {
    let mut s = LocalSource::new();
    let rows: Vec<Tuple> = events
        .iter()
        .map(|e| {
            let ms = e.body.attention.map(|a| a.ms as i64).unwrap_or(0);
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
            ]
        })
        .collect();
    s.add("events", &["neuron", "pathname", "ts", "kind", "ms", "actor", "agent_name"], rows);

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
            Some(vec![Value::str(&e.body.neuron), Value::str(c), Value::int(e.body.timestamp as i64)])
        })
        .collect();
    s.add("geo_ev", &["neuron", "country", "ts"], geo_rows);

    let browser_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let b = e.device.browser.as_ref()?;
            Some(vec![Value::str(&e.body.neuron), Value::str(b), Value::int(e.body.timestamp as i64)])
        })
        .collect();
    s.add("browser_ev", &["neuron", "browser", "ts"], browser_rows);

    let os_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let o = e.device.os.as_ref()?;
            Some(vec![Value::str(&e.body.neuron), Value::str(o), Value::int(e.body.timestamp as i64)])
        })
        .collect();
    s.add("os_ev", &["neuron", "os", "ts"], os_rows);

    let class_rows: Vec<Tuple> = events
        .iter()
        .filter_map(|e| {
            let c = e.device.device.as_ref()?;
            Some(vec![Value::str(&e.body.neuron), Value::str(c), Value::int(e.body.timestamp as i64)])
        })
        .collect();
    s.add("class_ev", &["neuron", "class", "ts"], class_rows);

    s
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
    let neurons = scalar(&src, "dn[neuron] := events{neuron}\n?[count(neuron)] := dn[neuron]");
    let views = scalar(&src, r#"?[count(pathname)] := events{kind: "pageview", pathname}"#);
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

/// top particles by views — each pathname is a particle (`graph::page_particle`
/// hashes hostname+pathname); `pathname` here is the particle's human-readable
/// name, not its hash.
pub fn particles(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    let mut attention: BTreeMap<String, u64> = BTreeMap::new();
    if let Ok(out) = q(&src, r#"?[pathname, sum(ms)] := events{kind: "attention", pathname, ms}"#)
    {
        for r in out.rows {
            attention.insert(as_str(&r[0]), as_u64(&r[1]));
        }
    }
    let mut rows: Vec<(String, u64)> = q(
        &src,
        r#"?[pathname, count(neuron)] := events{kind: "pageview", pathname, neuron}"#,
    )
    .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
    .unwrap_or_default();
    // inf's :sort took the aggregated column's inherited name in testing, but
    // ties need a stable secondary key to match the Rust reference exactly —
    // sort here rather than lean on the query's :sort/:limit for that reason.
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(path, pv)| {
            let att = attention.get(&path).copied().unwrap_or(0);
            json!({"pathname": path, "views": pv, "attention_ms": att})
        })
        .collect();
    json!(out)
}

pub fn actors(events: &[&Stored]) -> serde_json::Value {
    let src = events_source(events);

    let human_neurons =
        scalar(&src, r#"dn[neuron] := events{actor: "human", neuron}
?[count(neuron)] := dn[neuron]"#);
    let human_views =
        scalar(&src, r#"?[count(pathname)] := events{actor: "human", kind: "pageview", pathname}"#);
    let human_attn =
        scalar(&src, r#"?[sum(ms)] := events{actor: "human", kind: "attention", ms}"#);

    let agent_neurons =
        scalar(&src, r#"dn[neuron] := events{actor: "agent", neuron}
?[count(neuron)] := dn[neuron]"#);
    let agent_views =
        scalar(&src, r#"?[count(pathname)] := events{actor: "agent", kind: "pageview", pathname}"#);

    // declared: per agent name, count of ALL that name's events (matches the
    // existing Rust behavior precisely — it is not view-gated either).
    let declared: Vec<_> = q(
        &src,
        r#"?[agent_name, count(neuron)] := events{actor: "agent", agent_name, neuron}"#,
    )
    .map(|out| {
        let mut rows: Vec<(String, u64)> =
            out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect();
        rows.retain(|(name, _)| !name.is_empty());
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(16);
        rows.into_iter().map(|(n, c)| json!({"name": n, "views": c})).collect::<Vec<_>>()
    })
    .unwrap_or_default();

    json!({
        "human": {"neurons": human_neurons, "views": human_views, "attention_ms": human_attn},
        "agent": {"neurons": agent_neurons, "views": agent_views, "declared": declared},
    })
}

pub fn countries(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    let counts: Vec<(String, u64)> = q(&src, "?[country, count(neuron)] := geo_ev{country, neuron}")
        .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
        .unwrap_or_default();
    let distinct: BTreeMap<String, u64> =
        q(&src, "dn[country, neuron] := geo_ev{country, neuron}\n?[country, count(neuron)] := dn[country, neuron]")
            .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
            .unwrap_or_default();
    let mut rows = counts;
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(rows
        .into_iter()
        .map(|(c, n)| {
            let neurons = distinct.get(&c).copied().unwrap_or(0);
            json!({"country": c, "events": n, "neurons": neurons})
        })
        .collect::<Vec<_>>())
}

fn top_field(src: &LocalSource, rel: &str, col: &str, limit: usize) -> Vec<serde_json::Value> {
    let script = format!("?[{col}, count(neuron)] := {rel}{{{col}, neuron}}");
    let mut rows: Vec<(String, u64)> = q(src, &script)
        .map(|out| out.rows.iter().map(|r| (as_str(&r[0]), as_u64(&r[1]))).collect())
        .unwrap_or_default();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    rows.into_iter().map(|(k, n)| json!({col: k, "events": n})).collect()
}

pub fn devices(events: &[&Stored], limit: usize) -> serde_json::Value {
    let src = events_source(events);
    json!({
        "browsers": top_field(&src, "browser_ev", "browser", limit),
        "os": top_field(&src, "os_ev", "os", limit),
        "classes": top_field(&src, "class_ev", "class", limit),
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
    let fs_rows: Vec<Tuple> =
        fs.rows.iter().map(|r| vec![r[0].clone(), r[1].clone()]).collect();
    fs_src.add("fs", &["neuron", "first"], fs_rows);
    // events also needed in the same source for the join
    let ev_rows: Vec<Tuple> = refs
        .iter()
        .map(|e| vec![Value::str(&e.body.neuron), Value::int(e.body.timestamp as i64)])
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
            matrix.entry(cohort).or_default().insert(offset, as_u64(&r[2]));
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
        .map(|e| vec![Value::str(&e.body.neuron), Value::int(e.body.timestamp as i64)])
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
        cohort.rows.iter().map(|r| vec![r[0].clone(), r[1].clone()]).collect(),
    );
    let ev_rows2: Vec<Tuple> = refs
        .iter()
        .map(|e| vec![Value::str(&e.body.neuron), Value::int(e.body.timestamp as i64)])
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
                agent: agent_name.map(|n| AgentDecl { name: n.into(), operator: "op".into() }),
                kind: kind.clone(),
                navigation: nav,
                hostname: "cyber.page".into(),
                pathname: path.into(),
                referrer: None,
                utm: None,
                attention: (att > 0).then_some(lytics_event::Attention { ms: att, scroll_depth: 0 }),
                props: None,
                revenue: None,
                timestamp: ts,
            },
            event_hash: format!("{neuron}-{path}-{ts}-{kind:?}"),
            attribution: Attribution { source: None, channel: Channel::Direct },
            device: Device { browser: None, browser_version: None, os: None, device: None },
            geo: None,
            received_at: ts,
        }
    }

    fn pv(neuron: &str, path: &str, ts: u64) -> Stored {
        ev(neuron, path, ts, Kind::Pageview, Some(Navigation::External), 0, Actor::Human, None)
    }
    fn attn(neuron: &str, path: &str, ts: u64, ms: u64) -> Stored {
        ev(neuron, path, ts, Kind::Attention, None, ms, Actor::Human, None)
    }
    fn with_geo(mut s: Stored, country: &str) -> Stored {
        s.geo = Some(Geo { country: Some(country.into()), region: None, city: None });
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
            ev("n3", "/c", 1300, Kind::Pageview, Some(Navigation::External), 0, Actor::Agent, Some("bot")),
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
        v.as_array_mut().unwrap().sort_by(|a, b| {
            a["pathname"].as_str().cmp(&b["pathname"].as_str())
        });
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
            ev("n2", "/b", 1200, Kind::Pageview, Some(Navigation::External), 0, Actor::Agent, Some("claude")),
            ev("n2", "/c", 1300, Kind::Pageview, Some(Navigation::External), 0, Actor::Agent, Some("claude")),
            ev("n3", "/d", 1400, Kind::Pageview, Some(Navigation::External), 0, Actor::Agent, Some("perplexity")),
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
        assert_eq!(us["events"], 3);
        assert_eq!(us["neurons"], 2);
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
        v.as_array_mut().unwrap().sort_by(|a, b| {
            a["t"].as_u64().cmp(&b["t"].as_u64())
        });
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
}
