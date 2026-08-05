// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! read-time projections over the append-only event stream.
//!
//! arrivals, passages and windows per the attention model — no sessions,
//! no timeouts. all arithmetic is integer; ratios are rendered at the
//! dashboard edge.
//!
//! `inf_reports` answers every one of these reports through real inf
//! datalog now — `main.rs` calls only `inf_reports::` functions. everything
//! below `Stored`/`in_window` is `#[cfg(test)]`: it exists solely as the
//! differential-testing oracle `inf_reports.rs`'s tests compare against, and
//! is not part of the release binary at all — not dead code kept around out
//! of caution, genuinely absent from a non-test build.

use crate::enrich::{Attribution, Device};
use lytics_event::{EventBody, Kind, Navigation};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use lytics_event::Actor;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

/// a stored, enriched event — payload-log plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    pub body: EventBody,
    pub event_hash: String,
    pub attribution: Attribution,
    pub device: Device,
    #[serde(default)]
    pub geo: Option<crate::geo::Geo>,
    pub received_at: u64,
}

impl Stored {
    pub fn is_pageview(&self) -> bool {
        self.body.kind == Kind::Pageview
    }

    /// arrival: a pageview whose navigation is external or direct, or that
    /// carries utm. attribution attaches here.
    pub fn is_arrival(&self) -> bool {
        self.is_pageview()
            && (matches!(
                self.body.navigation,
                Some(Navigation::External) | Some(Navigation::Direct)
            ) || self.body.utm.is_some())
    }

    pub fn attention_ms(&self) -> u64 {
        self.body.attention.map(|a| a.ms).unwrap_or(0)
    }
}

pub fn in_window(events: &[Stored], from: u64, to: u64) -> Vec<&Stored> {
    events
        .iter()
        .filter(|e| e.body.timestamp >= from && e.body.timestamp < to)
        .collect()
}

/// events grouped per neuron, ordered by timestamp.
#[cfg(test)]
fn per_neuron<'a>(events: &[&'a Stored]) -> BTreeMap<&'a str, Vec<&'a Stored>> {
    let mut map: BTreeMap<&str, Vec<&Stored>> = BTreeMap::new();
    for e in events {
        map.entry(e.body.neuron.as_str()).or_default().push(e);
    }
    for list in map.values_mut() {
        list.sort_by_key(|e| e.body.timestamp);
    }
    map
}

/// a passage: the run of a neuron's events from one arrival to the next.
/// a stream that opens without an observed arrival still opens a passage —
/// the first event is where the run began, arrival or no.
#[cfg(test)]
pub struct Passage<'a> {
    pub events: Vec<&'a Stored>,
}

#[cfg(test)]
impl Passage<'_> {
    pub fn views(&self) -> usize {
        self.events.iter().filter(|e| e.is_pageview()).count()
    }
    pub fn entry(&self) -> Option<&str> {
        self.events
            .iter()
            .find(|e| e.is_pageview())
            .map(|e| e.body.pathname.as_str())
    }
    pub fn exit(&self) -> Option<&str> {
        self.events
            .iter()
            .rev()
            .find(|e| e.is_pageview())
            .map(|e| e.body.pathname.as_str())
    }
}

#[cfg(test)]
pub fn passages<'a>(events: &[&'a Stored]) -> Vec<Passage<'a>> {
    let mut out = Vec::new();
    for (_neuron, list) in per_neuron(events) {
        let mut current: Vec<&Stored> = Vec::new();
        for e in list {
            if e.is_arrival() && !current.is_empty() {
                out.push(Passage {
                    events: std::mem::take(&mut current),
                });
            }
            current.push(e);
        }
        if !current.is_empty() {
            out.push(Passage { events: current });
        }
    }
    out
}

#[cfg(test)]
fn distinct_neurons(events: &[&Stored]) -> usize {
    events
        .iter()
        .map(|e| e.body.neuron.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
pub fn overview(events: &[&Stored]) -> serde_json::Value {
    let views = events.iter().filter(|e| e.is_pageview()).count();
    let attention: u64 = events.iter().map(|e| e.attention_ms()).sum();
    let agents = events
        .iter()
        .filter(|e| e.body.actor == Actor::Agent)
        .map(|e| e.body.neuron.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    // visit = passage (stream from one external entry to the next). arrivals
    // stay an internal event label for attribution; the public count is visits.
    let p = passages(events);
    let visits = p.len();
    // depth / dwell: pageviews and attention per visit (integer milli-precision)
    let views_per_visit_milli = if visits > 0 {
        (views as u64 * 1000) / visits as u64
    } else {
        0
    };
    let attention_ms_per_visit = if visits > 0 {
        attention / visits as u64
    } else {
        0
    };
    // single-page visits (classic bounce-shaped, but visit-bounded)
    let single_page_visits = p.iter().filter(|v| v.views() <= 1).count();
    json!({
        "neurons": distinct_neurons(events),
        "views": views,
        "visits": visits,
        "attention_ms": attention,
        "agent_neurons": agents,
        "views_per_visit_milli": views_per_visit_milli,
        "attention_ms_per_visit": attention_ms_per_visit,
        "single_page_visits": single_page_visits,
    })
}

/// bucket ms: "hour" or "day".
#[cfg(test)]
pub fn timeseries(events: &[&Stored], bucket_ms: u64) -> serde_json::Value {
    let mut buckets: BTreeMap<u64, (BTreeSet<&str>, u64, u64)> = BTreeMap::new();
    for e in events {
        let b = e.body.timestamp / bucket_ms * bucket_ms;
        let slot = buckets.entry(b).or_default();
        slot.0.insert(e.body.neuron.as_str());
        if e.is_pageview() {
            slot.1 += 1;
        }
        slot.2 += e.attention_ms();
    }
    let rows: Vec<_> = buckets
        .into_iter()
        .map(|(t, (n, pv, att))| json!({"t": t, "neurons": n.len(), "views": pv, "attention_ms": att}))
        .collect();
    json!(rows)
}

#[cfg(test)]
fn top_counts<'a, F: Fn(&&'a Stored) -> Option<String>>(
    events: &[&'a Stored],
    key: F,
    limit: usize,
) -> Vec<(String, u64)> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for e in events {
        if let Some(k) = key(e) {
            *counts.entry(k).or_default() += 1;
        }
    }
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    rows
}

/// top particles by views — each pathname is a particle (`graph::page_particle`
/// hashes hostname+pathname); `pathname` here is the particle's human-readable
/// name, not its hash.
#[cfg(test)]
pub fn particles(events: &[&Stored], limit: usize) -> serde_json::Value {
    let mut attention: BTreeMap<String, u64> = BTreeMap::new();
    for e in events {
        *attention.entry(e.body.pathname.clone()).or_default() += e.attention_ms();
    }
    let rows = top_counts(
        events,
        |e| e.is_pageview().then(|| e.body.pathname.clone()),
        limit,
    );
    let out: Vec<_> = rows
        .into_iter()
        .map(|(path, pv)| {
            let att = attention.get(&path).copied().unwrap_or(0);
            json!({"pathname": path, "views": pv, "attention_ms": att})
        })
        .collect();
    json!(out)
}

/// visits by source, with views + attention rolled up from each visit's events.
#[cfg(test)]
pub fn sources(events: &[&Stored], limit: usize) -> serde_json::Value {
    visit_breakdown(events, limit, |e| {
        e.attribution
            .source
            .clone()
            .unwrap_or_else(|| "direct".into())
    })
}

/// visits by channel (same rollup as sources).
#[cfg(test)]
pub fn channels(events: &[&Stored]) -> serde_json::Value {
    visit_breakdown(events, 32, |e| {
        format!("{:?}", e.attribution.channel).to_lowercase()
    })
}

/// group visits by a key taken from the visit's first arrival (or first event).
#[cfg(test)]
fn visit_breakdown<F: Fn(&Stored) -> String>(
    events: &[&Stored],
    limit: usize,
    key_of: F,
) -> serde_json::Value {
    // source key → (visits, views, attention_ms)
    let mut map: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for pass in passages(events) {
        let key = pass
            .events
            .iter()
            .find(|e| e.is_arrival())
            .or_else(|| pass.events.first())
            .map(|e| key_of(e))
            .unwrap_or_else(|| "unknown".into());
        let slot = map.entry(key).or_default();
        slot.0 += 1;
        slot.1 += pass.views() as u64;
        slot.2 += pass.events.iter().map(|e| e.attention_ms()).sum::<u64>();
    }
    let mut rows: Vec<_> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(&b.0)));
    rows.truncate(limit);
    json!(
        rows.into_iter()
            .map(|(k, (visits, views, att))| {
                let vpv_milli = (views * 1000).checked_div(visits).unwrap_or(0);
                let att_pv = att.checked_div(visits).unwrap_or(0);
                json!({
                    "key": k,
                    "source": k,
                    "channel": k,
                    "visits": visits,
                    "views": views,
                    "attention_ms": att,
                    "views_per_visit_milli": vpv_milli,
                    "attention_ms_per_visit": att_pv,
                })
            })
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
pub fn actors(events: &[&Stored]) -> serde_json::Value {
    let humans: Vec<&Stored> = events
        .iter()
        .filter(|e| e.body.actor == Actor::Human)
        .copied()
        .collect();
    let agents: Vec<&Stored> = events
        .iter()
        .filter(|e| e.body.actor == Actor::Agent)
        .copied()
        .collect();
    let agent_names = top_counts(
        &agents,
        |e| e.body.agent.as_ref().map(|a| a.name.clone()),
        16,
    );
    json!({
        "human": {"neurons": distinct_neurons(&humans), "views": humans.iter().filter(|e| e.is_pageview()).count(), "attention_ms": humans.iter().map(|e| e.attention_ms()).sum::<u64>()},
        "agent": {"neurons": distinct_neurons(&agents), "views": agents.iter().filter(|e| e.is_pageview()).count(), "declared": agent_names.into_iter().map(|(n, c)| json!({"name": n, "views": c})).collect::<Vec<_>>()},
    })
}

#[cfg(test)]
pub fn countries(events: &[&Stored], limit: usize) -> serde_json::Value {
    let mut neurons: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for e in events {
        if let Some(geo) = &e.geo
            && let Some(c) = &geo.country {
                neurons
                    .entry(c.clone())
                    .or_default()
                    .insert(e.body.neuron.as_str());
            }
    }
    let rows = top_counts(
        events,
        |e| e.geo.as_ref().and_then(|g| g.country.clone()),
        limit,
    );
    json!(
        rows.into_iter()
            .map(|(c, n)| {
                let distinct = neurons.get(&c).map(|s| s.len()).unwrap_or(0);
                json!({"country": c, "events": n, "neurons": distinct})
            })
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
pub fn devices(events: &[&Stored], limit: usize) -> serde_json::Value {
    let browsers = top_counts(events, |e| e.device.browser.clone(), limit);
    let oses = top_counts(events, |e| e.device.os.clone(), limit);
    let classes = top_counts(events, |e| e.device.device.clone(), limit);
    json!({
        "browsers": browsers.into_iter().map(|(k, n)| json!({"browser": k, "events": n})).collect::<Vec<_>>(),
        "os": oses.into_iter().map(|(k, n)| json!({"os": k, "events": n})).collect::<Vec<_>>(),
        "classes": classes.into_iter().map(|(k, n)| json!({"class": k, "events": n})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
const WEEK_MS: u64 = 7 * 24 * 3600 * 1000;

/// retention matrix over ALL events (cohorts need full history):
/// cohort week (first-seen) × week offset → distinct neurons active.
#[cfg(test)]
pub fn retention(events: &[Stored], weeks: usize) -> serde_json::Value {
    let mut first_seen: BTreeMap<&str, u64> = BTreeMap::new();
    for e in events {
        let entry = first_seen
            .entry(e.body.neuron.as_str())
            .or_insert(e.body.timestamp);
        if e.body.timestamp < *entry {
            *entry = e.body.timestamp;
        }
    }
    // cohort week → offset → set of neurons
    let mut matrix: BTreeMap<u64, BTreeMap<u64, BTreeSet<&str>>> = BTreeMap::new();
    for e in events {
        let first = first_seen[e.body.neuron.as_str()];
        let cohort = first / WEEK_MS;
        let offset = e.body.timestamp / WEEK_MS - cohort;
        if (offset as usize) < weeks {
            matrix
                .entry(cohort)
                .or_default()
                .entry(offset)
                .or_default()
                .insert(&e.body.neuron);
        }
    }
    let rows: Vec<_> = matrix
        .into_iter()
        .map(|(cohort, offsets)| {
            let size = offsets.get(&0).map(|s| s.len()).unwrap_or(0);
            let cells: Vec<usize> =
                (0..weeks as u64).map(|o| offsets.get(&o).map(|s| s.len()).unwrap_or(0)).collect();
            json!({"cohort_week": cohort, "cohort_start_ms": cohort * WEEK_MS, "size": size, "weeks": cells})
        })
        .collect();
    json!(rows)
}

/// ordered funnel: how many neurons complete each prefix of `steps`
/// (pathnames) within the window.
#[cfg(test)]
pub fn funnel(events: &[&Stored], steps: &[String]) -> serde_json::Value {
    if steps.is_empty() {
        return json!([]);
    }
    let mut reached = vec![0usize; steps.len()];
    for (_neuron, list) in per_neuron(events) {
        let mut at = 0usize;
        for e in list {
            if at < steps.len() && e.is_pageview() && e.body.pathname == steps[at] {
                at += 1;
            }
        }
        for slot in reached.iter_mut().take(at) {
            *slot += 1;
        }
    }
    json!(
        steps
            .iter()
            .zip(reached)
            .map(|(s, n)| json!({"step": s, "neurons": n}))
            .collect::<Vec<_>>()
    )
}

/// return probability: of neurons first seen in [from, to), how many came
/// back within `horizon_ms` after their first event. integers only —
/// (returned, total) — the ratio renders at the edge.
#[cfg(test)]
pub fn returns(events: &[Stored], from: u64, to: u64, horizon_ms: u64) -> serde_json::Value {
    let mut first_seen: BTreeMap<&str, u64> = BTreeMap::new();
    for e in events {
        let entry = first_seen
            .entry(e.body.neuron.as_str())
            .or_insert(e.body.timestamp);
        if e.body.timestamp < *entry {
            *entry = e.body.timestamp;
        }
    }
    let cohort: BTreeMap<&str, u64> = first_seen
        .into_iter()
        .filter(|(_, t)| *t >= from && *t < to)
        .collect();
    let mut returned: BTreeSet<&str> = BTreeSet::new();
    for e in events {
        if let Some(first) = cohort.get(e.body.neuron.as_str())
            && e.body.timestamp > *first && e.body.timestamp <= first + horizon_ms {
                returned.insert(&e.body.neuron);
            }
    }
    json!({"cohort": cohort.len(), "returned": returned.len(), "horizon_ms": horizon_ms})
}

#[cfg(test)]
pub fn passages_report(events: &[&Stored], limit: usize) -> serde_json::Value {
    let p = passages(events);
    let total = p.len();
    let views_total: usize = p.iter().map(|x| x.views()).sum();
    let mut entries: BTreeMap<String, u64> = BTreeMap::new();
    let mut exits: BTreeMap<String, u64> = BTreeMap::new();
    for x in &p {
        if let Some(e) = x.entry() {
            *entries.entry(e.to_string()).or_default() += 1;
        }
        if let Some(e) = x.exit() {
            *exits.entry(e.to_string()).or_default() += 1;
        }
    }
    let top = |m: BTreeMap<String, u64>| {
        let mut rows: Vec<_> = m.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows.into_iter()
            .map(|(k, n)| json!({"pathname": k, "passages": n}))
            .collect::<Vec<_>>()
    };
    json!({
        "passages": total,
        "views_total": views_total,
        "entries": top(entries),
        "exits": top(exits),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::Channel;
    use lytics_event::event::Utm;

    fn ev(neuron: &str, path: &str, ts: u64, nav: Option<Navigation>, att: u64) -> Stored {
        Stored {
            body: EventBody {
                neuron: neuron.into(),
                actor: Actor::Human,
                agent: None,
                kind: if att > 0 {
                    Kind::Attention
                } else {
                    Kind::Pageview
                },
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
            event_hash: format!("{neuron}-{path}-{ts}"),
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

    #[test]
    fn passages_split_on_arrivals_never_on_pauses() {
        let events = [
            ev("n1", "/a", 1000, Some(Navigation::External), 0),
            // a six-hour pause — same passage, no timeout exists
            ev(
                "n1",
                "/b",
                1000 + 6 * 3600 * 1000,
                Some(Navigation::Internal),
                0,
            ),
            // a new arrival — new passage
            ev(
                "n1",
                "/c",
                1000 + 7 * 3600 * 1000,
                Some(Navigation::External),
                0,
            ),
        ];
        let refs: Vec<&Stored> = events.iter().collect();
        let p = passages(&refs);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].views(), 2);
        assert_eq!(p[0].entry(), Some("/a"));
        assert_eq!(p[0].exit(), Some("/b"));
        assert_eq!(p[1].entry(), Some("/c"));
    }

    #[test]
    fn utm_pageview_is_arrival() {
        let mut e = ev("n1", "/a", 1, Some(Navigation::Internal), 0);
        e.body.utm = Some(Utm {
            source: Some("nl".into()),
            medium: None,
            campaign: None,
            term: None,
            content: None,
        });
        assert!(e.is_arrival());
    }

    #[test]
    fn funnel_counts_ordered_prefixes() {
        let events = [
            ev("n1", "/a", 1, Some(Navigation::External), 0),
            ev("n1", "/b", 2, Some(Navigation::Internal), 0),
            ev("n2", "/a", 1, Some(Navigation::External), 0),
            ev("n3", "/b", 1, Some(Navigation::External), 0), // out of order: /b before /a
        ];
        let refs: Vec<&Stored> = events.iter().collect();
        let f = funnel(&refs, &["/a".into(), "/b".into()]);
        let rows = f.as_array().unwrap();
        assert_eq!(rows[0]["neurons"], 2); // n1, n2 reached /a
        assert_eq!(rows[1]["neurons"], 1); // only n1 continued to /b
    }

    #[test]
    fn retention_places_neurons_in_cohorts() {
        let w = WEEK_MS;
        let events = vec![
            ev("n1", "/", 0, Some(Navigation::External), 0),
            ev("n1", "/", w + 10, Some(Navigation::External), 0), // returns week 1
            ev("n2", "/", 5, Some(Navigation::External), 0),      // never returns
        ];
        let r = retention(&events, 4);
        let rows = r.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["size"], 2);
        assert_eq!(rows[0]["weeks"][0], 2);
        assert_eq!(rows[0]["weeks"][1], 1);
    }

    #[test]
    fn returns_counts_cohort_and_returned() {
        let events = vec![
            ev("n1", "/", 100, Some(Navigation::External), 0),
            ev("n1", "/", 200, Some(Navigation::External), 0),
            ev("n2", "/", 150, Some(Navigation::External), 0),
        ];
        let r = returns(&events, 0, 1000, 1000);
        assert_eq!(r["cohort"], 2);
        assert_eq!(r["returned"], 1);
    }

    #[test]
    fn attention_sums_into_overview() {
        let events = [ev("n1", "/a", 1, Some(Navigation::External), 0),
            ev("n1", "/a", 2, None, 42_000)];
        let refs: Vec<&Stored> = events.iter().collect();
        let o = overview(&refs);
        assert_eq!(o["attention_ms"], 42_000);
        assert_eq!(o["views"], 1);
        assert_eq!(o["neurons"], 1);
    }
}
