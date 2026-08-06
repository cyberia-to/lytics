// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! product-juice reports that don't need datalog: frequency shape,
//! path transitions, and live presence. pure rust over `&[Stored]`.

use crate::reports::Stored;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn short_neuron(n: &str) -> String {
    if n.len() <= 12 {
        n.to_string()
    } else {
        format!("{}…{}", &n[..6], &n[n.len() - 4..])
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn hist_buckets(values: &[u64], ranges: &[(u64, u64, &str)]) -> Vec<serde_json::Value> {
    ranges
        .iter()
        .map(|(lo, hi, label)| {
            let neurons = values.iter().filter(|&&v| v >= *lo && v <= *hi).count() as u64;
            json!({
                "label": *label,
                "min": lo,
                "max": if *hi == u64::MAX { serde_json::Value::Null } else { json!(hi) },
                "neurons": neurons,
            })
        })
        .collect()
}

/// events grouped per neuron, ordered by timestamp.
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

/// visits/days-active distribution per neuron — "one whale or healthy tail?".
pub fn frequency(events: &[&Stored]) -> serde_json::Value {
    const DAY_MS: u64 = 86_400_000;
    let mut arrivals: BTreeMap<&str, u64> = BTreeMap::new();
    let mut days: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    let mut views: BTreeMap<&str, u64> = BTreeMap::new();
    let mut att: BTreeMap<&str, u64> = BTreeMap::new();
    let mut neurons: BTreeSet<&str> = BTreeSet::new();

    for e in events {
        let n = e.body.neuron.as_str();
        neurons.insert(n);
        days.entry(n).or_default().insert(e.body.timestamp / DAY_MS);
        if e.is_arrival() {
            *arrivals.entry(n).or_default() += 1;
        }
        if e.is_pageview() {
            *views.entry(n).or_default() += 1;
        }
        *att.entry(n).or_default() += e.attention_ms();
    }

    // visits = arrivals; active with no arrival counts as 1 (mid-stream open).
    let mut per: Vec<(String, u64, u64, u64, u64)> = neurons
        .iter()
        .map(|n| {
            let v = match arrivals.get(n).copied().unwrap_or(0) {
                0 => 1,
                x => x,
            };
            let d = days.get(n).map(|s| s.len() as u64).unwrap_or(0);
            let vw = views.get(n).copied().unwrap_or(0);
            let a = att.get(n).copied().unwrap_or(0);
            ((*n).to_string(), v, d, vw, a)
        })
        .collect();

    let mut visit_vals: Vec<u64> = per.iter().map(|r| r.1).collect();
    visit_vals.sort_unstable();
    let mut day_vals: Vec<u64> = per.iter().map(|r| r.2).collect();
    day_vals.sort_unstable();

    let visit_buckets = hist_buckets(
        &visit_vals,
        &[
            (1, 1, "1"),
            (2, 3, "2–3"),
            (4, 7, "4–7"),
            (8, 15, "8–15"),
            (16, 31, "16–31"),
            (32, u64::MAX, "32+"),
        ],
    );
    let day_buckets = hist_buckets(
        &day_vals,
        &[
            (1, 1, "1"),
            (2, 3, "2–3"),
            (4, 7, "4–7"),
            (8, 14, "8–14"),
            (15, u64::MAX, "15+"),
        ],
    );

    per.sort_by(|a, b| b.1.cmp(&a.1).then(b.4.cmp(&a.4)));
    let top: Vec<_> = per
        .iter()
        .take(10)
        .map(|(n, v, d, vw, a)| {
            json!({
                "neuron": short_neuron(n),
                "visits": v,
                "days": d,
                "views": vw,
                "attention_ms": a,
            })
        })
        .collect();

    json!({
        "neurons": neurons.len(),
        "visits": {
            "buckets": visit_buckets,
            "median": percentile(&visit_vals, 0.5),
            "p90": percentile(&visit_vals, 0.9),
            "max": visit_vals.last().copied().unwrap_or(0),
        },
        "days": {
            "buckets": day_buckets,
            "median": percentile(&day_vals, 0.5),
            "p90": percentile(&day_vals, 0.9),
            "max": day_vals.last().copied().unwrap_or(0),
        },
        "top": top,
    })
}

/// consecutive pageview transitions inside passages.
pub fn pathflow(events: &[&Stored], limit: usize) -> serde_json::Value {
    // walk each neuron's stream, splitting passages on arrival boundaries
    // (same model as reports::passages).
    let mut edges: BTreeMap<(String, String), (u64, BTreeSet<String>)> = BTreeMap::new();
    let mut entry_n: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut exit_n: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut through_n: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (neuron, list) in per_neuron(events) {
        let mut pages: Vec<String> = Vec::new();
        let flush = |pages: &mut Vec<String>,
                     edges: &mut BTreeMap<(String, String), (u64, BTreeSet<String>)>,
                     entry_n: &mut BTreeMap<String, BTreeSet<String>>,
                     exit_n: &mut BTreeMap<String, BTreeSet<String>>,
                     through_n: &mut BTreeMap<String, BTreeSet<String>>,
                     neuron: &str| {
            if pages.is_empty() {
                return;
            }
            // collapse consecutive identical paths (refresh spam)
            pages.dedup();
            entry_n
                .entry(pages[0].clone())
                .or_default()
                .insert(neuron.to_string());
            exit_n
                .entry(pages[pages.len() - 1].clone())
                .or_default()
                .insert(neuron.to_string());
            for p in pages.iter() {
                through_n
                    .entry(p.clone())
                    .or_default()
                    .insert(neuron.to_string());
            }
            for w in pages.windows(2) {
                if w[0] == w[1] {
                    continue;
                }
                let slot = edges.entry((w[0].clone(), w[1].clone())).or_default();
                slot.0 += 1;
                slot.1.insert(neuron.to_string());
            }
            pages.clear();
        };

        for e in list {
            if e.is_arrival() && !pages.is_empty() {
                flush(
                    &mut pages,
                    &mut edges,
                    &mut entry_n,
                    &mut exit_n,
                    &mut through_n,
                    neuron,
                );
            }
            if e.is_pageview() {
                pages.push(e.body.pathname.clone());
            }
        }
        flush(
            &mut pages,
            &mut edges,
            &mut entry_n,
            &mut exit_n,
            &mut through_n,
            neuron,
        );
    }

    let mut edge_rows: Vec<_> = edges
        .into_iter()
        .map(|((from, to), (transitions, ns))| {
            let neurons = ns.len() as u64;
            (from, to, transitions, neurons)
        })
        .collect();
    edge_rows.sort_by(|a, b| b.3.cmp(&a.3).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    edge_rows.truncate(limit);

    let mut node_keys: BTreeSet<String> = BTreeSet::new();
    for (f, t, _, _) in &edge_rows {
        node_keys.insert(f.clone());
        node_keys.insert(t.clone());
    }
    let mut entries_ranked: Vec<_> = entry_n
        .iter()
        .map(|(p, ns)| (p.clone(), ns.len() as u64))
        .collect();
    entries_ranked.sort_by(|a, b| b.1.cmp(&a.1));
    for (p, _) in entries_ranked.iter().take(8) {
        node_keys.insert(p.clone());
    }

    let nodes: Vec<_> = node_keys
        .into_iter()
        .map(|path| {
            json!({
                "path": path.clone(),
                "entries": entry_n.get(&path).map(|s| s.len()).unwrap_or(0),
                "exits": exit_n.get(&path).map(|s| s.len()).unwrap_or(0),
                "neurons": through_n.get(&path).map(|s| s.len()).unwrap_or(0),
            })
        })
        .collect();

    json!({
        "edges": edge_rows.into_iter().map(|(from, to, transitions, neurons)| json!({
            "from": from,
            "to": to,
            "transitions": transitions,
            "neurons": neurons,
        })).collect::<Vec<_>>(),
        "nodes": nodes,
    })
}

/// who's active right now — last `horizon_ms` of activity.
pub fn live(events: &[&Stored], now_ms: u64, horizon_ms: u64) -> serde_json::Value {
    let from = now_ms.saturating_sub(horizon_ms);
    let recent: Vec<&&Stored> = events
        .iter()
        .filter(|e| e.body.timestamp >= from && e.body.timestamp <= now_ms)
        .collect();

    struct Agg {
        last_ts: u64,
        last_path: String,
        views: u64,
        attention_ms: u64,
        country: String,
    }

    let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
    for e in &recent {
        let n = e.body.neuron.as_str();
        let entry = by.entry(n).or_insert_with(|| Agg {
            last_ts: 0,
            last_path: "—".into(),
            views: 0,
            attention_ms: 0,
            country: "—".into(),
        });
        if e.body.timestamp >= entry.last_ts {
            entry.last_ts = e.body.timestamp;
            if e.is_pageview() {
                entry.last_path = e.body.pathname.clone();
            }
            if let Some(c) = e.geo.as_ref().and_then(|g| g.country.as_deref()) {
                entry.country = c.to_string();
            }
        }
        if e.is_pageview() {
            entry.views += 1;
        }
        entry.attention_ms += e.attention_ms();
    }

    let mut rows: Vec<_> = by
        .into_iter()
        .map(|(neuron, a)| {
            json!({
                "neuron": short_neuron(neuron),
                "last_ts": a.last_ts,
                "path": a.last_path,
                "views": a.views,
                "attention_ms": a.attention_ms,
                "country": a.country,
                "ago_ms": now_ms.saturating_sub(a.last_ts),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b["last_ts"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["last_ts"].as_u64().unwrap_or(0))
    });
    let active = rows.len();
    let views: u64 = recent.iter().filter(|e| e.is_pageview()).count() as u64;
    let attention_ms: u64 = recent.iter().map(|e| e.attention_ms()).sum();

    json!({
        "horizon_ms": horizon_ms,
        "as_of": now_ms,
        "active": active,
        "views": views,
        "attention_ms": attention_ms,
        "neurons": rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{Attribution, Channel, Device};
    use lytics_event::{EventBody, Kind, Navigation};

    fn pv(neuron: &str, path: &str, ts: u64, nav: Navigation) -> Stored {
        Stored {
            body: EventBody {
                neuron: neuron.into(),
                actor: lytics_event::Actor::Human,
                agent: None,
                kind: Kind::Pageview,
                navigation: Some(nav),
                hostname: "cyber.page".into(),
                pathname: path.into(),
                referrer: None,
                utm: None,
                attention: None,
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
    fn frequency_buckets_a_whale_and_a_one_timer() {
        let events = [
            pv("whale", "/", 1000, Navigation::External),
            pv("whale", "/a", 1100, Navigation::Internal),
            pv("whale", "/", 2000, Navigation::External),
            pv("once", "/", 3000, Navigation::External),
        ];
        let r: Vec<&Stored> = events.iter().collect();
        let out = frequency(&r);
        assert_eq!(out["neurons"], 2);
        assert_eq!(out["visits"]["max"], 2);
        let buckets = out["visits"]["buckets"].as_array().unwrap();
        let one = buckets.iter().find(|b| b["label"] == "1").unwrap();
        let two = buckets.iter().find(|b| b["label"] == "2–3").unwrap();
        assert_eq!(one["neurons"], 1);
        assert_eq!(two["neurons"], 1);
    }

    #[test]
    fn pathflow_records_entry_to_next() {
        let events = [
            pv("n1", "/", 1000, Navigation::External),
            pv("n1", "/tokens", 1100, Navigation::Internal),
            pv("n1", "/token/usd", 1200, Navigation::Internal),
            pv("n2", "/", 2000, Navigation::External),
            pv("n2", "/tokens", 2100, Navigation::Internal),
        ];
        let r: Vec<&Stored> = events.iter().collect();
        let out = pathflow(&r, 20);
        let edges = out["edges"].as_array().unwrap();
        assert!(
            edges
                .iter()
                .any(|e| e["from"] == "/" && e["to"] == "/tokens" && e["neurons"] == 2),
            "expected / → /tokens for 2 neurons, got {edges:?}"
        );
        assert!(
            edges
                .iter()
                .any(|e| e["from"] == "/tokens" && e["to"] == "/token/usd"),
            "expected /tokens → /token/usd"
        );
    }

    #[test]
    fn live_lists_recent_only() {
        let events = [
            pv("old", "/", 1000, Navigation::External),
            pv("now", "/tokens", 10_000, Navigation::External),
        ];
        let r: Vec<&Stored> = events.iter().collect();
        let out = live(&r, 10_500, 2000); // horizon covers only `now`
        assert_eq!(out["active"], 1);
        assert_eq!(out["neurons"][0]["path"], "/tokens");
    }
}
