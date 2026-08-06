// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! lytics ingest — the engine: verify → enrich → append → cast → report.
//!
//! spec: lytics/specs/README.md. the payload log is the source of truth;
//! the cell and the in-memory index are replayed from it at startup.

mod enrich;
mod geo;
mod graph;
mod inf_reports;
mod reports;
mod store;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{delete, get, post};
use cybergraph::Cybergraph;
use lytics_event::{Event, event_hash, pow_verify, sig_verify, target_from_difficulty};
use reports::Stored;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;
const STALE_HORIZON_MS: u64 = 24 * 3600 * 1000;
const DEFAULT_EVENT_HASHES: u64 = 3000;
const DEFAULT_ENROLL_MULT: u64 = 100;

struct Cfg {
    hrp: String,
    event_target: u64,
    enroll_target: u64,
    owner_token: String,
}

struct App {
    cfg: Cfg,
    geo: Option<geo::GeoDb>,
    store: store::Store,
    cell: Cybergraph,
    chains: graph::Chains,
    events: Vec<Stored>,
    seen: BTreeSet<[u8; 32]>,
    /// bumped on every mutation to `events` after boot (accept, shred) — a
    /// report cached at a given version is exactly the query inf would
    /// still return, because nothing it could read has changed since.
    data_version: u64,
    /// full report responses keyed by (report name, query params as
    /// received). inf's passage-grouping queries genuinely need this: the
    /// running-count self-join `passage_ids` uses is real work every time
    /// it runs (unindexed inequality join, worse than the Rust loop it
    /// replaced at scale) — repeat GETs of an unchanged window (a dashboard
    /// polling in real time, mostly between actual new events) should not
    /// pay for it again. never served across a version bump.
    report_cache: BTreeMap<(String, String), (u64, serde_json::Value)>,
}

type Shared = Arc<Mutex<App>>;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
enum Reject {
    Bad(String),
    Auth(String),
    Pow(String),
}

impl Reject {
    fn respond(self) -> (StatusCode, Json<serde_json::Value>) {
        match self {
            Reject::Bad(m) => (StatusCode::BAD_REQUEST, Json(json!({"error": m}))),
            Reject::Auth(m) => (StatusCode::UNAUTHORIZED, Json(json!({"error": m}))),
            Reject::Pow(m) => (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": m}))),
        }
    }
}

/// the verification pipeline — spec order: canonical → dedup → skew →
/// signature → pow (enrollment target for unseen neurons) → enrich → append
/// → cast.
fn ingest(
    app: &mut App,
    event: Event,
    ua: Option<&str>,
    ip: Option<std::net::IpAddr>,
) -> Result<(&'static str, String), Reject> {
    let body_bytes = event.body_bytes();
    let hash = event_hash(&body_bytes);
    let hash_hex = hex::encode(hash);

    // idempotency is the dedup: same particle, no-op
    if app.seen.contains(&hash) {
        return Ok(("duplicate", hash_hex));
    }

    // timestamps bound skew, never history
    let now = now_ms();
    if event.body.timestamp > now + FUTURE_SKEW_MS {
        return Err(Reject::Bad("timestamp from the future".into()));
    }
    if event.body.timestamp + STALE_HORIZON_MS < now {
        return Err(Reject::Bad("timestamp beyond the stale horizon".into()));
    }

    sig_verify(
        &body_bytes,
        &event.body.neuron,
        &event.pubkey,
        &event.signature,
        &app.cfg.hrp,
    )
    .map_err(|e| Reject::Auth(e.to_string()))?;

    // server target — client-reported difficulty is a record, not an input
    let target = if app.store.known(&event.body.neuron) {
        app.cfg.event_target
    } else {
        app.cfg.enroll_target
    };
    if !pow_verify(&hash, event.pow.nonce, target) {
        return Err(Reject::Pow("insufficient work".into()));
    }

    let attribution = enrich::attribute(&event.body);
    let device = enrich::parse_ua(ua);
    // ip is read, used for one lookup, and discarded — never stored
    let geo = match (&app.geo, ip) {
        (Some(db), Some(ip)) => db.lookup(ip),
        _ => None,
    };
    let native = *hemera::hash(
        &base64_decode(&event.pubkey).ok_or_else(|| Reject::Bad("pubkey b64".into()))?,
    )
    .as_bytes();

    let stored = Stored {
        body: event.body.clone(),
        event_hash: hash_hex.clone(),
        attribution,
        device,
        geo,
        received_at: now,
    };
    let plaintext = serde_json::to_vec(&stored).map_err(|e| Reject::Bad(e.to_string()))?;
    app.store
        .append(&event.body.neuron, &plaintext)
        .map_err(|e| Reject::Bad(e.to_string()))?;

    // bbg's root is lazy now, so casting no longer recommits per insert —
    // it runs inline on the hot path again
    let page = graph::page_particle(&event.body.hostname, &event.body.pathname);
    if let Err(e) = app.chains.cast(
        &mut app.cell,
        native,
        hash,
        page,
        event.body.timestamp / 1000,
    ) {
        eprintln!("cell cast failed for {hash_hex}: {e}");
    }

    app.seen.insert(hash);
    app.events.push(stored);
    app.data_version += 1;
    Ok(("accepted", hash_hex))
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// rebuild index + cell from the payload log. natives are recomputed from
/// stored neuron strings — the cell chain restarts per boot, deterministic
/// because the log order is fixed.
fn replay(app: &mut App) {
    let frames = match app.store.replay() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("replay failed: {e}");
            return;
        }
    };
    for (_neuron, plaintext) in frames {
        let Ok(stored) = serde_json::from_slice::<Stored>(&plaintext) else {
            continue;
        };
        let Ok(raw) = hex::decode(&stored.event_hash) else {
            continue;
        };
        let Ok(hash) = <[u8; 32]>::try_from(raw.as_slice()) else {
            continue;
        };
        // native id for replay: hemera of the bech32 — a stable per-neuron
        // chain id (the pubkey lives only in the wire event)
        let native = *hemera::hash(stored.body.neuron.as_bytes()).as_bytes();
        let page = graph::page_particle(&stored.body.hostname, &stored.body.pathname);
        let _ = app.chains.cast(
            &mut app.cell,
            native,
            hash,
            page,
            stored.body.timestamp / 1000,
        );
        app.seen.insert(hash);
        app.events.push(stored);
    }
    app.events.sort_by_key(|e| e.body.timestamp);
}

// ── handlers ─────────────────────────────────────────────────────────────────

async fn post_event(
    State(state): State<Shared>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(event): Json<Event>,
) -> impl IntoResponse {
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    // first hop of x-forwarded-for when behind a proxy, else the peer
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .or(Some(peer.ip()));
    let mut app = state.lock().expect("lock");
    match ingest(&mut app, event, ua.as_deref(), ip) {
        Ok((status, hash)) => (
            StatusCode::ACCEPTED,
            Json(json!({"status": status, "event": hash})),
        )
            .into_response(),
        Err(r) => r.respond().into_response(),
    }
}

async fn get_difficulty(
    State(state): State<Shared>,
    Query(q): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let app = state.lock().expect("lock");
    let enrolled = q.get("neuron").map(|n| app.store.known(n)).unwrap_or(false);
    Json(json!({
        "event_target": app.cfg.event_target.to_string(),
        "enroll_target": app.cfg.enroll_target.to_string(),
        "enrolled": enrolled,
    }))
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {token}"))
        .unwrap_or(false)
}

async fn delete_neuron(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(neuron): Path<String>,
) -> impl IntoResponse {
    let mut app = state.lock().expect("lock");
    if !authorized(&headers, &app.cfg.owner_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match app.store.shred(&neuron) {
        Ok(_) => {
            app.events.retain(|e| e.body.neuron != neuron);
            app.data_version += 1;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn post_query(
    State(state): State<Shared>,
    headers: HeaderMap,
    script: String,
) -> impl IntoResponse {
    let app = state.lock().expect("lock");
    if !authorized(&headers, &app.cfg.owner_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match app.cell.query(&script) {
        Ok(out) => Json(json!({
            "columns": out.columns,
            "rows": out.rows.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:?}")).into_response(),
    }
}

async fn get_report(
    State(state): State<Shared>,
    Path(name): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let mut app = state.lock().expect("lock");
    let now = now_ms();
    let parse_u64 = |k: &str, d: u64| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let from = parse_u64("from", now.saturating_sub(7 * 24 * 3600 * 1000));
    let to = parse_u64("to", now + 1);
    let limit = parse_u64("limit", 10) as usize;

    // every report is answered by inf_reports:: — a fresh LocalSource built
    // from the same event slice, answered by parse→plan→eval. reports.rs's
    // matching functions still exist, but only under #[cfg(test)]: they are
    // the differential-testing oracle inf_reports's tests compare against,
    // never a fallback the release binary can reach.
    //
    // the passage-grouped reports (sources/channels/passages/funnel,
    // overview's visit fields) run a real self-join to find passage
    // boundaries — measured at ~0.5s per call on 1600 synthetic events, and
    // the naive nested-loop join behind it does not scale gently. a
    // dashboard polling in real time mostly asks the same question again
    // before anything changed, so cache the full response per (report,
    // query params) and only recompute when `data_version` has moved —
    // i.e. an event was actually accepted or shredded since. `from`/`to`/
    // `as_of` are patched onto `overview` fresh below regardless of cache
    // origin — they are wall-clock, not query results, and cheap either way.
    let cache_key = (name.clone(), format!("{q:?}"));
    let cached = app
        .report_cache
        .get(&cache_key)
        .filter(|(ver, _)| *ver == app.data_version)
        .map(|(_, v)| v.clone());

    // audience cut: new = first-seen inside [from,to); returning = first-seen
    // before `from` but active in the window. retention/returns ignore it —
    // they need the full history for cohort math.
    let audience = match q.get("audience").map(String::as_str) {
        Some("new") => "new",
        Some("returning") => "returning",
        _ => "all",
    };

    let mut out = if let Some(v) = cached {
        v
    } else {
        let windowed_all = reports::in_window(&app.events, from, to);
        let first_seen = reports::first_seen(&app.events);
        let windowed = reports::filter_audience(&windowed_all, &first_seen, from, audience);
        let computed = match name.as_str() {
            "overview" => {
                let mut o = inf_reports::overview(&windowed);
                // when unfiltered, attach both slices so the dash can show
                // the new|returning split without a second round-trip.
                if audience == "all"
                    && let Some(obj) = o.as_object_mut()
                {
                    let new_ev = reports::filter_audience(&windowed_all, &first_seen, from, "new");
                    let ret_ev =
                        reports::filter_audience(&windowed_all, &first_seen, from, "returning");
                    obj.insert("new".into(), inf_reports::overview(&new_ev));
                    obj.insert("returning".into(), inf_reports::overview(&ret_ev));
                }
                if let Some(obj) = o.as_object_mut() {
                    obj.insert("audience".into(), json!(audience));
                }
                o
            }
            "timeseries" => {
                let bucket = match q.get("bucket").map(String::as_str) {
                    Some("hour") => 3600 * 1000,
                    _ => 24 * 3600 * 1000,
                };
                inf_reports::timeseries(&windowed, bucket)
            }
            "particles" => inf_reports::particles(&windowed, limit),
            "sources" => inf_reports::sources(&windowed, limit),
            "channels" => inf_reports::channels(&windowed),
            "actors" => inf_reports::actors(&windowed),
            "devices" => inf_reports::devices(&windowed, limit),
            "countries" => inf_reports::countries(&windowed, limit),
            "passages" => inf_reports::passages_report(&windowed, limit),
            "retention" => inf_reports::retention(&app.events, parse_u64("weeks", 8) as usize),
            "returns" => inf_reports::returns(
                &app.events,
                from,
                to,
                parse_u64("horizon_ms", 7 * 24 * 3600 * 1000),
            ),
            "funnel" => {
                let steps: Vec<String> = q
                    .get("steps")
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
                inf_reports::funnel(&windowed, &steps)
            }
            _ => return (StatusCode::NOT_FOUND, "unknown report").into_response(),
        };
        let ver = app.data_version;
        app.report_cache.insert(cache_key, (ver, computed.clone()));
        computed
    };

    if name == "overview"
        && let Some(obj) = out.as_object_mut()
    {
        obj.insert("from".into(), json!(from));
        obj.insert("to".into(), json!(to));
        obj.insert("as_of".into(), json!(now));
    }
    Json(out).into_response()
}

async fn dash() -> Html<&'static str> {
    Html(include_str!("../static/dash.html"))
}

async fn demo() -> Html<&'static str> {
    Html(include_str!("../static/demo.html"))
}

/// serve a tracker asset from LYTICS_STATIC on disk (loader + wasm + bindings)
/// so JS fixes ship without recompiling the binary.
async fn tracker_asset(Path(name): Path<String>) -> impl IntoResponse {
    let mime = |n: &str| {
        if n.ends_with(".wasm") {
            "application/wasm"
        } else {
            "text/javascript"
        }
    };
    let headers = |m: &'static str| {
        [
            (axum::http::header::CONTENT_TYPE, m),
            // short TTL — endpoint/loader fixes must not stick for an hour
            (axum::http::header::CACHE_CONTROL, "public, max-age=60"),
        ]
    };
    const ALLOWED: &[&str] = &[
        "loader.js",
        "lytics_core.js",
        "lytics_core_bg.wasm",
        "words.js",
    ];
    if !ALLOWED.contains(&name.as_str()) {
        return (StatusCode::NOT_FOUND, "unknown asset").into_response();
    }
    let dir = std::env::var("LYTICS_STATIC")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/static/tracker").into());
    match std::fs::read(format!("{dir}/{name}")) {
        Ok(bytes) => (headers(mime(&name)), bytes).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "tracker not built — run build-tracker.sh / deploy static/tracker",
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    let env = |k: &str| std::env::var(k).ok();
    let data_dir = env("LYTICS_DATA").unwrap_or_else(|| "lytics-data".into());
    let port: u16 = env("LYTICS_PORT")
        .and_then(|p| p.parse().ok())
        .unwrap_or(8090);
    let hrp = env("LYTICS_HRP").unwrap_or_else(|| "lytics".into());
    let event_hashes: u64 = env("LYTICS_EVENT_HASHES")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EVENT_HASHES);
    let enroll_mult: u64 = env("LYTICS_ENROLL_MULT")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ENROLL_MULT);
    let owner_token = env("LYTICS_OWNER_TOKEN").unwrap_or_else(|| {
        let t = hex::encode(hemera::hash(format!("{}", now_ms()).as_bytes()).as_bytes());
        eprintln!("LYTICS_OWNER_TOKEN not set — generated: {t}");
        t
    });

    let geo_db = geo::GeoDb::open_default();

    let store = store::Store::open(&data_dir).expect("store");
    let mut app = App {
        cfg: Cfg {
            hrp,
            event_target: target_from_difficulty(event_hashes),
            enroll_target: target_from_difficulty(event_hashes.saturating_mul(enroll_mult)),
            owner_token,
        },
        geo: geo_db,
        store,
        cell: Cybergraph::new(),
        chains: graph::Chains::default(),
        events: Vec::new(),
        seen: BTreeSet::new(),
        data_version: 0,
        report_cache: BTreeMap::new(),
    };
    replay(&mut app);
    eprintln!("replayed {} events", app.events.len());

    let shared: Shared = Arc::new(Mutex::new(app));
    let router = Router::new()
        .route("/", get(dash))
        .route("/demo", get(demo))
        .route("/tracker/{name}", get(tracker_asset))
        .route("/api/event", post(post_event))
        .route("/api/difficulty", get(get_difficulty))
        .route("/api/neuron/{neuron}", delete(delete_neuron))
        .route("/api/query", post(post_query))
        .route("/api/report/{name}", get(get_report))
        .with_state(shared);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("lytics ingest on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use lytics_event::{Actor, EventBody, Kind, Navigation, Pow, Seed, solve};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_app() -> App {
        let dir = std::env::temp_dir().join(format!(
            "lytics-ingest-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        App {
            cfg: Cfg {
                hrp: "lytics".into(),
                event_target: target_from_difficulty(4),
                enroll_target: target_from_difficulty(16),
                owner_token: "t".into(),
            },
            geo: None,
            store: store::Store::open(&dir.to_string_lossy()).unwrap(),
            cell: Cybergraph::new(),
            chains: graph::Chains::default(),
            events: Vec::new(),
            seen: BTreeSet::new(),
            data_version: 0,
            report_cache: BTreeMap::new(),
        }
    }

    fn signed_event(seed: &Seed, path: &str, target: u64) -> Event {
        let n = seed.neuron("cyber.page", "lytics").unwrap();
        let body = EventBody {
            neuron: n.bech32.clone(),
            actor: Actor::Human,
            agent: None,
            kind: Kind::Pageview,
            navigation: Some(Navigation::External),
            hostname: "cyber.page".into(),
            pathname: path.into(),
            referrer: Some("https://chatgpt.com/c/1".into()),
            utm: None,
            attention: None,
            props: None,
            revenue: None,
            timestamp: now_ms(),
        };
        let body_bytes = lytics_event::encode_body(&body);
        let hash = event_hash(&body_bytes);
        let nonce = solve(&hash, target);
        let (pubkey, signature) = lytics_event::sign_body(n.signing_key(), &body_bytes, &n.bech32);
        Event {
            body,
            pow: Pow {
                nonce,
                difficulty: target,
            },
            pubkey,
            signature,
        }
    }

    #[test]
    fn accept_then_duplicate_then_report() {
        let mut app = test_app();
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        // first event from an unseen neuron must meet the enrollment target
        let ev = signed_event(&seed, "/a", app.cfg.enroll_target);
        let (status, _) = ingest(&mut app, ev.clone(), Some("Mozilla/5.0"), None).unwrap();
        assert_eq!(status, "accepted");
        // replayed: idempotent
        let (status, _) = ingest(&mut app, ev, None, None).unwrap();
        assert_eq!(status, "duplicate");
        assert_eq!(app.events.len(), 1);
        // enrolled now: the cheaper event target suffices
        let ev2 = signed_event(&seed, "/b", app.cfg.event_target);
        let (status, _) = ingest(&mut app, ev2, None, None).unwrap();
        assert_eq!(status, "accepted");
        // attribution: chatgpt referral is the ai channel
        assert!(matches!(
            app.events[0].attribution.channel,
            enrich::Channel::Ai
        ));
    }

    #[test]
    fn forged_signature_rejected() {
        let mut app = test_app();
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let mut ev = signed_event(&seed, "/a", app.cfg.enroll_target);
        ev.body.pathname = "/tampered".into();
        // re-solve pow so the failure isolates to the signature
        let bytes = lytics_event::encode_body(&ev.body);
        let h = event_hash(&bytes);
        ev.pow.nonce = solve(&h, app.cfg.enroll_target);
        assert!(matches!(
            ingest(&mut app, ev, None, None),
            Err(Reject::Auth(_))
        ));
    }

    #[test]
    fn weak_pow_rejected_for_unseen_neuron() {
        let mut app = test_app();
        // make enrollment effectively impossible, event target trivial
        app.cfg.enroll_target = 1;
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let ev = signed_event(&seed, "/a", target_from_difficulty(4));
        assert!(matches!(
            ingest(&mut app, ev, None, None),
            Err(Reject::Pow(_))
        ));
    }

    #[test]
    fn future_timestamp_rejected() {
        let mut app = test_app();
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let mut ev = signed_event(&seed, "/a", app.cfg.enroll_target);
        ev.body.timestamp = now_ms() + 10 * 60 * 1000;
        assert!(matches!(
            ingest(&mut app, ev, None, None),
            Err(Reject::Bad(_))
        ));
    }
}
