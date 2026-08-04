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
mod reports;
mod store;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use cybergraph::Cybergraph;
use lytics_event::{event_hash, pow_verify, sig_verify, target_from_difficulty, Event};
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
    let body_bytes = event.body_bytes().map_err(|e| Reject::Bad(e.to_string()))?;
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
    if let Err(e) = app.chains.cast(&mut app.cell, native, hash, page, event.body.timestamp / 1000) {
        eprintln!("cell cast failed for {hash_hex}: {e}");
    }

    app.seen.insert(hash);
    app.events.push(stored);
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
        let Ok(stored) = serde_json::from_slice::<Stored>(&plaintext) else { continue };
        let Ok(raw) = hex::decode(&stored.event_hash) else { continue };
        let Ok(hash) = <[u8; 32]>::try_from(raw.as_slice()) else { continue };
        // native id for replay: hemera of the bech32 — a stable per-neuron
        // chain id (the pubkey lives only in the wire event)
        let native = *hemera::hash(stored.body.neuron.as_bytes()).as_bytes();
        let page = graph::page_particle(&stored.body.hostname, &stored.body.pathname);
        let _ = app.chains.cast(&mut app.cell, native, hash, page, stored.body.timestamp / 1000);
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
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(String::from);
    // first hop of x-forwarded-for when behind a proxy, else the peer
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .or(Some(peer.ip()));
    let mut app = state.lock().expect("lock");
    match ingest(&mut app, event, ua.as_deref(), ip) {
        Ok((status, hash)) => {
            (StatusCode::ACCEPTED, Json(json!({"status": status, "event": hash}))).into_response()
        }
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
    let app = state.lock().expect("lock");
    let now = now_ms();
    let parse_u64 = |k: &str, d: u64| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let from = parse_u64("from", now.saturating_sub(7 * 24 * 3600 * 1000));
    let to = parse_u64("to", now + 1);
    let limit = parse_u64("limit", 10) as usize;
    let windowed = reports::in_window(&app.events, from, to);

    let out = match name.as_str() {
        "overview" => reports::overview(&windowed),
        "timeseries" => {
            let bucket = match q.get("bucket").map(String::as_str) {
                Some("hour") => 3600 * 1000,
                _ => 24 * 3600 * 1000,
            };
            reports::timeseries(&windowed, bucket)
        }
        "pages" => reports::pages(&windowed, limit),
        "sources" => reports::sources(&windowed, limit),
        "channels" => reports::channels(&windowed),
        "actors" => reports::actors(&windowed),
        "devices" => reports::devices(&windowed, limit),
        "countries" => reports::countries(&windowed, limit),
        "passages" => reports::passages_report(&windowed, limit),
        "retention" => reports::retention(&app.events, parse_u64("weeks", 8) as usize),
        "returns" => reports::returns(
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
            reports::funnel(&windowed, &steps)
        }
        _ => return (StatusCode::NOT_FOUND, "unknown report").into_response(),
    };
    Json(out).into_response()
}

async fn dash() -> Html<&'static str> {
    Html(include_str!("../static/dash.html"))
}

async fn demo() -> Html<&'static str> {
    Html(include_str!("../static/demo.html"))
}

/// serve a tracker asset. loader.js is source (embedded); the wasm core and
/// its bindings are generated (read from disk, built by build-tracker.sh).
async fn tracker_asset(Path(name): Path<String>) -> impl IntoResponse {
    let mime = |n: &str| if n.ends_with(".wasm") { "application/wasm" } else { "text/javascript" };
    let headers = |m: &'static str| {
        [
            (axum::http::header::CONTENT_TYPE, m),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ]
    };
    if name == "loader.js" {
        return (headers("text/javascript"), include_str!("../static/tracker/loader.js")).into_response();
    }
    if name == "lytics_core.js" || name == "lytics_core_bg.wasm" || name == "words.js" {
        let dir = std::env::var("LYTICS_STATIC")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/static/tracker").into());
        match std::fs::read(format!("{dir}/{name}")) {
            Ok(bytes) => return (headers(mime(&name)), bytes).into_response(),
            Err(_) => {
                return (StatusCode::NOT_FOUND, "tracker not built — run build-tracker.sh")
                    .into_response()
            }
        }
    }
    (StatusCode::NOT_FOUND, "unknown asset").into_response()
}

#[tokio::main]
async fn main() {
    let env = |k: &str| std::env::var(k).ok();
    let data_dir = env("LYTICS_DATA").unwrap_or_else(|| "lytics-data".into());
    let port: u16 = env("LYTICS_PORT").and_then(|p| p.parse().ok()).unwrap_or(8090);
    let hrp = env("LYTICS_HRP").unwrap_or_else(|| "lytics".into());
    let event_hashes: u64 =
        env("LYTICS_EVENT_HASHES").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_EVENT_HASHES);
    let enroll_mult: u64 =
        env("LYTICS_ENROLL_MULT").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_ENROLL_MULT);
    let owner_token = env("LYTICS_OWNER_TOKEN").unwrap_or_else(|| {
        let t = hex::encode(hemera::hash(format!("{}", now_ms()).as_bytes()).as_bytes());
        eprintln!("LYTICS_OWNER_TOKEN not set — generated: {t}");
        t
    });

    let geo_db = env("LYTICS_GEO_DB")
        .or_else(|| {
            let local = "data/dbip-city-lite.mmdb";
            std::path::Path::new(local).exists().then(|| local.to_string())
        })
        .and_then(|p| match geo::GeoDb::open(&p) {
            Ok(db) => {
                eprintln!("geo db loaded: {p}");
                Some(db)
            }
            Err(e) => {
                eprintln!("geo db unavailable ({p}): {e}");
                None
            }
        });

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
    use lytics_event::{solve, Actor, EventBody, Kind, Navigation, Pow, Seed};

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
        let body_bytes = lytics_event::canonical_json(&body).unwrap();
        let hash = event_hash(&body_bytes);
        let nonce = solve(&hash, target);
        let (pubkey, signature) = lytics_event::sign_body(n.signing_key(), &body_bytes, &n.bech32);
        Event { body, pow: Pow { nonce, difficulty: target }, pubkey, signature }
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
        assert!(matches!(app.events[0].attribution.channel, enrich::Channel::Ai));
    }

    #[test]
    fn forged_signature_rejected() {
        let mut app = test_app();
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let mut ev = signed_event(&seed, "/a", app.cfg.enroll_target);
        ev.body.pathname = "/tampered".into();
        // re-solve pow so the failure isolates to the signature
        let bytes = lytics_event::canonical_json(&ev.body).unwrap();
        let h = event_hash(&bytes);
        ev.pow.nonce = solve(&h, app.cfg.enroll_target);
        assert!(matches!(ingest(&mut app, ev, None, None), Err(Reject::Auth(_))));
    }

    #[test]
    fn weak_pow_rejected_for_unseen_neuron() {
        let mut app = test_app();
        // make enrollment effectively impossible, event target trivial
        app.cfg.enroll_target = 1;
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let ev = signed_event(&seed, "/a", target_from_difficulty(4));
        assert!(matches!(ingest(&mut app, ev, None, None), Err(Reject::Pow(_))));
    }

    #[test]
    fn future_timestamp_rejected() {
        let mut app = test_app();
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let mut ev = signed_event(&seed, "/a", app.cfg.enroll_target);
        ev.body.timestamp = now_ms() + 10 * 60 * 1000;
        assert!(matches!(ingest(&mut app, ev, None, None), Err(Reject::Bad(_))));
    }
}
