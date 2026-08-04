// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! lytics reference agent — proof that the event api needs no browser.
//!
//! any signer that speaks canonical encoding + PoW + ADR-036 is a visitor.
//! commands:
//!   lytics-agent visit  <server> <domain> <path> [--agent name:operator]
//!   lytics-agent browse <server> <domain> <paths,comma> — one passage with attention
//!   lytics-agent load   <server> <domain> <events> <neurons> — throughput gate

use lytics_event::{
    canonical_json, event_hash, sign_body, solve, Actor, Attention, Event, EventBody, Kind,
    Navigation, Pow, Seed,
};
use std::time::Instant;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct Difficulty {
    event_target: u64,
    enroll_target: u64,
}

fn fetch_difficulty(server: &str) -> Difficulty {
    let resp: serde_json::Value = ureq::get(&format!("{server}/api/difficulty"))
        .call()
        .expect("difficulty oracle")
        .into_json()
        .expect("difficulty json");
    let get = |k: &str| resp[k].as_str().and_then(|s| s.parse().ok()).expect("target");
    Difficulty { event_target: get("event_target"), enroll_target: get("enroll_target") }
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    seed: &Seed,
    domain: &str,
    path: &str,
    kind: Kind,
    navigation: Option<Navigation>,
    attention: Option<Attention>,
    agent: Option<(String, String)>,
    target: u64,
    timestamp: u64,
) -> Event {
    let neuron = seed.neuron(domain, "lytics").expect("derive");
    let body = EventBody {
        neuron: neuron.bech32.clone(),
        actor: if agent.is_some() { Actor::Agent } else { Actor::Human },
        agent: agent.map(|(name, operator)| lytics_event::event::AgentDecl { name, operator }),
        kind,
        navigation,
        hostname: domain.into(),
        pathname: path.into(),
        referrer: None,
        utm: None,
        attention,
        props: None,
        revenue: None,
        timestamp,
    };
    let bytes = canonical_json(&body).expect("canonical");
    let hash = event_hash(&bytes);
    let nonce = solve(&hash, target);
    let (pubkey, signature) = sign_body(neuron.signing_key(), &bytes, &neuron.bech32);
    Event { body, pow: Pow { nonce, difficulty: target }, pubkey, signature }
}

fn post(server: &str, event: &Event) -> (u16, String) {
    let payload = serde_json::to_value(event).expect("event json");
    match ureq::post(&format!("{server}/api/event")).send_json(payload) {
        Ok(resp) => {
            let code = resp.status();
            (code, resp.into_string().unwrap_or_default())
        }
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => (0, e.to_string()),
    }
}

fn parse_agent_flag(args: &[String]) -> Option<(String, String)> {
    let at = args.iter().position(|a| a == "--agent")?;
    let spec = args.get(at + 1)?;
    let (name, operator) = spec.split_once(':').unwrap_or((spec.as_str(), "unknown"));
    Some((name.to_string(), operator.to_string()))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: lytics-agent <visit|browse|load> <server> <domain> ...";
    let cmd = args.get(1).expect(usage).as_str();
    let server = args.get(2).expect(usage).trim_end_matches('/').to_string();
    let domain = args.get(3).expect(usage).clone();

    let seed = match std::env::var("LYTICS_MNEMONIC") {
        Ok(phrase) => Seed::from_mnemonic(&phrase).expect("mnemonic"),
        Err(_) => {
            let (seed, phrase) = Seed::generate();
            eprintln!("generated identity — export LYTICS_MNEMONIC to keep it:\n{phrase}");
            seed
        }
    };
    let diff = fetch_difficulty(&server);
    let neuron = seed.neuron(&domain, "lytics").expect("derive");
    let enrolled: bool = ureq::get(&format!("{}/api/difficulty?neuron={}", server, neuron.bech32))
        .call()
        .ok()
        .and_then(|r| r.into_json::<serde_json::Value>().ok())
        .and_then(|v| v["enrolled"].as_bool())
        .unwrap_or(false);
    let first_target = if enrolled { diff.event_target } else { diff.enroll_target };

    match cmd {
        "visit" => {
            let path = args.get(4).cloned().unwrap_or_else(|| "/".into());
            let agent = parse_agent_flag(&args);
            let ev = build_event(
                &seed, &domain, &path, Kind::Pageview, Some(Navigation::External),
                None, agent, first_target, now_ms(),
            );
            let (code, body) = post(&server, &ev);
            println!("{code} {body}");
        }
        "browse" => {
            // one passage: external arrival, internal pages, attention on each
            let paths: Vec<String> = args
                .get(4)
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_else(|| vec!["/".into()]);
            let agent = parse_agent_flag(&args);
            let mut target = first_target;
            for (i, path) in paths.iter().enumerate() {
                let nav = if i == 0 { Navigation::External } else { Navigation::Internal };
                let ts = now_ms();
                let pv = build_event(
                    &seed, &domain, path, Kind::Pageview, Some(nav),
                    None, agent.clone(), target, ts,
                );
                let (code, _) = post(&server, &pv);
                target = diff.event_target; // enrolled after the first accept
                let att = build_event(
                    &seed, &domain, path, Kind::Attention, None,
                    Some(Attention { ms: 30_000 + (i as u64) * 12_000, scroll_depth: 60 }),
                    agent.clone(), target, ts + 1 + i as u64,
                );
                let (code2, _) = post(&server, &att);
                println!("{path}: pageview {code}, attention {code2}");
            }
        }
        "load" => {
            let total: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1000);
            let neurons: usize = args.get(5).and_then(|v| v.parse().ok()).unwrap_or(10);
            // enroll each synthetic neuron once (its own derived domain child
            // via distinct sub-labels), then hammer events
            let mut events = Vec::with_capacity(total);
            eprintln!("preparing {total} signed events across {neurons} neurons…");
            let prep = Instant::now();
            for n in 0..neurons {
                let sub = format!("{n}.load.{domain}");
                let ts0 = now_ms();
                events.push(build_event(
                    &seed, &sub, "/", Kind::Pageview, Some(Navigation::External),
                    None, None, diff.enroll_target, ts0,
                ));
                for i in 1..total / neurons {
                    events.push(build_event(
                        &seed, &sub, &format!("/p{}", i % 7), Kind::Pageview,
                        Some(Navigation::Internal), None, None, diff.event_target,
                        ts0 + i as u64,
                    ));
                }
            }
            eprintln!("prepared in {:?} — posting…", prep.elapsed());
            let run = Instant::now();
            let mut accepted = 0usize;
            for ev in &events {
                let (code, _) = post(&server, ev);
                if code == 202 {
                    accepted += 1;
                }
            }
            let secs = run.elapsed().as_secs_f64();
            println!(
                "{accepted}/{} accepted in {:.2}s → {:.0} events/s",
                events.len(), secs, accepted as f64 / secs
            );
        }
        _ => eprintln!("{usage}"),
    }
}
