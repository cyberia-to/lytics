---
title: lytics specs
tags: cyber, lytics, analytics, soft3, spec
crystal-type: spec
crystal-domain: cyber
---

# lytics — specification

the canonical specification and build plan. the product story lives in
[../README.md](../README.md). when this document and code disagree, this
document is fixed first, then the code.

## architecture

```text
visitor browser                     server                       reader
┌─────────────────┐   HTTPS   ┌──────────────────┐        ┌──────────────┐
│ loader.js ~2KB  │  ───────► │ ingest (axum)    │        │ dashboard    │
│  capture + queue│           │  verify sig+pow  │        │ leptos/trunk │
│ core.wasm ≤64KB │           │  ua · geo · ref  │  ───►  │  d3 widgets  │
│  keys·sign·pow  │           │  cast signal     │        └──────────────┘
└─────────────────┘           │ cell (cybergraph)│              ▲
                              │  bbg state·time  │              │
                              │ query (inf)      │──────────────┘
                              └──────────────────┘   HTTP /api/query
```

| component | language | role |
|---|---|---|
| loader | JS, ≤2 KB inline | fires on page load, captures pageview + SPA route changes instantly, queues events until the core is ready |
| core | Rust → wasm, ≤64 KB gzip budget | keygen, per-domain derivation, secp256k1 signing, PoW, beacon transport; loaded async so page performance never waits on crypto |
| ingest | Rust, axum | signature + PoW verification, replay dedup, UA parsing, MaxMind geo (ip read, used, discarded), referrer→source attribution, adaptive difficulty, signal casting into the cell |
| store | [[cybergraph]] cell + [[bbg]] | the ingest service embeds a cell in-process; events enter as signed signals, bbg holds the state and its time dimension indexes the stream |
| query | [[inf]] datalog over bbg | timeseries, top-N, passages, retention, funnels — each report is one inf rule; the path is live: cybergraph already runs inf over bbg state in-process |
| dashboard | Rust, Leptos + Trunk | wasm dashboard, d3 widgets, realtime by polling |

the tracker splits in two on purpose: the loader guarantees plausible-grade
capture latency and size; the wasm core carries the cryptography. events
fired before the core loads are queued and signed retroactively before they
leave the page.

the loader exists because the browser admits wasm only through JS: a wasm
module is fetched and instantiated by `WebAssembly.instantiateStreaming` —
a JS API — and every DOM, storage and network touch (pushState hooks,
IndexedDB, sendBeacon) crosses a JS import boundary. wasm-bindgen emits this
glue anyway; the loader is that glue plus the instant-capture queue, held to
a 2 KB budget. the crypto and all logic stay in Rust — JS is confined to the
bootstrap the platform requires.

`/api/query` is owner-authenticated; public dashboards expose named,
parameterized reports only — raw datalog never faces the open internet.

## identity pipeline

keys follow the [[mudra]] bridge (`mudra/specs/bridge.md`) exactly:

```text
mnemonic ──BIP-39──▶ seed ──BIP-32/44──▶ secp256k1 key (per-domain child)
                                              │
                     compressed pubkey (33 B) ◀┘
                              │
        bech32(hrp, ripemd160(sha256(pubkey)))  = neuron (wire form)
        Hemera(compressed_pubkey)               = native neuron id (32 B)
```

per-domain derivation folds the domain into the BIP44 account level:
`account' = u31(Hemera(domain))`, path `m/44'/118'/account'/0/0` — one
seed, one hardened child per domain, so two sites observe two unlinkable
neurons. the wire hrp defaults to `lytics` and is a deployment setting.
events are signed in ADR-036 shape, and the claim is key-level (any
secp256k1 key qualifies, path plays no part), so the existing mudra claim
(`legacy address → native neuron`) carries any lytics neuron into the
native graph unchanged.

## event schema

```text
event {
  neuron         per-domain visitor neuron (bech32)
  actor          human | agent                      agent: self-declared machine reader
  agent { name, operator }          optional, declared agents only
  kind           pageview | attention | <custom>
  navigation     external | direct | internal       pageview: how the neuron arrived
  hostname, pathname
  referrer, source, channel, utm{source,medium,campaign,term,content}
  country, region, city             derived from ip, ip discarded
  browser, browser_version, os, os_version, device
  attention { ms, scroll_depth }    attention events: measured on-device
  props { key: value, ... }         typed custom properties
  revenue { amount, currency }      optional
  timestamp
  pow { nonce, difficulty }
  signature                          secp256k1 over the canonical encoding, ADR-036 shape
}
```

### canonical encoding

the signed bytes are the event as canonical JSON — sorted keys, no
whitespace, integers only — wrapped in the ADR-036 sign doc. the event
hash is [[hemera]] over those bytes; it doubles as the particle hash and
as the dedup key.

### proof of work

the PoW predicate is one hash: find `nonce` such that
`Hemera(event_hash ‖ nonce) < target`. the per-site `target` comes from
the difficulty oracle (`GET /api/difficulty`), tuned so a median phone
spends ~0.042 s; verification is a single hash. ingest rejects events
whose timestamp falls outside a ±5 min window and events whose hash was
already seen — a replayed signature buys nothing.

### erasure

the cell is append-only, and erasure still must be real. event payloads
are encrypted at rest with a per-neuron data key held by the site;
`DELETE /api/neuron` destroys the key. the graph keeps its hashes, the
data becomes unreadable, already-published aggregates stay — the standard
crypto-shredding resolution of append-only against the right to erase.

## the attention model

the tracker is a sensor. the browser emits the real boundaries —
visibilitychange, focus, blur, pagehide — and the wasm core integrates
attention on-device: time accumulates while the page is visible and the
neuron is active, and ships as signed attention events (on hide, on leave,
on a heartbeat that bounds loss). what other tools infer from timestamp
gaps, lytics receives as measurement.

agent attention arrives by declaration: an agent has no visibility or
focus to sense, so it states what it read in signed events with
`actor: agent`. sensed human attention and declared agent attention are
distinct streams; every report keeps them separable.

grouping falls out of observables, never out of a clock constant:

- arrival — a pageview whose navigation is external: outside referrer,
  utm-tagged, or direct entry. attribution attaches to the arrival event
  itself; entry page is the arrival's page.
- passage — the run of a neuron's events from one arrival to the next (or
  to the end of the stream). exit page is the passage's last page. every
  question classically asked of a "session" — pages per visit, entry, exit,
  source — is asked of a passage, and a passage is bounded by what the
  neuron did, never by how long they paused.
- window — when a question needs a time span (funnels, retention,
  timeseries), the span is an explicit query parameter: hour, day, week,
  between arrivals. the analyst states the window; the engine never invents
  one.

arrivals, passages and windows are read-time projections over the
append-only event stream — ingest stays pure append, the discipline the
cybergraph demands.

one honest convention survives: heartbeat cadence (default 15 s) and the
activity window (default: 5 s of input silence pauses the clock) are
measurement granularity — they bound how much attention a killed tab can
lose. they are tuning knobs of the instrument, never semantics of the
visitor.

## reuse map

| piece | source | how |
|---|---|---|
| query engine | [[inf]] native (`inf-parse/plan/eval`) | the implementation foundation — datalog over bbg, already wired via cybergraph `query()` |
| datalog reference | `inf/rs/cozo` | reference only: behavior and api shapes to check against, never a dependency |
| dashboard skeleton | `cyberstates` | Leptos + Trunk + d3, already deployed once |
| tracker injection | `optica` `[analytics]` config | cyber.page pages already carry a snippet slot; point it at lytics |
| referrer→source engine | plausible core (AGPL) + snowplow referer db | clean reimplementation in Rust; behavior parity, fresh code |
| geo | `maxminddb` crate + GeoLite2 | same lookup plausible uses |
| ua parsing | `uaparser`/`woothee` crate | device class, browser, os |
| identity pipeline | [[mudra]] bridge (`mudra/specs/bridge.md`) | BIP39 → BIP32/44 → secp256k1 → bech32, neuron = Hemera(pubkey), ADR-036 signing — the existing bridge claim carries a lytics neuron into the native graph |
| pow + hashing | [[hemera]] Poseidon2 | event hash and PoW share the stack's native hash — a lytics event hash is already a particle hash |

## implementation plan

estimates follow the dev model: pomodoro = 30 min, session = 3 h.

### phase 1 — identity + tracker (3 sessions)

wasm core: keygen, IndexedDB seed storage, per-domain derivation, BIP39
export/import, secp256k1 signing in ADR-036 shape, Poseidon2 PoW with
adaptive difficulty, on-device attention integration (visibilitychange /
focus / blur / pagehide + heartbeat), canonical event encoding, sendBeacon
transport. loader.js: instant capture, SPA pushState hook, sensor hooks,
queue-until-ready. size gate in CI: core ≤64 KB gzip, loader ≤2 KB.

### phase 2 — ingest (3 sessions)

axum service embedding a cybergraph cell: `POST /api/event` — verify
signature, verify PoW, parse UA, geo lookup, referrer→source→channel
attribution (Rust port of plausible behavior over the snowplow referer
database, with assistant referrals as a first-class channel), cast the
event as a signed signal into the cell. difficulty oracle endpoint.
erasure endpoint (per-neuron data-key destruction).

### phase 3 — queries: the full report set (4 sessions)

inf rules for: neurons/pageviews/attention timeseries, top pages, sources,
countries, devices, goals, custom props — and the identity-powered tier:
retention matrix, cohorts, funnels, attention per arrival, return
probability within a stated window. arrival and passage segmentation at
read time. all engine arithmetic is integer and field-element ([[inf]]
values are field elements; ratios render at the dashboard edge). where the
report set needs primitives inf lacks today (count, group-by time bucket,
top-N, ordered sequence match), extend inf itself, with behavior checked
against the cozo reference. this phase lands the features plausible
paywalls, because here they are one rule each.

### phase 4 — dashboard (3 sessions)

Leptos app from the cyberstates skeleton: period picker, comparison,
realtime, the classic widgets (neurons, pages, sources, geo, devices,
goals) recast on attention metrics, plus retention grid and funnel view.
public dashboard links.

### phase 5 — integration + verification (1 session)

deploy beside cyber.page, flip the optica `[analytics]` snippet from
plausible.io to lytics, watch live events end to end, verify every widget
against raw queries. the phase ends when cyber.page runs on lytics and the
plausible subscription is off.

total to usable: ~14 sessions. retention, cohorts and funnels ship inside
that number — they are the point, never an add-on.

### phase 6 — the network and the proofs (blocked, by design)

events live in the cell from phase 2, so settlement needs no replay. what
remains is the stack tail: cells syncing over the real transport
(radio/iroh, unwired today), bbg QueryProof serde and the query wire
protocol for provable reads, and [[zheng]] proving the aggregates — "this
page truly had N visitors" verified by anyone. these wait on the stack's
known blockers and land the moment the stack does.

## confidence milestone

```bash
# a page with the snippet produces a signed, pow-carrying event
curl -s https://lytics.local/api/event -d @signed-event.json   # → 202

# forged signature and weak pow are rejected
curl -s https://lytics.local/api/event -d @forged.json          # → 401
curl -s https://lytics.local/api/event -d @weak-pow.json        # → 429

# the premium tier answers
echo '?[cohort, week, retained] := ...' | curl -s -d @- https://lytics.local/api/query

# erasure destroys the neuron's data key
curl -s -X DELETE https://lytics.local/api/neuron/<bech32>      # → 204, payloads unreadable

# cyber.page dashboard shows live visitors from lytics, plausible.io off
```

## license

cyber license: don't trust. don't fear. don't beg.
