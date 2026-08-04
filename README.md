---
title: lytics
tags: cyber, lytics, analytics, soft3
crystal-type: spec
crystal-domain: cyber
icon: "📈"
alias: cyber analytics, web analytics, lytics analytics
---

# lytics

> every visitor is a neuron

web analytics built on [[soft3]] principles: the visitor owns a keypair, every
event is a signed assertion, every signal costs a small proof of work, and the
graph of visits becomes queryable knowledge — retention, cohorts and funnels
included from day one.

lytics is the first consumer application of the soft3 stack — and the neuron
onramp for [[cyber]]: every visitor of every site running lytics carries a
portable cryptographic identity that can later claim a place in the
[[cybergraph]].

## the gap lytics fills

plausible proved the market: a 1.3 KB script, six report widgets, and honest
privacy beat a 135 KB surveillance suite. their engine is ~30% of a 250k-line
Elixir codebase; the rest is SaaS scaffolding. but plausible's identity model
caps the product:

| plausible | consequence |
|---|---|
| `user_id = hash(daily_salt + domain + ip + ua)` | identity dies every 24h |
| salt deleted daily | retention and cohorts impossible by construction |
| funnels, revenue, sites api | proprietary `extra/` — readable, unusable |
| bot filtering | a curated 32k-IP blocklist, also proprietary |

lytics replaces the rotating salt with a visitor-owned keypair. that single
change unlocks the entire premium tier — retention matrices, cohort analysis,
multi-day funnels — as core features, and replaces blocklist bot-filtering
with economics: every event carries a [[costly signal]].

## the identity model

the browser holds a keypair. the visitor is a [[neuron]].

1. first visit: the wasm core generates a seed, stores it in IndexedDB,
   derives the neuron. zero interaction — the visitor sees nothing.
2. every event is signed by the visitor key. an unsigned event is spam by
   definition.
3. every event carries a proof of work over the event hash — target ~0.042 s
   on a median phone, verified server-side in microseconds. bots pay for
   every fake pageview with real compute. difficulty adapts per site.
4. the seed exports as a BIP39 mnemonic. the visitor can import it in
   another browser and keep their identity — or burn it and start clean.
   identity belongs to the visitor, never to the site.
5. per-domain derivation: the neuron a site sees is derived from
   `(seed, domain)`. two sites see two unlinkable neurons. cross-site
   profiles are impossible by construction; linking identities is a choice
   the visitor makes, never a default.

the same key that signs a pageview can later sign a [[cyberlink]]. a lytics
neuron is a proto-neuron of the [[cybergraph]]: the event schema is shaped so
that settlement into the cybergraph is a replay, never a migration.

### privacy stance, stated plainly

a persistent per-domain neuron is pseudonymous data. sites running lytics
disclose it like any analytics. the design compensates with user sovereignty:
the visitor holds the key, can export it, can erase their trail (deletion by
neuron is one query), and cannot be tracked across sites. raw IP is used for
geo lookup and discarded, following the plausible standard.

## what the identity unlocks

| feature | mechanism |
|---|---|
| retention | first-seen cohort × weekly return matrix over stable neurons |
| cohorts | group by first-seen week, campaign, or landing page |
| funnels | ordered event-sequence match per neuron, across days |
| bot filtering | PoW + signature verification at ingest — economic, not curated |
| goals and revenue | named events with typed props, summed per cohort |
| provable stats (endgame) | aggregates proven by [[zheng]] — "this page truly had N visitors" is a claim no other analytics can make |

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
| core | Rust → wasm, ≤64 KB gzip budget | keygen, per-domain derivation, ed25519 signing, PoW, beacon transport; loaded async so page performance never waits on crypto |
| ingest | Rust, axum | signature + PoW verification, UA parsing, MaxMind geo, referrer→source attribution, adaptive difficulty, batched writes |
| store | [[cybergraph]] cell + [[bbg]] | the ingest service embeds a cell in-process; events enter as signed signals, bbg holds the state and its time dimension indexes the stream |
| query | [[inf]] datalog over bbg | timeseries, top-N, episodes, retention, funnels — each report is one inf rule; the path is live: cybergraph already runs inf over bbg state in-process |
| dashboard | Rust, Leptos + Trunk | wasm dashboard, d3 widgets, realtime by polling |

the tracker splits in two on purpose: the loader guarantees plausible-grade
capture latency and size; the wasm core carries the cryptography. events
fired before the core loads are queued and signed retroactively in the same
page session.

the loader exists because the browser admits wasm only through JS: a wasm
module is fetched and instantiated by `WebAssembly.instantiateStreaming` —
a JS API — and every DOM, storage and network touch (pushState hooks,
IndexedDB, sendBeacon) crosses a JS import boundary. wasm-bindgen emits this
glue anyway; the loader is that glue plus the instant-capture queue, held to
a 2 KB budget. the crypto and all logic stay in Rust — JS is confined to the
bootstrap the platform requires.

## event schema

```text
event {
  neuron         per-domain visitor neuron (bech32)
  name           pageview | engagement | <custom>
  hostname, pathname
  referrer, source, channel, utm{source,medium,campaign,term,content}
  country, region, city             derived from ip, ip discarded
  browser, browser_version, os, os_version, device
  props { key: value, ... }         typed custom properties
  revenue { amount, currency }      optional
  timestamp
  pow { nonce, difficulty }
  signature                          ed25519 over the canonical encoding
}
```

sessions are computed at read time: a session is a gap-free run of events per
neuron with idle timeout 30 min. storing sessions as derived data keeps
ingest append-only — the same discipline the cybergraph demands.

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
| key mnemonics | [[mudra]] conventions | BIP39 seed → bech32 address, same path a neuron claim uses |
| pow + hashing | [[hemera]] Poseidon2 | event hash and PoW share the stack's native hash — a lytics event hash is already a particle hash |

## what lytics rejects

- the daily salt. anonymity through amnesia trades the entire retention tier
  for a privacy property the visitor never controls. sovereign keys give the
  visitor stronger control and keep the data model whole.
- clickhouse. the store is the cybergraph itself: bbg state inside an
  embedded cell, read by inf. the target scale (cyber.page and peer sites)
  fits; a columnar engine stays a swap-in behind the query layer if a site
  ever outgrows it.
- the SaaS scaffolding. billing, quotas, team roles, importers — 70% of
  plausible's codebase serves their cloud business. lytics ships the engine.

## implementation plan

estimates follow the dev model: pomodoro = 30 min, session = 3 h.

### phase 1 — identity + tracker (3 sessions)

wasm core: keygen, IndexedDB seed storage, per-domain derivation, BIP39
export/import, ed25519 signing, Poseidon2 PoW with adaptive difficulty,
canonical event encoding, sendBeacon transport. loader.js: instant capture,
SPA pushState hook, queue-until-ready. size gate in CI: core ≤64 KB gzip,
loader ≤2 KB.

### phase 2 — ingest (3 sessions)

axum service embedding a cybergraph cell: `POST /api/event` — verify
signature, verify PoW, parse UA, geo lookup, referrer→source→channel
attribution (Rust port of plausible behavior over the snowplow referer
database), cast the event as a signed signal into the cell. difficulty
oracle endpoint. deletion-by-neuron endpoint.

### phase 3 — queries: the full report set (4 sessions)

inf rules for: visitors/pageviews timeseries, top pages, sources,
countries, devices, goals, custom props — and the identity-powered tier:
retention matrix, cohorts, funnels. episode segmentation at read time.
where the report set needs primitives inf lacks today (count, group-by
time bucket, top-N, ordered sequence match), extend inf itself, with
behavior checked against the cozo reference. this phase lands the features
plausible paywalls, because here they are one rule each.

### phase 4 — dashboard (3 sessions)

Leptos app from the cyberstates skeleton: period picker, comparison,
realtime, the six classic widgets plus retention grid and funnel view.
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

# cyber.page dashboard shows live visitors from lytics, plausible.io off
```

## license

cyber license: don't trust. don't fear. don't beg.
