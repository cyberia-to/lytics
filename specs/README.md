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
│ core.wasm ~27KB │           │  ua · geo · ref  │  ───►  │  d3 widgets  │
│  keys·sign·pow  │           │  cast signal     │        └──────────────┘
└─────────────────┘           │ cell (cybergraph)│              ▲
                              │  bbg state·time  │              │
                              │ query (inf)      │──────────────┘
                              └──────────────────┘   HTTP /api/query
```

| component | language | role |
|---|---|---|
| loader | JS module, ~2 KB source | fires on page load, captures pageview + SPA route changes instantly, runs the attention sensor, queues events until the core is ready |
| core | Rust → wasm, ~32 KB gzip / ~27 KB brotli measured | keygen, per-domain derivation, secp256k1 signing, PoW; loaded async so page performance never waits on crypto |
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
localStorage, fetch) crosses a JS import boundary. the crypto and all logic
stay in Rust — JS is confined to the bootstrap the platform requires and the
sensor the platform exposes.

on core size: the original ≤64 KB budget did not survive contact with the
primitives, but eight cuts brought the core from ~172 KB gzip to ~32 KB gzip
(~27 KB brotli):

1. the 2048-word list left the hot path — the secret is raw 32-byte entropy,
   and the BIP39 mnemonic is a lazy backup in `words.js`, loaded only on
   export/import.
2. k256 was trimmed to sign-and-derive only (no pkcs8/pem/serde/schnorr/ecdh,
   no precomputed tables).
3. serde_json left entirely — `encode_body` is a hand-written canonical
   encoder pinned byte-for-byte to the serde_json output by parity tests, so
   the signing path carries no JSON machinery and no float formatting.
4. BIP32 gave way to a hemera KDF (`d = Hemera(entropy ‖ 0x00 ‖ domain) mod
   n`), dropping HMAC-SHA512 and bip32 — one hash where a derivation ladder
   was.
5. the signing path dropped core::fmt — hand-written decimal and \u00XX
   hex writers, static error strings.
6. panics became `immediate-abort` (build-std): a panic is a bare trap, so
   the whole panic/fmt machinery and its message strings left the binary —
   the native test suite carries the readable messages.
7. base64 and the allocator went hand-rolled/minimal (a ~40-line RFC 4648
   codec pinned by parity tests; lol_alloc's free-list replaces dlmalloc —
   the tracker is single-threaded and allocates small short-lived strings).
8. `wasm-opt -Oz` ran over the result.

what remains is the honest floor: secp256k1 signing (k256, now the largest
piece) plus Poseidon2 (hemera, a mere ~3 KB) for the event hash, the KDF,
and PoW. it loads async and gates nothing — the loader captures the first
pageview and the whole attention stream before the core compiles, then signs
the queue retroactively. the deepest remaining lever is a hand-rolled
minimal secp256k1, or moving signing to `@noble/secp256k1` in JS (~4 KB,
same curve) — deferred; the curve stays secp256k1 either way so the mudra
bridge and on-chain identity hold.

first-load transfer, measured: ~41 KB gzip / ~34 KB brotli total (wasm +
wasm-bindgen glue + loader), one time, then served from cache. the loader
is a JS module; `words.js` (~6 KB brotli, the wordlist) transfers only when
a visitor exports or imports their identity.

`/api/query` is owner-authenticated; public dashboards expose named,
parameterized reports only — raw datalog never faces the open internet.

## identity pipeline

the secret is 32 bytes of entropy; each domain derives its own secp256k1
key from it through one hemera hash — the stack's own hash, no BIP32/BIP39
ladder on the signing path:

```text
d = Hemera(entropy ‖ 0x00 ‖ domain) mod n      per-domain secret scalar
pubkey = d·G                                    SEC1-compressed (33 B)
                    │
  bech32(hrp, ripemd160(sha256(pubkey)))  = neuron (wire form)
  Hemera(pubkey)                          = native neuron id (32 B)

  entropy ◀──BIP-39 (lazy, words.js)──▶ 24-word backup   (import/export only)
```

per-domain unlinkability comes from the hash: a distinct `domain` yields an
independent scalar, so two sites observe two unlinkable neurons and a
leaked per-domain key reveals nothing about the others — the same property
BIP32 hardening gave, without BIP32's HMAC-SHA512 weight in the wasm. the
`0x00` separator keeps `(entropy, domain)` pairs from colliding by
concatenation. `domain` is the registrable domain (eTLD+1 per the public
suffix list), so one site's subdomains see one neuron. reducing the 32-byte
digest mod n carries ~2⁻¹²⁸ bias (n ≈ 2²⁵⁶) and is zero with probability
~2⁻²⁵⁶ — negligible; the reduced scalar is a valid key. the wire hrp
defaults to `lytics` and is a deployment setting.

why a hemera KDF, not BIP32: lytics neurons are freshly minted keys that
never lived in a BIP32 wallet, and the per-domain path was custom anyway
(`account = Hemera(domain)`), so no standard wallet reproduced these keys
regardless. dropping BIP32 for a single hemera hash is smaller (no
sha512/bip32 in the wasm), cyber-native (one hash across the whole stack),
and recovers with a one-line formula — `d = Hemera(entropy ‖ 0x00 ‖ domain)
mod n` — that any tool with hemera and secp256k1 reproduces from the
entropy. the entropy backup stays standard BIP39 (words.js, lazy): the
phrase round-trips the 32-byte entropy with any BIP39 tool; only the
key-stretching is ours.

events are signed in ADR-036 shape, and the mudra claim is key-level (any
secp256k1 key qualifies — no derivation path is part of it), so the
existing bridge claim (`legacy address → native neuron`) carries any lytics
neuron into the native graph unchanged.

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
  attention { ms, scroll_depth }    attention events: ms integer, scroll_depth percent 0-100
  props { key: value, ... }         typed custom properties
  revenue { amount, currency }      optional; amount integer, minor units
  timestamp                          unix milliseconds
  pow { nonce, difficulty }          difficulty: the solved target, a record
  pubkey                             base64 SEC1-compressed secp256k1 (33 B)
  signature                          base64 compact secp256k1 over the ADR-036 doc
}
```

the client signs the body — every field above pow. `pubkey` rides outside
the body because the bech32 neuron is a hash of it and verification needs
the preimage. server enrichment (source, channel, geo, device) is
server-attested, derived at ingest, and never part of the signature.

### canonical encoding

the signed bytes are the event body as canonical JSON — sorted keys, no
whitespace, integers only — wrapped in the ADR-036 sign doc. the event
hash is [[hemera]] over the body bytes; it doubles as the particle hash
and as the dedup key.

### proof of work

the PoW predicate is one hash: find `nonce` such that
`Hemera(event_hash ‖ nonce) < target`. verification is a single hash
against the server's current target — the client-reported
`pow.difficulty` is a record, never an input to acceptance. targets come
from the difficulty oracle (`GET /api/difficulty`), tuned so a median
phone spends ~0.042 s per event.

two targets, one knob: an unseen neuron's first event must meet the
enrollment target — default 100× the event target, ~4 s of background
work — so identity itself is minted with work. a neuron farm pays two
orders of magnitude more than a visitor, while a real first visit absorbs
the cost invisibly behind reading. PoW prices signals; it never
authenticates humanity — that honesty stands.

### replay and time

events are content-addressed: the event hash is the particle hash, so a
replayed event is the same particle and appending it again is a no-op —
idempotency is the dedup. timestamps bound skew, never history: events
from the future (> +5 min) are rejected; stale events are accepted up to
a deployment horizon (default 24 h) so offline queues survive flaky
networks.

### erasure

the cell is append-only, and erasure still must be real. event payloads
are encrypted at rest with a per-neuron data key held by the site;
`DELETE /api/neuron` destroys the key. the graph keeps its hashes, the
data becomes unreadable, already-published aggregates stay — the standard
crypto-shredding resolution of append-only against the right to erase.
erasure erases the past and forbids nothing forward: the neuron's next
event simply enrolls a fresh data key.

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
distinct streams; every report keeps them separable. the declaration is a
claim bound to the key: standing accrues to the neuron, names are labels.
binding `operator` to an external identity (an operator-signed delegation)
is deferred past v1.

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
| identity pipeline | [[mudra]] bridge (`mudra/specs/bridge.md`) | entropy → Hemera KDF → secp256k1 → bech32, neuron = Hemera(pubkey), ADR-036 signing — the existing bridge claim carries a lytics neuron into the native graph |
| pow + hashing | [[hemera]] Poseidon2 | event hash and PoW share the stack's native hash — a lytics event hash is already a particle hash |

## repo layout

```text
lytics/
├── README.md      product page
├── specs/         this document — canonical
└── rs/            cargo workspace
    ├── event/     shared crypto spine — canonical encoding, hash, pow, keys, adr-036
    ├── ingest/    axum service embedding the cell + reports + static dashboard
    │   └── static/dash.html    the symbolic dashboard
    ├── agent/     reference agent client + load generator
    └── core/      wasm tracker core (phase: tracker) + loader.js
```

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
erasure endpoint (per-neuron data-key destruction). `agent/`: a reference
Rust client (canonical encoding + PoW + ADR-036) proving the API needs no
browser. acceptance gate: sustain 100 events/s on one core with the cell
embedded.

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

# a replayed event is idempotent
curl -s https://lytics.local/api/event -d @signed-event.json   # → 202 again, counts unchanged

# the premium tier answers
echo '?[cohort, week, retained] := ...' | curl -s -d @- https://lytics.local/api/query

# erasure destroys the neuron's data key
curl -s -X DELETE https://lytics.local/api/neuron/<bech32>      # → 204, payloads unreadable

# cyber.page dashboard shows live visitors from lytics, plausible.io off
```

## license

cyber license: don't trust. don't fear. don't beg.
