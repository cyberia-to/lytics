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
│ core.wasm ~26KB │           │  ua · geo · ref  │  ───►  │  d3 widgets  │
│  keys·sign·pow  │           │  cast signal     │        └──────────────┘
└─────────────────┘           │ cell (cybergraph)│              ▲
                              │  bbg state·time  │              │
                              │ query (inf)      │──────────────┘
                              └──────────────────┘   HTTP /api/report/*
```

| component | language | role |
|---|---|---|
| loader | JS module, ~2 KB source | fires on page load, captures pageview + SPA route changes instantly, runs the attention sensor, queues events until the core is ready |
| core | Rust → wasm, ~31 KB gzip / ~26 KB brotli measured | keygen, per-domain derivation, secp256k1 signing, PoW; loaded async so page performance never waits on crypto |
| ingest | Rust, axum | signature + PoW verification, replay dedup, UA parsing, MaxMind geo (ip read, used, discarded), referrer→source attribution, adaptive difficulty, signal casting into the cell |
| store | in-process event log, cast towards [[cybergraph]] cell + [[bbg]] | events enter signed and hash-addressed; the cell/bbg wiring for provable state is phase 6 — reports today read the ingest process's own log |
| query | [[inf]] native (`inf-parse/plan/eval`) over a `LocalSource` built from the log | every report — including sources, channels, passages and funnels, which group by *passage* — is a real inf rule; no report answers from a Rust loop over the event stream in the release binary |
| dashboard | static HTML + vanilla JS (`static/dash.html`) | polls the report endpoints, no build step; the Leptos/Trunk/d3 skeleton below was never built |

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
primitives, but nine cuts brought the core from ~172 KB gzip to ~31 KB gzip
(~26 KB brotli):

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
8. hex went hand-rolled too (~30 lines) — the crate's generic decode
   iterator (`GenericShunt<Map<Enumerate<Chunks>>>`) costs more than the
   table lookup it wraps.
9. `wasm-opt -Oz` ran over the result.

what remains is the honest floor: secp256k1 signing (k256, now the largest
piece) plus Poseidon2 (hemera, a mere ~3 KB) for the event hash, the KDF,
and PoW. it loads async and gates nothing — the loader captures the first
pageview and the whole attention stream before the core compiles, then signs
the queue retroactively. the deepest remaining lever is a hand-rolled
minimal secp256k1, or moving signing to `@noble/secp256k1` in JS (~4 KB,
same curve) — deferred; the curve stays secp256k1 either way so the mudra
bridge and on-chain identity hold.

first-load transfer, measured: ~38 KB gzip / ~32 KB brotli total (wasm +
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

### work quanta — attention mining (design, unbuilt)

the same PoW machinery inverts into a reward channel: during an active
attention window the core accumulates work quanta — background hashes at
duty-cycle rates (a few percent of one core, thermals first) — and each
signed attention event carries its quanta count as a `work` field beside
`pow`. a chain-side contract (the uhash attachable-proof envelope, see
`uhash/docs/viewing-economy.md` and rewards §8) turns accumulated quanta
into period lottery tickets: viewing becomes the first rung of cyber's
distribution ladder — "get paid to understand", literally. the honesty
conventions carry over unchanged: quanta price attention, they never
prove it; a bot that burns CPU earns no more than a plain miner, so
faking viewing is strictly wasteful. unbuilt: the `work` field, the
quanta accumulator in core.wasm, and the contract wiring are phase 6+
work and appear here so the event schema reserves the seam.

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
| query engine | [[inf]] native (`inf-parse/plan/eval`) | live: `inf_reports.rs` builds a `LocalSource` from the event log per request and answers every report through real inf rules, each pinned to a `#[cfg(test)]`-only Rust reference by a differential test |
| datalog reference | `inf/rs/cozo` | reference only: behavior and api shapes to check against, never a dependency |
| dashboard | `static/dash.html` | plain HTML/JS, polling the report endpoints — no Leptos/Trunk build, shipped deliberately smaller |
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

### phase 3 — queries: the full report set (4 sessions) — done

every report is an inf rule: neurons/views/attention timeseries, top
particles, countries, devices, actors, retention matrix, return probability
within a stated window, and — sources, channels, passages, funnels. all
engine arithmetic is integer ([[inf]] has no floats; ratios render at the
dashboard edge). differential tests pin every migrated report to the Rust
implementation it replaced; that implementation is `#[cfg(test)]` only —
not present in the release binary at all.

sources/channels/passages/funnel group by *passage* (the run of a neuron's
events from one arrival to the next), which looked at first like it needed
an ordered scan carrying state between consecutive events — a window/lag
primitive inf's language does not have, confirmed directly against the
evaluator. it turned out not to: a passage boundary is just a count. the
passage id of an event is the number of that neuron's arrivals strictly
after its first-ever event and at-or-before this event's own timestamp — an
inequality self-join plus `count`, the same running-count technique
`retention`/`returns` already used for cohort/offset math. funnels needed no
new technique at all — "does an increasing-timestamp subsequence exist" is
what a chain of ordered existential joins already answers, provably
equivalent to the greedy single-pass scan the Rust reference used.

### phase 4 — dashboard (3 sessions) — done, smaller than planned

no Leptos app: `static/dash.html` is plain HTML/JS polling the report
endpoints, deliberately — no build step, no wasm dashboard bundle on top
of the tracker's own. period picker, the classic widgets (neurons,
particles, sources, geo, devices) recast on attention metrics, retention
grid. comparison view and public dashboard links are still open.

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

# the premium tier answers — retention runs as a real inf rule, not a stub
curl -s 'https://lytics.local/api/report/retention?weeks=8'

# erasure destroys the neuron's data key
curl -s -X DELETE https://lytics.local/api/neuron/<bech32>      # → 204, payloads unreadable

# cyber.page dashboard shows live visitors from lytics, plausible.io off
```

## license

cyber license: don't trust. don't fear. don't beg.
