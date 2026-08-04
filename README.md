---
title: lytics
tags: cyber, lytics, analytics, soft3
crystal-type: entity
crystal-domain: cyber
icon: "📈"
alias: cyber analytics, web analytics, lytics analytics
---

# lytics

> every visitor is a neuron

[[attention]] is the scarce quantity every site competes for, and analytics
is the feedback loop that measures it: who attends, from where, to what, and
whether they return. lytics measures exactly that loop — on [[soft3]]
principles: the visitor owns a keypair, every event is a signed assertion,
every signal costs a small proof of work, and the stream of attention becomes
queryable knowledge — retention, cohorts and funnels included from day one.

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

## what changed under analytics' feet

plausible answered 2019, when cookies were the sin and GA the monopoly.
2026 asks harder questions, and each one lands on a lytics primitive:

- agents arrived. a growing share of traffic is AI agents reading pages on
  a person's behalf. user-agent sniffing cannot separate them, and
  blocklists punish the honest ones. lytics hands an agent the same
  primitive a human gets — a [[neuron]]. declared agent attention becomes a
  first-class, filterable audience; undeclared floods pay PoW for every
  fake view.
- attribution collapsed. referrers are stripped, links travel through
  chats and AI assistants, and "direct" swallowed the truth. lytics
  attaches attribution to signed arrival events, treats assistant
  referrals as a channel of their own — and recognizes a returning neuron
  with zero referrer information.
- numbers demand proof. sponsors, advertisers and acquirers audit traffic
  claims they cannot verify, and fraud lives in that gap. every lytics
  count is backed by keys and work today, and by [[zheng]] proofs at the
  endgame — traffic worth money because anyone can verify it.
- consent fatigue won. banners trained the web to click reject. lytics
  runs first-party and self-hosted, with identity the visitor owns,
  exports and erases — the disclosure is one honest sentence.

## the identity model

the browser holds a keypair. the visitor is a [[neuron]].

1. first visit: the wasm core generates a seed, stores it in IndexedDB,
   derives the neuron along the [[mudra]] bridge pipeline — BIP39 →
   BIP32/44 → secp256k1 → bech32, neuron id = [[hemera]] of the pubkey.
   zero interaction — the visitor sees nothing.
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
neuron is bridge-ready by construction: the mudra claim (`legacy address →
native neuron`, ADR-036 signed) works on it unchanged, so every visitor of
every lytics site holds a standing invitation into the [[cybergraph]] — and
the event schema is shaped so settlement is a replay, never a migration.

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
| bot filtering | PoW + signature verification at ingest — filtering by economics |
| goals and revenue | named events with typed props, summed per cohort |
| provable stats (endgame) | aggregates proven by [[zheng]] — "this page truly had N visitors" is a claim no other analytics can make |

## attention, measured

lytics has no sessions. the 30-minute idle timeout that defines a "session"
everywhere else is folklore inherited from 90s log analyzers — a guess about
what silence means, standardized by google analytics and copied since,
plausible included. silence in an event log is ambiguous: reading, parked
tab, gone. lytics refuses to guess and measures instead: the tracker is a
sensor, the browser reports the real boundaries (visibility, focus, leave),
and attention is integrated on-device and shipped as signed events.

| classic | lytics |
|---|---|
| session duration — inferred from gaps, last page counts as zero | attention time — integrated visible-and-active ms, measured on-device |
| bounce rate | attention per arrival + return probability within a stated window |
| sessions count | arrivals, broken down by source |
| pages per session | pages per passage |

visits become arrivals and passages — segments bounded by what the neuron
did, never by how long they paused. the formal model lives in
[specs/](specs/README.md).

## what lytics rejects

- the daily salt. anonymity through amnesia trades the entire retention tier
  for a privacy property the visitor never controls. sovereign keys give the
  visitor stronger control and keep the data model whole.
- the session. a 30-minute idle timeout is a guess about silence dressed
  as a standard, and every metric built on it — bounce rate, session
  duration, exit page — inherits the guess. lytics measures attention and
  segments by arrivals; no clock constant defines the visitor.
- clickhouse. the store is the cybergraph itself: bbg state inside an
  embedded cell, read by inf. the target scale (cyber.page and peer sites)
  fits; a columnar engine stays a swap-in behind the query layer if a site
  ever outgrows it.
- the SaaS scaffolding. billing, quotas, team roles, importers — 70% of
  plausible's codebase serves their cloud business. lytics ships the engine.

## deeper

the canonical specification — architecture, event schema, the formal
attention model, the reuse map, the implementation plan and its confidence
milestone — lives in [specs/](specs/README.md).

## license

cyber license: don't trust. don't fear. don't beg.
