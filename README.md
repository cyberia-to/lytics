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

[[attention]] is the scarce quantity every site competes for; analytics is
the feedback loop that measures it. the web now has two kinds of readers —
people and agents — and conventional analytics fails both: it guesses at
human attention through sessions and salts, and meets machine attention
with blocklists and captchas, as if the fastest-growing audience were
noise.

lytics measures the whole loop for both, on [[soft3]] principles: the
visitor owns a keypair, every event is a signed assertion, every signal
costs a small proof of work — and attention becomes queryable knowledge,
retention, cohorts and funnels included. a [[neuron]] is anyone who can
sign — human, AI, sensor or program.

lytics is the first consumer application of the soft3 stack and the neuron
onramp for [[cyber]]: every visitor carries a portable identity that can
later claim a place in the [[cybergraph]].

## the two failures of conventional analytics

it guesses at people. the flagship metrics are inferences from silence: a
"session" is a 30-minute guess about a pause, "bounce" calls a satisfied
reader a failure, "duration" counts the last page as zero. the most
private tools guess hardest — a daily salt erases identity every 24 hours,
so retention and cohorts are impossible by construction.

it wars with machines. agent attention is treated as fraud: UA sniffing,
IP blocklists, captchas. honest agents get blocked, disguised ones walk
through, and the numbers are wrong both ways — precisely when agents
decide what gets cited, compared and bought.

plausible, the best incumbent — 1.3 KB of script, honest privacy — proved
the market and inherits both failures:

| plausible | consequence |
|---|---|
| `user_id = hash(daily_salt + domain + ip + ua)` | identity dies every 24h |
| salt deleted daily | retention and cohorts impossible |
| funnels, revenue, sites api | proprietary — readable, unusable |
| bot filtering | a 32k-IP blocklist — machine attention as enemy |

lytics replaces the salt with a visitor-owned keypair and the blocklist
with economics. one change closes both failures: stable identity makes the
premium tier core; a [[costly signal]] on every event prices spam while
declared agents become an audience.

## what changed under analytics' feet

plausible answered 2019 — cookies the sin, GA the monopoly. 2026 asks
harder:

- agents arrived. traffic increasingly reads on a person's behalf,
  choosing what gets cited and bought. an agent gets the same primitive as
  a human — a neuron with its own retention and funnels; undeclared floods
  pay PoW per fake view.
- attribution collapsed. referrers stripped, links travel through chats,
  "direct" swallowed the truth. lytics binds attribution to signed arrival
  events, gives assistant referrals their own channel, and recognizes a
  returning neuron with zero referrer.
- numbers demand proof. sponsors audit traffic they cannot verify; fraud
  lives in that gap. every count is backed by keys and work today, by
  [[zheng]] proofs at the endgame — traffic anyone can verify.
- consent fatigue won. banners trained the web to click reject. lytics is
  first-party and self-hosted; identity is owned, exported and erased by
  the visitor.

## the identity model

the browser holds a keypair. the visitor is a [[neuron]].

1. first visit: the wasm core generates a seed in IndexedDB and derives
   the neuron along the [[mudra]] bridge pipeline — BIP39 → BIP32 →
   secp256k1 → bech32, id = [[hemera]] of the pubkey. the visitor sees
   nothing.
2. every event is signed. unsigned is spam by definition.
3. every event carries proof of work — ~0.042 s on a median phone,
   microseconds to verify, difficulty per site.
4. the seed exports as a BIP39 mnemonic: import elsewhere, or burn and
   start clean. identity belongs to the visitor.
5. per-domain derivation: a site sees a neuron from `(seed, domain)`. two
   sites, two unlinkable neurons; linking is the visitor's choice.
6. agents enroll the same way — keys, signatures, PoW, a declaration in
   the event. a well-behaved agent earns standing no blocklist could
   grant.

the same key can later sign a [[cyberlink]]: the mudra claim works
unchanged, so every visitor holds a standing invitation into the
cybergraph — settlement is a replay, never a migration.

### privacy, stated plainly

a per-domain neuron is pseudonymous data; lytics sites disclose it like
any analytics. the visitor holds the key, exports it, erases the trail
(deletion by neuron is one query), and cannot be tracked across sites.
raw IP serves geo lookup and is discarded.

## what the identity unlocks

| feature | mechanism |
|---|---|
| retention | first-seen cohort × return matrix over stable neurons |
| cohorts | by first-seen week, campaign, or landing page |
| funnels | ordered event sequences per neuron, across days |
| agent audience | declared agent neurons, separable in every report; undeclared floods pay PoW |
| goals and revenue | named events with typed props, summed per cohort |
| provable stats (endgame) | [[zheng]]-proven aggregates — "this page truly had N visitors", a claim no other analytics can make |

## attention, measured

lytics has no sessions. the 30-minute timeout is folklore from 90s log
analyzers — a guess about silence, standardized by GA and copied since.
silence is ambiguous: reading, parked tab, gone. lytics measures: the
tracker is a sensor, the browser reports the real boundaries, and
attention integrates on-device and ships signed.

human attention is sensed — visibility, focus, scroll. agent attention is
declared — the agent states what it read, bound to its key. both signed,
both queryable, never silently blended.

| classic | lytics |
|---|---|
| session duration — inferred from gaps, last page counts zero | attention time — visible-and-active ms, measured on-device |
| bounce rate | attention per arrival + return probability in a stated window |
| sessions count | arrivals, by source |
| pages per session | pages per passage |
| bot traffic — subtracted by blocklist guesswork | agent attention — declared, signed, reported in its own right |

visits become arrivals and passages — bounded by what the neuron did,
never by how long it paused. formal model: [specs/](specs/README.md).

## what lytics rejects

- the daily salt. anonymity through amnesia trades the retention tier for
  a privacy property the visitor never controls.
- the session. a timeout is a guess dressed as a standard; bounce,
  duration and exit page inherit it.
- the bot war. detection and disguise escalate forever, and both sides
  lie. lytics prices the signal: spam pays in compute, honesty earns an
  audience.
- clickhouse. the store is the cybergraph itself — bbg state in an
  embedded cell, read by inf; a columnar engine remains a swap-in.
- the SaaS scaffolding. billing, quotas, roles, importers — 70% of
  plausible serves their cloud. lytics ships the engine.

## deeper

architecture, event schema, the formal attention model, the reuse map and
the build plan: [specs/](specs/README.md).

## license

cyber license: don't trust. don't fear. don't beg.
