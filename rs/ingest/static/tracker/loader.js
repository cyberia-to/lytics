// ---
// tags: lytics, javascript
// crystal-type: source
// crystal-domain: cyber
// ---
// lytics loader — the browser glue the wasm core cannot reach: identity
// persistence, the attention sensor, SPA navigation, transport. all crypto
// (keys, signing, pow) lives in the wasm core; this file only observes and
// ships. spec: lytics/specs/README.md, the attention model.

import init, { Tracker, generate_entropy } from "./lytics_core.js";

// type=module scripts have document.currentScript === null — resolve our tag.
const script =
  document.currentScript ||
  document.querySelector('script[src*="loader.js"][data-endpoint]') ||
  document.querySelector('script[type="module"][src*="/lytics/tracker/"]') ||
  document.querySelector('script[type="module"][src*="loader.js"]');
// default /lytics when embedded on cyberstates (same-origin subpath)
const ENDPOINT = (script?.dataset?.endpoint || "/lytics").replace(/\/$/, "");
// the real site a visit happened on — per-event, never fed into key derivation.
const HOSTNAME =
  script?.dataset?.domain || location.hostname.replace(/^www\./, "");
// the key-derivation salt. every site sharing one identity domain derives the
// same neuron from the same entropy — this is what makes a visitor's identity
// portable across cyb.ai/soft3.org/cyber.page/cyberstates.net at all. do not
// default this to HOSTNAME: that would silently re-fragment identity back to
// one neuron per site, defeating cross-domain linking below.
const IDENTITY_DOMAIN = script?.dataset?.identityDomain || "cyberia";
const HRP = script?.dataset?.hrp || "lytics";
// sibling sites in the same identity domain — outbound links to these carry
// the visitor's entropy across the origin boundary (localStorage can't).
// cookies can't either: none of these are subdomains of a shared parent.
const SIBLINGS = (
  script?.dataset?.siblings ||
  "cyber.page,cyb.ai,soft3.org,cyberstates.net,bostrom.network"
)
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s && s !== HOSTNAME);
const LINK_PARAM = "_ly";
const HEARTBEAT_MS = 15000; // instrument granularity — bounds attention lost to a killed tab
const IDLE_MS = 5000; // input silence pauses the attention clock

const KEY = `lytics:entropy:${IDENTITY_DOMAIN}`;
let tracker, eventTarget, enrollTarget, ready;
const queue = []; // events captured before the core is live

// ── identity: 32-byte entropy lives in localStorage, per identity domain ────
// localStorage is origin-scoped — cyb.ai's JS cannot read soft3.org's entry,
// and none of SIBLINGS shares a parent domain to cookie-share across. the
// only channel between origins is the URL itself: a sibling site that just
// sent this visitor here can carry the entropy as a one-shot query param.
// adoptIncomingIdentity runs before the wasm core loads so the param is
// consumed (and scrubbed from the visible URL) as early as possible.
const ENTROPY_RE = /^[0-9a-f]{64}$/i;
function adoptIncomingIdentity() {
  const url = new URL(location.href);
  const incoming = url.searchParams.get(LINK_PARAM);
  if (!incoming || !ENTROPY_RE.test(incoming)) return;
  // a sibling's decorated link is a deliberate "this is the same visitor"
  // claim — trust it over whatever (or nothing) is already stored locally.
  localStorage.setItem(KEY, incoming.toLowerCase());
  url.searchParams.delete(LINK_PARAM);
  history.replaceState(history.state, "", url.pathname + url.search + url.hash);
}
function loadOrCreateEntropy() {
  let e = localStorage.getItem(KEY);
  if (!e) {
    e = generate_entropy(); // hex, no wordlist touched
    localStorage.setItem(KEY, e);
  }
  return e;
}
// decorate outbound links to sibling sites with this visitor's entropy so
// the landing page can adopt it via adoptIncomingIdentity above — the only
// way identity crosses an origin boundary here. capture phase + mutating
// the href in place (not a synthetic navigation) means this works
// regardless of how the click is handled downstream: plain click, new tab,
// ctrl/cmd-click, middle-click all read the same href.
function decorateOutboundLinks() {
  document.addEventListener(
    "click",
    (ev) => {
      const a = ev.target.closest && ev.target.closest("a[href]");
      if (!a) return;
      let dest;
      try {
        dest = new URL(a.href, location.href);
      } catch {
        return;
      }
      if (!SIBLINGS.includes(dest.hostname.replace(/^www\./, ""))) return;
      const entropy = localStorage.getItem(KEY);
      if (!entropy) return;
      dest.searchParams.set(LINK_PARAM, entropy);
      a.href = dest.toString();
    },
    { capture: true },
  );
}
// export/import as a human-readable 24-word backup loads the wordlist lazily
// — a rare, deliberate action, never on the signing path. `words.js` wraps
// @scure/bip39 (entropy <-> phrase); shipped separately, imported on demand.
window.lytics = window.lytics || {};
window.lytics.exportEntropy = () => localStorage.getItem(KEY);
window.lytics.exportPhrase = async () => {
  const { entropyToPhrase } = await import("./words.js");
  return entropyToPhrase(localStorage.getItem(KEY));
};
window.lytics.importPhrase = async (phrase) => {
  const { phraseToEntropy } = await import("./words.js");
  localStorage.setItem(KEY, phraseToEntropy(phrase));
  location.reload();
};
window.lytics.forget = () => {
  localStorage.removeItem(KEY);
};

// ── transport ───────────────────────────────────────────────────────────────
async function difficulty() {
  const neuron = tracker.neuron;
  const r = await fetch(`${ENDPOINT}/api/difficulty?neuron=${neuron}`);
  const d = await r.json();
  eventTarget = BigInt(d.event_target);
  enrollTarget = BigInt(d.enroll_target);
  return d.enrolled;
}
let enrolled = false;
function currentTarget() {
  return enrolled ? eventTarget : enrollTarget;
}
async function send(spec) {
  const target = currentTarget();
  // wasm signs + pow's from explicit args and returns the ready-to-POST JSON
  // (no JSON parse in the wasm; nothing to stringify here)
  const json = tracker.build_event(
    spec.kind,
    HOSTNAME,
    spec.pathname,
    spec.navigation ?? undefined,
    spec.referrer ?? undefined,
    spec.attention_ms ?? undefined,
    spec.scroll_depth ?? undefined,
    spec.agent_name ?? undefined,
    spec.agent_operator ?? undefined,
    spec.timestamp,
    target,
  );
  const r = await fetch(`${ENDPOINT}/api/event`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: json,
    keepalive: true,
  });
  if (r.status === 202) enrolled = true; // first accept enrolls the neuron
  return r.status;
}

// ── the attention sensor ─────────────────────────────────────────────────────
// integrate time while the page is visible AND the neuron is active. `counting`
// is the single truth of whether the clock runs; every stretch is accrued
// before the clock stops, so no visible time is ever lost to a transition.
let attentionMs = 0,
  scrollDepth = 0,
  lastTick = 0,
  counting = false,
  lastInput = 0;
function now() {
  return Date.now();
}
function startCounting() {
  if (!counting) {
    counting = true;
    lastTick = now();
  }
}
function stopCounting() {
  accrue();
  counting = false;
}
function accrue() {
  if (!counting) return;
  const t = now();
  attentionMs += t - lastTick;
  lastTick = t;
  if (t - lastInput > IDLE_MS) counting = false; // idle → pause the clock
}
function markActive() {
  lastInput = now();
  if (document.visibilityState === "visible") startCounting();
}
function trackScroll() {
  const h = document.documentElement;
  const denom = h.scrollHeight - h.clientHeight || 1;
  const pct = Math.min(100, Math.round((h.scrollTop / denom) * 100));
  if (pct > scrollDepth) scrollDepth = pct;
}
async function flushAttention() {
  accrue();
  if (attentionMs < 1000) return;
  const ms = attentionMs;
  attentionMs = 0;
  await afterReady(() =>
    send({
      kind: "attention",
      pathname: location.pathname,
      attention_ms: ms,
      scroll_depth: scrollDepth,
      timestamp: now(),
    }),
  );
}

// ── pageview + SPA ───────────────────────────────────────────────────────────
let firstView = true;
function pageview() {
  const nav = firstView
    ? document.referrer && !document.referrer.includes(HOSTNAME)
      ? "external"
      : "direct"
    : "internal";
  firstView = false;
  scrollDepth = 0;
  attentionMs = 0;
  markActive();
  const spec = {
    kind: "pageview",
    pathname: location.pathname,
    navigation: nav,
    referrer: document.referrer || null,
    timestamp: now(),
  };
  afterReady(() => send(spec));
}
function afterReady(fn) {
  if (ready) return fn();
  queue.push(fn); // captured before the core loaded — signed retroactively
}
function hookHistory() {
  for (const m of ["pushState", "replaceState"]) {
    const orig = history[m];
    history[m] = function () {
      const r = orig.apply(this, arguments);
      onRoute();
      return r;
    };
  }
  addEventListener("popstate", onRoute);
}
let lastPath = location.pathname;
function flushAndView() {
  flushAttention().then(pageview);
}
function onRoute() {
  if (location.pathname === lastPath) return;
  lastPath = location.pathname;
  flushAndView();
}

// ── boot ──────────────────────────────────────────────────────────────────────
addEventListener("scroll", trackScroll, { passive: true });
for (const e of ["mousemove", "keydown", "click", "scroll", "touchstart"]) {
  addEventListener(e, markActive, { passive: true });
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    stopCounting();
    flushAttention();
  } else {
    markActive();
  }
});
addEventListener("pagehide", () => {
  stopCounting();
  flushAttention();
});
addEventListener("blur", accrue);
setInterval(flushAttention, HEARTBEAT_MS);

// adopt a sibling-handoff identity (and scrub it from the URL) before
// anything else reads location.href or localStorage.
adoptIncomingIdentity();
decorateOutboundLinks();
// capture the first pageview immediately, then bring the core up
pageview();
hookHistory();
(async () => {
  await init();
  tracker = new Tracker(loadOrCreateEntropy(), IDENTITY_DOMAIN, HRP);
  enrolled = await difficulty();
  ready = true;
  window.lytics.neuron = tracker.neuron;
  while (queue.length) {
    const fn = queue.shift();
    await fn();
  }
})().catch((e) => console.error("lytics:", e));
