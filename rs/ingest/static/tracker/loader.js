// ---
// tags: lytics, javascript
// crystal-type: source
// crystal-domain: cyber
// ---
// lytics loader — the browser glue the wasm core cannot reach: identity
// persistence, the attention sensor, SPA navigation, transport. all crypto
// (keys, signing, pow) lives in the wasm core; this file only observes and
// ships. spec: lytics/specs/README.md, the attention model.

import init, { Tracker, generate_mnemonic } from "./lytics_core.js";

const script = document.currentScript;
const ENDPOINT = (script?.dataset.endpoint || "").replace(/\/$/, "");
const DOMAIN = script?.dataset.domain || location.hostname.replace(/^www\./, "");
const HRP = script?.dataset.hrp || "lytics";
const HEARTBEAT_MS = 15000; // instrument granularity — bounds attention lost to a killed tab
const IDLE_MS = 5000; // input silence pauses the attention clock

const KEY = `lytics:seed:${DOMAIN}`;
let tracker, eventTarget, enrollTarget, ready;
const queue = []; // events captured before the core is live

// ── identity: the seed lives in localStorage, exportable, per-domain ────────
function loadOrCreateMnemonic() {
  let m = localStorage.getItem(KEY);
  if (!m) {
    m = generate_mnemonic();
    localStorage.setItem(KEY, m);
  }
  return m;
}
// exposed so a site can offer export/import/erase
window.lytics = window.lytics || {};
window.lytics.exportSeed = () => localStorage.getItem(KEY);
window.lytics.importSeed = (m) => { localStorage.setItem(KEY, m); location.reload(); };
window.lytics.forget = () => { localStorage.removeItem(KEY); };

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
  // wasm returns a signed, pow-carrying event as JSON
  const json = tracker.build_event(JSON.stringify(spec), target);
  const r = await fetch(`${ENDPOINT}/api/event`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: json, keepalive: true,
  });
  if (r.status === 202) enrolled = true; // first accept enrolls the neuron
  return r.status;
}

// ── the attention sensor ─────────────────────────────────────────────────────
// integrate time while the page is visible AND the neuron is active. `counting`
// is the single truth of whether the clock runs; every stretch is accrued
// before the clock stops, so no visible time is ever lost to a transition.
let attentionMs = 0, scrollDepth = 0, lastTick = 0, counting = false, lastInput = 0;
function now() { return Date.now(); }
function startCounting() { if (!counting) { counting = true; lastTick = now(); } }
function stopCounting() { accrue(); counting = false; }
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
  const denom = (h.scrollHeight - h.clientHeight) || 1;
  const pct = Math.min(100, Math.round((h.scrollTop / denom) * 100));
  if (pct > scrollDepth) scrollDepth = pct;
}
async function flushAttention() {
  accrue();
  if (attentionMs < 1000) return;
  const ms = attentionMs; attentionMs = 0;
  await afterReady(() => send({
    kind: "attention", pathname: location.pathname,
    attention_ms: ms, scroll_depth: scrollDepth, timestamp: now(),
  }));
}

// ── pageview + SPA ───────────────────────────────────────────────────────────
let firstView = true;
function pageview() {
  const nav = firstView
    ? (document.referrer && !document.referrer.includes(DOMAIN) ? "external" : "direct")
    : "internal";
  firstView = false;
  scrollDepth = 0; attentionMs = 0; markActive();
  const spec = {
    kind: "pageview", pathname: location.pathname, navigation: nav,
    referrer: document.referrer || null, timestamp: now(),
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
    history[m] = function () { const r = orig.apply(this, arguments); onRoute(); return r; };
  }
  addEventListener("popstate", onRoute);
}
let lastPath = location.pathname;
function flushAndView() { flushAttention().then(pageview); }
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
  if (document.visibilityState === "hidden") { stopCounting(); flushAttention(); }
  else { markActive(); }
});
addEventListener("pagehide", () => { stopCounting(); flushAttention(); });
addEventListener("blur", accrue);
setInterval(flushAttention, HEARTBEAT_MS);

// capture the first pageview immediately, then bring the core up
pageview();
hookHistory();
(async () => {
  await init();
  tracker = new Tracker(loadOrCreateMnemonic(), DOMAIN, HRP);
  enrolled = await difficulty();
  ready = true;
  window.lytics.neuron = tracker.neuron;
  while (queue.length) { const fn = queue.shift(); await fn(); }
})().catch((e) => console.error("lytics:", e));
