// ---
// tags: lytics, javascript
// crystal-type: source
// crystal-domain: cyber
// ---
// lytics core worker — the wasm core (keys, signing, proof of work) off the
// main thread. the enrolment proof of a fresh neuron is seconds of hashing
// on a phone; on the main thread that was a frozen tab (cyb.money, 2026-10-21).
// the loader posts { type: "init" } once with the entropy it owns (localStorage
// is main-thread only), then { type: "build", id, args, target } per event and
// receives { type: "built", id, json }. nothing here touches the DOM or storage.

import init, { Tracker, generate_entropy } from "./lytics_core.js";

let tracker = null;

self.onmessage = async (ev) => {
  const m = ev.data || {};
  try {
    if (m.type === "init") {
      await init();
      // a fresh visitor has no entropy yet: the core makes it here and hands
      // it back for the loader to persist (localStorage is main-thread only)
      const entropy = m.entropy || generate_entropy();
      tracker = new Tracker(entropy, m.identityDomain, m.hrp);
      self.postMessage({ type: "ready", neuron: tracker.neuron, entropy });
    } else if (m.type === "build") {
      if (!tracker) throw new Error("core not initialised");
      const json = tracker.build_event(...m.args, m.target);
      self.postMessage({ type: "built", id: m.id, json });
    }
  } catch (e) {
    self.postMessage({ type: "error", id: m.id, message: String((e && e.message) || e) });
  }
};
