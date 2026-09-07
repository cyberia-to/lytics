// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! casting events into the cell — one signal per event.
//!
//! the event particle links to the page particle inside the neuron's signal
//! chain; the chain (step, prev) is tracked per native neuron so cybergraph's
//! ordering gate accepts every append. the cell is a derived index — it is
//! rebuilt from the payload log at startup.

use cybergraph::{Cybergraph, CyberlinkRecord, Signal, SELF_NETWORK};
use std::collections::BTreeMap;

pub type NeuronId = [u8; 32];
pub type Particle = [u8; 32];

/// page particle: hemera over "hostname pathname".
pub fn page_particle(hostname: &str, pathname: &str) -> Particle {
    let mut input = Vec::with_capacity(hostname.len() + 1 + pathname.len());
    input.extend_from_slice(hostname.as_bytes());
    input.push(b' ');
    input.extend_from_slice(pathname.as_bytes());
    *hemera::hash(&input).as_bytes()
}

/// per-neuron signal-chain cursor.
#[derive(Default)]
pub struct Chains {
    cursors: BTreeMap<NeuronId, (u64, Particle)>,
}

impl Chains {
    /// cast one event into the cell: event particle → page particle.
    pub fn cast(
        &mut self,
        cell: &mut Cybergraph,
        native: NeuronId,
        event_particle: Particle,
        page: Particle,
        ts_secs: u64,
    ) -> Result<(), String> {
        let (step, prev) = self.cursors.get(&native).copied().unwrap_or((0, [0u8; 32]));
        let link = CyberlinkRecord {
            neuron: native,
            from: event_particle,
            to: page,
            token: [0u8; 32],
            amount: 1,
            valence: 1,
            height: ts_secs,
        };
        let signal = Signal {
            neuron: native,
            network: SELF_NETWORK,
            links: vec![link],
            delta_pi: vec![],
            box_moves: vec![], // private conviction spends (WP3) — none in analytics casts
            prev,
            step,
            height: ts_secs,
            proof: None,
        };
        let hash = signal.hash();
        cell.link(signal).map_err(|e| format!("{e:?}"))?;
        self.cursors.insert(native, (step + 1, hash));
        Ok(())
    }
}
