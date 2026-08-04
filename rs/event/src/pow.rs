// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! proof of work — one hash to verify.
//!
//! predicate: `u64_be(Hemera(event_hash ‖ nonce_le)[..8]) < target`.
//! lower target = harder. the enrollment target (first event of an unseen
//! neuron) defaults to 100× harder than the event target.

use crate::Particle;

/// score a nonce: the first 8 bytes of the hash as a big-endian u64.
fn score(event_hash: &Particle, nonce: u64) -> u64 {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(event_hash);
    input[32..].copy_from_slice(&nonce.to_le_bytes());
    let h = hemera::hash(&input);
    let b = h.as_bytes();
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// verify is a single hash.
pub fn verify(event_hash: &Particle, nonce: u64, target: u64) -> bool {
    score(event_hash, nonce) < target
}

/// solve by linear scan; returns the nonce. the scan starts at zero — each
/// event has a distinct hash, so two solvers never share a solution space
/// and a fixed start costs nothing. keeping it deterministic and free of
/// clock/entropy calls is what lets the identical code run in wasm.
pub fn solve(event_hash: &Particle, target: u64) -> u64 {
    let mut nonce = 0u64;
    loop {
        if verify(event_hash, nonce, target) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// expected hashes to solve = 2^64 / target. a "difficulty" of d hashes
/// maps to target = 2^64 / d.
pub fn target_from_difficulty(expected_hashes: u64) -> u64 {
    if expected_hashes <= 1 {
        return u64::MAX;
    }
    u64::MAX / expected_hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify() {
        let event_hash = [7u8; 32];
        // easy target: ~16 expected hashes
        let target = target_from_difficulty(16);
        let nonce = solve(&event_hash, target);
        assert!(verify(&event_hash, nonce, target));
    }

    #[test]
    fn wrong_nonce_fails_hard_target() {
        let event_hash = [9u8; 32];
        // essentially impossible target
        assert!(!verify(&event_hash, 12345, 1));
    }

    #[test]
    fn difficulty_maps_sanely() {
        assert_eq!(target_from_difficulty(0), u64::MAX);
        assert_eq!(target_from_difficulty(1), u64::MAX);
        assert!(target_from_difficulty(100) < target_from_difficulty(10));
    }
}
