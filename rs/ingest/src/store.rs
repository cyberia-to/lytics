// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! encrypted append-only payload store — crypto-shredding erasure.
//!
//! frames: `[u32 le frame_len][u16 le neuron_len][neuron bech32][12 B nonce][ciphertext]`.
//! each neuron's payloads are encrypted with a per-neuron data key held in
//! `keys/<bech32>`; destroying the key file shreds every past frame. the log
//! is the source of truth — the in-memory index and the cell are replayed
//! from it at startup, skipping unreadable (shredded) frames.

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("corrupt frame")]
    Corrupt,
}

pub struct Store {
    dir: PathBuf,
    log: fs::File,
}

impl Store {
    pub fn open(dir: &str) -> Result<Self, StoreError> {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(dir.join("keys"))?;
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.log"))?;
        Ok(Self { dir, log })
    }

    fn key_path(&self, neuron: &str) -> PathBuf {
        self.dir.join("keys").join(neuron)
    }

    /// the data key for a neuron, creating one on first sight.
    pub fn data_key(&self, neuron: &str) -> Result<[u8; 32], StoreError> {
        let path = self.key_path(neuron);
        if let Ok(bytes) = fs::read(&path) {
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| StoreError::Corrupt)?;
            return Ok(key);
        }
        let key: [u8; 32] = ChaCha20Poly1305::generate_key(&mut OsRng).into();
        fs::write(&path, key)?;
        Ok(key)
    }

    pub fn known(&self, neuron: &str) -> bool {
        self.key_path(neuron).exists()
    }

    /// erasure: destroy the data key. every past frame of this neuron
    /// becomes unreadable; the next event enrolls a fresh key.
    pub fn shred(&self, neuron: &str) -> Result<bool, StoreError> {
        let path = self.key_path(neuron);
        if path.exists() {
            fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// append one encrypted payload frame.
    pub fn append(&mut self, neuron: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let key = self.data_key(neuron)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| StoreError::Crypto(e.to_string()))?;
        let neuron_bytes = neuron.as_bytes();
        let frame_len = 2 + neuron_bytes.len() + 12 + ct.len();
        let mut buf = Vec::with_capacity(4 + frame_len);
        buf.extend_from_slice(&(frame_len as u32).to_le_bytes());
        buf.extend_from_slice(&(neuron_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(neuron_bytes);
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ct);
        self.log.write_all(&buf)?;
        self.log.flush()?;
        Ok(())
    }

    /// replay every readable frame: (neuron, plaintext). shredded frames skip.
    pub fn replay(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let mut file = match fs::File::open(self.dir.join("events.log")) {
            Ok(f) => f,
            Err(_) => return Ok(vec![]),
        };
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= raw.len() {
            let frame_len =
                u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]) as usize;
            at += 4;
            if at + frame_len > raw.len() {
                break; // torn tail write — ignore
            }
            let frame = &raw[at..at + frame_len];
            at += frame_len;
            if frame.len() < 2 {
                continue;
            }
            let nlen = u16::from_le_bytes([frame[0], frame[1]]) as usize;
            if frame.len() < 2 + nlen + 12 {
                continue;
            }
            let neuron = match std::str::from_utf8(&frame[2..2 + nlen]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let key_bytes = match fs::read(self.key_path(&neuron)) {
                Ok(b) => b,
                Err(_) => continue, // shredded
            };
            let key: [u8; 32] = match key_bytes.as_slice().try_into() {
                Ok(k) => k,
                Err(_) => continue,
            };
            let nonce_bytes: [u8; 12] = frame[2 + nlen..2 + nlen + 12].try_into().unwrap();
            let nonce = Nonce::from(nonce_bytes);
            let ct = &frame[2 + nlen + 12..];
            let cipher = ChaCha20Poly1305::new((&key).into());
            if let Ok(pt) = cipher.decrypt(&nonce, ct) {
                out.push((neuron, pt));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> String {
        let d = std::env::temp_dir().join(format!(
            "lytics-store-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn append_replay_roundtrip() {
        let dir = tmp();
        let mut s = Store::open(&dir).unwrap();
        s.append("lytics1aaa", b"one").unwrap();
        s.append("lytics1bbb", b"two").unwrap();
        let frames = s.replay().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], ("lytics1aaa".into(), b"one".to_vec()));
        assert_eq!(frames[1], ("lytics1bbb".into(), b"two".to_vec()));
    }

    #[test]
    fn shred_makes_frames_unreadable_and_reenrolls() {
        let dir = tmp();
        let mut s = Store::open(&dir).unwrap();
        s.append("lytics1aaa", b"secret").unwrap();
        s.append("lytics1bbb", b"kept").unwrap();
        assert!(s.shred("lytics1aaa").unwrap());
        let frames = s.replay().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, "lytics1bbb");
        // forward: next event enrolls a fresh key and is readable again
        s.append("lytics1aaa", b"after").unwrap();
        let frames = s.replay().unwrap();
        assert_eq!(frames.len(), 2);
    }
}
