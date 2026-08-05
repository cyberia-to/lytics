// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! geo lookup — ip in, (country, region, city) out, ip discarded.
//!
//! reads any mmdb city database (GeoLite2 or db-ip city lite). the ip is
//! used for exactly one lookup and never stored; only the derived names
//! enter the payload log.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Geo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    pub fn open(path: &str) -> Result<Self, String> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        Ok(Self { reader })
    }

    /// resolve and open the geo db for server startup: `LYTICS_GEO_DB` if
    /// set, else the cwd-relative default `data/dbip-city-lite.mmdb`.
    ///
    /// always logs to stderr — either where the db loaded from, or why it
    /// didn't — so a missing/misconfigured db is never silent. only
    /// cwd-relative resolution is attempted (no binary-relative search):
    /// the server is expected to be launched from the repo root, and
    /// `LYTICS_GEO_DB` is the escape hatch for any other layout.
    pub fn open_default() -> Option<Self> {
        let path =
            std::env::var("LYTICS_GEO_DB").unwrap_or_else(|_| "data/dbip-city-lite.mmdb".into());
        match Self::open(&path) {
            Ok(db) => {
                eprintln!("geo db loaded: {path}");
                Some(db)
            }
            Err(e) => {
                eprintln!("geo db unavailable ({path}): {e}");
                None
            }
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Geo> {
        let city: maxminddb::geoip2::City = self.reader.lookup(ip).ok()?;
        let country = city.country.and_then(|c| c.iso_code).map(String::from);
        let region = city
            .subdivisions
            .as_ref()
            .and_then(|s| s.first())
            .and_then(|s| s.iso_code)
            .map(String::from);
        let city_name = city
            .city
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").copied())
            .map(String::from);
        Some(Geo { country, region, city: city_name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_path_errs() {
        assert!(GeoDb::open("does/not/exist.mmdb").is_err());
    }

    /// smoke test against the real db-ip city lite file, when present in the
    /// checkout. skips (not fails) if the multi-hundred-MB file isn't there
    /// — it's gitignored data, not guaranteed in every environment.
    #[test]
    fn open_real_db_if_present() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/dbip-city-lite.mmdb");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping open_real_db_if_present: {path} not present in this checkout");
            return;
        }
        let db = GeoDb::open(path).expect("open real geo db");
        // a lookup against localhost may or may not resolve, but must not panic
        let _ = db.lookup("8.8.8.8".parse().unwrap());
    }
}
