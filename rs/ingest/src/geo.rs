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
