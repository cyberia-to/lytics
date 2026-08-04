// ---
// tags: lytics, rust
// crystal-type: source
// crystal-domain: cyber
// ---
//! canonical JSON — sorted keys, no whitespace, integers only.
//!
//! serde_json's default map is a BTreeMap, so object keys serialize sorted;
//! `to_string` emits no whitespace. this module adds the integer discipline:
//! any float anywhere in the tree is rejected.

use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CanonicalError {
    #[error("floats are forbidden in canonical encoding: {0}")]
    Float(String),
    #[error("json: {0}")]
    Json(String),
}

/// Re-encode a serializable value as canonical JSON bytes.
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Json(e.to_string()))?;
    reject_floats(&v, "$")?;
    Ok(serde_json::to_string(&v)
        .map_err(|e| CanonicalError::Json(e.to_string()))?
        .into_bytes())
}

fn reject_floats(v: &Value, path: &str) -> Result<(), CanonicalError> {
    match v {
        Value::Number(n) if n.is_f64() => Err(CanonicalError::Float(path.to_string())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                reject_floats(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, item) in map {
                reject_floats(item, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sort_and_whitespace_drops() {
        let v = json!({"b": 1, "a": {"z": 2, "y": [3, 4]}});
        let bytes = canonical_json(&v).unwrap();
        assert_eq!(bytes, br#"{"a":{"y":[3,4],"z":2},"b":1}"#.to_vec());
    }

    #[test]
    fn floats_rejected_with_path() {
        let v = json!({"a": {"bad": 1.5}});
        let err = canonical_json(&v).unwrap_err();
        assert_eq!(err, CanonicalError::Float("$.a.bad".into()));
    }

    #[test]
    fn encoding_is_deterministic() {
        let v = json!({"n": 42, "s": "x", "t": [1, 2]});
        assert_eq!(canonical_json(&v).unwrap(), canonical_json(&v).unwrap());
    }
}
