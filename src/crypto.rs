//! Hashing, signing and canonical JSON helpers shared by evidence, orders and the audit log.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// HMAC-SHA256 of `message` with `key`, as lowercase hex (the simulator's demo signature).
pub fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Canonical JSON: object keys sorted recursively, no insignificant whitespace.
///
/// Hashes are always computed over this form so any tool that sorts keys can re-check them.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("string keys serialize"));
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).expect("scalars serialize")),
    }
}

/// SHA-256 over the canonical JSON form of `value`.
pub fn hash_value(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

/// Random lowercase hex token with `bytes` bytes of entropy from the OS generator.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    hex::encode(buf)
}

/// Constant-time string comparison for tokens and signatures.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Text the simulator expects to be signed for a blocking order.
pub fn order_message(order_id: &str, kind_wire: &str, target: &str, expires_min: i64, judge_id: &str) -> String {
    format!("{order_id}|{kind_wire}|{target}|{expires_min}|{judge_id}")
}

/// Text the simulator expects to be signed to lift an order.
pub fn lift_message(order_id: &str, judge_id: &str) -> String {
    format!("LEVANTAR|{order_id}|{judge_id}")
}

/// Text the platform signs to record a judge's decision over a case file.
pub fn decision_message(
    case_id: &str,
    case_hash: &str,
    verdict: &str,
    measure: &str,
    judge_id: &str,
    minute: f64,
) -> String {
    format!("DECISION|{case_id}|{case_hash}|{verdict}|{measure}|{judge_id}|{minute:.3}")
}

/// Text the platform signs to record a judge's decision over a claim.
pub fn claim_decision_message(claim_id: &str, verdict: &str, judge_id: &str, minute: f64) -> String {
    format!("RECLAMO|{claim_id}|{verdict}|{judge_id}|{minute:.3}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::crypto::{canonical_json, constant_time_eq, hmac_sha256_hex, lift_message, order_message};

    #[test]
    fn order_signature_matches_the_simulator() {
        // Vector computed with Python's hmac module, the simulator's own implementation.
        let message = order_message("ord-0001", "ip", "203.0.113.10", 105, "jueza-laura-ficticia");
        assert_eq!(
            hmac_sha256_hex(b"demo-clave-laura-0b7e", &message),
            "7d9e7fcd07de3fa5e0b18744cce33ef90c79bc036bd8a3517a3ed5c26ad0e507"
        );
    }

    #[test]
    fn lift_signature_matches_the_simulator() {
        let message = lift_message("ord-0001", "juez-martin-ejemplo");
        assert_eq!(
            hmac_sha256_hex(b"demo-clave-martin-4c21", &message),
            "c2b9d1ad8e36d194114c2046e8d8fbb1ee14d8fe310f1c1ed836182136ee7dde"
        );
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let value = json!({"b": 1, "a": {"d": [1, {"z": true, "y": null}], "c": "x"}});
        assert_eq!(canonical_json(&value), r#"{"a":{"c":"x","d":[1,{"y":null,"z":true}]},"b":1}"#);
    }

    #[test]
    fn constant_time_eq_compares_content() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
