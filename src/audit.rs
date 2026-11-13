//! Append-only, hash-chained audit log (JSON Lines).
//!
//! Every entry carries the hash of the previous one; the hash of an entry is the SHA-256 of the
//! canonical JSON of the entry without its `hash` field. Changing, removing or reordering any line
//! breaks the chain from that point on, and the public registry shows the current head so third
//! parties can pin it.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::crypto::hash_value;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub at: String,
    pub match_min: Option<f64>,
    pub actor: String,
    pub event: String,
    pub data: Value,
    pub prev_hash: String,
    pub hash: String,
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    seq: u64,
    head: String,
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn entry_hash(entry_without_hash: &Value) -> String {
    hash_value(entry_without_hash)
}

impl AuditLog {
    /// Starts a new log. An existing file is kept, renamed with a timestamp suffix.
    pub fn create(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if path.exists() {
            let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
            let rotated = path.with_extension(format!("{stamp}.jsonl"));
            std::fs::rename(path, &rotated).with_context(|| format!("rotating {}", path.display()))?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { path: path.to_path_buf(), file, seq: 0, head: GENESIS_HASH.to_string() })
    }

    /// Continues an existing log after verifying its chain.
    pub fn resume(path: &Path) -> anyhow::Result<Self> {
        let report = verify_file(path)?;
        if let Some(problem) = report.problem {
            bail!("audit log {} failed verification: {problem}", path.display());
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { path: path.to_path_buf(), file, seq: report.entries, head: report.head })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sequence number and hash of the last entry.
    pub fn head(&self) -> (u64, String) {
        (self.seq, self.head.clone())
    }

    pub fn record(&mut self, match_min: Option<f64>, actor: &str, event: &str, data: Value) -> AuditEntry {
        let mut body = json!({
            "seq": self.seq + 1,
            "at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "match_min": match_min.map(round3),
            "actor": actor,
            "event": event,
            "data": data,
            "prev_hash": self.head,
        });
        let hash = entry_hash(&body);
        body.as_object_mut().expect("entry is an object").insert("hash".into(), Value::String(hash.clone()));
        let line = serde_json::to_string(&body).expect("entry serializes");
        if let Err(e) = writeln!(self.file, "{line}").and_then(|_| self.file.flush()) {
            // The in-memory chain stays consistent; the operator sees the failure in the logs.
            tracing::error!(error = %e, "could not write the audit log");
        }
        self.seq += 1;
        self.head = hash;
        serde_json::from_value(body).expect("entry round-trips")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub entries: u64,
    pub head: String,
    pub problem: Option<String>,
}

/// Re-computes the whole chain of a log file.
pub fn verify_file(path: &Path) -> anyhow::Result<VerifyReport> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut prev = GENESIS_HASH.to_string();
    let mut entries = 0u64;
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let line_no = index + 1;
        let fail = |problem: String| VerifyReport { entries, head: prev.clone(), problem: Some(problem) };
        let mut value: Map<String, Value> = match serde_json::from_str(&line) {
            Ok(Value::Object(map)) => map,
            _ => return Ok(fail(format!("line {line_no}: not a JSON object"))),
        };
        let Some(Value::String(hash)) = value.remove("hash") else {
            return Ok(fail(format!("line {line_no}: missing hash")));
        };
        if value.get("prev_hash").and_then(Value::as_str) != Some(prev.as_str()) {
            return Ok(fail(format!("line {line_no}: prev_hash does not match the previous entry")));
        }
        if value.get("seq").and_then(Value::as_u64) != Some(entries + 1) {
            return Ok(fail(format!("line {line_no}: sequence gap")));
        }
        if entry_hash(&Value::Object(value)) != hash {
            return Ok(fail(format!("line {line_no}: content does not match its hash")));
        }
        prev = hash;
        entries += 1;
    }
    Ok(VerifyReport { entries, head: prev, problem: None })
}

/// Reads every entry of a log file (no verification).
pub fn read_entries(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(true))
        .map(|l| Ok(serde_json::from_str(&l?)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::audit::{AuditLog, verify_file};

    #[test]
    fn chain_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("strack-audit-{}", crate::crypto::random_token(6)));
        let path = dir.join("audit.jsonl");
        let mut log = AuditLog::create(&path).unwrap();
        log.record(Some(1.0), "system", "a", json!({"x": 1}));
        log.record(Some(2.0), "judge:x", "b", json!({"y": [1, 2]}));
        log.record(None, "system", "c", json!({}));
        let report = verify_file(&path).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.problem.is_none());
        assert_eq!(report.head, log.head().1);

        let resumed = AuditLog::resume(&path).unwrap();
        assert_eq!(resumed.head(), log.head());

        let text = std::fs::read_to_string(&path).unwrap().replace("\"y\":[1,2]", "\"y\":[1,3]");
        std::fs::write(&path, text).unwrap();
        let report = verify_file(&path).unwrap();
        assert!(report.problem.unwrap().contains("line 2"));
        std::fs::remove_dir_all(dir).ok();
    }
}
