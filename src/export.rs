//! Delivery exports (case file, audit log, transparency registry) and their verification.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use serde_json::{Value, json};

use crate::app::{audit_path, state_path};
use crate::audit::{AuditEntry, read_entries, verify_file};
use crate::model::{Case, CaseStatus, Store};
use crate::workflow::{now_rfc3339, registry, verify_case_hash};

pub const CASE_FILE_FORMAT: &str = "strack.case-file/1";

pub fn load_store(state_dir: &Path) -> anyhow::Result<Store> {
    let path = state_path(state_dir);
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn mentions(entry: &AuditEntry, case: &Case, order_ids: &[String], claim_ids: &[String], trace_ids: &[String]) -> bool {
    let field = |name: &str| entry.data.get(name).and_then(Value::as_str);
    field("case_id") == Some(case.id.as_str())
        || field("order_id").is_some_and(|id| order_ids.iter().any(|o| o == id))
        || field("claim_id").is_some_and(|id| claim_ids.iter().any(|c| c == id))
        || field("trace_id").is_some_and(|id| trace_ids.iter().any(|t| t == id))
}

/// Self-contained case file: evidence, decision, orders, related claims and their audit trail.
pub fn case_file(store: &Store, case: &Case, audit: &[AuditEntry], head: (u64, String)) -> Value {
    let orders: Vec<_> = store.orders_of_case(&case.id).collect();
    let order_ids: Vec<String> = orders.iter().map(|o| o.order_id.clone()).collect();
    let claims: Vec<_> = store.claims.iter().filter(|c| c.cases.contains(&case.id)).collect();
    let claim_ids: Vec<String> = claims.iter().map(|c| c.id.clone()).collect();
    let traces: Vec<_> = store.traces.iter().filter(|t| t.case_id.as_deref() == Some(case.id.as_str())).collect();
    let trace_ids: Vec<String> = traces.iter().map(|t| t.id.clone()).collect();
    let trail: Vec<&AuditEntry> =
        audit.iter().filter(|e| mentions(e, case, &order_ids, &claim_ids, &trace_ids)).collect();
    json!({
        "format": CASE_FILE_FORMAT,
        "exported_at": now_rfc3339(),
        "match": store.match_info,
        "case": case,
        "orders": orders,
        "claims": claims,
        "leak_traces": traces,
        "audit_trail": trail,
        "audit_head": {"seq": head.0, "hash": head.1},
        "checks": {
            "case_hash_ok": verify_case_hash(case),
            "evidence_problems": case.evidence.integrity_problems(),
        },
    })
}

fn pick_case<'a>(store: &'a Store, wanted: Option<&str>) -> anyhow::Result<&'a Case> {
    if let Some(id) = wanted {
        return store.case(id).ok_or_else(|| anyhow!("case {id} not found"));
    }
    let applied = |c: &&Case| store.orders_of_case(&c.id).any(|o| o.applied_min.is_some());
    store
        .cases
        .iter()
        .filter(|c| c.status == CaseStatus::Approved)
        .find(applied)
        .or_else(|| store.cases.iter().find(|c| c.status == CaseStatus::Approved))
        .or_else(|| store.cases.first())
        .ok_or_else(|| anyhow!("the state has no cases yet"))
}

/// Writes the delivery files into `out_dir` and returns their paths.
pub fn export(state_dir: &Path, out_dir: &Path, wanted: Option<&str>) -> anyhow::Result<Vec<PathBuf>> {
    let store = load_store(state_dir)?;
    let audit_file = audit_path(state_dir);
    let report = verify_file(&audit_file)?;
    if let Some(problem) = &report.problem {
        return Err(anyhow!("the audit log failed verification: {problem}"));
    }
    let entries = read_entries(&audit_file)?;
    let case = pick_case(&store, wanted)?;
    std::fs::create_dir_all(out_dir)?;

    let mut written = Vec::new();
    let case_path = out_dir.join(format!("expediente-{}.json", case.id));
    let file = case_file(&store, case, &entries, (report.entries, report.head.clone()));
    std::fs::write(&case_path, serde_json::to_string_pretty(&file)? + "\n")?;
    written.push(case_path);

    let audit_copy = out_dir.join("registro-auditoria.jsonl");
    std::fs::copy(&audit_file, &audit_copy)?;
    written.push(audit_copy);

    let registry_path = out_dir.join("registro-transparencia.json");
    let registry_doc = json!({
        "exported_at": now_rfc3339(),
        "match": store.match_info.as_ref().map(|m| json!({"id": m.id, "name": m.name})),
        "audit_head": {"seq": report.entries, "hash": report.head},
        "entries": registry(&store),
    });
    std::fs::write(&registry_path, serde_json::to_string_pretty(&registry_doc)? + "\n")?;
    written.push(registry_path);
    Ok(written)
}

/// Checks a case file on its own and, with the full audit log, against the chain.
pub fn verify_case_file(path: &Path, audit: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: Value = serde_json::from_str(&text)?;
    if doc.get("format").and_then(Value::as_str) != Some(CASE_FILE_FORMAT) {
        return Err(anyhow!("not a {CASE_FILE_FORMAT} document"));
    }
    let case: Case = serde_json::from_value(doc["case"].clone()).context("reading the case")?;
    let mut problems = case.evidence.integrity_problems();
    if !verify_case_hash(&case) {
        problems.push("case_hash does not match the case content".into());
    }
    if let Some(audit) = audit {
        let report = verify_file(audit)?;
        if let Some(problem) = report.problem {
            problems.push(format!("audit log: {problem}"));
        }
        let entries = read_entries(audit)?;
        let opened = entries.iter().find(|e| {
            matches!(e.event.as_str(), "case_created" | "case_dismissed")
                && e.data.get("case_id").and_then(Value::as_str) == Some(case.id.as_str())
        });
        match opened {
            None => problems.push("the audit log has no entry opening this case".into()),
            Some(e) if e.data.get("case_hash").and_then(Value::as_str) != Some(case.case_hash.as_str()) => {
                problems.push(format!("case_hash differs from the one recorded in audit entry {}", e.seq))
            }
            Some(_) => {}
        }
        if let Some(decision) = &case.decision {
            let recorded = entries.iter().find(|e| {
                matches!(e.event.as_str(), "case_approved" | "case_rejected")
                    && e.data.get("case_id").and_then(Value::as_str) == Some(case.id.as_str())
            });
            if recorded.and_then(|e| e.data.get("decision_signature")).and_then(Value::as_str)
                != Some(decision.signature.as_str())
            {
                problems.push("the decision signature differs from the audit log".into());
            }
        }
    }
    Ok(problems)
}
