//! Case, order and claim workflows: state transitions over `Core`. The only I/O is the audit log.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::app::{Core, Settings};
use crate::crypto::{
    claim_decision_message, decision_message, hash_value, hmac_sha256_hex, lift_message, order_message,
};
use crate::evidence::{BlockKind, Evidence, Proposal, host_in_domain, plan_measure, site_of};
use crate::judges::{can_sign, duty_judge};
use crate::model::{
    Case, CaseStatus, Claim, ClaimDecision, ClaimStatus, ClaimVerdict, Decision, LiftRequest, LiftStatus, OrderPurpose,
    OrderRecord, OrderStatus, Sighting, Store,
};
use crate::simulator::{
    Detection, DnsByDomain, DnsByIp, LiftBody, MatchInfo, OrderBody, ProviderOrderView, SimClaim, SimError,
};

/// Unsealed signing keys of judges with a live session, by judge id.
pub type SigningKeys = HashMap<String, Zeroizing<Vec<u8>>>;

#[derive(Debug, Clone)]
pub struct JudgeCtx {
    pub judge_id: String,
    pub judge_name: String,
    pub court_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowError {
    NotFound,
    AlreadyDecided,
    NotAssigned,
    NotOnDuty,
    NoSigningKey,
    MatchOver,
    NothingToDo,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn judge_actor(judge_id: &str) -> String {
    format!("judge:{judge_id}")
}

pub fn stream_key(host: &str, ip: &str) -> String {
    format!("{}|{}", host.to_ascii_lowercase(), ip)
}

/// Host part of a URL, lowercase, without credentials or port.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// IP blocks end with the match; domain blocks may last `domain_extra` minutes more.
pub fn expiry_minutes(end_min: f64, domain_extra: i64) -> (i64, i64) {
    let ip = end_min.ceil() as i64;
    (ip, ip + domain_extra.max(0))
}

pub fn case_hash(id: &str, created_at: &str, evidence: &Evidence, proposal: Option<&Proposal>) -> String {
    hash_value(&json!({"case_id": id, "created_at": created_at, "evidence": evidence, "proposal": proposal}))
}

pub fn verify_case_hash(case: &Case) -> bool {
    case_hash(&case.id, &case.created_at, &case.evidence, case.proposal.as_ref()) == case.case_hash
}

fn is_licensee_domain(domain: &str, info: Option<&MatchInfo>) -> bool {
    info.is_some_and(|m| m.licensees.iter().any(|l| l.authorized_domains.iter().any(|a| host_in_domain(domain, a))))
}

// --- detections and cases --------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingest {
    Created(String),
    Attached(String),
    Duplicate,
}

/// True when the detection opens a stream we have not seen (needs passive DNS before ingest).
pub fn is_new_stream(core: &Core, detection: &Detection) -> bool {
    let key = stream_key(&detection.stream_host, &detection.server_ip);
    !core.store.cases.iter().any(|c| c.stream_key == key)
}

/// Who an ingested detection is recorded under: the person who loaded it, the intake API, or the
/// platform itself for the live feed.
pub fn detection_actor(raw: &Value) -> String {
    match (raw.get("origen").and_then(Value::as_str), raw.get("cargado_por").and_then(Value::as_str)) {
        (Some(crate::intake::ORIGIN_MANUAL), Some(user)) => format!("user:{user}"),
        (Some(crate::intake::ORIGIN_API), _) => "api".to_string(),
        _ => "system".to_string(),
    }
}

pub fn ingest_detection(
    core: &mut Core,
    settings: &Settings,
    raw: Value,
    detection: &Detection,
    dns_ip: Option<&DnsByIp>,
    dns_domain: Option<&DnsByDomain>,
) -> Ingest {
    let key = stream_key(&detection.stream_host, &detection.server_ip);
    let now = core.now();
    let received_at = now_rfc3339();
    let actor = detection_actor(&raw);

    if let Some(case) = core.store.cases.iter_mut().find(|c| c.stream_key == key) {
        let founding = case.evidence.detection.get("id").and_then(Value::as_str) == Some(detection.id.as_str());
        if founding || case.sightings.iter().any(|s| s.detection_id == detection.id) {
            return Ingest::Duplicate;
        }
        let sighting = Sighting {
            detection_id: detection.id.clone(),
            minute: detection.minute,
            received_at,
            detection_sha256: hash_value(&raw),
        };
        let case_id = case.id.clone();
        let data = json!({
            "case_id": case_id, "detection_id": sighting.detection_id, "minute": sighting.minute,
            "detection_sha256": sighting.detection_sha256,
        });
        case.sightings.push(sighting);
        core.store.dirty = true;
        core.record(&actor, "detection_attached", data);
        return Ingest::Attached(case_id);
    }

    let Some(info) = core.store.match_info.clone() else {
        return Ingest::Duplicate;
    };
    core.store.case_seq += 1;
    let id = format!("EXP-{}-{:06}", chrono::Utc::now().format("%Y"), core.store.case_seq);
    let evidence = Evidence::build(raw, detection, &info, dns_ip, dns_domain, received_at.clone(), now);
    let blockable = evidence.watermark.verdict.blockable();
    let proposal = blockable.then(|| {
        let (expires_ip, expires_domain) = expiry_minutes(info.end_min, settings.domain_extra_min);
        plan_measure(
            evidence.collateral.recommended,
            &detection.server_ip,
            &detection.stream_host,
            &core.store.providers,
            expires_ip,
            expires_domain,
        )
    });
    let hash = case_hash(&id, &received_at, &evidence, proposal.as_ref());
    let page_site = url_host(&detection.page).map(|h| site_of(&h));
    let related: Vec<String> = core
        .store
        .cases
        .iter()
        .filter(|c| c.status != CaseStatus::Dismissed)
        .filter(|c| {
            c.evidence.collateral.site == evidence.collateral.site
                || (page_site.is_some() && url_host(&c.evidence.server.page).map(|h| site_of(&h)) == page_site)
        })
        .map(|c| c.id.clone())
        .collect();
    let assigned = blockable.then(|| duty_judge(&core.shifts(), now, settings.shift_margin_min)).flatten();
    let data = json!({
        "case_id": id,
        "case_hash": hash,
        "detection_id": detection.id,
        "detection_minute": detection.minute,
        "detection_sha256": evidence.detection_sha256,
        "capture_sha256": evidence.capture.sha256,
        "stream_host": detection.stream_host,
        "server_ip": detection.server_ip,
        "watermark": evidence.watermark.extracted,
        "watermark_verdict": evidence.watermark.verdict,
        "shared_ip": evidence.collateral.shared_ip,
        "recommended": proposal.as_ref().map(|p| p.measure),
        "related_cases": related,
        "assigned_judge": assigned,
    });
    core.store.cases.push(Case {
        id: id.clone(),
        created_at: received_at,
        created_min: now,
        stream_key: key,
        evidence,
        proposal,
        case_hash: hash,
        related_cases: related,
        sightings: Vec::new(),
        status: if blockable { CaseStatus::PendingJudge } else { CaseStatus::Dismissed },
        assigned_judge: assigned.clone(),
        decision: None,
    });
    core.store.touch();
    core.record(&actor, if blockable { "case_created" } else { "case_dismissed" }, data);
    if let Some(judge_id) = assigned {
        core.record("system", "judge_notified", json!({"case_id": id, "judge_id": judge_id}));
    }
    Ingest::Created(id)
}

// --- orders ----------------------------------------------------------------------------------

fn next_attempt(store: &Store, case_id: &str, provider_id: &str) -> u32 {
    store
        .orders
        .iter()
        .filter(|o| o.case_id == case_id && o.provider_id == provider_id)
        .map(|o| o.attempt)
        .max()
        .unwrap_or(0)
        + 1
}

fn order_id(run_id: &str, case_id: &str, provider_id: &str, attempt: u32) -> String {
    let tail = case_id.rsplit('-').next().unwrap_or(case_id);
    format!("o{run_id}-{tail}-{provider_id}-{attempt}")
}

#[allow(clippy::too_many_arguments)]
fn new_order(
    store: &Store,
    case_id: &str,
    provider_id: &str,
    kind: BlockKind,
    target: String,
    expires_min: i64,
    purpose: OrderPurpose,
    now: f64,
) -> OrderRecord {
    let attempt = next_attempt(store, case_id, provider_id);
    OrderRecord {
        order_id: order_id(&store.run_id, case_id, provider_id, attempt),
        case_id: case_id.to_string(),
        provider_id: provider_id.to_string(),
        kind,
        target,
        expires_min,
        judge_id: None,
        court_id: None,
        signature: None,
        attempt,
        purpose,
        status: OrderStatus::AwaitingSignature,
        created_min: now,
        sent_min: None,
        applied_min: None,
        ended_min: None,
        last_error: None,
        send_attempts: 0,
        superseded_by: None,
        replaces: None,
        lift: None,
        next_send_at: None,
    }
}

fn sign_order(order: &mut OrderRecord, judge: &JudgeCtx, key: &[u8]) {
    let message = order_message(&order.order_id, order.kind.wire(), &order.target, order.expires_min, &judge.judge_id);
    order.signature = Some(hmac_sha256_hex(key, &message));
    order.judge_id = Some(judge.judge_id.clone());
    order.court_id = Some(judge.court_id.clone());
    order.status = OrderStatus::Signed;
}

fn order_audit(o: &OrderRecord) -> Value {
    json!({
        "case_id": o.case_id, "order_id": o.order_id, "provider_id": o.provider_id, "kind": o.kind.wire(),
        "target": o.target, "expires_min": o.expires_min, "judge_id": o.judge_id, "attempt": o.attempt,
        "purpose": o.purpose, "replaces": o.replaces,
    })
}

fn with_field(mut value: Value, key: &str, extra: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        map.insert(key.to_string(), extra);
    }
    value
}

/// Records the judge's signed approval and signs one order per provider.
pub fn approve_case(
    core: &mut Core,
    settings: &Settings,
    case_id: &str,
    judge: &JudgeCtx,
    key: &[u8],
    force_domain: bool,
) -> Result<Vec<String>, WorkflowError> {
    let now = core.now();
    let shifts = core.shifts();
    let case = core.store.case(case_id).ok_or(WorkflowError::NotFound)?;
    if case.status != CaseStatus::PendingJudge {
        return Err(WorkflowError::AlreadyDecided);
    }
    if case.assigned_judge.as_deref() != Some(judge.judge_id.as_str()) {
        return Err(WorkflowError::NotAssigned);
    }
    if !can_sign(&shifts, &judge.judge_id, now, settings.shift_margin_min) {
        return Err(WorkflowError::NotOnDuty);
    }
    let proposal = case.proposal.clone().ok_or(WorkflowError::NothingToDo)?;
    let measure = if force_domain { BlockKind::Domain } else { proposal.measure };
    let plan = if measure == proposal.measure {
        proposal
    } else {
        plan_measure(
            measure,
            &proposal.ip,
            &proposal.host,
            &core.store.providers,
            proposal.expires_ip_min,
            proposal.expires_domain_min,
        )
    };
    if !plan.providers.iter().filter_map(|p| p.expires_min).any(|e| e as f64 > now) {
        return Err(WorkflowError::MatchOver);
    }
    let case_hash = case.case_hash.clone();
    let signature =
        hmac_sha256_hex(key, &decision_message(case_id, &case_hash, "approve", measure.code(), &judge.judge_id, now));

    let mut orders = Vec::new();
    for p in &plan.providers {
        let (Some(kind), Some(target), Some(expires)) = (p.kind, p.target.clone(), p.expires_min) else {
            continue;
        };
        if expires as f64 <= now {
            continue;
        }
        let mut order =
            new_order(&core.store, case_id, &p.provider_id, kind, target, expires, OrderPurpose::Original, now);
        sign_order(&mut order, judge, key);
        orders.push(order);
    }
    let ids: Vec<String> = orders.iter().map(|o| o.order_id.clone()).collect();
    let case = core.store.case_mut(case_id).expect("case exists");
    case.status = CaseStatus::Approved;
    case.decision = Some(Decision {
        judge_id: judge.judge_id.clone(),
        judge_name: judge.judge_name.clone(),
        court_id: judge.court_id.clone(),
        approved: true,
        measure: Some(measure),
        reason: None,
        minute: now,
        at: now_rfc3339(),
        signature: signature.clone(),
    });
    let actor = judge_actor(&judge.judge_id);
    core.record(
        &actor,
        "case_approved",
        json!({"case_id": case_id, "case_hash": case_hash, "measure": measure, "decision_signature": signature, "orders": ids}),
    );
    for order in &orders {
        core.record(&actor, "order_signed", order_audit(order));
    }
    core.store.orders.extend(orders);
    core.store.touch();
    Ok(ids)
}

pub fn reject_case(
    core: &mut Core,
    settings: &Settings,
    case_id: &str,
    judge: &JudgeCtx,
    key: &[u8],
    reason: &str,
) -> Result<(), WorkflowError> {
    let now = core.now();
    let shifts = core.shifts();
    let case = core.store.case(case_id).ok_or(WorkflowError::NotFound)?;
    if case.status != CaseStatus::PendingJudge {
        return Err(WorkflowError::AlreadyDecided);
    }
    if case.assigned_judge.as_deref() != Some(judge.judge_id.as_str()) {
        return Err(WorkflowError::NotAssigned);
    }
    if !can_sign(&shifts, &judge.judge_id, now, settings.shift_margin_min) {
        return Err(WorkflowError::NotOnDuty);
    }
    let case_hash = case.case_hash.clone();
    let signature =
        hmac_sha256_hex(key, &decision_message(case_id, &case_hash, "reject", "none", &judge.judge_id, now));
    let case = core.store.case_mut(case_id).expect("case exists");
    case.status = CaseStatus::Rejected;
    case.decision = Some(Decision {
        judge_id: judge.judge_id.clone(),
        judge_name: judge.judge_name.clone(),
        court_id: judge.court_id.clone(),
        approved: false,
        measure: None,
        reason: Some(reason.to_string()),
        minute: now,
        at: now_rfc3339(),
        signature: signature.clone(),
    });
    core.record(
        &judge_actor(&judge.judge_id),
        "case_rejected",
        json!({"case_id": case_id, "case_hash": case_hash, "reason": reason, "decision_signature": signature}),
    );
    core.store.touch();
    Ok(())
}

/// True when a claim already lifted this case's block on the same target.
fn lifted_by_claim(store: &Store, order: &OrderRecord) -> bool {
    store
        .orders
        .iter()
        .any(|o| o.case_id == order.case_id && o.kind == order.kind && o.target == order.target && o.lift.is_some())
}

/// Replaces a failed order with a new order id. The judge who approved the case signs it while
/// still on duty with a live session; otherwise it waits for the judge on duty.
pub fn schedule_retry(core: &mut Core, settings: &Settings, failed_id: &str, keys: &SigningKeys) {
    let now = core.now();
    let shifts = core.shifts();
    let Some(failed) = core.store.order(failed_id).cloned() else {
        return;
    };
    if failed.superseded_by.is_some() {
        return;
    }
    if lifted_by_claim(&core.store, &failed) {
        core.record("system", "retry_skipped", json!({"order_id": failed_id, "reason": "lifted_by_claim"}));
        return;
    }
    if failed.expires_min as f64 <= now + 0.05 {
        core.record("system", "retry_skipped", json!({"order_id": failed_id, "reason": "match_over"}));
        return;
    }
    let mut retry = new_order(
        &core.store,
        &failed.case_id,
        &failed.provider_id,
        failed.kind,
        failed.target.clone(),
        failed.expires_min,
        OrderPurpose::Retry,
        now,
    );
    retry.replaces = Some(failed_id.to_string());
    let signer = failed
        .judge_id
        .as_deref()
        .filter(|j| can_sign(&shifts, j, now, settings.shift_margin_min))
        .and_then(|j| keys.get(j).map(|k| (j.to_string(), k)));
    if let Some((judge_id, key)) = signer {
        let ctx = JudgeCtx {
            judge_name: core.store.judge_name(&judge_id),
            court_id: failed.court_id.clone().unwrap_or_default(),
            judge_id,
        };
        sign_order(&mut retry, &ctx, key);
        let data = with_field(order_audit(&retry), "basis", json!("approval_of_the_same_judge"));
        core.record(&judge_actor(&ctx.judge_id), "order_retry_signed", data);
    } else {
        let assignee = duty_judge(&shifts, now, settings.shift_margin_min);
        let data = with_field(order_audit(&retry), "assigned_judge", json!(assignee));
        core.record("system", "retry_awaiting_signature", data);
    }
    let retry_id = retry.order_id.clone();
    if let Some(f) = core.store.order_mut(failed_id) {
        f.superseded_by = Some(retry_id);
    }
    core.store.orders.push(retry);
    core.store.touch();
}

/// The judge on duty signs the retries of a case that were waiting for a signature.
pub fn sign_pending_retries(
    core: &mut Core,
    settings: &Settings,
    case_id: &str,
    judge: &JudgeCtx,
    key: &[u8],
) -> Result<Vec<String>, WorkflowError> {
    let now = core.now();
    if !can_sign(&core.shifts(), &judge.judge_id, now, settings.shift_margin_min) {
        return Err(WorkflowError::NotOnDuty);
    }
    let ids: Vec<String> = core
        .store
        .orders_of_case(case_id)
        .filter(|o| o.status == OrderStatus::AwaitingSignature)
        .map(|o| o.order_id.clone())
        .collect();
    if ids.is_empty() {
        return Err(WorkflowError::NothingToDo);
    }
    let mut signed = Vec::new();
    for id in &ids {
        let order = core.store.order_mut(id).expect("order exists");
        if order.expires_min as f64 <= now {
            order.status = OrderStatus::Abandoned;
            let data = with_field(order_audit(order), "reason", json!("match_over"));
            core.record("system", "order_abandoned", data);
            continue;
        }
        sign_order(order, judge, key);
        let data = with_field(order_audit(order), "basis", json!("explicit_approval_of_the_judge_on_duty"));
        core.record(&judge_actor(&judge.judge_id), "order_retry_signed", data);
        signed.push(id.clone());
    }
    core.store.touch();
    Ok(signed)
}

/// Syncs our orders with a provider's view; failures get a retry with a new order id.
pub fn apply_provider_views(
    core: &mut Core,
    settings: &Settings,
    provider_id: &str,
    views: &[ProviderOrderView],
    keys: &SigningKeys,
) -> bool {
    let now = core.now();
    let mut events = Vec::new();
    let mut failed = Vec::new();
    for view in views {
        let Some(order) =
            core.store.orders.iter_mut().find(|o| o.order_id == view.order_id && o.provider_id == provider_id)
        else {
            continue;
        };
        if !order.status.at_provider() {
            continue;
        }
        let base = json!({"case_id": order.case_id, "order_id": order.order_id, "provider_id": provider_id,
                          "kind": order.kind.wire(), "target": order.target});
        match view.state.as_str() {
            "aplicada" if order.status != OrderStatus::Applied => {
                order.status = OrderStatus::Applied;
                order.applied_min = view.applied_min.or(Some(now));
                events.push(("order_applied", with_field(base, "applied_min", json!(order.applied_min))));
            }
            "fallida" => {
                order.status = OrderStatus::Failed;
                order.last_error = view.reason.clone();
                events.push(("order_failed", with_field(base, "reason", json!(view.reason))));
                failed.push(order.order_id.clone());
            }
            "vencida" => {
                order.status = OrderStatus::Expired;
                order.ended_min = view.ended_min.or(Some(now));
                events.push(("order_expired", with_field(base, "ended_min", json!(order.ended_min))));
            }
            "levantada" => {
                order.status = OrderStatus::Lifted;
                order.ended_min = view.ended_min.or(Some(now));
                if let Some(lift) = order.lift.as_mut() {
                    lift.status = LiftStatus::Done;
                }
                events.push(("order_lifted", with_field(base, "ended_min", json!(order.ended_min))));
            }
            _ => {}
        }
    }
    let changed = !events.is_empty();
    let actor = format!("provider:{provider_id}");
    for (event, data) in events {
        core.record(&actor, event, data);
    }
    for id in failed {
        schedule_retry(core, settings, &id, keys);
    }
    if changed {
        core.store.touch();
    }
    changed
}

/// Orders ready to send: marked `Sending` and returned with their wire body.
pub fn take_ready_sends(core: &mut Core) -> Vec<(String, String, OrderBody)> {
    let now = core.now();
    let instant = Instant::now();
    let mut out = Vec::new();
    let mut abandoned = Vec::new();
    for o in core
        .store
        .orders
        .iter_mut()
        .filter(|o| o.status == OrderStatus::Signed && o.next_send_at.is_none_or(|t| t <= instant))
    {
        if o.expires_min as f64 <= now {
            o.status = OrderStatus::Abandoned;
            abandoned.push(order_audit(o));
            continue;
        }
        o.status = OrderStatus::Sending;
        o.send_attempts += 1;
        out.push((
            o.order_id.clone(),
            o.provider_id.clone(),
            OrderBody {
                order_id: o.order_id.clone(),
                case_id: o.case_id.clone(),
                kind: o.kind.wire().to_string(),
                target: o.target.clone(),
                expires_min: o.expires_min,
                court_id: o.court_id.clone().unwrap_or_default(),
                judge_id: o.judge_id.clone().unwrap_or_default(),
                signature: o.signature.clone().unwrap_or_default(),
            },
        ));
    }
    if !abandoned.is_empty() {
        for data in abandoned {
            core.record("system", "order_abandoned", with_field(data, "reason", json!("match_over")));
        }
        core.store.touch();
    }
    out
}

pub fn apply_send_result(
    core: &mut Core,
    settings: &Settings,
    order_id: &str,
    result: Result<Value, SimError>,
    keys: &SigningKeys,
) {
    let now = core.now();
    let Some(order) = core.store.order_mut(order_id) else {
        return;
    };
    if order.status != OrderStatus::Sending {
        return;
    }
    let base = order_audit(order);
    let mut retry = false;
    let event = match result {
        // A 2xx body we could not decode still means the provider took the order.
        Ok(_) | Err(SimError::Decode(_)) => {
            order.status = OrderStatus::Received;
            order.sent_min = Some(now);
            Some(("order_sent", base))
        }
        // An earlier attempt with this id reached the provider before the connection failed.
        Err(SimError::Http { status: 409, .. }) if order.send_attempts > 1 => {
            order.status = OrderStatus::Received;
            order.sent_min = Some(now);
            Some(("order_sent", with_field(base, "note", json!("duplicate_after_transport_error"))))
        }
        Err(SimError::Http { status, message }) if status < 500 => {
            let expired = order.expires_min as f64 <= now;
            order.status = if expired { OrderStatus::Abandoned } else { OrderStatus::Rejected };
            order.last_error = Some(message.clone());
            // An order id clash (409) is retried with a fresh id; other refusals are final.
            retry = status == 409 && !expired;
            Some(("order_rejected", with_field(with_field(base, "status", json!(status)), "message", json!(message))))
        }
        Err(e) => {
            order.status = OrderStatus::Signed;
            let exponent = order.send_attempts.saturating_sub(1).min(4);
            order.next_send_at = Some(Instant::now() + Duration::from_millis(500 * (1 << exponent)));
            order.last_error = Some(e.to_string());
            let n = order.send_attempts;
            (n <= 3 || n.is_power_of_two()).then(|| {
                ("order_send_error", with_field(with_field(base, "error", json!(e.to_string())), "attempt", json!(n)))
            })
        }
    };
    if let Some((name, data)) = event {
        let actor = if name == "order_rejected" { "provider" } else { "system" };
        core.record(actor, name, data);
    }
    core.store.touch();
    if retry {
        schedule_retry(core, settings, order_id, keys);
    }
}

/// Signed lifts of orders the provider holds, marked `Sending`.
pub fn take_ready_lifts(core: &mut Core) -> Vec<(String, String, LiftBody)> {
    let mut out = Vec::new();
    for o in core.store.orders.iter_mut().filter(|o| o.status.at_provider()) {
        let Some(lift) = o.lift.as_mut() else { continue };
        if lift.status != LiftStatus::Signed {
            continue;
        }
        lift.status = LiftStatus::Sending;
        out.push((
            o.order_id.clone(),
            o.provider_id.clone(),
            LiftBody {
                judge_id: lift.judge_id.clone(),
                signature: lift.signature.clone(),
                reason: lift.reason.clone(),
            },
        ));
    }
    out
}

pub fn apply_lift_result(core: &mut Core, order_id: &str, result: Result<Value, SimError>) {
    let now = core.now();
    let Some(order) = core.store.order_mut(order_id) else {
        return;
    };
    let Some(lift) = order.lift.as_mut() else {
        return;
    };
    let base = json!({"case_id": order.case_id, "order_id": order.order_id, "provider_id": order.provider_id,
                      "claim_id": lift.claim_id, "judge_id": lift.judge_id});
    let event = match result {
        Ok(_) | Err(SimError::Decode(_)) => {
            lift.status = LiftStatus::Done;
            order.status = OrderStatus::Lifted;
            order.ended_min = Some(now);
            Some(("order_lifted", base))
        }
        Err(SimError::Http { status: 409, message }) => {
            lift.status = LiftStatus::Done;
            lift.error = Some(message.clone());
            Some(("lift_not_needed", with_field(base, "message", json!(message))))
        }
        Err(SimError::Http { status, message }) if status < 500 => {
            lift.status = LiftStatus::Failed;
            lift.error = Some(message.clone());
            Some(("lift_refused", with_field(with_field(base, "status", json!(status)), "message", json!(message))))
        }
        Err(e) => {
            lift.status = LiftStatus::Signed;
            lift.error = Some(e.to_string());
            None
        }
    };
    if let Some((name, data)) = event {
        core.record("system", name, data);
    }
    core.store.touch();
}

// --- claims ----------------------------------------------------------------------------------

/// Our orders whose block reaches `domain` (IP blocks through passive DNS, domain blocks by name).
fn orders_reaching(store: &Store, domain: &str, statuses: &[OrderStatus]) -> Vec<String> {
    store
        .orders
        .iter()
        .filter(|o| statuses.contains(&o.status) && o.lift.is_none())
        .filter(|o| match o.kind {
            BlockKind::Ip => store
                .case(&o.case_id)
                .is_some_and(|c| c.evidence.collateral.co_hosted.iter().any(|d| d.eq_ignore_ascii_case(domain))),
            BlockKind::Domain => host_in_domain(domain, &o.target),
        })
        .map(|o| o.order_id.clone())
        .collect()
}

const AT_PROVIDER: &[OrderStatus] = &[OrderStatus::Received, OrderStatus::Applied];
const NOT_SENT: &[OrderStatus] = &[OrderStatus::AwaitingSignature, OrderStatus::Signed];

pub fn ingest_claim(core: &mut Core, settings: &Settings, claim: &SimClaim) -> bool {
    if core.store.claim(&claim.id).is_some() {
        return false;
    }
    let now = core.now();
    let affected = orders_reaching(&core.store, &claim.domain, AT_PROVIDER);
    let cases: Vec<String> = affected
        .iter()
        .filter_map(|id| core.store.order(id).map(|o| o.case_id.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let is_licensee = is_licensee_domain(&claim.domain, core.store.match_info.as_ref());
    let claimant_site = site_of(&claim.domain);
    let verdict = if affected.is_empty() {
        ClaimVerdict::NoActiveBlock
    } else if !is_licensee
        && cases.iter().all(|id| core.store.case(id).is_some_and(|c| c.evidence.collateral.site == claimant_site))
    {
        ClaimVerdict::PirateSite
    } else {
        ClaimVerdict::Legitimate
    };
    let (status, assigned) = match verdict {
        ClaimVerdict::NoActiveBlock => (ClaimStatus::Closed, None),
        _ => (ClaimStatus::PendingJudge, duty_judge(&core.shifts(), now, settings.shift_margin_min)),
    };
    let data = json!({
        "claim_id": claim.id, "domain": claim.domain, "provider_id": claim.provider_id, "claim_minute": claim.minute,
        "message": claim.message, "verdict": verdict, "is_licensee": is_licensee, "affected_orders": affected,
        "cases": cases, "assigned_judge": assigned,
    });
    core.store.claims.push(Claim {
        id: claim.id.clone(),
        minute: claim.minute,
        received_at: now_rfc3339(),
        domain: claim.domain.clone(),
        provider_id: claim.provider_id.clone(),
        message: claim.message.clone(),
        verdict,
        is_licensee,
        affected_orders: affected,
        cases,
        status,
        assigned_judge: assigned.clone(),
        decision: None,
    });
    core.store.touch();
    core.record("system", "claim_received", data);
    if let Some(judge_id) = assigned {
        core.record("system", "judge_notified", json!({"claim_id": claim.id, "judge_id": judge_id}));
    }
    true
}

/// Lifts every order that reaches the claimant (all providers) and, when the lifted block was by
/// IP, replaces it with a precise domain block on the pirate stream host.
pub fn approve_claim(
    core: &mut Core,
    settings: &Settings,
    claim_id: &str,
    judge: &JudgeCtx,
    key: &[u8],
) -> Result<(Vec<String>, Vec<String>), WorkflowError> {
    let now = core.now();
    let shifts = core.shifts();
    let claim = core.store.claim(claim_id).cloned().ok_or(WorkflowError::NotFound)?;
    if claim.status != ClaimStatus::PendingJudge {
        return Err(WorkflowError::AlreadyDecided);
    }
    if claim.assigned_judge.as_deref() != Some(judge.judge_id.as_str()) {
        return Err(WorkflowError::NotAssigned);
    }
    if !can_sign(&shifts, &judge.judge_id, now, settings.shift_margin_min) {
        return Err(WorkflowError::NotOnDuty);
    }
    let actor = judge_actor(&judge.judge_id);
    let reason = format!("Reclamo {} de {} aceptado por el juez de turno", claim.id, claim.domain);
    let to_lift = orders_reaching(&core.store, &claim.domain, AT_PROVIDER);
    let to_abandon = orders_reaching(&core.store, &claim.domain, NOT_SENT);

    for id in &to_lift {
        let order = core.store.order_mut(id).expect("order exists");
        order.lift = Some(LiftRequest {
            claim_id: claim.id.clone(),
            judge_id: judge.judge_id.clone(),
            signature: hmac_sha256_hex(key, &lift_message(id, &judge.judge_id)),
            reason: reason.clone(),
            requested_min: now,
            status: LiftStatus::Signed,
            error: None,
        });
        let data = with_field(order_audit(order), "claim_id", json!(claim.id));
        core.record(&actor, "lift_signed", data);
    }
    for id in &to_abandon {
        let order = core.store.order_mut(id).expect("order exists");
        order.status = OrderStatus::Abandoned;
        order.last_error = Some(format!("superseded by claim {}", claim.id));
        let data = with_field(order_audit(order), "claim_id", json!(claim.id));
        core.record(&actor, "order_abandoned", data);
    }

    let claimant_site = site_of(&claim.domain);
    let info = core.store.match_info.clone();
    let mut replacements: Vec<OrderRecord> = Vec::new();
    let mut planned: HashSet<(String, String)> = HashSet::new();
    for id in to_lift.iter().chain(to_abandon.iter()) {
        let Some(lifted) = core.store.order(id).cloned() else { continue };
        if lifted.kind != BlockKind::Ip {
            continue;
        }
        let Some(case) = core.store.case(&lifted.case_id) else { continue };
        let host = case.host().to_string();
        if case.evidence.collateral.site == claimant_site || is_licensee_domain(&host, info.as_ref()) {
            continue;
        }
        let expires = case.proposal.as_ref().map_or(lifted.expires_min, |p| p.expires_domain_min);
        let accepts_domain =
            core.store.provider(&lifted.provider_id).is_some_and(|p| p.accepts(BlockKind::Domain.wire()));
        let already = core.store.orders.iter().any(|o| {
            o.case_id == lifted.case_id
                && o.provider_id == lifted.provider_id
                && o.kind == BlockKind::Domain
                && o.target == host
                && o.status.is_open()
        });
        if !accepts_domain
            || already
            || expires as f64 <= now
            || !planned.insert((lifted.provider_id.clone(), host.clone()))
        {
            continue;
        }
        let mut order = new_order(
            &core.store,
            &lifted.case_id,
            &lifted.provider_id,
            BlockKind::Domain,
            host,
            expires,
            OrderPurpose::Replacement,
            now,
        );
        // Attempts are counted from the store; account for replacements planned in this loop.
        order.attempt +=
            replacements.iter().filter(|r| r.case_id == order.case_id && r.provider_id == order.provider_id).count()
                as u32;
        order.order_id = order_id(&core.store.run_id, &order.case_id, &order.provider_id, order.attempt);
        order.replaces = Some(lifted.order_id.clone());
        sign_order(&mut order, judge, key);
        replacements.push(order);
    }
    for order in &replacements {
        core.record(&actor, "order_signed", with_field(order_audit(order), "claim_id", json!(claim.id)));
    }
    let replacement_ids: Vec<String> = replacements.iter().map(|o| o.order_id.clone()).collect();
    core.store.orders.extend(replacements);

    let lifted_ids: Vec<String> = to_lift.iter().chain(to_abandon.iter()).cloned().collect();
    let signature = hmac_sha256_hex(key, &claim_decision_message(claim_id, "approve", &judge.judge_id, now));
    if let Some(c) = core.store.claims.iter_mut().find(|c| c.id == claim_id) {
        c.status = ClaimStatus::Resolved;
        c.decision = Some(ClaimDecision {
            judge_id: judge.judge_id.clone(),
            judge_name: judge.judge_name.clone(),
            approved: true,
            reason: None,
            minute: now,
            at: now_rfc3339(),
            signature: signature.clone(),
            lifted_orders: lifted_ids.clone(),
            replacement_orders: replacement_ids.clone(),
        });
    }
    core.record(
        &actor,
        "claim_approved",
        json!({"claim_id": claim_id, "domain": claim.domain, "lifted_orders": lifted_ids,
               "replacement_orders": replacement_ids, "decision_signature": signature}),
    );
    // Other pending claims about the same site are covered by this decision.
    let covered: Vec<String> = core
        .store
        .claims
        .iter_mut()
        .filter(|c| {
            c.id != claim_id && c.status == ClaimStatus::PendingJudge && c.domain.eq_ignore_ascii_case(&claim.domain)
        })
        .map(|c| {
            c.status = ClaimStatus::Closed;
            c.id.clone()
        })
        .collect();
    for id in covered {
        core.record("system", "claim_closed", json!({"claim_id": id, "covered_by": claim_id}));
    }
    core.store.touch();
    Ok((lifted_ids, replacement_ids))
}

pub fn reject_claim(
    core: &mut Core,
    settings: &Settings,
    claim_id: &str,
    judge: &JudgeCtx,
    key: &[u8],
    reason: &str,
) -> Result<(), WorkflowError> {
    let now = core.now();
    let shifts = core.shifts();
    let claim = core.store.claim(claim_id).ok_or(WorkflowError::NotFound)?;
    if claim.status != ClaimStatus::PendingJudge {
        return Err(WorkflowError::AlreadyDecided);
    }
    if claim.assigned_judge.as_deref() != Some(judge.judge_id.as_str()) {
        return Err(WorkflowError::NotAssigned);
    }
    if !can_sign(&shifts, &judge.judge_id, now, settings.shift_margin_min) {
        return Err(WorkflowError::NotOnDuty);
    }
    let signature = hmac_sha256_hex(key, &claim_decision_message(claim_id, "reject", &judge.judge_id, now));
    if let Some(c) = core.store.claims.iter_mut().find(|c| c.id == claim_id) {
        c.status = ClaimStatus::Rejected;
        c.decision = Some(ClaimDecision {
            judge_id: judge.judge_id.clone(),
            judge_name: judge.judge_name.clone(),
            approved: false,
            reason: Some(reason.to_string()),
            minute: now,
            at: now_rfc3339(),
            signature: signature.clone(),
            lifted_orders: Vec::new(),
            replacement_orders: Vec::new(),
        });
    }
    core.record(
        &judge_actor(&judge.judge_id),
        "claim_rejected",
        json!({"claim_id": claim_id, "reason": reason, "decision_signature": signature}),
    );
    core.store.touch();
    Ok(())
}

// --- shifts ----------------------------------------------------------------------------------

/// At a shift change, pending cases and claims pass to the incoming judge.
pub fn handover(core: &mut Core, settings: &Settings) -> bool {
    let now = core.now();
    let shifts = core.shifts();
    let margin = settings.shift_margin_min;
    let target = duty_judge(&shifts, now, margin);
    let mut moves = Vec::new();
    for case in core.store.cases.iter_mut().filter(|c| c.status == CaseStatus::PendingJudge) {
        let holder_ok = case.assigned_judge.as_deref().is_some_and(|j| can_sign(&shifts, j, now, margin));
        if !holder_ok && case.assigned_judge != target {
            moves.push(("case_reassigned", json!({"case_id": case.id, "from": case.assigned_judge, "to": target})));
            case.assigned_judge = target.clone();
        }
    }
    for claim in core.store.claims.iter_mut().filter(|c| c.status == ClaimStatus::PendingJudge) {
        let holder_ok = claim.assigned_judge.as_deref().is_some_and(|j| can_sign(&shifts, j, now, margin));
        if !holder_ok && claim.assigned_judge != target {
            moves.push(("claim_reassigned", json!({"claim_id": claim.id, "from": claim.assigned_judge, "to": target})));
            claim.assigned_judge = target.clone();
        }
    }
    let changed = !moves.is_empty();
    for (event, data) in moves {
        core.record("system", event, data);
    }
    if changed {
        core.store.touch();
    }
    changed
}

// --- public registry and metrics -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryStatus {
    InProgress,
    Active,
    Expired,
    Lifted,
    NotApplied,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryEntry {
    pub case_id: String,
    pub kind: BlockKind,
    pub target: String,
    pub stream_host: String,
    pub ordered_by: String,
    pub judge_id: String,
    pub court: String,
    pub ordered_min: f64,
    pub first_applied_min: Option<f64>,
    pub expires_min: i64,
    pub ended_min: Option<f64>,
    pub providers_applied: Vec<String>,
    pub status: RegistryStatus,
    pub lift_reason: Option<String>,
}

/// What was blocked, when, by whose order and until when: one row per case and target.
pub fn registry(store: &Store) -> Vec<RegistryEntry> {
    let mut groups: BTreeMap<(String, String, String), Vec<&OrderRecord>> = BTreeMap::new();
    for o in &store.orders {
        if o.judge_id.is_none() {
            continue;
        }
        groups.entry((o.case_id.clone(), o.kind.code().to_string(), o.target.clone())).or_default().push(o);
    }
    let mut rows: Vec<RegistryEntry> = groups
        .into_iter()
        .map(|((case_id, _, target), orders)| {
            let first = orders[0];
            let judge_id = first.judge_id.clone().unwrap_or_default();
            let status = if orders.iter().any(|o| o.status == OrderStatus::Applied) {
                RegistryStatus::Active
            } else if orders.iter().any(|o| o.status.is_open()) {
                RegistryStatus::InProgress
            } else if orders.iter().any(|o| o.status == OrderStatus::Lifted) {
                RegistryStatus::Lifted
            } else if orders.iter().any(|o| o.status == OrderStatus::Expired) {
                RegistryStatus::Expired
            } else {
                RegistryStatus::NotApplied
            };
            let mut providers: Vec<String> = orders
                .iter()
                .filter(|o| o.applied_min.is_some())
                .map(|o| store.provider(&o.provider_id).map_or(o.provider_id.clone(), |p| p.name.clone()))
                .collect();
            providers.sort();
            providers.dedup();
            RegistryEntry {
                stream_host: store.case(&case_id).map(|c| c.host().to_string()).unwrap_or_default(),
                case_id,
                kind: first.kind,
                target,
                ordered_by: store.judge_name(&judge_id),
                court: store.court_of(&judge_id).map(|c| c.name.clone()).unwrap_or_default(),
                judge_id,
                ordered_min: orders.iter().map(|o| o.created_min).fold(f64::INFINITY, f64::min),
                first_applied_min: orders.iter().filter_map(|o| o.applied_min).reduce(f64::min),
                expires_min: first.expires_min,
                ended_min: (status != RegistryStatus::Active)
                    .then(|| orders.iter().filter_map(|o| o.ended_min).reduce(f64::max))
                    .flatten(),
                providers_applied: providers,
                status,
                lift_reason: orders.iter().find_map(|o| o.lift.as_ref().map(|l| l.reason.clone())),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.ordered_min.total_cmp(&b.ordered_min));
    rows
}

/// Minutes from the first detection to the first applied block of a case.
pub fn time_to_block(store: &Store, case: &Case) -> Option<f64> {
    store
        .orders_of_case(&case.id)
        .filter_map(|o| o.applied_min)
        .reduce(f64::min)
        .map(|applied| (applied - case.first_detection_min()).max(0.0))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use crate::app::{Core, Settings};
    use crate::audit::AuditLog;
    use crate::clock::MatchClock;
    use crate::evidence::BlockKind;
    use crate::model::{ClaimStatus, ClaimVerdict, LiftStatus, OrderPurpose, OrderStatus, Store};
    use crate::simulator::{
        Court, Courts, Detection, DnsByIp, JudgeRef, MatchInfo, Provider, Shift, SimClaim, ValidWatermark,
    };
    use crate::workflow::{
        Ingest, JudgeCtx, SigningKeys, approve_case, approve_claim, expiry_minutes, ingest_claim, ingest_detection,
        url_host,
    };

    fn settings() -> Settings {
        Settings {
            poll_interval: Duration::from_millis(500),
            domain_extra_min: 0,
            shift_margin_min: 0.1,
            secure_cookies: false,
            state_dir: std::env::temp_dir(),
            intake_token: None,
            ffmpeg: "ffmpeg".into(),
            allow_private_streams: false,
            egress_proxy: None,
            accounts_path: std::env::temp_dir().join("accounts.json"),
            platforms_path: std::env::temp_dir().join("platforms.json"),
        }
    }

    fn core() -> Core {
        let mut store = Store::new("t1".into());
        store.match_info = Some(MatchInfo {
            id: "m".into(),
            name: "Test".into(),
            rights_holder: String::new(),
            start_iso: String::new(),
            end_min: 105.0,
            valid_watermarks: vec![ValidWatermark { prefix: "LP26-PRA-OFI".into(), origin: "oficial".into() }],
            licensees: vec![],
        });
        store.providers = vec![
            Provider {
                id: "aurora".into(),
                name: "Aurora".into(),
                size: None,
                customers: 10,
                capabilities: vec!["ip".into(), "dominio".into()],
            },
            Provider {
                id: "valle".into(),
                name: "Valle".into(),
                size: None,
                customers: 1,
                capabilities: vec!["dominio".into()],
            },
        ];
        store.courts = Some(Courts {
            courts: vec![Court {
                id: "jg".into(),
                name: "Juzgado".into(),
                jurisdiction: String::new(),
                judges: vec![JudgeRef { id: "laura".into(), name: "Laura".into() }],
            }],
            shifts: vec![Shift { judge_id: "laura".into(), from_min: -60.0, until_min: 240.0 }],
        });
        let dir = std::env::temp_dir().join(format!("strack-wf-{}", crate::crypto::random_token(6)));
        Core { store, audit: AuditLog::create(&dir.join("audit.jsonl")).unwrap(), clock: MatchClock::default() }
    }

    fn detection(host: &str, ip: &str) -> (serde_json::Value, Detection) {
        let raw = json!({
            "id": "D-1", "minuto": 0.0, "pagina": "https://pirata.test/vivo", "stream_url": format!("https://{host}/x.m3u8"),
            "host_stream": host, "ip_servidor": ip, "asn": 64600, "marca_de_agua_extraida": "LP26-PRA-OFI-S1",
            "captura": {"capturada_min": 0.0, "formato": "mpegts", "duracion_seg": 6, "contenido_b64": "R0FCQw=="},
            "promocion": [],
        });
        let parsed = serde_json::from_value(raw.clone()).unwrap();
        (raw, parsed)
    }

    fn laura() -> JudgeCtx {
        JudgeCtx { judge_id: "laura".into(), judge_name: "Laura".into(), court_id: "jg".into() }
    }

    #[test]
    fn approval_signs_one_order_per_provider_in_the_type_it_accepts() {
        let mut core = core();
        let (raw, d) = detection("s1.pirata.test", "203.0.113.10");
        let dns = DnsByIp {
            ip: d.server_ip.clone(),
            asn: Some(64600),
            organization: Some("Dedicado".into()),
            domains: vec!["s1.pirata.test".into()],
        };
        let Ingest::Created(id) = ingest_detection(&mut core, &settings(), raw, &d, Some(&dns), None) else { panic!() };
        assert_eq!(core.store.case(&id).unwrap().assigned_judge.as_deref(), Some("laura"));
        let ids = approve_case(&mut core, &settings(), &id, &laura(), b"key", false).unwrap();
        assert_eq!(ids.len(), 2);
        let aurora = core.store.order(&ids[0]).unwrap();
        let valle = core.store.order(&ids[1]).unwrap();
        assert_eq!((aurora.kind, aurora.target.as_str(), aurora.expires_min), (BlockKind::Ip, "203.0.113.10", 105));
        assert_eq!((valle.kind, valle.target.as_str()), (BlockKind::Domain, "s1.pirata.test"));
        assert!(aurora.signature.is_some() && aurora.status == OrderStatus::Signed);
    }

    #[test]
    fn a_legitimate_claim_lifts_the_ip_block_and_replaces_it_by_domain() {
        let mut core = core();
        let (raw, d) = detection("s1.pirata.test", "203.0.113.10");
        // Passive DNS only learned about the bakery after the order: simulate an IP block already applied.
        let dns = DnsByIp {
            ip: d.server_ip.clone(),
            asn: Some(64600),
            organization: Some("Dedicado".into()),
            domains: vec!["s1.pirata.test".into(), "panaderia.test".into()],
        };
        let Ingest::Created(id) = ingest_detection(&mut core, &settings(), raw, &d, Some(&dns), None) else { panic!() };
        core.store.case_mut(&id).unwrap().proposal.as_mut().unwrap().measure = BlockKind::Ip;
        let mut proposal = core.store.case(&id).unwrap().proposal.clone().unwrap();
        proposal.providers[0].kind = Some(BlockKind::Ip);
        proposal.providers[0].target = Some("203.0.113.10".into());
        core.store.case_mut(&id).unwrap().proposal = Some(proposal);
        let ids = approve_case(&mut core, &settings(), &id, &laura(), b"key", false).unwrap();
        for oid in &ids {
            core.store.order_mut(oid).unwrap().status = OrderStatus::Applied;
        }

        let claim = SimClaim {
            id: "R-001".into(),
            minute: 3.0,
            domain: "panaderia.test".into(),
            provider_id: "aurora".into(),
            message: "caída".into(),
        };
        assert!(ingest_claim(&mut core, &settings(), &claim));
        let stored = core.store.claim("R-001").unwrap();
        assert_eq!(stored.verdict, ClaimVerdict::Legitimate);
        assert_eq!(stored.affected_orders, vec![ids[0].clone()]);

        let (lifted, replacements) = approve_claim(&mut core, &settings(), "R-001", &laura(), b"key").unwrap();
        assert_eq!(lifted, vec![ids[0].clone()]);
        assert_eq!(core.store.order(&ids[0]).unwrap().lift.as_ref().unwrap().status, LiftStatus::Signed);
        assert_eq!(replacements.len(), 1);
        let replacement = core.store.order(&replacements[0]).unwrap();
        assert_eq!((replacement.kind, replacement.target.as_str()), (BlockKind::Domain, "s1.pirata.test"));
        assert_eq!(replacement.purpose, OrderPurpose::Replacement);
        assert_eq!(replacement.status, OrderStatus::Signed);
        assert_ne!(replacement.order_id, ids[0]);
        assert_eq!(core.store.claim("R-001").unwrap().status, ClaimStatus::Resolved);
        let _: SigningKeys = SigningKeys::new();
    }

    #[test]
    fn url_host_strips_scheme_path_and_port() {
        assert_eq!(url_host("https://pelotaya.test/en-vivo").as_deref(), Some("pelotaya.test"));
        assert_eq!(url_host("http://user@Host.Test:8080/x?y").as_deref(), Some("host.test"));
        assert_eq!(url_host("").as_deref(), None);
    }

    #[test]
    fn ip_blocks_end_with_the_match() {
        assert_eq!(expiry_minutes(105.0, 0), (105, 105));
        assert_eq!(expiry_minutes(104.2, 60), (105, 165));
    }
}
