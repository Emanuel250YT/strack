//! Background loops, one set per match: bootstrap, polling its simulator and dispatching signed
//! orders and lifts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::app::{App, MatchRun};
use crate::simulator::{Detection, SimError};
use crate::workflow;

/// Claims are fetched with this many match minutes of overlap (deduplicated by id), so a claim
/// emitted with a minute just before our last cut-off is never skipped.
const CLAIM_OVERLAP_MIN: f64 = 2.0;

/// Follows every match at the same time; each one has its own loops and lock.
pub async fn run(app: Arc<App>) {
    let mut runs = JoinSet::new();
    for m in app.matches.clone() {
        runs.spawn(run_match(app.clone(), m));
    }
    while runs.join_next().await.is_some() {}
}

async fn run_match(app: Arc<App>, m: Arc<MatchRun>) {
    bootstrap(&m).await;
    let dispatcher = tokio::spawn(run_dispatcher(app.clone(), m.clone()));
    run_poller(app, m).await;
    dispatcher.abort();
}

async fn bootstrap(m: &Arc<MatchRun>) {
    let mut wait = Duration::from_millis(500);
    loop {
        match load_reference_data(m).await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!(error = %e, simulator = m.sim.base_url(), "match source not ready, retrying");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(5));
            }
        }
    }
}

async fn load_reference_data(m: &Arc<MatchRun>) -> Result<(), SimError> {
    let info = m.sim.match_info().await?;
    let providers = m.sim.providers().await?;
    let courts = m.sim.courts().await?;
    let status = m.sim.status().await?;
    let mut core = m.core();
    core.clock.update(&status);
    if let Some(previous) = core.store.match_info.as_ref().filter(|m| m.id != info.id) {
        tracing::warn!(previous = %previous.id, current = %info.id, "resumed state belongs to another match");
    }
    let data = json!({
        "match_id": info.id,
        "name": info.name,
        "end_min": info.end_min,
        "valid_watermarks": info.valid_watermarks.iter().map(|w| &w.prefix).collect::<Vec<_>>(),
        "licensees": info.licensees.iter().map(|l| json!({"name": l.name, "authorized_domains": l.authorized_domains})).collect::<Vec<_>>(),
        "providers": providers.iter().map(|p| json!({"id": p.id, "customers": p.customers, "capabilities": p.capabilities})).collect::<Vec<_>>(),
        "shifts": courts.shifts,
    });
    tracing::info!(key = %m.key, match_name = %info.name, minute = status.minute, speedup = status.speedup, "match source ready");
    core.store.match_info = Some(info);
    core.store.providers = providers;
    core.store.courts = Some(courts);
    core.store.touch();
    core.record("system", "match_loaded", data);
    Ok(())
}

async fn run_poller(app: Arc<App>, m: Arc<MatchRun>) {
    let mut interval = tokio::time::interval(app.settings.poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(e) = poll_status(&app, &m).await {
            tracing::warn!(key = %m.key, error = %e, "status poll failed");
        }
        if let Err(e) = poll_detections(&app, &m).await {
            tracing::warn!(key = %m.key, error = %e, "detection poll failed");
        }
        if let Err(e) = poll_orders(&app, &m).await {
            tracing::warn!(key = %m.key, error = %e, "order tracking failed");
        }
        if let Err(e) = poll_claims(&app, &m).await {
            tracing::warn!(key = %m.key, error = %e, "claim poll failed");
        }
        m.dispatch.notify_one();
        m.persist();
    }
}

async fn poll_status(app: &Arc<App>, m: &Arc<MatchRun>) -> Result<(), SimError> {
    let status = m.sim.status().await?;
    let mut core = m.core();
    core.clock.update(&status);
    workflow::handover(&mut core, &app.settings);
    Ok(())
}

async fn poll_detections(app: &Arc<App>, m: &Arc<MatchRun>) -> Result<(), SimError> {
    let since = m.core().store.detection_cursor;
    let feed = m.sim.detections(since).await?;
    for raw in feed.detections {
        // A lookup failure leaves the cursor where it was: the batch is fetched again next tick
        // and detections already ingested are recognised by id.
        if let Some(workflow::Ingest::Created(id)) = ingest(app, m, raw, "system").await? {
            tracing::info!(key = %m.key, case = %id, "case opened");
        }
    }
    let mut core = m.core();
    core.store.detection_cursor = feed.minute;
    core.store.dirty = true;
    Ok(())
}

/// Turns one detection (from the feed, the intake form or the intake API) into a case, or into a
/// sighting of an existing one. New streams get their passive DNS first. `None` when the detection
/// cannot be read (recorded in the audit log under `actor`).
pub async fn ingest(
    app: &Arc<App>,
    m: &Arc<MatchRun>,
    raw: Value,
    actor: &str,
) -> Result<Option<workflow::Ingest>, SimError> {
    let detection: Detection = match serde_json::from_value(raw.clone()) {
        Ok(d) => d,
        Err(e) => {
            m.core().record(actor, "detection_unreadable", json!({"error": e.to_string(), "detection": raw}));
            return Ok(None);
        }
    };
    let new_stream = workflow::is_new_stream(&m.core(), &detection);
    let (dns_ip, dns_domain) = if new_stream {
        (m.sim.dns_by_ip(&detection.server_ip).await?, m.sim.dns_by_domain(&detection.stream_host).await?)
    } else {
        (None, None)
    };
    let mut core = m.core();
    let outcome =
        workflow::ingest_detection(&mut core, &app.settings, raw, &detection, dns_ip.as_ref(), dns_domain.as_ref());
    Ok(Some(outcome))
}

async fn poll_orders(app: &Arc<App>, m: &Arc<MatchRun>) -> Result<(), SimError> {
    let providers: Vec<String> = {
        let core = m.core();
        let mut ids: Vec<String> =
            core.store.orders.iter().filter(|o| o.status.at_provider()).map(|o| o.provider_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    };
    for provider_id in providers {
        let views = m.sim.provider_orders(&provider_id).await?;
        let keys = app.sessions().signing_keys();
        let mut core = m.core();
        workflow::apply_provider_views(&mut core, &app.settings, &provider_id, &views, &keys);
    }
    Ok(())
}

async fn poll_claims(app: &Arc<App>, m: &Arc<MatchRun>) -> Result<(), SimError> {
    let since = m.core().store.claim_cursor;
    let feed = m.sim.claims(since).await?;
    let mut core = m.core();
    for claim in &feed.claims {
        if workflow::ingest_claim(&mut core, &app.settings, claim) {
            tracing::info!(key = %m.key, claim = %claim.id, domain = %claim.domain, "claim received");
        }
    }
    core.store.claim_cursor = feed.minute - CLAIM_OVERLAP_MIN;
    Ok(())
}

enum Job {
    Send(String, Result<Value, SimError>),
    Lift(String, Result<Value, SimError>),
}

async fn run_dispatcher(app: Arc<App>, m: Arc<MatchRun>) {
    loop {
        tokio::select! {
            _ = m.dispatch.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        dispatch_once(&app, &m).await;
    }
}

/// Sends every signed order and lift in parallel, then records the outcomes.
async fn dispatch_once(app: &Arc<App>, m: &Arc<MatchRun>) {
    let (sends, lifts) = {
        let mut core = m.core();
        (workflow::take_ready_sends(&mut core), workflow::take_ready_lifts(&mut core))
    };
    if sends.is_empty() && lifts.is_empty() {
        return;
    }
    let mut jobs = JoinSet::new();
    for (order_id, provider_id, body) in sends {
        let m = m.clone();
        jobs.spawn(async move {
            let result = m.sim.send_order(&provider_id, &body).await;
            Job::Send(order_id, result)
        });
    }
    for (order_id, provider_id, body) in lifts {
        let m = m.clone();
        jobs.spawn(async move {
            let result = m.sim.lift_order(&provider_id, &order_id, &body).await;
            Job::Lift(order_id, result)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = jobs.join_next().await {
        match joined {
            Ok(job) => results.push(job),
            Err(e) => tracing::error!(error = %e, "dispatch task failed"),
        }
    }
    let keys = app.sessions().signing_keys();
    {
        let mut core = m.core();
        for job in results {
            match job {
                Job::Send(id, result) => workflow::apply_send_result(&mut core, &app.settings, &id, result, &keys),
                Job::Lift(id, result) => workflow::apply_lift_result(&mut core, &id, result),
            }
        }
    }
    m.persist();
    // Retries signed while applying the results go out right away.
    m.dispatch.notify_one();
}
