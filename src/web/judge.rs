//! Judge panel: live inbox, case review with signed decisions, claims and retries.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;

use crate::app::{App, Core, MatchRun, Settings, match_label};
use crate::evidence::BlockKind;
use crate::judges::{Role, Session, can_sign, duty_judge, next_shift, shift_at};
use crate::model::{CaseStatus, ClaimStatus, OrderRecord, OrderStatus, Store};
use crate::web::labels::{self, error_code, minute, span};
use crate::web::layout::{Nav, page};
use crate::web::traces::case_leaks;
use crate::web::views::{decision_summary, evidence_panel, flash, measure_summary, notice, orders_table, status};
use crate::web::{csrf_ok, current_session, error_page};
use crate::workflow::{self, JudgeCtx};

#[derive(Deserialize)]
pub struct FlashQuery {
    msg: Option<String>,
    error: Option<String>,
    /// Match a claim link points at (claim ids may repeat across matches).
    partido: Option<String>,
}

#[derive(Deserialize)]
pub struct DecisionForm {
    csrf: String,
    decision: String,
    measure: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

struct Duty {
    synced: bool,
    now: f64,
    can_sign: bool,
    /// Pending work is routed to this judge right now.
    holder: bool,
    until: Option<f64>,
    next_from: Option<f64>,
}

fn duty_of(core: &Core, settings: &Settings, judge_id: &str) -> Duty {
    let now = core.now();
    let shifts = core.shifts();
    let margin = settings.shift_margin_min;
    Duty {
        synced: core.clock.synced,
        now,
        can_sign: can_sign(&shifts, judge_id, now, margin),
        holder: duty_judge(&shifts, now, margin).as_deref() == Some(judge_id),
        until: shift_at(&shifts, judge_id, now).map(|s| s.until_min),
        next_from: next_shift(&shifts, judge_id, now).map(|s| s.from_min),
    }
}

fn duty_notice(d: &Duty) -> Markup {
    if !d.synced {
        return notice("Todavía no hay conexión con el partido.", "warn");
    }
    if d.can_sign {
        let until = d.until.unwrap_or_default();
        return notice(
            &format!(
                "Está de turno hasta el {} (quedan {}) y puede firmar.",
                minute(until),
                span((until - d.now).max(0.0))
            ),
            "ok",
        );
    }
    if d.holder {
        let from = d.next_from.map(minute).unwrap_or_else(|| "—".into());
        return notice(&format!("Su turno empieza al {from}. Lo pendiente ya pasó a usted."), "warn");
    }
    let next = match d.next_from {
        Some(from) => format!("Su próximo turno empieza al {}.", minute(from)),
        None => "No tiene más turnos en este partido.".to_string(),
    };
    notice(&format!("Fuera de turno: no puede firmar. Lo pendiente lo atiende el juez de turno. {next}"), "warn")
}

#[allow(clippy::result_large_err)]
fn judge_session(app: &App, headers: &HeaderMap) -> Result<(Session, String), Response> {
    let Some(session) = current_session(app, headers) else {
        return Err(Redirect::to("/login").into_response());
    };
    match (&session.role, session.judge_id.clone()) {
        (Role::Judge, Some(judge_id)) => Ok((session, judge_id)),
        _ => Err(error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "Solo para jueces",
            "Esta sección es del panel del juez.",
        )),
    }
}

fn judge_ctx(session: &Session, judge_id: &str) -> JudgeCtx {
    JudgeCtx {
        judge_id: judge_id.to_string(),
        judge_name: session.display_name.clone(),
        court_id: session.court_id.clone().unwrap_or_default(),
    }
}

fn retries_by_case(store: &Store) -> Vec<(String, Vec<&OrderRecord>)> {
    let mut out: Vec<(String, Vec<&OrderRecord>)> = Vec::new();
    for o in store.orders.iter().filter(|o| o.status == OrderStatus::AwaitingSignature) {
        match out.iter_mut().find(|(c, _)| *c == o.case_id) {
            Some((_, list)) => list.push(o),
            None => out.push((o.case_id.clone(), vec![o])),
        }
    }
    out
}

/// One match's share of a judge's inbox, rendered piece by piece so several matches merge into
/// one list.
#[derive(Default)]
struct InboxPart {
    notice: Option<Markup>,
    cases: Vec<Markup>,
    claims: Vec<Markup>,
    retries: Vec<Markup>,
    decided: Vec<(f64, Markup)>,
    pending: usize,
    version: String,
}

fn inbox_part(store: &Store, key: &str, label: Option<&str>, judge_id: &str, duty: &Duty, csrf: &str) -> InboxPart {
    let tag = |m: Markup| html! { @if let Some(l) = label { span class="match-tag" { (l) } } (m) };
    let mut cases: Vec<_> = store
        .cases
        .iter()
        .filter(|c| c.status == CaseStatus::PendingJudge && c.assigned_judge.as_deref() == Some(judge_id))
        .collect();
    cases.sort_by(|a, b| a.created_min.total_cmp(&b.created_min));
    let claims: Vec<_> = store
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::PendingJudge && c.assigned_judge.as_deref() == Some(judge_id))
        .collect();
    let retries = if duty.holder { retries_by_case(store) } else { Vec::new() };
    let pending = cases.len() + claims.len() + retries.len();
    let notice = match label {
        Some(l) => html! { div class="duty-line" { span class="match-tag" { (l) } (duty_notice(duty)) } },
        None => duty_notice(duty),
    };
    InboxPart {
        notice: Some(notice),
        cases: cases
            .iter()
            .map(|c| {
                html! {
                    li class="card" {
                        div class="card-head" {
                            a href={ "/judge/cases/" (c.id) } { strong { (c.evidence.collateral.site) } }
                            span class="hint" {
                                "Detectado al " (minute(c.first_detection_min()))
                                " · espera hace " (span((duty.now - c.created_min).max(0.0)))
                            }
                        }
                        (tag(html! { p class="hint" { (c.id) } }))
                        p { span class="mono" { (c.host()) } " · " span class="mono" { (c.ip()) } }
                        p {
                            (status(labels::watermark(c.evidence.watermark.verdict)))
                            @if let Some(p) = &c.proposal { " · se propone bloquear " strong { (labels::kind_phrase(p.measure)) } }
                        }
                        @if !c.related_cases.is_empty() {
                            p class="hint" { "Mismo sitio que " (c.related_cases.join(", ")) ": cambió de servidor." }
                        }
                        div class="card-actions" {
                            a class="button primary" href={ "/judge/cases/" (c.id) } { "Revisar y decidir" }
                        }
                    }
                }
            })
            .collect(),
        claims: claims
            .iter()
            .map(|c| {
                html! {
                    li class="card claim" {
                        div class="card-head" {
                            a href={ "/judge/claims/" (c.id) "?partido=" (key) } { strong { "Reclamo de " (c.domain) } }
                            span class="hint" { "Al " (minute(c.minute)) }
                        }
                        (tag(html! { p class="hint" { (c.id) " · vía " (store.provider(&c.provider_id).map_or(c.provider_id.as_str(), |p| p.name.as_str())) } }))
                        p { (status(labels::claim_verdict(c.verdict))) }
                        div class="card-actions" {
                            a class="button primary" href={ "/judge/claims/" (c.id) "?partido=" (key) } { "Revisar reclamo" }
                        }
                    }
                }
            })
            .collect(),
        retries: retries
            .iter()
            .map(|(case_id, orders)| {
                html! {
                    li class="card" {
                        div class="card-head" {
                            strong { "Reenvíos de " (case_id) }
                            span class="hint" { (orders.len()) (if orders.len() == 1 { " orden" } else { " órdenes" }) }
                        }
                        (tag(html! {}))
                        p {
                            "Un proveedor falló al aplicar la orden y el juez que la aprobó ya no está de turno. "
                            "Se reenvía el mismo bloqueo con un número de orden nuevo."
                        }
                        ul class="plain" {
                            @for o in orders {
                                li { (store.provider(&o.provider_id).map_or(o.provider_id.as_str(), |p| p.name.as_str())) ": "
                                     (labels::kind(o.kind)) " " span class="mono" { (o.target) } }
                            }
                        }
                        div class="card-actions" {
                            a href={ "/judge/cases/" (case_id) } { "Ver expediente" }
                            form method="post" action={ "/judge/cases/" (case_id) "/retries" } data-once {
                                input type="hidden" name="csrf" value=(csrf);
                                button class="button primary" type="submit" disabled[!duty.can_sign] { "Firmar reenvío" }
                            }
                        }
                    }
                }
            })
            .collect(),
        decided: store
            .cases
            .iter()
            .filter_map(|c| c.decision.as_ref().filter(|d| d.judge_id == judge_id).map(|d| (c, d)))
            .map(|(c, d)| {
                (d.minute, html! {
                    tr {
                        th scope="row" { a href={ "/judge/cases/" (c.id) } { (c.id) } }
                        @if let Some(l) = label { td { (l) } }
                        td { (status(labels::case_status(c.status))) }
                        td class="mono" { (c.host()) }
                        td class="num" { (minute(d.minute)) }
                    }
                })
            })
            .collect(),
        pending,
        version: format!("{key}:{}-{}-{}", store.inbox_version, duty.can_sign, duty.holder),
    }
}

/// The whole inbox: every match the judge works on, merged into one list.
fn inbox_markup(app: &App, judge_id: &str, csrf: &str) -> (Markup, usize, String) {
    let many = app.matches.len() > 1;
    let mut all = InboxPart::default();
    for m in &app.matches {
        let core = m.core();
        let duty = duty_of(&core, &app.settings, judge_id);
        let label = many.then(|| match_label(&m.key, core.store.match_info.as_ref().map(|i| i.name.as_str())));
        let part = inbox_part(&core.store, &m.key, label.as_deref(), judge_id, &duty, csrf);
        all.notice = Some(html! { @if let Some(n) = all.notice.take() { (n) } @if let Some(n) = part.notice { (n) } });
        all.cases.extend(part.cases);
        all.claims.extend(part.claims);
        all.retries.extend(part.retries);
        all.decided.extend(part.decided);
        all.pending += part.pending;
        all.version.push_str(&part.version);
        all.version.push(';');
    }
    all.decided.sort_by(|a, b| b.0.total_cmp(&a.0));
    all.decided.truncate(12);
    let pending = all.pending;
    let markup = html! {
        @if let Some(n) = all.notice { (n) }
        h2 { "Pendientes de firma (" (pending) ")" }
        @if pending == 0 {
            p { "No tiene nada pendiente. Esta lista se actualiza sola y avisa cuando llega un pedido." }
        }
        @if !all.cases.is_empty() {
            h3 { "Pedidos de bloqueo" }
            ul class="cards" { @for c in &all.cases { (c) } }
        }
        @if !all.claims.is_empty() {
            h3 { "Reclamos de sitios afectados" }
            ul class="cards" { @for c in &all.claims { (c) } }
        }
        @if !all.retries.is_empty() {
            h3 { "Reenvíos que esperan su firma" }
            ul class="cards" { @for c in &all.retries { (c) } }
        }
        @if !all.decided.is_empty() {
            h2 { "Mis decisiones recientes" }
            div class="table-wrap" role="region" aria-label="Mis decisiones recientes" tabindex="0" {
                table {
                    caption { "Últimas " (all.decided.len()) " decisiones" }
                    thead { tr {
                        th scope="col" { "Expediente" }
                        @if many { th scope="col" { "Partido" } }
                        th scope="col" { "Decisión" }
                        th scope="col" { "Objetivo" }
                        th scope="col" class="num" { "Cuándo" }
                    } }
                    tbody { @for (_, row) in &all.decided { (row) } }
                }
            }
        }
    };
    (markup, pending, all.version)
}

pub async fn dashboard(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let court = app.core().store.court_of(&judge_id).map(|c| c.name.clone()).unwrap_or_default();
    let (inbox, pending, version) = inbox_markup(&app, &judge_id, &session.csrf);
    let body = html! {
        h1 { "Panel del juez" }
        p class="lede" { (session.display_name) " · " (court) }
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        p { button class="button" type="button" data-enable-notifications { "Activar avisos del navegador" } }
        div id="inbox" data-refresh="/judge/inbox" data-version=(version) data-pending=(pending) data-interval="1500" { (inbox) }
    };
    Html(page("Panel del juez", Some(&session), Nav::Judge, body).into_string()).into_response()
}

pub async fn inbox_fragment(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(session) = current_session(&app, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(judge_id) = session.judge_id.clone() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    // The version includes each match's duty state so the list re-renders at a shift change.
    let (inbox, pending, version) = inbox_markup(&app, &judge_id, &session.csrf);
    ([("x-version", version), ("x-pending", pending.to_string())], Html(inbox.into_string())).into_response()
}

fn not_found(session: &Session, title: &str, text: &str) -> Response {
    error_page(StatusCode::NOT_FOUND, Some(session), title, text)
}

pub async fn case_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Leak traces live with the first match: read them before locking this case's match.
    let leaks = {
        let core = app.core();
        case_leaks(&core.store, &id)
    };
    let Some(m) = app.match_of_case(&id) else {
        return not_found(&session, "Expediente inexistente", "No existe ese expediente.");
    };
    let core = m.core();
    let Some(case) = core.store.case(&id) else {
        return not_found(&session, "Expediente inexistente", "No existe ese expediente.");
    };
    let many = app.matches.len() > 1;
    let match_name = match_label(&m.key, core.store.match_info.as_ref().map(|i| i.name.as_str()));
    let duty = duty_of(&core, &app.settings, &judge_id);
    // Pending retries are signed by the judge who holds the duty, so only that judge reaches an
    // approved case through them.
    let mine = case.assigned_judge.as_deref() == Some(judge_id.as_str())
        || case.decision.as_ref().is_some_and(|d| d.judge_id == judge_id)
        || (duty.holder
            && case.status == CaseStatus::Approved
            && retries_by_case(&core.store).iter().any(|(c, _)| *c == case.id));
    if !mine {
        return error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "No le corresponde",
            "Este expediente lo tiene asignado otro juez.",
        );
    }
    let actionable =
        case.status == CaseStatus::PendingJudge && case.assigned_judge.as_deref() == Some(judge_id.as_str());
    let orders: Vec<&OrderRecord> = core.store.orders_of_case(&case.id).collect();
    let recommended_ip = case.proposal.as_ref().is_some_and(|p| p.measure == BlockKind::Ip);
    let body = html! {
        p class="breadcrumb" { a href="/judge" { "← Volver al panel" } }
        (flash(q.error.as_deref().or(q.msg.as_deref())))
        p class="eyebrow" { "Expediente " (case.id) @if many { " · " (match_name) } }
        span hidden data-match-key=(m.key) {}
        h1 { (case.evidence.collateral.site) }
        p class="lede" {
            (status(labels::case_status(case.status)))
            " · detectado al " (minute(case.first_detection_min()))
            " · stream en " span class="mono" { (case.host()) }
            @if let Some(o) = labels::origin(&case.evidence.detection) { " · " (o) }
        }
        div class="split" {
            aside class="side" {
                section class="panel" aria-labelledby="decision-title" {
                    h2 id="decision-title" { "Qué se pide" }
                    (measure_summary(case))
                    @if !case.related_cases.is_empty() {
                        p class="hint" { "El mismo sitio ya tuvo los expedientes " (case.related_cases.join(", ")) ": cambió de servidor." }
                    }
                    @if actionable {
                        @if !duty.can_sign { (duty_notice(&duty)) }
                        form method="post" action={ "/judge/cases/" (case.id) "/decision" } data-once {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="decision" value="approve";
                            @if recommended_ip {
                                fieldset {
                                    legend { "Tipo de bloqueo" }
                                    label class="choice" {
                                        input type="radio" name="measure" value="recommended" checked;
                                        span { "Como se recomienda: por IP, y por dominio en los proveedores que solo aceptan dominio" }
                                    }
                                    label class="choice" {
                                        input type="radio" name="measure" value="domain";
                                        span { "Solo por dominio del host del stream" }
                                    }
                                }
                            } @else {
                                input type="hidden" name="measure" value="recommended";
                            }
                            button class="button primary" type="submit" disabled[!duty.can_sign] { "Aprobar y firmar" }
                        }
                        form method="post" action={ "/judge/cases/" (case.id) "/decision" } class="reject-form" data-once {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="decision" value="reject";
                            label for="reason" { "Motivo del rechazo" }
                            textarea id="reason" name="reason" required maxlength="500" {}
                            button class="button danger" type="submit" disabled[!duty.can_sign] { "Rechazar con firma" }
                        }
                    } @else {
                        (decision_summary(case))
                    }
                }
            }
            div class="main-col" {
                (evidence_panel(&core.store, case))
                (leaks)
                @if !orders.is_empty() {
                    section class="panel" aria-labelledby="orders-title" {
                        h2 id="orders-title" { "Órdenes a los proveedores" }
                        (orders_table(&core.store, &orders, "Órdenes de este expediente"))
                    }
                }
            }
        }
    };
    let title = format!("Expediente {}", case.id);
    Html(page(&title, Some(&session), Nav::Judge, body).into_string()).into_response()
}

pub async fn decide_case(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DecisionForm>,
) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let back = |code: &str| Redirect::to(&format!("/judge/cases/{id}?error={code}")).into_response();
    if !csrf_ok(&session, &form.csrf) {
        return back("csrf");
    }
    let Some(key) = session.signing_key.clone() else {
        return back("no_signing_key");
    };
    let ctx = judge_ctx(&session, &judge_id);
    let Some(m) = app.match_of_case(&id).cloned() else {
        return back("not_found");
    };
    let result = {
        let mut core = m.core();
        match form.decision.as_str() {
            "approve" => {
                let force_domain = form.measure.as_deref() == Some("domain");
                workflow::approve_case(&mut core, &app.settings, &id, &ctx, &key, force_domain).map(|_| "approved")
            }
            "reject" => {
                let reason = form.reason.as_deref().map(str::trim).unwrap_or_default();
                if reason.is_empty() {
                    return back("reason_required");
                }
                let reason: String = reason.chars().take(500).collect();
                workflow::reject_case(&mut core, &app.settings, &id, &ctx, &key, &reason).map(|_| "rejected")
            }
            _ => return back("not_found"),
        }
    };
    wake(&m);
    match result {
        Ok(code) => Redirect::to(&format!("/judge?msg={code}")).into_response(),
        Err(e) => back(error_code(e)),
    }
}

/// After a decision: send what was signed right away and save.
fn wake(m: &MatchRun) {
    m.dispatch.notify_one();
    m.persist();
}

pub async fn sign_retries(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/judge?error=csrf").into_response();
    }
    let Some(key) = session.signing_key.clone() else {
        return Redirect::to("/judge?error=no_signing_key").into_response();
    };
    let ctx = judge_ctx(&session, &judge_id);
    let Some(m) = app.match_of_case(&id).cloned() else {
        return Redirect::to("/judge?error=not_found").into_response();
    };
    let result = {
        let mut core = m.core();
        let holder = duty_of(&core, &app.settings, &judge_id).holder;
        if holder {
            workflow::sign_pending_retries(&mut core, &app.settings, &id, &ctx, &key)
        } else {
            Err(workflow::WorkflowError::NotAssigned)
        }
    };
    wake(&m);
    match result {
        Ok(_) => Redirect::to("/judge?msg=retries_signed").into_response(),
        Err(e) => Redirect::to(&format!("/judge?error={}", error_code(e))).into_response(),
    }
}

pub async fn claim_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(m) = app.match_of_claim(&id, q.partido.as_deref()) else {
        return not_found(&session, "Reclamo inexistente", "No existe ese reclamo.");
    };
    let core = m.core();
    let Some(claim) = core.store.claim(&id) else {
        return not_found(&session, "Reclamo inexistente", "No existe ese reclamo.");
    };
    let mine = claim.assigned_judge.as_deref() == Some(judge_id.as_str())
        || claim.decision.as_ref().is_some_and(|d| d.judge_id == judge_id);
    if !mine {
        return error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "No le corresponde",
            "Este reclamo lo atiende otro juez.",
        );
    }
    let duty = duty_of(&core, &app.settings, &judge_id);
    let actionable =
        claim.status == ClaimStatus::PendingJudge && claim.assigned_judge.as_deref() == Some(judge_id.as_str());
    let affected: Vec<&OrderRecord> = claim.affected_orders.iter().filter_map(|o| core.store.order(o)).collect();
    let providers: std::collections::BTreeSet<&str> = affected.iter().map(|o| o.provider_id.as_str()).collect();
    let ip_blocks = affected.iter().any(|o| o.kind == BlockKind::Ip);
    let hosts: Vec<String> =
        claim.cases.iter().filter_map(|c| core.store.case(c)).map(|c| c.host().to_string()).collect();
    let provider_name = core.store.provider(&claim.provider_id).map_or(claim.provider_id.clone(), |p| p.name.clone());
    let body = html! {
        p class="breadcrumb" { a href="/judge" { "← Volver al panel" } }
        (flash(q.error.as_deref().or(q.msg.as_deref())))
        h1 { "Reclamo " (claim.id) }
        span hidden data-match-key=(m.key) {}
        p class="lede" { (status(labels::claim_status(claim.status))) " · recibido al " (minute(claim.minute)) }
        div class="split" {
            aside class="side" {
                section class="panel" aria-labelledby="claim-decision" {
                    h2 id="claim-decision" { "Qué se pide" }
                    p {
                        "Levantar " (affected.len()) " orden(es) en " (providers.len()) " proveedor(es) que hoy bloquean "
                        span class="mono" { (claim.domain) } "."
                        @if ip_blocks && !hosts.is_empty() {
                            " Los bloqueos por IP se reemplazan por un bloqueo por dominio de "
                            span class="mono" { (hosts.join(", ")) } ", que sigue cortando el stream."
                        }
                    }
                    @if actionable {
                        @if !duty.can_sign { (duty_notice(&duty)) }
                        form method="post" action={ "/judge/claims/" (claim.id) "/decision?partido=" (m.key) } data-once {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="decision" value="approve";
                            button class="button primary" type="submit" disabled[!duty.can_sign] { "Aceptar reclamo y firmar" }
                        }
                        form method="post" action={ "/judge/claims/" (claim.id) "/decision?partido=" (m.key) } class="reject-form" data-once {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="decision" value="reject";
                            label for="reason" { "Motivo del rechazo" }
                            textarea id="reason" name="reason" required maxlength="500" {}
                            button class="button danger" type="submit" disabled[!duty.can_sign] { "Rechazar con firma" }
                        }
                    } @else if let Some(d) = &claim.decision {
                        dl class="facts" {
                            dt { "Decisión" } dd { (if d.approved { "Aceptado" } else { "Rechazado" }) }
                            dt { "Juez" } dd { (d.judge_name) }
                            dt { "Cuándo" } dd { "Al " (minute(d.minute)) }
                            @if let Some(r) = &d.reason { dt { "Motivo" } dd { (r) } }
                            dt { "Firma" } dd class="mono" { (d.signature) }
                        }
                    }
                }
            }
            div class="main-col" {
                section class="panel" aria-labelledby="claim-facts" {
                    h2 id="claim-facts" { "Reclamo" }
                    dl class="facts" {
                        dt { "Sitio" } dd class="mono" { (claim.domain) }
                        dt { "Recibido vía" } dd { (provider_name) }
                        dt { "Mensaje" } dd { (claim.message) }
                        dt { "Verificación" } dd { (status(labels::claim_verdict(claim.verdict))) }
                        dt { "Licenciatario autorizado" } dd { (if claim.is_licensee { "Sí" } else { "No" }) }
                        dt { "Expedientes" } dd { (claim.cases.join(", ")) }
                    }
                }
                @if !affected.is_empty() {
                    section class="panel" aria-labelledby="claim-orders" {
                        h2 id="claim-orders" { "Bloqueos que lo alcanzan" }
                        (orders_table(&core.store, &affected, "Órdenes que bloquean al reclamante"))
                    }
                }
            }
        }
    };
    let title = format!("Reclamo {}", claim.id);
    Html(page(&title, Some(&session), Nav::Judge, body).into_string()).into_response()
}

pub async fn decide_claim(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FlashQuery>,
    Form(form): Form<DecisionForm>,
) -> Response {
    let (session, judge_id) = match judge_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let partido = q.partido.clone().unwrap_or_default();
    let back = |code: &str| Redirect::to(&format!("/judge/claims/{id}?partido={partido}&error={code}")).into_response();
    if !csrf_ok(&session, &form.csrf) {
        return back("csrf");
    }
    let Some(key) = session.signing_key.clone() else {
        return back("no_signing_key");
    };
    let ctx = judge_ctx(&session, &judge_id);
    let Some(m) = app.match_of_claim(&id, q.partido.as_deref()).cloned() else {
        return back("not_found");
    };
    let result = {
        let mut core = m.core();
        match form.decision.as_str() {
            "approve" => workflow::approve_claim(&mut core, &app.settings, &id, &ctx, &key).map(|_| "claim_approved"),
            "reject" => {
                let reason = form.reason.as_deref().map(str::trim).unwrap_or_default();
                if reason.is_empty() {
                    return back("reason_required");
                }
                let reason: String = reason.chars().take(500).collect();
                workflow::reject_claim(&mut core, &app.settings, &id, &ctx, &key, &reason).map(|_| "claim_rejected")
            }
            _ => return back("not_found"),
        }
    };
    wake(&m);
    match result {
        Ok(code) => Redirect::to(&format!("/judge?msg={code}")).into_response(),
        Err(e) => back(error_code(e)),
    }
}
