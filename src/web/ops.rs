//! Operations board (rights holder / prosecutor / platform operator) and authenticated exports.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};

use crate::app::{App, MatchRun};
use crate::audit::read_entries;
use crate::judges::Session;
use crate::model::{CaseStatus, ClaimStatus, OrderRecord, OrderStatus, Store};
use crate::web::labels::{self, minute, span};
use crate::web::layout::{Nav, page};
use crate::web::traces::case_leaks;
use crate::web::ui::page_header;
use crate::web::views::{decision_summary, evidence_panel, flash, measure_summary, orders_table, ring, status};
use crate::web::{current_session, error_page};
use crate::workflow::time_to_block;

#[allow(clippy::result_large_err)]
fn ops_session(app: &App, headers: &HeaderMap) -> Result<Session, Response> {
    current_session(app, headers).ok_or_else(|| Redirect::to("/login").into_response())
}

fn latest_order<'a>(store: &'a Store, case_id: &str, provider_id: &str) -> Option<(&'a OrderRecord, usize)> {
    let orders: Vec<&OrderRecord> =
        store.orders.iter().filter(|o| o.case_id == case_id && o.provider_id == provider_id).collect();
    let count = orders.len();
    orders.into_iter().max_by_key(|o| o.attempt).map(|o| (o, count))
}

fn board_markup(store: &Store) -> Markup {
    let count_cases = |s: CaseStatus| store.cases.iter().filter(|c| c.status == s).count();
    let applied_now = store.orders.iter().filter(|o| o.status == OrderStatus::Applied).count();
    let retries = store.orders.iter().filter(|o| o.replaces.is_some() && o.lift.is_none()).count();
    let claims_pending = store.claims.iter().filter(|c| c.status == ClaimStatus::PendingJudge).count();
    let approved: Vec<_> = store.cases.iter().filter(|c| c.status == CaseStatus::Approved).collect();
    html! {
        dl class="kpis" {
            div class="kpi" { dt { "Esperan al juez" } dd { (count_cases(CaseStatus::PendingJudge)) } }
            div class="kpi" { dt { "Aprobados" } dd { (count_cases(CaseStatus::Approved)) } }
            div class="kpi" { dt { "Descartados" } dd { (count_cases(CaseStatus::Dismissed)) } }
            div class="kpi" { dt { "Bloqueos activos" } dd { (applied_now) } }
            div class="kpi" { dt { "Reenvíos" } dd { (retries) } }
            div class="kpi" { dt { "Reclamos abiertos" } dd { (claims_pending) } }
        }
        div class="charts" {
            section class="panel" aria-labelledby="chart-cases" {
                h2 id="chart-cases" { "Expedientes del partido" }
                (ring("expedientes", &[
                    ("amber", "Esperan al juez", count_cases(CaseStatus::PendingJudge)),
                    ("black", "Aprobados", count_cases(CaseStatus::Approved)),
                    ("coral", "Rechazados", count_cases(CaseStatus::Rejected)),
                    ("grey", "Descartados", count_cases(CaseStatus::Dismissed)),
                ]))
            }
            section class="panel" aria-labelledby="chart-providers" {
                h2 id="chart-providers" { "Bloqueos activos por proveedor" }
                @let approved_cases = count_cases(CaseStatus::Approved).max(1);
                ul class="bars" {
                    @for (i, p) in store.providers.iter().enumerate() {
                        @let active = store.orders.iter().filter(|o| o.provider_id == p.id && o.status == OrderStatus::Applied).count();
                        li {
                            span class="bar-name" { (p.name) }
                            progress class={ "bar " (["coral", "", "amber"][i % 3]) } max=(approved_cases.max(active)) value=(active)
                                aria-label={ "Bloqueos activos en " (p.name) } {}
                            span class="num" { (active) (if active == 1 { " activo" } else { " activos" }) }
                        }
                    }
                }
                p class="hint" { "Cada barra llega al total cuando el proveedor aplicó todos los bloqueos aprobados." }
            }
        }
        h2 { "Expedientes" }
        @if store.cases.is_empty() {
            p { "Todavía no se detectó ningún stream en este partido." }
        } @else {
            div class="table-wrap" role="region" aria-label="Expedientes" tabindex="0" {
                table {
                    caption { "Expedientes (" (store.cases.len()) ")" }
                    thead { tr {
                        th scope="col" { "Expediente" }
                        th scope="col" class="num" { "Detectado" }
                        th scope="col" { "Sitio" }
                        th scope="col" { "Señal" }
                        th scope="col" { "Bloqueo" }
                        th scope="col" { "Estado" }
                        th scope="col" { "Juez" }
                        th scope="col" class="num" { "Tiempo a bloqueo" }
                    } }
                    tbody {
                        @for c in store.cases.iter().rev() {
                            tr {
                                th scope="row" { a href={ "/ops/cases/" (c.id) } { (c.id) } }
                                td class="num" { (minute(c.first_detection_min())) }
                                td { (c.evidence.collateral.site) br; span class="mono hint" { (c.host()) " · " (c.ip()) } }
                                td { (status(labels::watermark(c.evidence.watermark.verdict))) }
                                td { (c.decision.as_ref().and_then(|d| d.measure).or(c.proposal.as_ref().map(|p| p.measure)).map(labels::kind).unwrap_or("—")) }
                                td { (status(labels::case_status(c.status))) }
                                td {
                                    (c.decision.as_ref().map(|d| d.judge_name.clone())
                                        .or_else(|| c.assigned_judge.as_deref().map(|j| store.judge_name(j)))
                                        .unwrap_or_else(|| "—".into()))
                                }
                                td class="num" { (time_to_block(store, c).map(span).unwrap_or_else(|| "—".into())) }
                            }
                        }
                    }
                }
            }
        }
        @if !approved.is_empty() {
            h2 { "Confirmación por proveedor" }
            div class="table-wrap" role="region" aria-label="Confirmación por proveedor" tabindex="0" {
                table {
                    caption { "Estado del bloqueo en cada proveedor" }
                    thead { tr {
                        th scope="col" { "Expediente" }
                        @for p in &store.providers { th scope="col" { (p.name) } }
                    } }
                    tbody {
                        @for c in approved.iter().rev() {
                            tr {
                                th scope="row" { a href={ "/ops/cases/" (c.id) } { (c.id) } }
                                @for p in &store.providers {
                                    td {
                                        @match latest_order(store, &c.id, &p.id) {
                                            Some((o, n)) => {
                                                (status(labels::order_status(o.status)))
                                                br; span class="hint" { (labels::kind(o.kind)) @if n > 1 { " · " (n) " órdenes" } }
                                            }
                                            None => { span class="hint" { "Sin orden" } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if !store.claims.is_empty() {
            h2 { "Reclamos" }
            div class="table-wrap" role="region" aria-label="Reclamos" tabindex="0" {
                table {
                    caption { "Reclamos de sitios afectados (" (store.claims.len()) ")" }
                    thead { tr {
                        th scope="col" { "Reclamo" }
                        th scope="col" { "Sitio" }
                        th scope="col" { "Verificación" }
                        th scope="col" { "Estado" }
                        th scope="col" class="num" { "Recibido" }
                    } }
                    tbody {
                        @for c in store.claims.iter().rev() {
                            tr {
                                th scope="row" { (c.id) }
                                td class="mono" { (c.domain) }
                                td { (status(labels::claim_verdict(c.verdict))) }
                                td { (status(labels::claim_status(c.status))) }
                                td class="num" { (minute(c.minute)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
pub struct MatchQuery {
    /// Which match a page shows (`?partido=2`); the first one when missing.
    pub partido: Option<String>,
    pub msg: Option<String>,
    pub error: Option<String>,
}

fn board_snapshot(m: &MatchRun) -> (Markup, u64) {
    let core = m.core();
    (board_markup(&core.store), core.store.inbox_version)
}

/// One line per match followed at the same time, each opening its board.
fn matches_overview(app: &App, current: &str) -> Markup {
    html! {
        ul class="match-list" {
            @for m in &app.matches {
                @let core = m.core();
                @let pending = core.store.cases.iter().filter(|c| c.status == CaseStatus::PendingJudge).count();
                @let active = core.store.orders.iter().filter(|o| o.status == OrderStatus::Applied).count();
                li {
                    a class="match-card" href={ "/ops?partido=" (m.key) } aria-current=[(m.key == current).then_some("page")] {
                        span class="match-card-name" { (crate::app::match_label(&m.key, core.store.match_info.as_ref().map(|i| i.name.as_str()))) }
                        span class="match-card-clock" {
                            @if !core.clock.synced { "Sin conexión" }
                            @else if core.clock.finished || core.now() >= core.clock.end_min { "Finalizado" }
                            @else { "En vivo · " (minute(core.now())) }
                        }
                        span class="hint" { (core.store.cases.len()) " expedientes · " (pending) " esperan al juez · " (active) " bloqueos activos" }
                    }
                }
            }
        }
    }
}

pub async fn board_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<MatchQuery>) -> Response {
    let session = match ops_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let m = app.match_or_primary(q.partido.as_deref()).clone();
    let (board, version) = board_snapshot(&m);
    let many = app.matches.len() > 1;
    let body = html! {
        (page_header(
            "Operaciones",
            "Los streams detectados en cada partido, lo que decidió el juez y cómo va el bloqueo en cada proveedor.",
            html! { a class="button primary" href={ "/ops/intake?partido=" (m.key) } { "Cargar sitios" } },
        ))
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        @if many {
            h2 { "Partidos en vivo" }
            (matches_overview(&app, &m.key))
            h2 data-match-key=(m.key) { (m.label()) }
        } @else {
            span hidden data-match-key=(m.key) {}
        }
        div data-refresh={ "/ops/board?partido=" (m.key) } data-version=(version) data-interval="2000" { (board) }
    };
    Html(page("Operaciones", Some(&session), Nav::Ops, body).into_string()).into_response()
}

pub async fn board_fragment(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<MatchQuery>) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let m = app.match_or_primary(q.partido.as_deref()).clone();
    let (board, version) = board_snapshot(&m);
    // The minute changes every tick, so the board always re-renders; the version keeps it cheap otherwise.
    let version = format!("{version}-{}", (m.core().now() * 10.0).floor());
    ([("x-version", version)], Html(board.into_string())).into_response()
}

pub async fn case_page(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let session = match ops_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    // Leak traces live with the first match: read them before locking this case's match.
    let leaks = {
        let core = app.core();
        case_leaks(&core.store, &id)
    };
    let Some(m) = app.match_of_case(&id).cloned() else {
        return error_page(
            StatusCode::NOT_FOUND,
            Some(&session),
            "Expediente inexistente",
            "No existe ese expediente.",
        );
    };
    let trail = read_entries(&m.audit_path()).unwrap_or_default();
    let core = m.core();
    let Some(case) = core.store.case(&id) else {
        return error_page(
            StatusCode::NOT_FOUND,
            Some(&session),
            "Expediente inexistente",
            "No existe ese expediente.",
        );
    };
    let match_name = crate::app::match_label(&m.key, core.store.match_info.as_ref().map(|i| i.name.as_str()));
    let orders: Vec<&OrderRecord> = core.store.orders_of_case(&case.id).collect();
    let order_ids: Vec<&str> = orders.iter().map(|o| o.order_id.as_str()).collect();
    let trail: Vec<_> = trail
        .iter()
        .filter(|e| {
            e.data.get("case_id").and_then(|v| v.as_str()) == Some(case.id.as_str())
                || e.data.get("order_id").and_then(|v| v.as_str()).is_some_and(|o| order_ids.contains(&o))
        })
        .collect();
    let body = html! {
        p class="breadcrumb" { a href={ "/ops?partido=" (m.key) } { "← Volver a operaciones" } }
        p class="eyebrow" { "Expediente " (case.id) " · " (match_name) }
        span hidden data-match-key=(m.key) {}
        h1 { (case.evidence.collateral.site) }
        p class="lede" {
            (status(labels::case_status(case.status)))
            " · detectado al " (minute(case.first_detection_min()))
            " · stream en " span class="mono" { (case.host()) }
            @if let Some(o) = labels::origin(&case.evidence.detection) { " · " (o) } " · "
            a href={ "/api/cases/" (case.id) } { "Exportar expediente (JSON)" }
        }
        section class="panel" aria-labelledby="summary-title" {
            h2 id="summary-title" { "Qué se pide" }
            (measure_summary(case))
            (decision_summary(case))
        }
        (evidence_panel(&core.store, case))
        (leaks)
        @if !orders.is_empty() {
            section class="panel" aria-labelledby="orders-title" {
                h2 id="orders-title" { "Órdenes a los proveedores" }
                (orders_table(&core.store, &orders, "Órdenes de este expediente"))
            }
        }
        section class="panel" aria-labelledby="trail-title" {
            h2 id="trail-title" { "Registro de auditoría del expediente" }
            div class="table-wrap" role="region" aria-label="Registro de auditoría" tabindex="0" {
                table {
                    caption { (trail.len()) " entradas encadenadas" }
                    thead { tr {
                        th scope="col" class="num" { "#" }
                        th scope="col" class="num" { "Partido" }
                        th scope="col" { "Quién" }
                        th scope="col" { "Evento" }
                        th scope="col" { "Hash" }
                    } }
                    tbody {
                        @for e in &trail {
                            tr {
                                th scope="row" class="num" { (e.seq) }
                                td class="num" { (e.match_min.map(minute).unwrap_or_else(|| "—".into())) }
                                td { (labels::actor(&core.store, &e.actor)) }
                                td { (labels::audit_event(&e.event)) }
                                td class="mono" { (e.hash[..16].to_string()) "…" }
                            }
                        }
                    }
                }
            }
        }
    };
    let title = format!("Expediente {}", case.id);
    Html(page(&title, Some(&session), Nav::Ops, body).into_string()).into_response()
}

pub async fn case_file_json(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(m) = app.match_of_case(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let entries = read_entries(&m.audit_path()).unwrap_or_default();
    let core = m.core();
    let Some(case) = core.store.case(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let doc = crate::export::case_file(&core.store, case, &entries, core.audit.head());
    let disposition = format!("attachment; filename=\"expediente-{}.json\"", case.id);
    ([(header::CONTENT_DISPOSITION, disposition)], Json(doc)).into_response()
}

pub async fn audit_jsonl(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<MatchQuery>) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let m = app.match_or_primary(q.partido.as_deref());
    let name = if m.key == "1" {
        "registro-auditoria.jsonl".to_string()
    } else {
        format!("registro-auditoria-partido-{}.jsonl", m.key)
    };
    match std::fs::read(m.audit_path()) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
