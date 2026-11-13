//! Public transparency registry, match clock and audit chain head.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use maud::{Markup, html};
use serde_json::{Value, json};

use crate::app::{App, match_label};
use crate::audit::verify_file;
use crate::web::current_session;
use crate::web::labels::{self, minute};
use crate::web::layout::{Nav, page};
use crate::web::ops::MatchQuery;
use crate::web::views::status;
use crate::workflow::{RegistryEntry, RegistryStatus, registry};

/// Every match's blocks, newest match first; `(label, match end, entry)`.
fn registry_rows(app: &App) -> (Vec<(String, i64, RegistryEntry)>, String) {
    let mut rows = Vec::new();
    let mut version = String::new();
    for m in &app.matches {
        let core = m.core();
        let label = match_label(&m.key, core.store.match_info.as_ref().map(|i| i.name.as_str()));
        let end = labels::match_end(&core.store);
        version.push_str(&format!("{}.", core.store.inbox_version));
        rows.extend(registry(&core.store).into_iter().map(|r| (label.clone(), end, r)));
    }
    (rows, version)
}

fn registry_markup(app: &App) -> (Markup, String) {
    let many = app.matches.len() > 1;
    let (rows, version) = registry_rows(app);
    let count = |s: RegistryStatus| rows.iter().filter(|(_, _, r)| r.status == s).count();
    let markup = html! {
        dl class="kpis" {
            div class="kpi" { dt { "Activos" } dd { (count(RegistryStatus::Active)) } }
            div class="kpi" { dt { "En curso" } dd { (count(RegistryStatus::InProgress)) } }
            div class="kpi" { dt { "Vencidos" } dd { (count(RegistryStatus::Expired)) } }
            div class="kpi" { dt { "Levantados" } dd { (count(RegistryStatus::Lifted)) } }
        }
        @if rows.is_empty() {
            p { "Todavía no hay bloqueos ordenados." }
        } @else {
            div class="table-wrap" role="region" aria-label="Bloqueos ordenados" tabindex="0" {
                table {
                    caption { "Bloqueos ordenados (" (rows.len()) ")" }
                    thead { tr {
                        th scope="col" { "Bloqueo" }
                        @if many { th scope="col" { "Partido" } }
                        th scope="col" { "Ordenó" }
                        th scope="col" class="num" { "Desde" }
                        th scope="col" { "Rige hasta" }
                        th scope="col" { "Estado" }
                        th scope="col" { "Lo aplicaron" }
                        th scope="col" { "Expediente" }
                    } }
                    tbody {
                        @for (label, end, r) in &rows {
                            tr {
                                th scope="row" { span class="mono" { (r.target) } br; span class="hint" { "Bloqueo " (labels::kind_phrase(r.kind)) } }
                                @if many { td { (label) } }
                                td { (r.ordered_by) br; span class="hint" { (r.court) } }
                                td class="num" { (r.first_applied_min.map(minute).unwrap_or_else(|| "—".into())) }
                                td { (labels::until_short(r.expires_min, *end)) }
                                td {
                                    (status(labels::registry_status(r.status)))
                                    @if let Some(ended) = r.ended_min { br; span class="hint" { "desde el " (minute(ended)) } }
                                    @if let Some(reason) = &r.lift_reason { br; span class="hint" { (reason) } }
                                }
                                td { (if r.providers_applied.is_empty() { "—".to_string() } else { r.providers_applied.join(", ") }) }
                                td class="mono" { (r.case_id) }
                            }
                        }
                    }
                }
            }
        }
    };
    (markup, version)
}

fn snapshot(app: &App) -> (Markup, String) {
    registry_markup(app)
}

pub async fn registry_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let session = current_session(&app, &headers);
    let (fragment, version) = snapshot(&app);
    let body = html! {
        h1 { "Bloqueos ordenados por la justicia" }
        p class="lede" {
            "Cada sitio bloqueado durante un partido, con el juez que lo ordenó y hasta cuándo rige. "
            "Los bloqueos por IP terminan solos con el partido."
        }
        div data-refresh="/registry/fragment" data-version=(version) data-interval="3000" { (fragment) }
        p class="hint" {
            "Esta lista sale del registro de auditoría, que no se puede modificar sin que se note. "
            a href="/api/registry" { "Descargar los datos (JSON)" } " · "
            a href="/api/audit/head" { "Verificar el registro" }
        }
    };
    Html(page("Transparencia", session.as_ref(), Nav::Registry, body).into_string()).into_response()
}

pub async fn registry_fragment(State(app): State<Arc<App>>) -> Response {
    let (fragment, version) = snapshot(&app);
    ([("x-version", version)], Html(fragment.into_string())).into_response()
}

/// Open data: every match with its blocks and the head of its audit chain.
pub async fn registry_json(State(app): State<Arc<App>>) -> Json<Value> {
    let matches: Vec<Value> = app
        .matches
        .iter()
        .map(|m| {
            let core = m.core();
            let head = core.audit.head();
            json!({
                "key": m.key,
                "match": core.store.match_info.as_ref().map(|i| json!({"id": i.id, "name": i.name, "end_min": i.end_min})),
                "audit_head": {"seq": head.0, "hash": head.1},
                "entries": registry(&core.store),
            })
        })
        .collect();
    Json(json!({ "matches": matches }))
}

/// Clock of the match a page shows (`?partido=`, the first one by default) and how many are live.
pub async fn clock_json(State(app): State<Arc<App>>, Query(q): Query<MatchQuery>) -> Json<Value> {
    let live = app
        .matches
        .iter()
        .filter(|m| {
            let core = m.core();
            core.clock.synced && !core.clock.finished && core.now() < core.clock.end_min
        })
        .count();
    let m = app.match_or_primary(q.partido.as_deref());
    let core = m.core();
    let clock = &core.clock;
    Json(json!({
        "key": m.key,
        "synced": clock.synced,
        "minute": clock.now(),
        "teams": core.store.match_info.as_ref().map(|i| match_label(&m.key, Some(&i.name))),
        "speedup": clock.speedup(),
        "end_min": clock.end_min,
        "finished": clock.finished,
        "judges_on_duty": clock.judges_on_duty,
        "matches": app.matches.len(),
        "live": live,
    }))
}

pub async fn audit_head(State(app): State<Arc<App>>, Query(q): Query<MatchQuery>) -> Json<Value> {
    let m = app.match_or_primary(q.partido.as_deref());
    let path = m.audit_path();
    let (seq, head) = m.core().audit.head();
    let report = verify_file(&path).ok();
    Json(json!({
        "key": m.key,
        "seq": seq,
        "hash": head,
        "file_valid": report.as_ref().map(|r| r.problem.is_none()),
        "file_entries": report.as_ref().map(|r| r.entries),
        "problem": report.and_then(|r| r.problem),
    }))
}
