//! Reference pages for everyone logged in: internet providers, courts with duty shifts, and the
//! audit log with filters and pages.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::html;
use serde::Deserialize;

use crate::app::{App, MatchRun};
use crate::audit::{read_entries, verify_file};
use crate::judges::{Role, Session, can_sign, shift_at};
use crate::model::OrderStatus;
use crate::web::current_session;
use crate::web::labels::{self, Label, minute};
use crate::web::layout::{Nav, page};
use crate::web::ui::{figure, figures, match_tabs, page_header, pager, query_value, when};
use crate::web::views::{format_thousands, status};

#[allow(clippy::result_large_err)]
fn logged_in(app: &App, headers: &HeaderMap) -> Result<Session, Response> {
    current_session(app, headers).ok_or_else(|| Redirect::to("/login").into_response())
}

pub async fn providers_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let session = match logged_in(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    // Orders of every match count toward each provider.
    let orders: Vec<crate::model::OrderRecord> =
        app.matches.iter().flat_map(|m| m.core().store.orders.clone()).collect();
    let core = app.core();
    let providers = &core.store.providers;
    let customers: u64 = providers.iter().map(|p| p.customers).sum();
    let ip = providers.iter().filter(|p| p.accepts("ip")).count();
    let domain_only = providers.iter().filter(|p| p.accepts("dominio") && !p.accepts("ip")).count();
    let body = html! {
        (page_header(
            "Proveedores de internet",
            "El registro de proveedores al que llegan las órdenes: cuántos clientes cubre cada uno y qué tipo de bloqueo acepta. Lo mantiene el regulador.",
            html! { a class="button" href="/ops" { "Ver confirmaciones" } },
        ))
        (figures(html! {
            (figure("Proveedores", providers.len(), None))
            (figure("Clientes cubiertos", format_thousands(customers), None))
            (figure("Aceptan IP", ip, None))
            (figure("Solo dominio", domain_only, None))
        }))
        div class="table-wrap" role="region" aria-label="Proveedores" tabindex="0" {
            table {
                caption { "Registro de proveedores (" (providers.len()) ")" }
                thead { tr {
                    th scope="col" { "Proveedor" }
                    th scope="col" { "Tamaño" }
                    th scope="col" class="num" { "Clientes" }
                    th scope="col" { "Acepta" }
                    th scope="col" class="num" { "Órdenes aplicadas ahora" }
                    th scope="col" class="num" { "Órdenes en total" }
                } }
                tbody {
                    @if providers.is_empty() {
                        tr { td colspan="6" class="hint" { "Todavía no hay conexión con el registro de proveedores." } }
                    }
                    @for p in providers {
                        @let orders: Vec<_> = orders.iter().filter(|o| o.provider_id == p.id).collect();
                        tr {
                            th scope="row" { (p.name) br; span class="hint mono" { (p.id) } }
                            td { (p.size.clone().unwrap_or_else(|| "—".into())) }
                            td class="num" { (format_thousands(p.customers)) }
                            td { (p.capabilities.iter().map(|c| if c == "ip" { "IP" } else { "Dominio" }).collect::<Vec<_>>().join(" y ")) }
                            td class="num" { (orders.iter().filter(|o| o.status == OrderStatus::Applied).count()) }
                            td class="num" { (orders.len()) }
                        }
                    }
                }
            }
        }
    };
    drop(core);
    Html(page("Proveedores", Some(&session), Nav::Providers, body).into_string()).into_response()
}

pub async fn courts_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(q): Query<crate::web::ops::MatchQuery>,
) -> Response {
    let session = match logged_in(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let accounts: Vec<(String, String)> =
        app.accounts().accounts.iter().filter_map(|a| Some((a.judge_id.clone()?, a.username.clone()))).collect();
    let m: &MatchRun = app.match_or_primary(q.partido.as_deref());
    let tabs = match_tabs(&app.match_list(), &m.key, "/ops/courts?");
    let core = m.core();
    let now = core.now();
    let margin = app.settings.shift_margin_min;
    let courts = core.store.courts.clone();
    let synced = core.clock.synced;
    let end = core.clock.end_min;
    drop(core);
    let shifts = courts.as_ref().map(|c| c.shifts.clone()).unwrap_or_default();
    let on_duty = |judge: &str| -> Label {
        if !synced {
            Label { text: "Sin reloj del partido", tone: "tone-muted" }
        } else if can_sign(&shifts, judge, now, margin) {
            Label { text: "De turno: puede firmar", tone: "tone-ok" }
        } else if shift_at(&shifts, judge, now).is_some() {
            Label { text: "Cerrando turno", tone: "tone-warn" }
        } else {
            Label { text: "Fuera de turno", tone: "tone-muted" }
        }
    };
    let body = html! {
        (page_header(
            "Juzgados y turnos",
            "Quién puede firmar en cada momento del partido. Al cambio de turno lo pendiente pasa al juez entrante; el saliente deja de firmar unos segundos antes.",
            html! { @if session.role == Role::Admin { a class="button" href="/admin/users?role=judge" { "Cuentas de jueces" } } },
        ))
        (tabs)
        span hidden data-match-key=(m.key) {}
        @match &courts {
            None => { p class="hint" { "Todavía no hay conexión con el partido: los juzgados aparecen al conectarse." } }
            Some(courts) => {
                @for court in &courts.courts {
                    section class="panel" aria-labelledby={ "court-" (court.id) } {
                        h2 id={ "court-" (court.id) } { (court.name) }
                        @if !court.jurisdiction.is_empty() { p class="hint" { (court.jurisdiction) } }
                        div class="table-wrap" role="region" aria-label={ "Jueces de " (court.name) } tabindex="0" {
                            table {
                                thead { tr {
                                    th scope="col" { "Juez" }
                                    th scope="col" { "Turno" }
                                    th scope="col" { "Ahora" }
                                    th scope="col" { "Cuenta en Strack" }
                                } }
                                tbody {
                                    @for judge in &court.judges {
                                        tr {
                                            th scope="row" { (judge.name) }
                                            td {
                                                (courts.shifts.iter().filter(|s| s.judge_id == judge.id)
                                                    .map(|s| labels::shift(s.from_min, s.until_min, end))
                                                    .collect::<Vec<_>>().join(" · "))
                                            }
                                            td { (status(on_duty(&judge.id))) }
                                            td {
                                                @match accounts.iter().find(|(j, _)| *j == judge.id) {
                                                    Some((_, user)) => {
                                                        @if session.role == Role::Admin {
                                                            a href={ "/admin/users/" (user) } { "@" (user) }
                                                        } @else { "@" (user) }
                                                    }
                                                    None => {
                                                        @if session.role == Role::Admin {
                                                            a href="/admin/users/new" { "Crear cuenta" }
                                                        } @else { span class="hint" { "Sin cuenta" } }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Html(page("Juzgados y turnos", Some(&session), Nav::Courts, body).into_string()).into_response()
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    q: Option<String>,
    event: Option<String>,
    page: Option<usize>,
    partido: Option<String>,
}

const AUDIT_PAGE: usize = 50;

pub async fn audit_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<AuditQuery>) -> Response {
    let session = match logged_in(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let m = app.match_or_primary(q.partido.as_deref()).clone();
    let tabs = match_tabs(&app.match_list(), &m.key, "/ops/audit?");
    let path = m.audit_path();
    let entries = read_entries(&path).unwrap_or_default();
    let report = verify_file(&path).ok();
    let core = m.core();
    let store = &core.store;
    let events: BTreeSet<String> = entries.iter().map(|e| e.event.clone()).collect();
    let search = q.q.clone().unwrap_or_default().trim().to_lowercase();
    let event = q.event.clone().unwrap_or_default();
    let shown: Vec<_> = entries
        .iter()
        .rev()
        .filter(|e| event.is_empty() || e.event == event)
        .filter(|e| {
            search.is_empty()
                || e.actor.to_lowercase().contains(&search)
                || e.event.contains(&search)
                || e.data.to_string().to_lowercase().contains(&search)
        })
        .collect();
    let total = shown.len();
    let page_no = q.page.unwrap_or(1).max(1).min(total.div_ceil(AUDIT_PAGE).max(1));
    let rows = shown.iter().skip((page_no - 1) * AUDIT_PAGE).take(AUDIT_PAGE);
    let base = format!("/ops/audit?partido={}&q={}&event={}&", m.key, query_value(&search), query_value(&event));
    let chain = match &report {
        Some(r) if r.problem.is_none() => Label { text: "Íntegra", tone: "tone-ok" },
        Some(_) => Label { text: "Alterada", tone: "tone-danger" },
        None => Label { text: "Sin archivo", tone: "tone-muted" },
    };
    let body = html! {
        (page_header(
            "Registro de auditoría",
            "Cada paso de la plataforma, encadenado por hashes: cualquier cambio posterior rompe la cadena.",
            html! { a class="button" href={ "/api/audit?partido=" (m.key) } { "Descargar registro" } },
        ))
        (tabs)
        span hidden data-match-key=(m.key) {}
        dl class="kpis" {
            div class="kpi" { dt class="kpi-label" { "Entradas" } dd class="kpi-value" { (entries.len()) } }
            div class="kpi" { dt class="kpi-label" { "Cadena" } dd class="kpi-value kpi-text" { (status(chain)) } }
            div class="kpi wide" { dt class="kpi-label" { "Último hash" } dd class="kpi-value kpi-text mono" { (entries.last().map(|e| e.hash.clone()).unwrap_or_default()) } }
        }
        form class="toolbar" method="get" action="/ops/audit" role="search" {
            input type="hidden" name="partido" value=(m.key);
            div class="toolbar-field grow" {
                label for="a-q" class="visually-hidden" { "Buscar en el registro" }
                input type="search" id="a-q" name="q" value=(search) placeholder="Buscar por actor, expediente, usuario…";
            }
            div class="toolbar-field" {
                label for="a-event" class="visually-hidden" { "Evento" }
                select id="a-event" name="event" data-autosubmit {
                    option value="" { "Todos los eventos" }
                    @for e in &events { option value=(e) selected[*e == event] { (labels::audit_event(e)) } }
                }
            }
            button class="button" type="submit" { "Filtrar registro" }
            @if !search.is_empty() || !event.is_empty() { a class="button ghost" href={ "/ops/audit?partido=" (m.key) } { "Limpiar filtros" } }
        }
        div class="table-wrap" role="region" aria-label="Registro de auditoría" tabindex="0" {
            table {
                caption { (total) " entradas" @if total != entries.len() { " de " (entries.len()) } }
                thead { tr {
                    th scope="col" class="num" { "#" }
                    th scope="col" { "Cuándo" }
                    th scope="col" class="num" { "Partido" }
                    th scope="col" { "Quién" }
                    th scope="col" { "Evento" }
                    th scope="col" { "Detalle" }
                    th scope="col" { "Hash" }
                } }
                tbody {
                    @if total == 0 { tr { td colspan="7" class="hint" { "Ninguna entrada coincide con el filtro." } } }
                    @for e in rows {
                        tr {
                            th scope="row" class="num" { (e.seq) }
                            td { (when(&e.at)) }
                            td class="num" { (e.match_min.map(minute).unwrap_or_else(|| "—".into())) }
                            td { (labels::actor(store, &e.actor)) }
                            td { (labels::audit_event(&e.event)) }
                            td class="data-cell" { (summary(store, &e.data)) }
                            td class="mono" { (e.hash[..12].to_string()) "…" }
                        }
                    }
                }
            }
        }
        (pager(&base, page_no, AUDIT_PAGE, total))
    };
    drop(core);
    Html(page("Auditoría", Some(&session), Nav::Audit, body).into_string()).into_response()
}

/// The identifying fields of an entry in words, short enough for a table cell.
fn summary(store: &crate::model::Store, data: &serde_json::Value) -> String {
    const KEYS: [&str; 10] = [
        "case_id",
        "order_id",
        "claim_id",
        "trace_id",
        "username",
        "platform_id",
        "provider_id",
        "client",
        "status",
        "reason",
    ];
    let parts: Vec<String> = KEYS
        .iter()
        .filter_map(|k| {
            let v = data.get(*k).filter(|v| !v.is_null())?;
            let text = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            Some(match *k {
                "order_id" => format!("orden {text}"),
                "claim_id" => format!("reclamo {text}"),
                "trace_id" => format!("rastreo {text}"),
                "username" => format!("@{text}"),
                "platform_id" => format!("plataforma {text}"),
                "provider_id" => store.provider(&text).map_or(text, |p| p.name.clone()),
                "client" => format!("abonado {text}"),
                "reason" => format!("motivo: {text}"),
                _ => text,
            })
        })
        .take(3)
        .collect();
    parts.join(" · ")
}
