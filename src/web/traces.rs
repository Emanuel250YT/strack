//! Leak tracing pages: start a trace on a pirate stream, follow it live, see the evidence frames.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;

use crate::app::App;
use crate::audit::read_entries;
use crate::demo::clock_time;
use crate::judges::Session;
use crate::leak::trace::{self, Leak, NoticeStatus, Trace, TraceStatus, frames_dir};
use crate::model::Store;
use crate::web::labels;
use crate::web::layout::{Nav, page};
use crate::web::views::{flash, status};
use crate::web::{csrf_ok, current_session, error_page};

const MAX_URL: usize = 500;

#[derive(Deserialize)]
pub struct FlashQuery {
    msg: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct StartForm {
    csrf: String,
    url: String,
    case_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

#[allow(clippy::result_large_err)]
fn session_or_login(app: &App, headers: &HeaderMap) -> Result<Session, Response> {
    current_session(app, headers).ok_or_else(|| Redirect::to("/login").into_response())
}

fn secs(value: Option<f64>) -> String {
    match value {
        Some(s) if s < 1.0 => format!("{} ms", ((s * 1000.0).round() as u64).max(1)),
        Some(s) => format!("{s:.1} s"),
        None => "—".into(),
    }
}

fn suspended(t: &Trace) -> usize {
    t.leaks.iter().filter(|l| l.notice.status == NoticeStatus::Acknowledged).count()
}

fn list_markup(store: &Store) -> Markup {
    html! {
        @if store.traces.is_empty() {
            p { "Todavía no se rastreó ningún stream." }
        } @else {
            div class="table-wrap" role="region" aria-label="Rastreos" tabindex="0" {
                table {
                    caption { "Rastreos (" (store.traces.len()) ")" }
                    thead { tr {
                        th scope="col" { "Rastreo" }
                        th scope="col" { "Stream pirata" }
                        th scope="col" { "Estado" }
                        th scope="col" class="num" { "Cuentas identificadas" }
                        th scope="col" class="num" { "Cuentas suspendidas" }
                        th scope="col" { "Inicio" }
                    } }
                    tbody {
                        @for t in store.traces.iter().rev() {
                            tr {
                                th scope="row" { a href={ "/ops/traces/" (t.id) } { (t.id) } }
                                td class="mono" { (t.url) }
                                td { (status(labels::trace_status(t))) }
                                td class="num" { (t.leaks.len()) }
                                td class="num" { (suspended(t)) }
                                td { (clock_time(&t.started_at)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn list_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let session = match session_or_login(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let (list, version) = {
        let core = app.core();
        (list_markup(&core.store), core.store.inbox_version)
    };
    let platforms: Vec<String> = app.platforms().platforms.iter().map(|p| p.name.clone()).collect();
    let body = html! {
        h1 { "Rastreo de origen" }
        p class="lede" {
            "Las plataformas licenciatarias esconden en su señal una marca por sesión: una marca de agua invisible "
            "(variaciones de brillo de 2 niveles sobre 255 que solo detecta un programa) y una copia como metadato de cada "
            "cuadro. Indica la plataforma, el abonado y la sesión. Strack la lee en el stream pirata, identifica la cuenta "
            "que lo filtra y avisa a la plataforma, que la suspende. El stream se corta en el origen, sin bloquear ninguna "
            "IP ni dominio."
        }
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        section class="panel" aria-labelledby="start-title" {
            h2 id="start-title" { "Rastrear un stream pirata" }
            form method="post" action="/ops/traces" class="form-grid" data-once {
                input type="hidden" name="csrf" value=(session.csrf);
                div {
                    label for="url" { "Dirección del stream o de la página pirata" }
                    input type="url" id="url" name="url" required maxlength=(MAX_URL)
                        placeholder="http://127.0.0.1:8200/stream.mjpg" aria-describedby="url-hint";
                    p class="hint" id="url-hint" {
                        "Acepta MJPEG, HLS (.m3u8), DASH (.mpd), MP4, MPEG-TS, WebM y RTMP. Si pegás la página donde se ve el partido, "
                        "Strack busca el video en ella (también dentro de reproductores embebidos) y rastrea cada stream que encuentra. "
                        "La marca se lee comparando cuadros de un segundo de diferencia; se lee hasta que se detenga, el stream caiga "
                        "o pasen 4 horas."
                    }
                }
                div {
                    label for="case_id" { "Expediente relacionado (opcional)" }
                    input type="text" id="case_id" name="case_id" maxlength="40" placeholder="EXP-2026-000001";
                }
                div { button class="button primary" type="submit" { "Empezar a rastrear" } }
            }
            p class="hint" {
                @if platforms.is_empty() {
                    "No hay plataformas registradas para recibir avisos (config/platforms.json): se identifica la cuenta pero no se avisa."
                } @else {
                    "Plataformas que reciben avisos: " (platforms.join(", ")) "."
                }
            }
        }
        h2 { "Rastreos" }
        div data-refresh="/ops/traces/fragment" data-version=(version) data-interval="3000" { (list) }
    };
    Html(page("Rastreo de origen", Some(&session), Nav::Traces, body).into_string()).into_response()
}

pub async fn list_fragment(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let core = app.core();
    let version = core.store.inbox_version.to_string();
    ([("x-version", version)], Html(list_markup(&core.store).into_string())).into_response()
}

pub async fn start(State(app): State<Arc<App>>, headers: HeaderMap, Form(form): Form<StartForm>) -> Response {
    let session = match session_or_login(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/ops/traces?error=csrf").into_response();
    }
    let url = form.url.trim().to_string();
    let valid = url.len() <= MAX_URL
        && reqwest::Url::parse(&url)
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https" | "rtmp" | "rtmps") && u.host().is_some());
    if !valid {
        return Redirect::to("/ops/traces?error=invalid_url").into_response();
    }
    let case_id = form.case_id.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    if let Some(id) = &case_id {
        if app.match_of_case(id).is_none() {
            return Redirect::to("/ops/traces?error=case_not_found").into_response();
        }
    }
    match trace::start_from(&app, url, case_id, &session.username).await {
        Ok(ids) if ids.len() == 1 => Redirect::to(&format!("/ops/traces/{}?msg=trace_started", ids[0])).into_response(),
        Ok(_) => Redirect::to("/ops/traces?msg=traces_started_from_page").into_response(),
        Err(_) => Redirect::to("/ops/traces?error=no_video_in_page").into_response(),
    }
}

pub async fn stop(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match session_or_login(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("/ops/traces/{id}?error=csrf")).into_response();
    }
    trace::request_stop(&app, &id, &session.username);
    Redirect::to(&format!("/ops/traces/{id}?msg=trace_stopping")).into_response()
}

fn leak_card(t: &Trace, l: &Leak) -> Markup {
    let platform = l.platform_name.clone().unwrap_or_else(|| l.mark.platform_hex());
    html! {
        li class="card" {
            div class="card-head" {
                h3 { "Cuenta " span class="mono" { (l.mark.client_label()) } " de " (platform) }
                (status(labels::notice_status(l.notice.status)))
            }
            div class="leak" {
                figure class="frame" {
                    img src={ "/ops/traces/" (t.id) "/frames/" (l.n) } loading="lazy"
                        alt={ "Cuadro del stream pirata donde se leyó la marca de la cuenta " (l.mark.client_label()) };
                    figcaption {
                        "SHA-256 del cuadro: " span class="mono" { (l.frame_sha256) }
                        @if let Some(sha) = &l.pair_frame_sha256 {
                            br;
                            "La marca invisible se leyó comparándolo con "
                            a href={ "/ops/traces/" (t.id) "/frames/" (l.n) "-ref" } { "un cuadro de un segundo antes" }
                            " (SHA-256 " span class="mono" { (sha) } ")."
                        }
                    }
                }
                dl class="facts" {
                    dt { "Marca leída" } dd class="mono" { (l.mark_text) }
                    dt { "Dónde se leyó" } dd { (l.sources.iter().map(|s| labels::mark_source(*s)).collect::<Vec<_>>().join(" y ")) }
                    dt { "Sesión" } dd class="mono" { (l.mark.session_hex()) }
                    dt { "Vista" } dd { "por primera vez " (clock_time(&l.first_seen_at)) ", última " (clock_time(&l.last_seen_at)) " (" (l.sightings) (if l.sightings == 1 { " cuadro)" } else { " cuadros)" }) }
                    dt { "Aviso a la plataforma" } dd {
                        span class="mono" { (l.notice.notice_id) }
                        @if l.notice.attempts > 1 { " · " (l.notice.attempts) " intentos" }
                        @if let Some(at) = &l.notice.answered_at { " · respondió " (clock_time(at)) }
                        @if let Some(e) = &l.notice.error { br; span class="hint" { (labels::notice_error(e)) } }
                    }
                    @if let Some(ack) = &l.notice.ack {
                        dt { "Respuesta" } dd {
                            (if ack.status == "already_suspended" { "La cuenta ya estaba suspendida" } else { "Cuenta suspendida" })
                            " · sesiones cerradas: " (ack.sessions_closed)
                        }
                    }
                    dt { "Hasta la suspensión" } dd { (secs(l.ack_after_secs)) " desde que se leyó la marca" }
                    dt { "Fuente cortada" } dd {
                        @match &l.cut_confirmed_at {
                            Some(at) => { "Confirmado " (clock_time(at)) ": la marca ya no aparece en el stream pirata (" (secs(l.cut_after_secs)) ")" }
                            None if l.notice.status == NoticeStatus::Acknowledged => { "Esperando confirmación en el stream pirata" }
                            None => { "—" }
                        }
                    }
                }
            }
            @if l.seen_after_ack {
                p class="notice warn" role="status" { "La marca siguió apareciendo después de que la plataforma dijo que cerró la sesión." }
            }
        }
    }
}

fn detail_markup(t: &Trace) -> Markup {
    let first_ack = t.leaks.iter().filter_map(|l| l.ack_after_secs).reduce(f64::min);
    html! {
        dl class="kpis" {
            div class="kpi" { dt { "Stream" } dd class="kpi-text" { (labels::stream_state(t.stream).text) } }
            div class="kpi" { dt { "Cuadros leídos" } dd { (t.frames_read) } }
            div class="kpi" { dt { "Cuadros analizados" } dd { (t.frames_scanned) } }
            div class="kpi" { dt { "Cuentas identificadas" } dd { (t.leaks.len()) } }
            div class="kpi" { dt { "Cuentas suspendidas" } dd { (suspended(t)) } }
            div class="kpi" { dt { "Primera suspensión" } dd { (secs(first_ack)) } }
        }
        @if t.leaks.is_empty() {
            p { "Todavía no se leyó ninguna marca de sesión en este stream." }
        } @else {
            ul class="cards" { @for l in t.leaks.iter().rev() { (leak_card(t, l)) } }
        }
        @if let Some(e) = &t.last_error {
            @if t.stream == trace::StreamState::Down { p class="hint" { "Último error de conexión: " span class="mono" { (e) } } }
        }
    }
}

fn detail_version(t: &Trace, inbox: u64) -> String {
    format!("{inbox}-{}", t.frames_scanned / 8)
}

pub async fn detail_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let session = match session_or_login(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let entries = read_entries(&app.settings.audit_path()).unwrap_or_default();
    let core = app.core();
    let Some(t) = core.store.trace(&id) else {
        return error_page(StatusCode::NOT_FOUND, Some(&session), "Rastreo inexistente", "No existe ese rastreo.");
    };
    let trail: Vec<_> =
        entries.iter().filter(|e| e.data.get("trace_id").and_then(|v| v.as_str()) == Some(id.as_str())).collect();
    let body = html! {
        p class="breadcrumb" { a href="/ops/traces" { "← Volver a rastreos" } }
        h1 { "Rastreo " (t.id) }
        p class="lede" {
            (status(labels::trace_status(t))) " · " span class="mono" { (t.url) }
            @if let Some(format) = &t.format { " · " (format) }
            @if let Some(page_url) = &t.page_url { " · encontrado en " span class="mono" { (page_url) } }
            @if let Some(case_id) = &t.case_id { " · expediente " a href={ "/ops/cases/" (case_id) } { (case_id) } }
            " · iniciado por " (t.started_by) " a las " (clock_time(&t.started_at))
        }
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        @if t.status == TraceStatus::Watching && !t.stop_requested {
            form method="post" action={ "/ops/traces/" (t.id) "/stop" } data-once {
                input type="hidden" name="csrf" value=(session.csrf);
                button class="button" type="submit" { "Detener el rastreo" }
            }
        }
        div data-refresh={ "/ops/traces/" (t.id) "/fragment" } data-version=(detail_version(t, core.store.inbox_version)) data-interval="1500" {
            (detail_markup(t))
        }
        section class="panel" aria-labelledby="trail-title" {
            h2 id="trail-title" { "Registro de auditoría del rastreo" }
            div class="table-wrap" role="region" aria-label="Registro de auditoría del rastreo" tabindex="0" {
                table {
                    caption { (trail.len()) " entradas encadenadas al cargar la página" }
                    thead { tr {
                        th scope="col" class="num" { "#" }
                        th scope="col" { "Hora" }
                        th scope="col" { "Actor" }
                        th scope="col" { "Evento" }
                        th scope="col" { "Hash" }
                    } }
                    tbody {
                        @for e in &trail {
                            tr {
                                th scope="row" class="num" { (e.seq) }
                                td { (clock_time(&e.at)) }
                                td class="mono" { (e.actor) }
                                td class="mono" { (e.event) }
                                td class="mono" { (e.hash[..16].to_string()) "…" }
                            }
                        }
                    }
                }
            }
        }
    };
    let title = format!("Rastreo {}", t.id);
    Html(page(&title, Some(&session), Nav::Traces, body).into_string()).into_response()
}

pub async fn detail_fragment(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let core = app.core();
    let Some(t) = core.store.trace(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let version = detail_version(t, core.store.inbox_version);
    ([("x-version", version)], Html(detail_markup(t).into_string())).into_response()
}

/// `/ops/traces/{id}/frames/{n}` is the evidence frame, `{n}-ref` the watermark's reference frame.
pub async fn frame(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, which)): Path<(String, String)>,
) -> Response {
    if current_session(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (n, reference) = match which.strip_suffix("-ref") {
        Some(n) => (n, true),
        None => (which.as_str(), false),
    };
    let Ok(n) = n.parse::<u32>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The file name comes from the stored record, never from the request path.
    let file = {
        let core = app.core();
        let leak = core.store.trace(&id).and_then(|t| t.leak(n));
        match (leak, reference) {
            (Some(leak), false) => leak.frame_file.clone(),
            (Some(leak), true) => match &leak.pair_frame_file {
                Some(file) => file.clone(),
                None => return StatusCode::NOT_FOUND.into_response(),
            },
            (None, _) => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    match std::fs::read(frames_dir(&app, &id).join(file)) {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, "private, max-age=3600")], bytes)
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Leaks traced for a case, for the case pages.
pub fn case_leaks(store: &Store, case_id: &str) -> Markup {
    let traces: Vec<&Trace> = store.traces.iter().filter(|t| t.case_id.as_deref() == Some(case_id)).collect();
    if traces.is_empty() {
        return html! {};
    }
    html! {
        section class="panel" aria-labelledby="leaks-title" {
            h2 id="leaks-title" { "Origen de la filtración" }
            ul class="plain" {
                @for t in &traces {
                    @if t.leaks.is_empty() {
                        li { a href={ "/ops/traces/" (t.id) } { (t.id) } ": todavía sin marca de sesión leída." }
                    }
                    @for l in &t.leaks {
                        li {
                            "Cuenta " span class="mono" { (l.mark.client_label()) } " de "
                            (l.platform_name.clone().unwrap_or_else(|| l.mark.platform_hex())) ": "
                            (labels::notice_status(l.notice.status).text) " · "
                            a href={ "/ops/traces/" (t.id) } { "ver rastreo " (t.id) }
                        }
                    }
                }
            }
        }
    }
}
