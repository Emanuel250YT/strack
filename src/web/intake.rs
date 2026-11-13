//! Loading pirate streams: the "Cargar sitios" page for prosecutors and rights holders, and the
//! intake API (`POST /api/detections`) for monitoring tools. Both feed `engine::ingest`, the same
//! path as the live feed.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Form;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine;
use maud::{Markup, html};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::{App, MatchRun};
use crate::crypto::{constant_time_eq, sha256_hex};
use crate::engine::ingest;
use crate::intake::{self, Item, ItemError, MAX_ITEMS, ORIGIN_API, ORIGIN_MANUAL, Parsed};
use crate::judges::{Role, Session};
use crate::leak::read::{MarkReading, read_mark};
use crate::leak::trace::{self, TraceStatus};
use crate::model::CaseStatus;
use crate::web::labels;
use crate::web::layout::{Nav, page};
use crate::web::ops::MatchQuery;
use crate::web::ui::page_header;
use crate::web::views::status;
use crate::web::{csrf_ok, current_session, error_page};
use crate::workflow::{Ingest, url_host};

const EXAMPLE: &str = "https://s1.pelotaya.test/hls/en-vivo/index.m3u8, LP26-PRA-OFI-S048211\n\
                       https://live.golazo-libre.test/hls/en-vivo/index.m3u8, LP26-PRA-OFI-S077310, https://golazo-libre.test/partido";

#[derive(Deserialize)]
pub struct IntakeForm {
    csrf: String,
    partido: Option<String>,
    streams: String,
    /// Also read each stream for a licensed platform's session mark (leak tracing).
    rastrear: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct IntakeQuery {
    partido: Option<String>,
    /// `1`: also start a leak trace for every loaded stream.
    rastrear: Option<String>,
}

/// Starts leak tracing for every loaded stream that is not being read already, linked to its case
/// when one opened or took it (a page address gets one trace per video found in it). Returns the
/// trace ids, comma separated, in the same order.
async fn start_traces(app: &Arc<App>, results: &[(Item, Loaded)], actor: &str) -> Vec<Option<String>> {
    let mut out = Vec::with_capacity(results.len());
    for (item, loaded) in results {
        let watching = app.core().store.traces.iter().any(|t| {
            (t.url == item.stream_url || t.page_url.as_deref() == Some(item.stream_url.as_str()))
                && t.status == TraceStatus::Watching
        });
        if watching {
            out.push(None);
            continue;
        }
        let case = match loaded {
            Loaded::Created(id) | Loaded::Attached(id) => Some(id.clone()),
            _ => None,
        };
        out.push(trace::start_from(app, item.stream_url.clone(), case, actor).await.ok().map(|ids| ids.join(", ")));
    }
    out
}

/// How long Strack reads a loaded stream for a licensed platform's mark before it opens the case
/// without one.
const READ_LIMIT: Duration = Duration::from_secs(45);

/// What happened to one loaded stream.
enum Loaded {
    Created(String),
    Attached(String),
    Duplicate,
    /// No watermark was given: Strack is reading it from the stream and opens the case when done.
    Reading,
    Failed(&'static str),
}

#[allow(clippy::result_large_err)]
fn loader_session(app: &App, headers: &HeaderMap) -> Result<Session, Response> {
    let Some(session) = current_session(app, headers) else {
        return Err(Redirect::to("/login").into_response());
    };
    if session.role == Role::Judge {
        return Err(error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "Solo para operaciones",
            "Los sitios los cargan la fiscalía o el titular de derechos; el juez los revisa en su panel.",
        ));
    }
    Ok(session)
}

/// Ingests each stream into `m`. A stream given without a watermark is read first, in the
/// background (`read_then_load`): its case opens once Strack has looked for the mark.
async fn load(
    app: &Arc<App>,
    m: &Arc<MatchRun>,
    items: Vec<Item>,
    origin: &'static str,
    by: Option<&str>,
) -> Vec<(Item, Loaded)> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if m.core().store.match_info.is_none() {
            out.push((item, Loaded::Failed("match_not_ready")));
            continue;
        }
        if item.watermark.is_none() {
            if !crate::leak::source::readable_target(&item.stream_url, app.settings.allow_private_streams).await {
                out.push((item, Loaded::Failed("address_not_allowed")));
                continue;
            }
            tokio::spawn(read_then_load(app.clone(), m.clone(), item.clone(), origin, by.map(str::to_string)));
            out.push((item, Loaded::Reading));
            continue;
        }
        let loaded = load_one(app, m, item.clone(), origin, by).await;
        out.push((item, loaded));
    }
    m.persist();
    out
}

/// The stream server's IP: the host itself when it is an address, else passive DNS, else what the
/// resolver answers.
async fn server_ip(m: &MatchRun, host: &str) -> Result<Option<String>, &'static str> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(Some(host.to_string()));
    }
    match m.sim.dns_by_domain(host).await {
        Ok(Some(found)) => {
            if let Some(ip) = found.ips.first() {
                return Ok(Some(ip.ip.clone()));
            }
        }
        Ok(None) => {}
        Err(_) => return Err("dns_unavailable"),
    }
    let resolved = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 80))).await;
    Ok(resolved.ok().and_then(Result::ok).and_then(|mut addrs| addrs.find(|a| a.is_ipv4())).map(|a| a.ip().to_string()))
}

/// Resolves one stream's server and ingests it into `m`.
async fn load_one(app: &Arc<App>, m: &Arc<MatchRun>, item: Item, origin: &str, by: Option<&str>) -> Loaded {
    let ip = match &item.ip {
        Some(ip) => Some(ip.clone()),
        None => match server_ip(m, &item.host).await {
            Ok(ip) => ip,
            Err(code) => return Loaded::Failed(code),
        },
    };
    let Some(ip) = ip else {
        return Loaded::Failed("server_unknown");
    };
    let (id, minute) = {
        let mut core = m.core();
        core.store.intake_seq += 1;
        core.store.dirty = true;
        (format!("M-{:04}", core.store.intake_seq), core.now())
    };
    let raw = intake::detection(&item, &id, minute, &ip, origin, by);
    let actor = crate::workflow::detection_actor(&raw);
    match ingest(app, m, raw, &actor).await {
        Ok(Some(Ingest::Created(case))) => Loaded::Created(case),
        Ok(Some(Ingest::Attached(case))) => Loaded::Attached(case),
        Ok(Some(Ingest::Duplicate)) => Loaded::Duplicate,
        Ok(None) => Loaded::Failed("invalid_stream_url"),
        Err(_) => Loaded::Failed("dns_unavailable"),
    }
}

/// Reads a stream loaded without a watermark for a licensed platform's session mark, turns what it
/// finds into the case's watermark and capture evidence, and then ingests it. Nothing is sent to the
/// platform here: tracing the account is a separate, explicit choice ("Rastrear").
async fn read_then_load(app: Arc<App>, m: Arc<MatchRun>, mut item: Item, origin: &'static str, by: Option<String>) {
    let actor = by.clone().unwrap_or_else(|| origin.to_string());
    match read_mark(&app, &item.stream_url, READ_LIMIT).await {
        Ok(Some(reading)) => apply_reading(&app, &m, &mut item, reading, &actor),
        Ok(None) => {
            m.core().record(&actor, "intake_mark_not_found", json!({ "stream_url": item.stream_url }));
        }
        Err(e) => {
            tracing::warn!(error = %e, url = %item.stream_url, "could not read a loaded stream");
            m.core().record(&actor, "intake_stream_unreadable", json!({ "stream_url": item.stream_url }));
        }
    }
    let stream_url = item.stream_url.clone();
    let loaded = load_one(&app, &m, item, origin, by.as_deref()).await;
    let (result, case_id) = match &loaded {
        Loaded::Created(id) => ("created", Some(id.clone())),
        Loaded::Attached(id) => ("attached", Some(id.clone())),
        Loaded::Duplicate => ("duplicate", None),
        Loaded::Reading => ("reading", None),
        Loaded::Failed(code) => (*code, None),
    };
    m.core().record(
        &actor,
        "intake_read_loaded",
        json!({ "stream_url": stream_url, "result": result, "case_id": case_id }),
    );
    m.persist();
    app.persist();
}

/// The watermark a reading proves: the prefix of the match's licensee whose platform put the mark
/// there plus the session, or the mark itself when no licensee of this match uses that platform
/// (then it is not this match's signal and the case cannot be approved).
fn apply_reading(app: &App, m: &MatchRun, item: &mut Item, reading: MarkReading, actor: &str) {
    let platform = app.platforms().find_by_code(reading.mark.platform).map(|p| p.id.clone());
    let (licensee, minute) = {
        let core = m.core();
        let licensee = core
            .store
            .match_info
            .as_ref()
            .and_then(|info| info.licensees.iter().find(|l| platform.is_some() && l.platform == platform).cloned());
        (licensee, (core.now() * 1000.0).round() / 1000.0)
    };
    let watermark = match &licensee {
        Some(l) => format!("{}-S{}", l.watermark_prefix, reading.mark.session_hex().to_uppercase()),
        None => reading.mark.text(),
    };
    if reading.stream_url != item.stream_url {
        if let Some(host) = url_host(&reading.stream_url) {
            item.host = host;
        }
        item.page = item.page.take().or(reading.page_url.clone());
        item.stream_url = reading.stream_url.clone();
    }
    let frame_sha256 = sha256_hex(&reading.frame);
    item.watermark = Some(watermark.clone());
    item.extra.insert(
        "captura".into(),
        json!({
            "capturada_min": minute,
            "formato": "jpeg",
            "duracion_seg": 0,
            "contenido_b64": base64::engine::general_purpose::STANDARD.encode(&reading.frame),
        }),
    );
    item.extra.insert(
        "marca_leida".into(),
        json!({ "marca": reading.mark.text(), "plataforma": platform, "formato": reading.format.label() }),
    );
    m.core().record(
        actor,
        "intake_mark_read",
        json!({
            "stream_url": item.stream_url,
            "page_url": reading.page_url,
            "platform": platform,
            "licensee": licensee.map(|l| l.name),
            "mark": reading.mark.text(),
            "watermark": watermark,
            "frame_sha256": frame_sha256,
        }),
    );
}

fn form_markup(app: &App, session: &Session, current: &str, text: &str, errors: &[(usize, ItemError)]) -> Markup {
    let matches = app.match_list();
    html! {
        (page_header(
            "Cargar sitios",
            "Para la fiscalía o el titular de derechos: cargá uno o varios streams piratas. Strack identifica el servidor, \
             verifica la marca de agua y abre un expediente por cada stream nuevo; los que ya estaban se suman a su expediente.",
            html! { a class="button" href={ "/ops?partido=" (current) } { "Volver a operaciones" } },
        ))
        span hidden data-match-key=(current) {}
        @if !errors.is_empty() {
            div class="notice danger" role="alert" {
                p { "Revisá estas líneas:" }
                ul class="plain" {
                    @for (line, e) in errors {
                        li { @if *line > 0 { "Línea " (line) ": " } (labels::intake_error(e.code())) }
                    }
                }
            }
        }
        form class="panel form-grid" method="post" action="/ops/intake" data-once {
            input type="hidden" name="csrf" value=(session.csrf);
            @if matches.len() > 1 {
                label for="in-match" { "Partido" }
                select id="in-match" name="partido" {
                    @for (key, label) in &matches { option value=(key) selected[key == current] { (label) } }
                }
            } @else {
                input type="hidden" name="partido" value=(current);
            }
            label for="in-streams" { "Streams" }
            p class="hint" id="in-streams-hint" {
                "Uno por línea: la dirección del stream y, separados por comas, la marca de agua que leyó tu herramienta, "
                "la página del reproductor y la IP del servidor si la conocés. También acepta el JSON del feed de detecciones. "
                "Hasta " (MAX_ITEMS) " por vez."
            }
            textarea id="in-streams" name="streams" rows="10" required aria-describedby="in-streams-hint"
                placeholder=(EXAMPLE) spellcheck="false" { (text) }
            div class="file-field" hidden data-file-field {
                label for="in-file" { "O subí un archivo (CSV, TXT o JSON)" }
                input type="file" id="in-file" accept=".csv,.txt,.json,text/csv,text/plain,application/json" data-file-into="in-streams";
            }
            label class="check-field" for="in-trace" {
                input type="checkbox" id="in-trace" name="rastrear" value="1";
                span {
                    "Rastrear también la cuenta de origen. "
                    span class="hint" { "Strack lee cada stream y, si lleva la marca de una plataforma con licencia, le avisa para que suspenda la cuenta." }
                }
            }
            div class="form-actions" {
                button class="button primary" type="submit" { "Cargar y armar expedientes" }
            }
        }
        details class="panel tech" {
            summary { "Integración por API para herramientas de monitoreo" }
            p {
                "Enviá " span class="mono" { "POST /api/detections?partido=" (current) } " con la cabecera "
                span class="mono" { "Authorization: Bearer <token>" } " y un objeto o una lista en el formato del feed "
                "(" span class="mono" { "stream_url" } ", " span class="mono" { "marca_de_agua_extraida" } ", "
                span class="mono" { "pagina" } ", " span class="mono" { "ip_servidor" } ", "
                span class="mono" { "captura" } ", " span class="mono" { "promocion" } "). "
                "El token lo configura la administración de Strack."
            }
        }
    }
}

pub async fn intake_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<MatchQuery>) -> Response {
    let session = match loader_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let current = app.match_or_primary(q.partido.as_deref()).key.clone();
    let body = form_markup(&app, &session, &current, "", &[]);
    Html(page("Cargar sitios", Some(&session), Nav::Intake, body).into_string()).into_response()
}

fn result_row(m: &MatchRun, item: &Item, loaded: &Loaded, trace_id: Option<&str>, traced: bool) -> Markup {
    let case_status = |id: &str| m.core().store.case(id).map(|c| (c.status, c.evidence.watermark.verdict));
    html! {
        tr {
            th scope="row" class="num" { (item.line) }
            td { span class="mono" { (item.host) } br; span class="hint mono" { (item.stream_url) } }
            td {
                @match loaded {
                    Loaded::Created(id) => {
                        @match case_status(id) {
                            Some((CaseStatus::Dismissed, verdict)) => {
                                (status(labels::Label { text: "Descartado", tone: "tone-muted" }))
                                br; span class="hint" { (labels::watermark_meaning(verdict)) "." }
                            }
                            _ => { (status(labels::Label { text: "Expediente nuevo: espera al juez", tone: "tone-ok" })) }
                        }
                    }
                    Loaded::Attached(_) => { (status(labels::Label { text: "Ya tenía expediente: se sumó", tone: "tone-info" })) }
                    Loaded::Duplicate => { (status(labels::Label { text: "Ya estaba cargado", tone: "tone-muted" })) }
                    Loaded::Reading => {
                        (status(labels::Label { text: "Leyendo la marca de agua del stream", tone: "tone-info" }))
                        br; span class="hint" { "El expediente aparece en Operaciones en cuanto termina la lectura (menos de un minuto)." }
                    }
                    Loaded::Failed(code) if trace_id.is_some() => {
                        (status(labels::Label { text: "Se rastrea la cuenta de origen", tone: "tone-info" }))
                        br; span class="hint" { "Sin expediente de bloqueo: " (labels::intake_error(code).to_lowercase()) }
                    }
                    Loaded::Failed(code) => {
                        (status(labels::Label { text: "No se cargó", tone: "tone-danger" }))
                        br; span class="hint" { (labels::intake_error(code)) }
                    }
                }
            }
            td {
                @match loaded {
                    Loaded::Created(id) | Loaded::Attached(id) => { a href={ "/ops/cases/" (id) } { (id) } }
                    _ => { "—" }
                }
            }
            @if traced {
                td {
                    @match trace_id {
                        Some(ids) => { @for (i, id) in ids.split(", ").enumerate() { @if i > 0 { ", " } a href={ "/ops/traces/" (id) } { (id) } } }
                        None => { span class="hint" { "Ya se estaba leyendo, o la página no tiene video" } }
                    }
                }
            }
        }
    }
}

pub async fn intake_submit(State(app): State<Arc<App>>, headers: HeaderMap, Form(form): Form<IntakeForm>) -> Response {
    let session = match loader_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let m = app.match_or_primary(form.partido.as_deref()).clone();
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("/ops/intake?partido={}&error=csrf", m.key)).into_response();
    }
    let Parsed { items, errors } = intake::parse_text(&form.streams);
    if items.is_empty() {
        let body = form_markup(&app, &session, &m.key, &form.streams, &errors);
        let html = page("Cargar sitios", Some(&session), Nav::Intake, body).into_string();
        return (StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response();
    }
    let results = load(&app, &m, items, ORIGIN_MANUAL, Some(&session.username)).await;
    let traced = form.rastrear.as_deref() == Some("1");
    let traces = if traced { start_traces(&app, &results, &session.username).await } else { vec![None; results.len()] };
    let created = results.iter().filter(|(_, l)| matches!(l, Loaded::Created(_))).count();
    let attached = results.iter().filter(|(_, l)| matches!(l, Loaded::Attached(_))).count();
    let failed = results.iter().filter(|(_, l)| matches!(l, Loaded::Failed(_))).count() + errors.len();
    let reading = results.iter().filter(|(_, l)| matches!(l, Loaded::Reading)).count();
    let label = m.label();
    let body = html! {
        (page_header(
            "Carga terminada",
            &format!("{label}: {} streams cargados.", results.len()),
            html! {
                a class="button" href={ "/ops/intake?partido=" (m.key) } { "Cargar más" }
                a class="button primary" href={ "/ops?partido=" (m.key) } { "Ver operaciones" }
            },
        ))
        span hidden data-match-key=(m.key) {}
        dl class="kpis" {
            div class="kpi" { dt { "Expedientes nuevos" } dd { (created) } }
            div class="kpi" { dt { "Se sumaron a uno existente" } dd { (attached) } }
            @if reading > 0 { div class="kpi" { dt { "Leyendo la marca" } dd { (reading) } } }
            div class="kpi" { dt { "Con problemas" } dd { (failed) } }
        }
        @if !errors.is_empty() {
            div class="notice warn" role="status" {
                p { "Estas líneas no se cargaron:" }
                ul class="plain" {
                    @for (line, e) in &errors {
                        li { @if *line > 0 { "Línea " (line) ": " } (labels::intake_error(e.code())) }
                    }
                }
            }
        }
        div class="table-wrap" role="region" aria-label="Resultado de la carga" tabindex="0" {
            table {
                caption { "Resultado de cada stream" }
                thead { tr {
                    th scope="col" class="num" { "Línea" }
                    th scope="col" { "Stream" }
                    th scope="col" { "Resultado" }
                    th scope="col" { "Expediente" }
                    @if traced { th scope="col" { "Rastreo" } }
                } }
                tbody {
                    @for ((item, loaded), trace_id) in results.iter().zip(&traces) {
                        (result_row(&m, item, loaded, trace_id.as_deref(), traced))
                    }
                }
            }
        }
    };
    Html(page("Carga terminada", Some(&session), Nav::Intake, body).into_string()).into_response()
}

fn api_error(code: StatusCode, error: &str) -> Response {
    (code, Json(json!({ "error": error }))).into_response()
}

/// `POST /api/detections[?partido=<n>]` with `Authorization: Bearer <token>`: one detection or a
/// list, in the feed's format.
pub async fn intake_api(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(q): Query<IntakeQuery>,
    body: Bytes,
) -> Response {
    let Some(token) = app.settings.intake_token.as_deref() else {
        return api_error(StatusCode::NOT_FOUND, "intake_disabled");
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_eq(presented, token) {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "unreadable_json");
    };
    let m = match q.partido.as_deref() {
        Some(key) => match app.match_run(key) {
            Some(m) => m.clone(),
            None => return api_error(StatusCode::NOT_FOUND, "unknown_match"),
        },
        None => app.primary().clone(),
    };
    let Parsed { items, errors } = intake::parse_json(&value);
    let results = load(&app, &m, items, ORIGIN_API, None).await;
    let traces = if q.rastrear.as_deref() == Some("1") {
        start_traces(&app, &results, "api").await
    } else {
        vec![None; results.len()]
    };
    let results: Vec<Value> = results
        .iter()
        .zip(&traces)
        .map(|((item, loaded), trace_id)| {
            let (state, case, error) = match loaded {
                Loaded::Created(id) => ("created", Some(id.as_str()), None),
                Loaded::Attached(id) => ("attached", Some(id.as_str()), None),
                Loaded::Duplicate => ("duplicate", None, None),
                Loaded::Reading => ("reading", None, None),
                Loaded::Failed(code) => ("failed", None, Some(*code)),
            };
            json!({ "index": item.line, "stream_url": item.stream_url, "result": state, "case_id": case, "error": error,
                    "trace_id": trace_id })
        })
        .collect();
    let errors: Vec<Value> =
        errors.iter().map(|(line, e)| json!({ "index": line, "result": "rejected", "error": e.code() })).collect();
    Json(json!({ "partido": m.key, "results": results, "rejected": errors })).into_response()
}
