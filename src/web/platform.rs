//! Portal for licensed platforms, the clients of the service: the accounts found leaking their
//! streams, the notices Strack sent and how the platform answered, a form to trace a pirate stream,
//! the integration settings and the integration guide.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use serde_json::json;

use crate::admin::{self, PlatformInput};
use crate::app::App;
use crate::judges::{Role, Session};
use crate::leak::mark::platform_code;
use crate::leak::platforms::{PlatformEntry, reaches_only_public};
use crate::leak::trace::{self, Leak, NoticeStatus, Trace};
use crate::web::admin::change_platforms;
use crate::web::labels;
use crate::web::layout::{Nav, page};
use crate::web::ui::{figure, figures, page_header, when};
use crate::web::views::{flash, status};
use crate::web::{csrf_ok, current_session, error_page};

const MAX_URL: usize = 2048;

#[derive(Deserialize, Default)]
pub struct PortalQuery {
    msg: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct TraceForm {
    csrf: String,
    url: String,
}

#[derive(Deserialize)]
pub struct IntegrationForm {
    csrf: String,
    api_url: String,
    notice_token: String,
}

#[allow(clippy::result_large_err)]
fn platform_session(app: &App, headers: &HeaderMap) -> Result<(Session, PlatformEntry), Response> {
    let Some(session) = current_session(app, headers) else {
        return Err(Redirect::to("/login").into_response());
    };
    if session.role != Role::Platform {
        return Err(error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "Solo para plataformas",
            "Este portal es para las plataformas con licencia que usan Strack.",
        ));
    }
    match session.platform_id.as_deref().and_then(|id| app.platforms().find(id).cloned()) {
        Some(entry) => Ok((session, entry)),
        None => Err(error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "Plataforma fuera del registro",
            "Tu plataforma ya no figura en el registro de Strack. Hablá con la administración.",
        )),
    }
}

/// Every leak of this platform's streams, newest first, with the trace it was found in.
fn my_leaks(traces: &[Trace], code: u16) -> Vec<(&Trace, &Leak)> {
    let mut rows: Vec<(&Trace, &Leak)> = traces
        .iter()
        .flat_map(|t| t.leaks.iter().filter(move |l| l.mark.platform == code).map(move |l| (t, l)))
        .collect();
    rows.sort_by(|a, b| b.1.first_seen_at.cmp(&a.1.first_seen_at));
    rows
}

fn notice_cell(leak: &Leak) -> Markup {
    html! {
        (status(labels::notice_status(leak.notice.status)))
        @if let Some(ack) = &leak.notice.ack {
            br; span class="hint" {
                (if ack.status == "already_suspended" { "Ya estaba suspendida" } else { "Suspendida" })
                " · " (ack.sessions_closed) (if ack.sessions_closed == 1 { " sesión cerrada" } else { " sesiones cerradas" })
            }
        }
        @if let Some(e) = &leak.notice.error { br; span class="hint" { (labels::notice_error(e)) } }
    }
}

pub async fn portal(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<PortalQuery>) -> Response {
    let (session, platform) = match platform_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let code = platform_code(&platform.id);
    let body = {
        let core = app.core();
        let leaks = my_leaks(&core.store.traces, code);
        let accounts: BTreeSet<u32> = leaks.iter().map(|(_, l)| l.mark.client).collect();
        let suspended = leaks.iter().filter(|(_, l)| l.notice.status == NoticeStatus::Acknowledged).count();
        let unanswered = leaks
            .iter()
            .filter(|(_, l)| matches!(l.notice.status, NoticeStatus::Failed | NoticeStatus::Rejected))
            .count();
        let mine: Vec<&Trace> = core.store.traces.iter().rev().filter(|t| t.started_by == session.username).collect();
        html! {
            (page_header(
                &platform.name,
                "Las cuentas de tu plataforma que aparecieron en copias piratas, los avisos que te mandó Strack y cómo quedaron.",
                html! { a class="button" href="/platform/guide" { "Guía de integración" } },
            ))
            (flash(q.msg.as_deref().or(q.error.as_deref())))
            (figures(html! {
                (figure("Cuentas identificadas", accounts.len(), Some("#leaks-title")))
                (figure("Suspendidas por tu plataforma", suspended, Some("#leaks-title")))
                (figure("Avisos sin confirmar", unanswered, Some("#leaks-title")))
                (figure("Rastreos que pediste", mine.len(), Some("#traces-title")))
            }))
            section class="panel" aria-labelledby="trace-title" {
                h2 id="trace-title" { "Rastrear un stream pirata" }
                p {
                    "Pegá la dirección de una copia pirata: el stream (MJPEG, HLS, DASH, MP4, RTMP…) o la página donde se ve. "
                    "Strack encuentra el video, lo lee y, si lleva la marca de tu plataforma, identifica la cuenta y te avisa."
                }
                form class="inline-form" method="post" action="/platform/traces" data-once {
                    input type="hidden" name="csrf" value=(session.csrf);
                    label for="pt-url" class="visually-hidden" { "Dirección del stream pirata" }
                    input type="url" id="pt-url" name="url" required maxlength=(MAX_URL) placeholder="https://sitio-pirata.example/partido-en-vivo";
                    button class="button primary" type="submit" { "Rastrear" }
                }
            }
            h2 id="leaks-title" { "Cuentas detectadas en copias piratas" }
            div class="table-wrap" role="region" aria-label="Cuentas detectadas" tabindex="0" {
                table {
                    caption { (leaks.len()) (if leaks.len() == 1 { " detección" } else { " detecciones" }) }
                    thead { tr {
                        th scope="col" { "Abonado" }
                        th scope="col" { "Sesión" }
                        th scope="col" { "Copia pirata" }
                        th scope="col" { "Vista" }
                        th scope="col" { "Aviso" }
                        th scope="col" { "Corte" }
                    } }
                    tbody {
                        @if leaks.is_empty() {
                            tr { td colspan="6" class="hint" { "Todavía no apareció ninguna cuenta tuya en una copia pirata." } }
                        }
                        @for (t, l) in &leaks {
                            tr {
                                th scope="row" class="mono" { (l.mark.client_label()) }
                                td class="mono" { (format!("{:08x}", l.mark.session)) }
                                td { span class="mono" { (t.url) } br; span class="hint" { (t.id) } }
                                td { (when(&l.first_seen_at)) br; span class="hint" { (l.sightings) " lecturas" } }
                                td { (notice_cell(l)) }
                                td {
                                    @match l.cut_after_secs {
                                        Some(secs) => { "Cortado a los " (labels::span(secs / 60.0)) }
                                        None => { span class="hint" { "—" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            h2 id="traces-title" { "Rastreos que pediste" }
            div class="table-wrap" role="region" aria-label="Rastreos que pediste" tabindex="0" {
                table {
                    thead { tr {
                        th scope="col" { "Rastreo" }
                        th scope="col" { "Stream" }
                        th scope="col" { "Formato" }
                        th scope="col" { "Estado" }
                        th scope="col" class="num" { "Cuentas tuyas" }
                    } }
                    tbody {
                        @if mine.is_empty() { tr { td colspan="5" class="hint" { "No pediste rastreos todavía." } } }
                        @for t in &mine {
                            tr {
                                th scope="row" class="mono" { (t.id) }
                                td {
                                    span class="mono" { (t.url) }
                                    @if let Some(page_url) = &t.page_url { br; span class="hint" { "en " (page_url) } }
                                }
                                td { (t.format.clone().unwrap_or_else(|| "—".into())) }
                                td { (status(labels::trace_status(t))) }
                                td class="num" { (t.leaks.iter().filter(|l| l.mark.platform == code).count()) }
                            }
                        }
                    }
                }
            }
            section class="panel" aria-labelledby="integration-title" {
                h2 id="integration-title" { "Integración" }
                dl class="facts" {
                    dt { "Identificador" } dd class="mono" { (platform.id) }
                    dt { "Código en la marca" } dd class="mono" { (format!("{code:04x}")) }
                    dt { "Ejemplo de marca" } dd class="mono" { "STK2|" (format!("{code:04x}")) "|42|1a2b3c4d" }
                    dt { "Dónde te avisamos" } dd class="mono" { (platform.api_url) "/api/notices" }
                }
                form method="post" action="/platform/integration" class="form-grid wide" data-once {
                    input type="hidden" name="csrf" value=(session.csrf);
                    div class="form-row" {
                        div {
                            label for="pi-url" { "Dirección de tu API" }
                            input type="url" id="pi-url" name="api_url" required maxlength="300" value=(platform.api_url)
                                aria-describedby="pi-url-hint";
                            p class="hint" id="pi-url-hint" { "Strack manda los avisos a esta dirección más /api/notices." }
                        }
                        div {
                            label for="pi-token" { "Token nuevo (opcional)" }
                            input type="password" id="pi-token" name="notice_token" autocomplete="off" minlength="16"
                                aria-describedby="pi-token-hint";
                            p class="hint" id="pi-token-hint" {
                                "El token que Strack presenta a tu API. Vacío deja el actual; si lo cambiás, actualizalo también en tu API."
                            }
                        }
                    }
                    div class="form-actions" { button class="button primary" type="submit" { "Guardar integración" } }
                }
            }
        }
    };
    Html(page(&platform.name, Some(&session), Nav::Portal, body).into_string()).into_response()
}

pub async fn start_trace(State(app): State<Arc<App>>, headers: HeaderMap, Form(form): Form<TraceForm>) -> Response {
    let (session, platform) = match platform_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/platform?error=csrf").into_response();
    }
    let url = form.url.trim().to_string();
    let valid = url.len() <= MAX_URL
        && reqwest::Url::parse(&url)
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https" | "rtmp" | "rtmps") && u.host().is_some());
    if !valid {
        return Redirect::to("/platform?error=invalid_url").into_response();
    }
    match trace::start_from(&app, url, None, &session.username).await {
        Ok(ids) => {
            tracing::info!(traces = ?ids, platform = %platform.id, "traces started from the platform portal");
            Redirect::to("/platform?msg=trace_started_portal#traces-title").into_response()
        }
        Err(trace::StartError::NotAllowed) => Redirect::to("/platform?error=address_not_allowed").into_response(),
        Err(_) => Redirect::to("/platform?error=no_video_in_page").into_response(),
    }
}

pub async fn save_integration(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<IntegrationForm>,
) -> Response {
    let (session, platform) = match platform_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/platform?error=csrf").into_response();
    }
    let token_changed = !form.notice_token.trim().is_empty();
    let new_url = form.api_url.trim().trim_end_matches('/').to_string();
    if new_url != platform.api_url && !reaches_only_public(&new_url).await {
        return Redirect::to("/platform?error=api_url_not_public#integration-title").into_response();
    }
    let id = platform.id.clone();
    let name = platform.name.clone();
    let changed_url = new_url != platform.api_url;
    let result = change_platforms(&app, move |file| {
        let mut entry = admin::update_platform(
            file,
            PlatformInput { id: &id, name: &name, api_url: &form.api_url, notice_token: &form.notice_token },
        )?;
        // An address the platform chose itself is checked again every time a notice goes out.
        if changed_url && let Some(e) = file.platforms.iter_mut().find(|p| p.id == id) {
            e.api_url_from_platform = true;
            entry.api_url_from_platform = true;
        }
        Ok(entry)
    })
    .await;
    match result {
        Ok(entry) => {
            app.core().record(
                &format!("user:{}", session.username),
                "platform_integration_updated",
                json!({"platform_id": entry.id, "api_url": entry.api_url, "token_changed": token_changed}),
            );
            Redirect::to("/platform?msg=integration_saved#integration-title").into_response()
        }
        Err(e) => Redirect::to(&format!("/platform?error={}#integration-title", e.code())).into_response(),
    }
}

pub async fn guide(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let (session, platform) = match platform_session(&app, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let code = format!("{:04x}", platform_code(&platform.id));
    let body = html! {
        p class="breadcrumb" { a href="/platform" { "← Volver al portal" } }
        h1 { "Guía de integración" }
        p class="lede" {
            "Tres piezas: una marca invisible distinta en el video de cada abonado, una API que recibe los avisos de Strack "
            "y una prueba para confirmar que todo funciona."
        }
        section class="panel" aria-labelledby="g-mark" {
            h2 id="g-mark" { "1. Marcá cada sesión" }
            p {
                "Cada vez que un abonado empieza a mirar, generá un número de sesión al azar (8 dígitos hexadecimales) y guardá "
                "a qué abonado se lo diste. El video de esa sesión lleva una marca invisible con tu código, el número de abonado "
                "y la sesión. Resiste recompresión, cambio de tamaño, recortes, espejado y logos encima."
            }
            dl class="facts" {
                dt { "Tu código" } dd class="mono" { (code) }
                dt { "Formato" } dd class="mono" { "STK2|" (code) "|<abonado>|<sesión>" }
            }
            h3 { "Con la herramienta de Strack" }
            p { "Marca un video o una señal para una sesión y te muestra la marca que quedó:" }
            pre class="code" { code {
                "strack mark --platform " (platform.id) " --client 42 --session 1a2b3c4d \\\n"
                "  --input señal.mp4 --output sesion-1a2b3c4d.mp4"
            } }
            p class="hint" {
                "Necesita ffmpeg. Para una señal en vivo, corré un proceso por sesión entre tu codificador y tu CDN, o "
                "incorporá el módulo de marca de Strack (Rust) a tu propio codificador."
            }
        }
        section class="panel" aria-labelledby="g-api" {
            h2 id="g-api" { "2. Recibí los avisos" }
            p {
                "Cuando Strack encuentra tu marca en una copia pirata, envía "
                span class="mono" { "POST " (platform.api_url) "/api/notices" } " con la cabecera "
                span class="mono" { "Authorization: Bearer <tu token>" } " y este cuerpo:"
            }
            pre class="code" { code {
                "{\n  \"notice_id\": \"RAS-000003-1\",\n  \"mark\": \"STK2|" (code) "|42|1a2b3c4d\",\n"
                "  \"pirate_url\": \"https://sitio-pirata.example/stream.mjpg\",\n  \"frame_sha256\": \"…\",\n"
                "  \"detected_at\": \"2026-11-13T21:14:05Z\",\n  \"case_id\": null,\n  \"issuer\": \"Strack\"\n}"
            } }
            p {
                "Comprobá que esa sesión la diste vos y a ese abonado; si es así, suspendé la cuenta, cerrá sus sesiones y respondé "
                span class="mono" { "200" } ":"
            }
            pre class="code" { code {
                "{ \"status\": \"suspended\", \"client_id\": \"c-00042\", \"session_id\": \"1a2b3c4d\",\n"
                "  \"sessions_closed\": 1, \"at\": \"2026-11-13T21:14:06Z\" }"
            } }
            p {
                "Si la cuenta ya estaba suspendida, respondé " span class="mono" { "already_suspended" } ". Si la sesión no es tuya "
                "o no corresponde a ese abonado, respondé 4xx con " span class="mono" { "{\"error\": \"unknown_session\"}" }
                " (Strack no insiste). Ante un 5xx o sin respuesta, Strack reintenta."
            }
        }
        section class="panel" aria-labelledby="g-test" {
            h2 id="g-test" { "3. Probá" }
            p {
                "Leé la marca de un video marcado con " span class="mono" { "strack trace <dirección>" }
                ", o pegá la dirección en \"Rastrear un stream pirata\" de tu portal: si tu API responde, la cuenta aparece "
                "como suspendida."
            }
        }
    };
    Html(page("Guía de integración", Some(&session), Nav::Guide, body).into_string()).into_response()
}

#[cfg(test)]
mod tests {
    use crate::leak::platforms::reaches_only_public;

    #[tokio::test]
    async fn notices_never_go_inside_the_network() {
        for url in [
            "http://127.0.0.1:8100",
            "http://localhost:8100",
            "http://10.0.0.5/api",
            "http://192.168.1.10",
            "http://172.16.0.1",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1",
            "http://0.0.0.0:80",
            "http://[::1]:8100",
            "http://[fd00::1]",
            "http://[fe80::1]",
            "http://[::ffff:127.0.0.1]",
            "http://[64:ff9b::7f00:1]",
            "http://[2002:7f00:1::1]",
            "http://[::7f00:1]",
            "not a url",
        ] {
            assert!(!reaches_only_public(url).await, "{url} must be refused");
        }
        assert!(reaches_only_public("https://8.8.8.8/api").await);
        assert!(reaches_only_public("https://[2001:4860:4860::8888]/api").await);
    }
}
