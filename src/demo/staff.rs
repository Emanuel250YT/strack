//! The platform staff's console: subscriber CRUD (create, list and search, detail, edit, suspend and
//! reactivate, password link, delete), viewing sessions and the notices Strack sent. Handlers never
//! render a page while holding the state lock (`platform::page` takes it).

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::html;
use serde::Deserialize;

use crate::crypto::{constant_time_eq, random_token};
use crate::demo::accounts::{MIN_PASSWORD, PLANS, Profile, WebSession, Who, check_password};
use crate::demo::platform::{
    FlashQuery, LinkKind, Platform, csrf_ok, flash, hash, mark_explanation, page, sign_in_cookie, web_session,
};
use crate::demo::site::{CsrfForm, ProfileForm, profile_fields, sessions_of, sessions_table};
use crate::demo::{clock_time, local_date};
use crate::leak::mark::client_label;
use crate::workflow::now_rfc3339;

const SHOWN_SUBSCRIBERS: usize = 60;

fn staff_session(p: &Platform, headers: &HeaderMap) -> Option<WebSession> {
    web_session(p, headers).filter(|s| s.who == Who::Staff)
}

fn sign_in_first() -> Response {
    Redirect::to("/admin/login?error=sign_in").into_response()
}

#[derive(Deserialize)]
pub struct StaffLoginForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

fn login_form(username: &str, msg: Option<&str>, error: Option<&str>) -> maud::Markup {
    let wrong = (error == Some("invalid_staff")).then_some("true");
    html! {
        h1 { "Acceso del personal" }
        p class="lede" { "Para el personal de la plataforma: gestión de abonados y avisos de Strack." }
        (flash(msg, error))
        form method="post" action="/admin/login" class="form" {
            div {
                label for="username" { "Usuario" }
                input type="text" id="username" name="username" value=(username) required autocomplete="username"
                    spellcheck="false" autocapitalize="none" aria-invalid=[wrong];
            }
            div {
                label for="password" { "Contraseña" }
                input type="password" id="password" name="password" required autocomplete="current-password" aria-invalid=[wrong];
            }
            div { button type="submit" { "Ingresar" } }
        }
        p { "¿Sos abonado? " a href="/login" { "Ingresá acá" } }
    }
}

pub async fn login_page(State(p): State<Arc<Platform>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    if staff_session(&p, &headers).is_some() {
        return Redirect::to("/admin").into_response();
    }
    page(&p, "Acceso del personal", None, login_form("", q.msg.as_deref(), q.error.as_deref())).into_response()
}

pub async fn login(State(p): State<Arc<Platform>>, Form(form): Form<StaffLoginForm>) -> Response {
    let username = form.username.trim().to_string();
    let key = format!("staff:{username}");
    let fail = |p: &Platform, status: StatusCode, code: &str| {
        (status, page(p, "Acceso del personal", None, login_form(&username, None, Some(code)))).into_response()
    };
    if p.state().web.is_locked_out(&key) {
        return fail(&p, StatusCode::TOO_MANY_REQUESTS, "locked_out");
    }
    // Both compared in constant time, and both always compared.
    let user_ok = constant_time_eq(&username, &p.staff_user);
    let password_ok = constant_time_eq(&form.password, &p.staff_password);
    if !(user_ok && password_ok) {
        p.state().web.record_failure(&key);
        return fail(&p, StatusCode::UNAUTHORIZED, "invalid_staff");
    }
    let session = {
        let mut state = p.state();
        state.web.clear_failures(&key);
        state.web.create(Who::Staff)
    };
    tracing::info!("staff signed in");
    ([(header::SET_COOKIE, sign_in_cookie(&session.token))], Redirect::to("/admin")).into_response()
}

// ---------------------------------------------------------------------------------------------
// Console: figures, subscribers (create, search, list), sessions and notices.

pub async fn console(State(p): State<Arc<Platform>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    let search = q.q.clone().unwrap_or_default().trim().to_lowercase();
    let error = q.error.as_deref();
    let body = {
        let state = p.state();
        let subscribers = &state.directory.subscribers;
        let matching: Vec<_> = subscribers
            .iter()
            .filter(|s| {
                search.is_empty()
                    || s.name.to_lowercase().contains(&search)
                    || s.email.contains(&search)
                    || s.label().contains(&search)
            })
            .collect();
        let suspended = subscribers.iter().filter(|s| s.suspended.is_some()).count();
        let open = state.sessions.iter().filter(|s| s.closed_at.is_none()).count();
        html! {
            h1 { "Abonados y sesiones" }
            p class="lede" { (mark_explanation(p.mode)) }
            (flash(q.msg.as_deref(), error))
            ul class="figures" aria-label="Resumen" {
                li { a class="tile" href="#subscribers-title" { span class="figure" { (subscribers.len()) } span class="label" { "abonados" } } }
                li { div class="tile" { span class="figure" { (subscribers.len() - suspended) } span class="label" { "activos" } } }
                li { div class="tile" { span class="figure" { (suspended) } span class="label" { "suspendidos" } } }
                li { a class="tile" href="#sessions-title" { span class="figure" { (open) } span class="label" { "sesiones abiertas" } } }
                li { a class="tile" href="#notices-title" { span class="figure" { (state.notices.len()) } span class="label" { "avisos de Strack" } } }
            }
            section aria-labelledby="subscribers-title" {
                h2 id="subscribers-title" { "Abonados" }
                details class="panel create" open[error.is_some()] {
                    summary { "Crear abonado" }
                    form method="post" action="/admin/subscribers" class="form wide" {
                        input type="hidden" name="csrf" value=(session.csrf);
                        (profile_fields("new", "", "", PLANS[0], error))
                        div {
                            label for="new-password" { "Contraseña (opcional)" }
                            input type="password" id="new-password" name="password" minlength=(MIN_PASSWORD) autocomplete="new-password"
                                aria-describedby="new-password-hint";
                            p class="hint" id="new-password-hint" {
                                "Si la dejás vacía, le mandamos un enlace para que la elija."
                            }
                        }
                        div { button type="submit" { "Crear abonado" } }
                    }
                }
                form method="get" action="/admin" class="inline-form search" role="search" {
                    div {
                        label for="sub-q" { "Buscar abonado" }
                        input type="search" id="sub-q" name="q" value=(search) placeholder="Nombre, correo o c-00042";
                    }
                    button type="submit" class="secondary" { "Buscar" }
                }
                div class="table-wrap" role="region" aria-label="Abonados" tabindex="0" {
                    table {
                        caption class="sr-only" { "Abonados" }
                        thead { tr {
                            th scope="col" { "Abonado" }
                            th scope="col" { "Correo" }
                            th scope="col" { "Plan" }
                            th scope="col" { "Estado" }
                            th scope="col" { "Acciones" }
                        } }
                        tbody {
                            @if matching.is_empty() { tr { td colspan="5" { "Ningún abonado coincide." } } }
                            @for s in matching.iter().take(SHOWN_SUBSCRIBERS) {
                                tr {
                                    th scope="row" {
                                        a href={ "/admin/subscribers/" (s.number) } { (s.name) }
                                        br; span class="mono" { (s.label()) }
                                    }
                                    td class="mono" { (s.email) }
                                    td { (s.plan) }
                                    @match &s.suspended {
                                        Some(susp) => {
                                            td { span class="pill bad" { "Suspendida" } " desde " (clock_time(&susp.at)) br; span class="mono" { (susp.notice_id) } }
                                        }
                                        None => { td { span class="pill ok" { "Activa" } } }
                                    }
                                    td class="actions" {
                                        a class="button secondary" href={ "/admin/subscribers/" (s.number) } {
                                            "Ver ficha" span class="sr-only" { " de " (s.name) }
                                        }
                                        @let action = if s.suspended.is_some() { "reactivate" } else { "suspend" };
                                        form method="post" action={ "/admin/subscribers/" (s.number) "/" (action) } {
                                            input type="hidden" name="csrf" value=(session.csrf);
                                            input type="hidden" name="back" value="list";
                                            button type="submit" class="secondary" {
                                                @if s.suspended.is_some() { "Reactivar" } @else { "Suspender" }
                                                span class="sr-only" { " a " (s.name) }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @if matching.len() > SHOWN_SUBSCRIBERS {
                    p { "Se muestran " (SHOWN_SUBSCRIBERS) " de " (matching.len()) ". Buscá por nombre, correo o número para ver otros." }
                }
            }
            section aria-labelledby="sessions-title" {
                h2 id="sessions-title" { "Sesiones" }
                @if state.sessions.is_empty() {
                    p { "Todavía no hay sesiones." }
                } @else {
                    (sessions_table("Sesiones", &state.sessions.iter().collect::<Vec<_>>(), true))
                }
            }
            section aria-labelledby="notices-title" {
                h2 id="notices-title" { "Avisos recibidos de Strack" }
                @if state.notices.is_empty() {
                    p { "Ningún aviso por ahora." }
                } @else {
                    (notices_table(&state.notices.iter().collect::<Vec<_>>()))
                }
            }
            form method="post" action="/admin/reset" class="reset" {
                input type="hidden" name="csrf" value=(session.csrf);
                button type="submit" class="secondary" { "Reiniciar la demo (reactivar cuentas y cerrar sesiones)" }
            }
        }
    };
    page(&p, "Abonados", Some(&session), body).into_response()
}

fn notices_table(notices: &[&crate::demo::platform::NoticeEntry]) -> maud::Markup {
    html! {
        div class="table-wrap" role="region" aria-label="Avisos recibidos" tabindex="0" {
            table {
                caption class="sr-only" { "Avisos recibidos de Strack" }
                thead { tr {
                    th scope="col" { "Hora" }
                    th scope="col" { "Aviso" }
                    th scope="col" { "Abonado" }
                    th scope="col" { "Sesión" }
                    th scope="col" { "Resultado" }
                    th scope="col" { "Dónde se retransmitía" }
                } }
                tbody {
                    @for n in notices.iter().rev() {
                        tr {
                            td { (clock_time(&n.at)) }
                            th scope="row" class="mono" { (n.notice_id) }
                            td class="mono" { (n.client) }
                            td class="mono" { (n.session) }
                            td { (n.result) }
                            td class="mono" { (n.pirate_url) }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    password: String,
}

pub async fn create(State(p): State<Arc<Platform>>, headers: HeaderMap, Form(form): Form<CreateForm>) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/admin?error=csrf").into_response();
    }
    let back = |code: &str| Redirect::to(&format!("/admin?error={code}")).into_response();
    let profile = Profile { name: &form.name, email: &form.email, plan: &form.plan };
    let checked = match p.state().directory.check_profile(&profile, None) {
        Ok(checked) => checked,
        Err(e) => return back(e.code()),
    };
    // Without a password the account gets an unusable random one and the subscriber chooses theirs.
    let welcome = form.password.is_empty();
    if !welcome && let Err(e) = check_password(&form.password, &form.password) {
        return back(e.code());
    }
    let password = if welcome { random_token(32) } else { form.password };
    let Some(password_hash) = hash(password).await else { return back("internal") };
    let added = {
        let mut state = p.state();
        state.directory.add(checked, password_hash, &now_rfc3339()).inspect(|number| {
            if welcome {
                state.send_link(&p.name, *number, LinkKind::Welcome);
            }
            p.save(&state);
        })
    };
    match added {
        Ok(number) => {
            tracing::info!(client = %client_label(number), welcome, "subscriber created by the staff");
            let msg = if welcome { "created_link" } else { "created" };
            Redirect::to(&format!("/admin/subscribers/{number}?msg={msg}")).into_response()
        }
        Err(e) => back(e.code()),
    }
}

// ---------------------------------------------------------------------------------------------
// One subscriber: detail, edit, actions.

pub async fn detail(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Path(number): Path<u32>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    let error = q.error.as_deref();
    let body = {
        let state = p.state();
        let Some(sub) = state.directory.find(number) else {
            drop(state);
            let body = html! {
                h1 { "Abonado inexistente" }
                p class="lede" { "No hay ningún abonado " span class="mono" { (client_label(number)) } "." }
                p { a href="/admin" { "Volver a abonados" } }
            };
            return (StatusCode::NOT_FOUND, page(&p, "Abonado inexistente", Some(&session), body)).into_response();
        };
        let sessions = sessions_of(&state.sessions, number);
        let open = sessions.iter().filter(|s| s.closed_at.is_none()).count();
        let label = sub.label();
        let notices: Vec<_> = state.notices.iter().filter(|n| n.client == label).collect();
        let base = format!("/admin/subscribers/{number}");
        html! {
            p { a href="/admin" { "← Volver a abonados" } }
            h1 { (sub.name) " · " span class="mono" { (label) } }
            (flash(q.msg.as_deref(), error))
            div class="columns" {
                section class="panel" aria-labelledby="data-title" {
                    h2 id="data-title" { "Datos" }
                    form method="post" action={ (base) "/profile" } class="form" {
                        input type="hidden" name="csrf" value=(session.csrf);
                        (profile_fields("edit", &sub.name, &sub.email, &sub.plan, error))
                        div { button type="submit" { "Guardar datos" } }
                    }
                }
                div {
                    section class="panel" aria-labelledby="state-title" {
                        h2 id="state-title" { "Estado" }
                        dl class="facts" {
                            dt { "Cuenta" } dd {
                                @match &sub.suspended {
                                    Some(susp) => {
                                        span class="pill bad" { "Suspendida" } " desde " (clock_time(&susp.at))
                                        @if susp.notice_id == "manual" { " (a mano)" } @else { " (aviso " span class="mono" { (susp.notice_id) } ")" }
                                    }
                                    None => { span class="pill ok" { "Activa" } }
                                }
                            }
                            dt { "Sesiones abiertas" } dd { (open) }
                            dt { "Alta" } dd { (local_date(&sub.created_at)) }
                        }
                        @let action = if sub.suspended.is_some() { "reactivate" } else { "suspend" };
                        form method="post" action={ (base) "/" (action) } {
                            input type="hidden" name="csrf" value=(session.csrf);
                            @if sub.suspended.is_some() {
                                button type="submit" { "Reactivar la cuenta" }
                            } @else {
                                button type="submit" class="secondary" { "Suspender y cerrar sesiones" }
                            }
                        }
                    }
                    section class="panel" aria-labelledby="password-title" {
                        h2 id="password-title" { "Contraseña" }
                        p {
                            "Le mandamos un enlace de un solo uso para que elija una contraseña nueva. "
                            "La actual sigue valiendo hasta que la cambie."
                        }
                        form method="post" action={ (base) "/password-link" } {
                            input type="hidden" name="csrf" value=(session.csrf);
                            button type="submit" class="secondary" { "Mandar enlace para elegir contraseña" }
                        }
                        p class="hint" { a href="/mailbox" { "Abrir el buzón de la demo" } }
                    }
                }
            }
            section aria-labelledby="sessions-title" {
                h2 id="sessions-title" { "Sesiones de este abonado" }
                @if sessions.is_empty() {
                    p { "Todavía no abrió ninguna sesión." }
                } @else {
                    (sessions_table("Sesiones de este abonado", &sessions, true))
                }
            }
            @if !notices.is_empty() {
                section aria-labelledby="notices-title" {
                    h2 id="notices-title" { "Avisos de Strack sobre este abonado" }
                    (notices_table(&notices))
                }
            }
            section class="panel danger" aria-labelledby="delete-title" {
                h2 id="delete-title" { "Eliminar abonado" }
                p { "Se borran sus datos y se cierran sus sesiones. Los avisos recibidos quedan en la lista de avisos." }
                form method="post" action={ (base) "/delete" } class="form" {
                    input type="hidden" name="csrf" value=(session.csrf);
                    div class="check" {
                        input type="checkbox" id="delete-confirm" name="confirm" value="yes" required;
                        label for="delete-confirm" { "Confirmo que quiero eliminar a " (sub.name) "." }
                    }
                    div { button type="submit" class="danger" { "Eliminar abonado" } }
                }
            }
        }
    };
    page(&p, "Ficha del abonado", Some(&session), body).into_response()
}

pub async fn update(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Path(number): Path<u32>,
    Form(form): Form<ProfileForm>,
) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    let base = format!("/admin/subscribers/{number}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{base}?error=csrf")).into_response();
    }
    let result = {
        let mut state = p.state();
        let profile = Profile { name: &form.name, email: &form.email, plan: &form.plan };
        let result =
            state.directory.check_profile(&profile, Some(number)).and_then(|c| state.directory.update(number, c));
        if result.is_ok() {
            p.save(&state);
        }
        result
    };
    match result {
        Ok(()) => Redirect::to(&format!("{base}?msg=profile_saved")).into_response(),
        Err(e) => Redirect::to(&format!("{base}?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ActionForm {
    #[serde(default)]
    csrf: String,
    confirm: Option<String>,
    /// `list` to come back to the console instead of the detail page.
    back: Option<String>,
}

/// `suspend` (and close sessions), `reactivate`, `password-link` and `delete` (needs `confirm=yes`).
pub async fn action(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Path((number, action)): Path<(u32, String)>,
    Form(form): Form<ActionForm>,
) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    let base = if form.back.as_deref() == Some("list") {
        "/admin".to_string()
    } else {
        format!("/admin/subscribers/{number}")
    };
    let go = |query: &str| Redirect::to(&format!("{base}?{query}")).into_response();
    if !csrf_ok(&session, &form.csrf) {
        return go("error=csrf");
    }
    let at = now_rfc3339();
    let mut state = p.state();
    let result = match action.as_str() {
        "suspend" => state.directory.suspend(number, &at, "manual").map(|_| {
            state.close_sessions(number, &at);
            "suspended"
        }),
        "reactivate" => state.directory.reactivate(number).map(|()| "reactivated"),
        "password-link" => {
            return if state.send_link(&p.name, number, LinkKind::Recovery) {
                go("msg=link_sent")
            } else {
                go("error=not_found")
            };
        }
        "delete" => {
            if form.confirm.as_deref() != Some("yes") {
                return go("error=confirm_required");
            }
            if state.directory.remove(number).is_err() {
                return Redirect::to("/admin?error=not_found").into_response();
            }
            state.close_sessions(number, &at);
            state.web.remove_subscriber(number, None);
            state.links.revoke(number);
            p.save(&state);
            tracing::info!(client = %client_label(number), "subscriber deleted by the staff");
            return Redirect::to("/admin?msg=deleted").into_response();
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    match result {
        Ok(msg) => {
            p.save(&state);
            tracing::info!(client = %client_label(number), action, "subscriber updated by the staff");
            go(&format!("msg={msg}"))
        }
        Err(e) => go(&format!("error={}", e.code())),
    }
}

pub async fn reset(State(p): State<Arc<Platform>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    let Some(session) = staff_session(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/admin?error=csrf").into_response();
    }
    p.reset();
    tracing::info!("demo reset: subscribers reactivated, sessions closed");
    Redirect::to("/admin?msg=demo_reset").into_response()
}
