//! The subscriber side of the demo platform: sign-up, sign-in, password recovery through the demo
//! mailbox, "Mi cuenta" (edit the profile, change the password, delete the account) and the live
//! player. Handlers never render a page while holding the state lock (`platform::page` takes it).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;

use crate::demo::accounts::{
    DEMO_EMAIL_DOMAIN, DEMO_PASSWORD, LINK_TTL, MIN_PASSWORD, PLANS, Profile, Subscriber, WebSession, Who,
    check_password, normalize_email,
};
use crate::demo::platform::{
    FlashQuery, LinkKind, LiveSession, MarkMode, Platform, csrf_ok, flash, hash, mark_explanation, page, parse_session,
    sign_in_cookie, sign_out_cookie, verify, web_session,
};
use crate::demo::{clock_time, local_date};
use crate::leak::mark::client_label;
use crate::workflow::now_rfc3339;

/// `aria-invalid` for a field when the error code is about it.
fn invalid(error: Option<&str>, codes: &[&str]) -> Option<&'static str> {
    error.filter(|e| codes.contains(e)).map(|_| "true")
}

fn signed_in_subscriber(p: &Platform, headers: &HeaderMap) -> Option<(WebSession, u32)> {
    let session = web_session(p, headers)?;
    match session.who {
        Who::Subscriber(number) => Some((session, number)),
        Who::Staff => None,
    }
}

fn sign_in_first() -> Response {
    Redirect::to("/login?error=sign_in").into_response()
}

/// Name, email and plan fields, shared by sign-up, "Mi cuenta" and the staff's edit form.
pub fn profile_fields(prefix: &str, name: &str, email: &str, plan: &str, error: Option<&str>) -> Markup {
    let id = |field: &str| format!("{prefix}-{field}");
    html! {
        div {
            label for=(id("name")) { "Nombre y apellido" }
            input type="text" id=(id("name")) name="name" value=(name) required maxlength="80" autocomplete="name"
                aria-invalid=[invalid(error, &["name_required"])];
        }
        div {
            label for=(id("email")) { "Correo electrónico" }
            input type="email" id=(id("email")) name="email" value=(email) required maxlength="254" autocomplete="email"
                spellcheck="false" autocapitalize="none" aria-invalid=[invalid(error, &["invalid_email", "email_taken"])];
        }
        div {
            label for=(id("plan")) { "Plan" }
            select id=(id("plan")) name="plan" {
                @for option in PLANS { option value=(option) selected[option == plan] { (option) } }
            }
        }
    }
}

fn new_password_fields(label: &str, error: Option<&str>) -> Markup {
    let wrong = invalid(error, &["password_too_short", "password_mismatch"]);
    html! {
        div {
            label for="password" { (label) }
            input type="password" id="password" name="password" required minlength=(MIN_PASSWORD) autocomplete="new-password"
                aria-describedby="password-hint" aria-invalid=[wrong];
            p class="hint" id="password-hint" { "Al menos " (MIN_PASSWORD) " caracteres." }
        }
        div {
            label for="repeat" { "Repetir la contraseña" }
            input type="password" id="repeat" name="repeat" required minlength=(MIN_PASSWORD) autocomplete="new-password"
                aria-invalid=[wrong];
        }
    }
}

pub fn sessions_table(caption: &str, sessions: &[&LiveSession], staff: bool) -> Markup {
    html! {
        div class="table-wrap" role="region" aria-label=(caption) tabindex="0" {
            table {
                caption class="sr-only" { (caption) }
                thead { tr {
                    th scope="col" { "Sesión" }
                    @if staff { th scope="col" { "Abonado" } }
                    th scope="col" { "Desde" }
                    th scope="col" { "Estado" }
                    th scope="col" { "Ver" }
                } }
                tbody {
                    @for s in sessions.iter().rev() {
                        tr {
                            th scope="row" class="mono" { (s.mark.session_hex()) }
                            @if staff {
                                td { a class="mono" href={ "/admin/subscribers/" (s.mark.client) } { (s.mark.client_label()) } }
                            }
                            td { (clock_time(&s.started_at)) }
                            td {
                                @match &s.closed_at {
                                    Some(at) => { span class="pill bad" { "Cerrada" } " " (clock_time(at)) }
                                    None => { span class="pill ok" { "Abierta" } }
                                }
                            }
                            td {
                                @if s.closed_at.is_none() {
                                    a href={ "/watch/" (s.mark.session_hex()) } { "Ver la sesión " span class="sr-only" { (s.mark.session_hex()) } }
                                } @else { "—" }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn sessions_of(sessions: &[LiveSession], number: u32) -> Vec<&LiveSession> {
    sessions.iter().filter(|s| s.mark.client == number).collect()
}

fn status_pill(subscriber: &Subscriber) -> Markup {
    html! {
        @if subscriber.suspended.is_some() { span class="pill bad" { "Suspendida" } } @else { span class="pill ok" { "Activa" } }
    }
}

// ---------------------------------------------------------------------------------------------
// Home.

pub async fn home(State(p): State<Arc<Platform>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let session = web_session(&p, &headers);
    let notes = flash(q.msg.as_deref(), q.error.as_deref());
    if let Some(s) = &session {
        match s.who {
            Who::Staff => return Redirect::to("/admin").into_response(),
            Who::Subscriber(number) => {
                let body = {
                    let state = p.state();
                    state
                        .directory
                        .find(number)
                        .map(|sub| subscriber_home(&p, s, sub, &sessions_of(&state.sessions, number), notes.clone()))
                };
                if let Some(body) = body {
                    return page(&p, "Partido en vivo", session.as_ref(), body).into_response();
                }
            }
        }
    }
    let body = html! {
        h1 { "El partido, en vivo" }
        p class="lede" {
            "Mirá el partido en vivo, con sonido y a la calidad original. Creá tu cuenta en un minuto o ingresá con la que ya tenés."
        }
        (notes)
        div class="cta-row" {
            a class="button" href="/signup" { "Crear cuenta" }
            a class="button secondary" href="/login" { "Ingresar" }
        }
        section aria-labelledby="plans-title" {
            h2 id="plans-title" { "Planes" }
            ul class="plans" {
                li { strong { "Fútbol" } ": todos los partidos en vivo." }
                li { strong { "Fútbol + series" } ": los partidos y el catálogo de series." }
                li { strong { "Premium" } ": todo, en dos pantallas a la vez." }
            }
        }
        section aria-labelledby="mark-title" {
            h2 id="mark-title" { "Cada sesión lleva una marca" }
            p { (mark_explanation(p.mode)) }
        }
        aside class="backstage" aria-labelledby="demo-title" {
            h2 id="demo-title" { "Para la demo" }
            p {
                "Hay abonados de prueba: " span class="mono" { "abonado41@" (DEMO_EMAIL_DOMAIN) } ", "
                span class="mono" { "abonado42@" (DEMO_EMAIL_DOMAIN) } " y siguientes (o su número, "
                span class="mono" { "c-00041" } "), todos con la contraseña " span class="mono" { (DEMO_PASSWORD) } ". "
                "Los correos de la plataforma (recuperar la contraseña, cuentas nuevas) llegan al "
                a href="/mailbox" { "buzón de la demo" } "."
            }
        }
    };
    page(&p, "Inicio", None, body).into_response()
}

fn subscriber_home(
    p: &Platform,
    session: &WebSession,
    subscriber: &Subscriber,
    sessions: &[&LiveSession],
    notes: Markup,
) -> Markup {
    let ended = p.ended.load(Ordering::Relaxed);
    html! {
        h1 { "Hola, " (subscriber.name) }
        (notes)
        @if let Some(susp) = &subscriber.suspended {
            div class="alert" role="alert" {
                p { strong { "Tu cuenta está suspendida." } }
                p {
                    "Desde las " (clock_time(&susp.at)) ": una sesión tuya se estaba retransmitiendo sin autorización"
                    @if susp.notice_id != "manual" { " (aviso " span class="mono" { (susp.notice_id) } ")" }
                    ". Mientras siga suspendida no podés abrir sesiones. Si creés que es un error, comunicate con atención al cliente."
                }
            }
        } @else if ended {
            p class="alert" role="status" { "La transmisión terminó: el partido llegó al final." }
        } @else {
            section class="panel live-card" aria-labelledby="live-title" {
                h2 id="live-title" { span class="live-dot" aria-hidden="true" {} "Partido en vivo" }
                p { "En vivo, con sonido y a la calidad original. Tu sesión lleva una marca invisible con tu número de abonado." }
                form method="post" action="/watch" {
                    input type="hidden" name="csrf" value=(session.csrf);
                    button type="submit" { "Mirar el partido" }
                }
            }
        }
        section class="panel" aria-labelledby="me-title" {
            h2 id="me-title" { "Tu cuenta" }
            dl class="facts" {
                dt { "Abonado" } dd class="mono" { (subscriber.label()) }
                dt { "Plan" } dd { (subscriber.plan) }
                dt { "Correo" } dd { (subscriber.email) }
                dt { "Estado" } dd { (status_pill(subscriber)) }
            }
            p { a href="/account" { "Editar tus datos, cambiar la contraseña o eliminar la cuenta" } }
        }
        @if !sessions.is_empty() {
            section aria-labelledby="sessions-title" {
                h2 id="sessions-title" { "Tus sesiones" }
                (sessions_table("Tus sesiones", sessions, false))
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sign-up, sign-in, sign-out.

#[derive(Deserialize, Default)]
pub struct SignupForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    repeat: String,
}

fn signup_form(form: &SignupForm, error: Option<&str>) -> Markup {
    let plan = if form.plan.is_empty() { PLANS[0] } else { form.plan.as_str() };
    html! {
        h1 { "Crear cuenta" }
        p class="lede" { "Con tu cuenta mirás el partido en vivo desde cualquier navegador." }
        (flash(None, error))
        form method="post" action="/signup" class="form" {
            (profile_fields("su", &form.name, &form.email, plan, error))
            (new_password_fields("Contraseña", error))
            div { button type="submit" { "Crear cuenta" } }
        }
        p { "¿Ya tenés cuenta? " a href="/login" { "Ingresar" } }
    }
}

pub async fn signup_page(State(p): State<Arc<Platform>>, headers: HeaderMap) -> Response {
    if web_session(&p, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    page(&p, "Crear cuenta", None, signup_form(&SignupForm::default(), None)).into_response()
}

fn signup_retry(p: &Platform, form: &SignupForm, code: &str) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, page(p, "Crear cuenta", None, signup_form(form, Some(code)))).into_response()
}

pub async fn signup(State(p): State<Arc<Platform>>, Form(form): Form<SignupForm>) -> Response {
    let profile = Profile { name: &form.name, email: &form.email, plan: &form.plan };
    let checked = p
        .state()
        .directory
        .check_profile(&profile, None)
        .and_then(|checked| check_password(&form.password, &form.repeat).map(|()| checked));
    let checked = match checked {
        Ok(checked) => checked,
        Err(e) => return signup_retry(&p, &form, e.code()),
    };
    let Some(password_hash) = hash(form.password.clone()).await else {
        return signup_retry(&p, &form, "internal");
    };
    let added = {
        let mut state = p.state();
        state.directory.add(checked, password_hash, &now_rfc3339()).map(|number| {
            p.save(&state);
            (number, state.web.create(Who::Subscriber(number)))
        })
    };
    match added {
        Ok((number, session)) => {
            tracing::info!(client = %client_label(number), "subscriber signed up");
            ([(header::SET_COOKIE, sign_in_cookie(&session.token))], Redirect::to("/?msg=welcome")).into_response()
        }
        Err(e) => signup_retry(&p, &form, e.code()),
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    login: String,
    #[serde(default)]
    password: String,
}

fn login_form(login: &str, msg: Option<&str>, error: Option<&str>) -> Markup {
    html! {
        h1 { "Ingresar" }
        (flash(msg, error))
        form method="post" action="/login" class="form" {
            div {
                label for="login" { "Correo o número de abonado" }
                input type="text" id="login" name="login" value=(login) required autocomplete="username"
                    spellcheck="false" autocapitalize="none" aria-invalid=[invalid(error, &["invalid_login"])];
            }
            div {
                label for="password" { "Contraseña" }
                input type="password" id="password" name="password" required autocomplete="current-password"
                    aria-invalid=[invalid(error, &["invalid_login"])];
            }
            div { button type="submit" { "Ingresar" } }
        }
        p { a href="/recover" { "¿Olvidaste tu contraseña?" } }
        p { "¿No tenés cuenta? " a href="/signup" { "Crear cuenta" } }
    }
}

pub async fn login_page(State(p): State<Arc<Platform>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    if web_session(&p, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    page(&p, "Ingresar", None, login_form("", q.msg.as_deref(), q.error.as_deref())).into_response()
}

pub async fn login(State(p): State<Arc<Platform>>, Form(form): Form<LoginForm>) -> Response {
    let login = form.login.trim().to_string();
    let fail = |p: &Platform, status: StatusCode, code: &str| {
        (status, page(p, "Ingresar", None, login_form(&login, None, Some(code)))).into_response()
    };
    if p.state().web.is_locked_out(&login) {
        return fail(&p, StatusCode::TOO_MANY_REQUESTS, "locked_out");
    }
    let found = p.state().directory.find_login(&login).map(|s| (s.number, s.password_hash.clone()));
    let verified = verify(found.as_ref().map(|(_, hash)| hash.clone()), form.password).await;
    let Some((number, _)) = found.filter(|_| verified) else {
        p.state().web.record_failure(&login);
        return fail(&p, StatusCode::UNAUTHORIZED, "invalid_login");
    };
    let session = {
        let mut state = p.state();
        state.web.clear_failures(&login);
        state.web.create(Who::Subscriber(number))
    };
    tracing::info!(client = %client_label(number), "subscriber signed in");
    ([(header::SET_COOKIE, sign_in_cookie(&session.token))], Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf: String,
}

pub async fn logout(State(p): State<Arc<Platform>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    let Some(session) = web_session(&p, &headers) else { return Redirect::to("/").into_response() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/?error=csrf").into_response();
    }
    p.state().web.remove(&session.token);
    let target = if session.who == Who::Staff { "/admin/login?msg=signed_out" } else { "/?msg=signed_out" };
    ([(header::SET_COOKIE, sign_out_cookie())], Redirect::to(target)).into_response()
}

// ---------------------------------------------------------------------------------------------
// Recovery: a one-time link by "email" (the demo mailbox).

#[derive(Deserialize)]
pub struct EmailForm {
    #[serde(default)]
    email: String,
}

fn email_form(action: &str, value: &str, button: &str) -> Markup {
    html! {
        form method="post" action=(action) class="form" {
            div {
                label for="email" { "Correo electrónico" }
                input type="email" id="email" name="email" value=(value) required autocomplete="email"
                    spellcheck="false" autocapitalize="none";
            }
            div { button type="submit" { (button) } }
        }
    }
}

pub async fn recover_page(State(p): State<Arc<Platform>>) -> Response {
    let body = html! {
        h1 { "Recuperar la cuenta" }
        p class="lede" { "Escribí el correo de tu cuenta y te mandamos un enlace para elegir una contraseña nueva." }
        (email_form("/recover", "", "Mandar el enlace"))
        p { a href="/login" { "Volver a ingresar" } }
    };
    page(&p, "Recuperar la cuenta", None, body).into_response()
}

pub async fn recover(State(p): State<Arc<Platform>>, Form(form): Form<EmailForm>) -> Response {
    let sent = {
        let mut state = p.state();
        let number = state.directory.find_by_email(&form.email).map(|s| s.number);
        number.filter(|n| state.send_link(&p.name, *n, LinkKind::Recovery))
    };
    if let Some(number) = sent {
        tracing::info!(client = %client_label(number), "password link sent");
    }
    // The same answer whether the account exists or not.
    let body = html! {
        h1 { "Revisá tu correo" }
        p class="lede" {
            "Si hay una cuenta con ese correo, te mandamos un enlace para elegir una contraseña nueva. "
            "Sirve una sola vez y vence en " (LINK_TTL.as_secs() / 60) " minutos."
        }
        aside class="backstage" {
            p { "En la demo no sale ningún correo: llegan al " a href="/mailbox" { "buzón de la demo" } "." }
        }
        p { a href="/login" { "Volver a ingresar" } }
    };
    page(&p, "Revisá tu correo", None, body).into_response()
}

fn dead_link(p: &Platform) -> Response {
    let body = html! {
        h1 { "El enlace ya no sirve" }
        p class="lede" { "Venció o ya se usó. Pedí uno nuevo y usalo dentro de los " (LINK_TTL.as_secs() / 60) " minutos." }
        div class="cta-row" { a class="button" href="/recover" { "Pedir otro enlace" } }
    };
    (StatusCode::GONE, page(p, "Enlace vencido", None, body)).into_response()
}

fn reset_form(token: &str, email: &str, error: Option<&str>) -> Markup {
    html! {
        h1 { "Elegí una contraseña nueva" }
        p class="lede" { "Para la cuenta " strong { (email) } ". Al guardarla se cierran todas tus sesiones." }
        (flash(None, error))
        form method="post" action={ "/reset/" (token) } class="form" {
            (new_password_fields("Contraseña nueva", error))
            div { button type="submit" { "Guardar la contraseña" } }
        }
    }
}

pub async fn reset_page(State(p): State<Arc<Platform>>, Path(token): Path<String>) -> Response {
    let email = {
        let mut state = p.state();
        let number = state.links.peek(&token);
        number.and_then(|n| state.directory.find(n)).map(|s| s.email.clone())
    };
    match email {
        Some(email) => page(&p, "Contraseña nueva", None, reset_form(&token, &email, None)).into_response(),
        None => dead_link(&p),
    }
}

#[derive(Deserialize)]
pub struct NewPasswordForm {
    #[serde(default)]
    password: String,
    #[serde(default)]
    repeat: String,
}

pub async fn reset(
    State(p): State<Arc<Platform>>,
    Path(token): Path<String>,
    Form(form): Form<NewPasswordForm>,
) -> Response {
    let email = {
        let mut state = p.state();
        let number = state.links.peek(&token);
        number.and_then(|n| state.directory.find(n)).map(|s| s.email.clone())
    };
    let Some(email) = email else { return dead_link(&p) };
    if let Err(e) = check_password(&form.password, &form.repeat) {
        let body = reset_form(&token, &email, Some(e.code()));
        return (StatusCode::UNPROCESSABLE_ENTITY, page(&p, "Contraseña nueva", None, body)).into_response();
    }
    let Some(password_hash) = hash(form.password).await else {
        return Redirect::to("/recover").into_response();
    };
    let done = {
        let mut state = p.state();
        let number = state.links.consume(&token);
        let number = number.filter(|n| state.directory.set_password_hash(*n, password_hash).is_ok());
        if let Some(n) = number {
            state.web.remove_subscriber(n, None);
            p.save(&state);
        }
        number
    };
    match done {
        Some(number) => {
            tracing::info!(client = %client_label(number), "password set with a one-time link");
            ([(header::SET_COOKIE, sign_out_cookie())], Redirect::to("/login?msg=password_reset")).into_response()
        }
        None => dead_link(&p),
    }
}

/// The demo's stand-in for email: shows what was sent to an address.
pub async fn mailbox_page(State(p): State<Arc<Platform>>, headers: HeaderMap) -> Response {
    let session = web_session(&p, &headers);
    let body = mailbox_body("", None);
    page(&p, "Buzón de la demo", session.as_ref(), body).into_response()
}

pub async fn mailbox(State(p): State<Arc<Platform>>, headers: HeaderMap, Form(form): Form<EmailForm>) -> Response {
    let session = web_session(&p, &headers);
    let email = normalize_email(&form.email);
    let mails = {
        let state = p.state();
        state
            .mailbox
            .to(&email)
            .into_iter()
            .map(|m| (m.at.clone(), m.subject.clone(), m.text.clone(), m.link.clone()))
            .collect::<Vec<_>>()
    };
    let body = mailbox_body(&email, Some(&mails));
    page(&p, "Buzón de la demo", session.as_ref(), body).into_response()
}

type MailView = (String, String, String, Option<String>);

fn mailbox_body(email: &str, mails: Option<&[MailView]>) -> Markup {
    html! {
        h1 { "Buzón de la demo" }
        p class="lede" {
            "La plataforma de la demo no manda correos de verdad: los deja acá. Escribí la dirección para ver lo que le llegó. "
            "En una plataforma real el enlace llega solo al correo del abonado."
        }
        (email_form("/mailbox", email, "Abrir el buzón"))
        @if let Some(mails) = mails {
            section aria-labelledby="mails-title" {
                h2 id="mails-title" { "Correos para " (email) }
                @if mails.is_empty() {
                    p { "No hay correos para esa dirección." }
                }
                @for (at, subject, text, link) in mails {
                    article class="mail" {
                        h3 { (subject) }
                        p class="hint" { "Recibido a las " (clock_time(at)) }
                        p { (text) }
                        @if let Some(link) = link {
                            p { a class="button" href=(link) { "Abrir el enlace" } }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// "Mi cuenta".

pub async fn account_page(State(p): State<Arc<Platform>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let Some((session, number)) = signed_in_subscriber(&p, &headers) else { return sign_in_first() };
    let error = q.error.as_deref();
    let body = {
        let state = p.state();
        let Some(sub) = state.directory.find(number) else { return sign_in_first() };
        html! {
            h1 { "Mi cuenta" }
            (flash(q.msg.as_deref(), error))
            div class="columns" {
                section class="panel" aria-labelledby="data-title" {
                    h2 id="data-title" { "Tus datos" }
                    form method="post" action="/account/profile" class="form" {
                        input type="hidden" name="csrf" value=(session.csrf);
                        (profile_fields("me", &sub.name, &sub.email, &sub.plan, error))
                        div { button type="submit" { "Guardar datos" } }
                    }
                }
                section class="panel" aria-labelledby="pw-title" {
                    h2 id="pw-title" { "Cambiar la contraseña" }
                    form method="post" action="/account/password" class="form" {
                        input type="hidden" name="csrf" value=(session.csrf);
                        div {
                            label for="current" { "Contraseña actual" }
                            input type="password" id="current" name="current" required autocomplete="current-password"
                                aria-invalid=[invalid(error, &["wrong_password"])];
                        }
                        (new_password_fields("Contraseña nueva", error))
                        p class="hint" { "Cerramos tus otras sesiones." }
                        div { button type="submit" { "Cambiar la contraseña" } }
                    }
                }
            }
            section class="panel" aria-labelledby="sub-title" {
                h2 id="sub-title" { "Tu abonado" }
                dl class="facts" {
                    dt { "Número" } dd class="mono" { (sub.label()) }
                    dt { "Alta" } dd { (local_date(&sub.created_at)) }
                    dt { "Estado" } dd { (status_pill(sub)) }
                }
            }
            section class="panel danger" aria-labelledby="delete-title" {
                h2 id="delete-title" { "Eliminar la cuenta" }
                p { "Se borran tus datos y se cierran tus sesiones. No se puede deshacer." }
                form method="post" action="/account/delete" class="form" {
                    input type="hidden" name="csrf" value=(session.csrf);
                    div {
                        label for="delete-password" { "Tu contraseña" }
                        input type="password" id="delete-password" name="password" required autocomplete="current-password";
                    }
                    div class="check" {
                        input type="checkbox" id="delete-confirm" name="confirm" value="yes" required;
                        label for="delete-confirm" { "Entiendo que mi cuenta se elimina para siempre." }
                    }
                    div { button type="submit" class="danger" { "Eliminar mi cuenta" } }
                }
            }
        }
    };
    page(&p, "Mi cuenta", Some(&session), body).into_response()
}

#[derive(Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub plan: String,
}

pub async fn account_profile(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Response {
    let Some((session, number)) = signed_in_subscriber(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/account?error=csrf").into_response();
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
        Ok(()) => Redirect::to("/account?msg=profile_saved").into_response(),
        Err(e) => Redirect::to(&format!("/account?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct OwnPasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    current: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    repeat: String,
}

pub async fn account_password(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Form(form): Form<OwnPasswordForm>,
) -> Response {
    let Some((session, number)) = signed_in_subscriber(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/account?error=csrf").into_response();
    }
    let stored = p.state().directory.find(number).map(|s| s.password_hash.clone());
    if !verify(stored, form.current).await {
        return Redirect::to("/account?error=wrong_password").into_response();
    }
    if let Err(e) = check_password(&form.password, &form.repeat) {
        return Redirect::to(&format!("/account?error={}", e.code())).into_response();
    }
    let Some(password_hash) = hash(form.password).await else {
        return Redirect::to("/account?error=internal").into_response();
    };
    {
        let mut state = p.state();
        if state.directory.set_password_hash(number, password_hash).is_err() {
            return sign_in_first();
        }
        state.web.remove_subscriber(number, Some(&session.token));
        state.links.revoke(number);
        p.save(&state);
    }
    tracing::info!(client = %client_label(number), "password changed by the subscriber");
    Redirect::to("/account?msg=password_changed").into_response()
}

#[derive(Deserialize)]
pub struct DeleteOwnForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    confirm: Option<String>,
}

pub async fn account_delete(
    State(p): State<Arc<Platform>>,
    headers: HeaderMap,
    Form(form): Form<DeleteOwnForm>,
) -> Response {
    let Some((session, number)) = signed_in_subscriber(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/account?error=csrf").into_response();
    }
    if form.confirm.as_deref() != Some("yes") {
        return Redirect::to("/account?error=confirm_required").into_response();
    }
    let stored = p.state().directory.find(number).map(|s| s.password_hash.clone());
    if !verify(stored, form.password).await {
        return Redirect::to("/account?error=wrong_password").into_response();
    }
    {
        let mut state = p.state();
        if state.directory.remove(number).is_ok() {
            state.close_sessions(number, &now_rfc3339());
            state.web.remove_subscriber(number, None);
            state.links.revoke(number);
            p.save(&state);
        }
    }
    tracing::info!(client = %client_label(number), "subscriber deleted their account");
    ([(header::SET_COOKIE, sign_out_cookie())], Redirect::to("/?msg=account_deleted")).into_response()
}

// ---------------------------------------------------------------------------------------------
// Watching.

pub async fn watch_start(State(p): State<Arc<Platform>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    let Some((session, number)) = signed_in_subscriber(&p, &headers) else { return sign_in_first() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/?error=csrf").into_response();
    }
    match p.open_session(number) {
        Ok((id, _)) => Redirect::to(&format!("/watch/{id}")).into_response(),
        Err("suspended") => Redirect::to("/?error=account_suspended").into_response(),
        Err("ended") => Redirect::to("/?error=ended").into_response(),
        Err(_) => Redirect::to("/?error=internal").into_response(),
    }
}

pub async fn watch_page(State(p): State<Arc<Platform>>, headers: HeaderMap, Path(session): Path<String>) -> Response {
    let Some(viewer) = web_session(&p, &headers) else { return sign_in_first() };
    let found = parse_session(&session).and_then(|id| {
        let state = p.state();
        state.sessions.iter().find(|s| s.mark.session == id).map(|s| (s.mark.client, s.closed_at.is_some()))
    });
    let allowed = found.filter(|(client, _)| viewer.who == Who::Staff || viewer.who == Who::Subscriber(*client));
    let Some((client, closed)) = allowed else {
        let body = html! {
            h1 { "Sesión inexistente" }
            p class="lede" { "Esa sesión no existe o no es tuya." }
            p { a href="/" { "Volver al inicio" } }
        };
        return (StatusCode::NOT_FOUND, page(&p, "Sesión inexistente", Some(&viewer), body)).into_response();
    };
    let caption = match p.mode {
        MarkMode::Invisible => {
            "Esta sesión lleva una marca de agua invisible con el número de abonado: no se ve, pero un programa la lee."
        }
        MarkMode::Visible => "Esta sesión muestra su marca como un QR visible con el número de abonado.",
    };
    let back = if viewer.who == Who::Staff {
        html! { a href={ "/admin/subscribers/" (client) } { "← Volver a la ficha del abonado" } }
    } else {
        html! { a href="/" { "← Volver al inicio" } }
    };
    let body = html! {
        p { (back) }
        h1 { "En vivo · abonado " span class="mono" { (client_label(client)) } }
        @if closed {
            p class="alert" role="alert" { "Esta sesión fue cerrada: la cuenta está suspendida por retransmisión no autorizada." }
        }
        @if p.ended.load(Ordering::Relaxed) {
            p class="alert" role="status" { "La transmisión terminó: el partido llegó al final." }
        }
        figure class="player" {
            video src={ "/live/" (session) ".mp4" } width=(p.picture.0) height=(p.picture.1) controls autoplay muted playsinline
                preload="auto" aria-label="Transmisión en vivo del partido" {
                "Tu navegador no puede reproducir este video."
            }
            figcaption {
                (caption) " Arranca sin sonido: activalo desde el reproductor. "
                "Dirección del stream: " span class="mono" { "/live/" (session) ".mp4" }
            }
        }
    };
    page(&p, "En vivo", Some(&viewer), body).into_response()
}
