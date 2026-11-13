//! Login and logout. Judges unseal their signing key with their password at login.

use std::sync::{Arc, OnceLock};

use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use serde_json::json;

use crate::app::App;
use crate::judges::{Role, authenticate, hash_password, verify_password};
use crate::web::layout::auth_page;
use crate::web::views::{flash, notice};
use crate::web::{SESSION_COOKIE, csrf_ok, current_session};

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

#[derive(Deserialize)]
pub struct MsgQuery {
    msg: Option<String>,
}

/// Hash checked when the username does not exist, so both paths take the same time.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("timing-equaliser-password").unwrap_or_default())
}

fn login_form(error: Option<&str>, username: &str) -> Markup {
    html! {
        h1 { "Ingresar a Strack" }
        p class="lede" { "Juzgados, fiscalías, plataformas con licencia y administración." }
        @if let Some(e) = error { (notice(e, "danger")) }
        form method="post" action="/login" class="auth-form" {
            div {
                label for="username" { "Usuario" }
                input type="text" id="username" name="username" autocomplete="username" required value=(username)
                    autocapitalize="none" spellcheck="false";
            }
            div {
                div class="label-row" {
                    label for="password" { "Contraseña" }
                    a href="/recover" { "¿La olvidaste?" }
                }
                input type="password" id="password" name="password" autocomplete="current-password" required;
            }
            button class="button primary block" type="submit" { "Ingresar" }
        }
        p class="auth-alt" { "¿No tenés cuenta? " a href="/access" { "Pedí acceso" } }
    }
}

pub async fn login_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<MsgQuery>) -> Response {
    if let Some(session) = current_session(&app, &headers) {
        let target = match session.role {
            Role::Judge => "/judge",
            Role::Platform => "/platform",
            _ => "/ops",
        };
        return Redirect::to(target).into_response();
    }
    let body = html! { (flash(q.msg.as_deref())) (login_form(None, "")) };
    Html(auth_page("Ingresar", body).into_string()).into_response()
}

pub async fn login_submit(State(app): State<Arc<App>>, Form(form): Form<LoginForm>) -> Response {
    let username = form.username.trim().to_string();
    let fail = |message: &str| {
        let body = login_form(Some(message), &username);
        (StatusCode::UNAUTHORIZED, Html(auth_page("Ingresar", body).into_string())).into_response()
    };
    if app.sessions().is_locked_out(&username) {
        return fail("Demasiados intentos fallidos. Espere 30 segundos y vuelva a intentar.");
    }
    let account = app.accounts().find(&username).cloned();
    let known = account.as_ref().map(|a| a.username.clone());
    let password = form.password;
    let outcome = tokio::task::spawn_blocking(move || match account {
        Some(account) => authenticate(&account, &password).map(|key| (account, key)),
        None => {
            verify_password(dummy_hash(), &password);
            None
        }
    })
    .await
    .ok()
    .flatten();
    let Some((account, key)) = outcome else {
        app.sessions().record_failure(&username);
        // Only an existing account is named: what someone typed in the username box (sometimes a
        // password) never reaches the audit log.
        let data = match &known {
            Some(name) => json!({"username": name}),
            None => json!({"unknown_account": true}),
        };
        app.core().record("system", "login_failed", data);
        return fail("Usuario o contraseña incorrectos.");
    };
    let session = {
        let mut sessions = app.sessions();
        sessions.clear_failures(&account.username);
        sessions.create(&account, key)
    };
    let actor = match &account.judge_id {
        Some(id) => format!("judge:{id}"),
        None => format!("user:{}", account.username),
    };
    app.core().record(
        &actor,
        "login",
        json!({"username": account.username, "role": account.role, "judge_id": account.judge_id,
               "signing_key_unsealed": session.signing_key.is_some()}),
    );
    let secure = if app.settings.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        session.token,
        crate::judges::SESSION_TTL.as_secs()
    );
    let target = match account.role {
        Role::Judge => "/judge",
        Role::Platform => "/platform",
        _ => "/ops",
    };
    ([(header::SET_COOKIE, cookie)], Redirect::to(target)).into_response()
}

pub async fn logout(State(app): State<Arc<App>>, headers: HeaderMap, Form(form): Form<CsrfForm>) -> Response {
    if let Some(session) = current_session(&app, &headers)
        && csrf_ok(&session, &form.csrf)
    {
        app.sessions().remove(&session.token);
        let actor =
            session.judge_id.as_ref().map_or_else(|| format!("user:{}", session.username), |id| format!("judge:{id}"));
        app.core().record(&actor, "logout", json!({"username": session.username}));
    }
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, cookie)], Redirect::to("/login?msg=logged_out")).into_response()
}
