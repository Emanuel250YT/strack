//! Web interface: public registry, judge login and panel, operations board and JSON exports.
//!
//! Server-rendered HTML (maud, auto-escaped) with one small script for live regions; no inline
//! scripts or styles, so the Content-Security-Policy can stay strict.

mod account;
mod admin;
mod assets;
mod auth;
mod intake;
mod judge;
mod labels;
mod layout;
mod ops;
mod platform;
mod public;
mod recovery;
mod reference;
mod traces;
mod ui;
mod views;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use maud::html;

use crate::app::App;
use crate::crypto::constant_time_eq;
use crate::judges::{Role, Session};
use crate::web::layout::{Nav, page};

pub const SESSION_COOKIE: &str = "strack_session";

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
                   base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(public::registry_page))
        .route("/registry/fragment", get(public::registry_fragment))
        .route("/api/registry", get(public::registry_json))
        .route("/api/clock", get(public::clock_json))
        .route("/api/audit/head", get(public::audit_head))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .route("/recover", get(recovery::recover_page).post(recovery::recover))
        .route("/access", get(recovery::access_page).post(recovery::access))
        .route("/password/{token}", get(recovery::password_page).post(recovery::password))
        .route("/judge", get(judge::dashboard))
        .route("/judge/inbox", get(judge::inbox_fragment))
        .route("/judge/cases/{id}", get(judge::case_page))
        .route("/judge/cases/{id}/decision", post(judge::decide_case))
        .route("/judge/cases/{id}/retries", post(judge::sign_retries))
        .route("/judge/claims/{id}", get(judge::claim_page))
        .route("/judge/claims/{id}/decision", post(judge::decide_claim))
        .route("/ops", get(ops::board_page))
        .route("/ops/board", get(ops::board_fragment))
        .route("/ops/cases/{id}", get(ops::case_page))
        .route("/platform", get(platform::portal))
        .route("/platform/traces", post(platform::start_trace))
        .route("/platform/integration", post(platform::save_integration))
        .route("/platform/guide", get(platform::guide))
        .route("/ops/intake", get(intake::intake_page).post(intake::intake_submit))
        .route("/api/detections", post(intake::intake_api))
        .route("/ops/traces", get(traces::list_page).post(traces::start))
        .route("/ops/traces/fragment", get(traces::list_fragment))
        .route("/ops/traces/{id}", get(traces::detail_page))
        .route("/ops/traces/{id}/fragment", get(traces::detail_fragment))
        .route("/ops/traces/{id}/stop", post(traces::stop))
        .route("/ops/traces/{id}/frames/{which}", get(traces::frame))
        .route("/ops/providers", get(reference::providers_page))
        .route("/ops/courts", get(reference::courts_page))
        .route("/ops/audit", get(reference::audit_page))
        .route("/account", get(account::account_page))
        .route("/account/password", post(account::account_password))
        .route("/admin/users", get(admin::users_page).post(admin::user_create))
        .route("/admin/users/new", get(admin::user_new_page))
        .route("/admin/users/{username}", get(admin::user_page))
        .route("/admin/users/{username}/profile", post(admin::user_profile))
        .route("/admin/users/{username}/password", post(admin::user_password))
        .route("/admin/users/{username}/status", post(admin::user_status))
        .route("/admin/users/{username}/sessions", post(admin::user_sessions))
        .route("/admin/users/{username}/delete", post(admin::user_delete))
        .route("/admin/users/{username}/link", post(admin::user_link))
        .route("/admin/access/{id}/reject", post(admin::access_reject))
        .route("/admin/platforms", get(admin::platforms_page).post(admin::platform_create))
        .route("/admin/platforms/new", get(admin::platform_new_page))
        .route("/admin/platforms/{id}", get(admin::platform_page).post(admin::platform_update))
        .route("/admin/platforms/{id}/delete", post(admin::platform_delete))
        .route("/api/cases/{id}", get(ops::case_file_json))
        .route("/api/audit", get(ops::audit_jsonl))
        .route("/static/app.css", get(assets::css))
        .route("/static/app.js", get(assets::js))
        .route("/favicon.svg", get(assets::favicon))
        .route("/static/fonts/{file}", get(assets::font))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(app.clone(), client_scope))
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

/// Accounts of licensed platforms reach only their portal, their own account and the public pages.
async fn client_scope(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let internal = ["/ops", "/judge", "/admin"].iter().any(|p| path == *p || path.starts_with(&format!("{p}/")))
        || path == "/api/audit"
        || path.starts_with("/api/cases/");
    if internal
        && let Some(session) = current_session(&app, request.headers())
        && session.role == Role::Platform
    {
        return error_page(
            StatusCode::FORBIDDEN,
            Some(&session),
            "Solo para el equipo de Strack",
            "Tu cuenta es de una plataforma con licencia: lo tuyo está en tu portal.",
        );
    }
    next.run(request).await
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

pub fn current_session(app: &App, headers: &HeaderMap) -> Option<Session> {
    let token = session_token(headers)?;
    app.sessions().get(&token)
}

pub fn csrf_ok(session: &Session, submitted: &str) -> bool {
    constant_time_eq(&session.csrf, submitted)
}

pub fn error_page(status: StatusCode, session: Option<&Session>, title: &str, message: &str) -> Response {
    let body = html! {
        h1 { (title) }
        p.lede { (message) }
        p { a href="/" { "Volver al registro público" } }
    };
    (status, Html(page(title, session, Nav::None, body).into_string())).into_response()
}

async fn not_found() -> Response {
    error_page(StatusCode::NOT_FOUND, None, "Página inexistente", "La dirección no corresponde a ninguna página.")
}
