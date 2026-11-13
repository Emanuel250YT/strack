//! "Mi cuenta": the logged-in user's profile and their own password change. A judge's signing key is
//! sealed again under the new password with the key already open in their session.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::html;
use serde::Deserialize;
use serde_json::json;

use crate::admin::{self, AdminError, MIN_PASSWORD};
use crate::app::App;
use crate::judges::{Role, verify_password};
use crate::web::layout::{Nav, page};
use crate::web::ui::{avatar, page_header, role_pill};
use crate::web::views::flash;
use crate::web::{csrf_ok, current_session};

#[derive(Deserialize)]
pub struct FlashQuery {
    msg: Option<String>,
    error: Option<String>,
}

pub async fn account_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let Some(session) = current_session(&app, &headers) else { return Redirect::to("/login").into_response() };
    let created = app.accounts().find(&session.username).and_then(|a| a.created_at.clone());
    let body = html! {
        (page_header("Mi cuenta", "Tus datos de acceso. Para cambiar el nombre o el rol, pedíselo a administración.", html! {}))
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        div class="split" {
            div class="main-col" {
                section class="panel" aria-labelledby="pw-title" {
                    h2 id="pw-title" { "Cambiar contraseña" }
                    form method="post" action="/account/password" class="form-grid wide" data-once {
                        input type="hidden" name="csrf" value=(session.csrf);
                        div {
                            label for="cur" { "Contraseña actual" }
                            input type="password" id="cur" name="current" required autocomplete="current-password";
                        }
                        div class="form-row" {
                            div {
                                label for="new" { "Nueva contraseña" }
                                input type="password" id="new" name="password" required minlength=(MIN_PASSWORD) autocomplete="new-password";
                            }
                            div {
                                label for="rep" { "Repetir contraseña" }
                                input type="password" id="rep" name="repeat" required minlength=(MIN_PASSWORD) autocomplete="new-password";
                            }
                        }
                        @if session.role == Role::Judge {
                            p class="hint" { "Tu clave de firma se vuelve a cifrar con la nueva contraseña. Tus otras sesiones se cierran." }
                        } @else {
                            p class="hint" { "Tus otras sesiones se cierran." }
                        }
                        div class="form-actions" { button class="button primary" type="submit" { "Cambiar contraseña" } }
                    }
                }
            }
            aside class="side" {
                section class="panel" aria-labelledby="me-title" {
                    div class="identity" {
                        (avatar(&session.display_name, false))
                        div {
                            h2 id="me-title" class="identity-name" { (session.display_name) }
                            p class="hint" { "@" (session.username) }
                        }
                    }
                    dl class="facts" {
                        dt { "Rol" } dd { (role_pill(session.role)) }
                        @if let Some(judge) = &session.judge_id { dt { "Juez" } dd class="mono" { (judge) } }
                        @if let Some(court) = &session.court_id { dt { "Juzgado" } dd class="mono" { (court) } }
                        dt { "Clave de firma" } dd {
                            (if session.signing_key.is_some() { "Abierta en esta sesión" } else if session.role == Role::Judge { "Cerrada" } else { "No corresponde" })
                        }
                        dt { "Alta" } dd { (created.as_deref().map(crate::web::ui::when).unwrap_or_else(|| "—".into())) }
                    }
                }
            }
        }
    };
    Html(page("Mi cuenta", Some(&session), Nav::Account, body).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct OwnPasswordForm {
    csrf: String,
    current: String,
    password: String,
    repeat: String,
}

pub async fn account_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<OwnPasswordForm>,
) -> Response {
    let Some(session) = current_session(&app, &headers) else { return Redirect::to("/login").into_response() };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/account?error=csrf").into_response();
    }
    if form.password != form.repeat {
        return Redirect::to("/account?error=password_mismatch").into_response();
    }
    let hash = app.accounts().find(&session.username).map(|a| a.password_hash.clone());
    let current = form.current.clone();
    let verified =
        tokio::task::spawn_blocking(move || hash.is_some_and(|h| verify_password(&h, &current))).await.unwrap_or(false);
    if !verified {
        return Redirect::to("/account?error=wrong_password").into_response();
    }
    let username = session.username.clone();
    let key = session.signing_key.as_ref().map(|k| k.to_vec());
    let password = form.password;
    let app2 = app.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut current = app2.accounts_mut();
        let mut draft = current.clone();
        admin::set_password(&mut draft, &username, &password, key.as_deref())?;
        draft.save(&app2.settings.accounts_path).map_err(|_| AdminError::Internal)?;
        *current = draft;
        Ok::<(), AdminError>(())
    })
    .await
    .unwrap_or(Err(AdminError::Internal));
    match result {
        Ok(()) => {
            let closed = app.sessions().remove_user(&session.username, Some(&session.token));
            app.core().record(
                &format!("user:{}", session.username),
                "account_password_changed",
                json!({"username": session.username, "sessions_closed": closed, "self_service": true}),
            );
            Redirect::to("/account?msg=password_changed").into_response()
        }
        Err(e) => Redirect::to(&format!("/account?error={}", e.code())).into_response(),
    }
}
