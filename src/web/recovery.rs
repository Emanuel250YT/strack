//! People without an account or without their password: "Pedir acceso", "¿Olvidaste tu
//! contraseña?" and the one-time link page where they choose the password. Admins review the
//! requests and issue the links in `web::admin`. Lock order: accounts, desk, sessions and core are
//! taken one at a time, never together.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use serde_json::json;

use crate::access::{AccessError, LINK_TTL, NewRequest};
use crate::admin::{self, AdminError, MIN_PASSWORD};
use crate::app::App;
use crate::judges::{Account, Role};
use crate::web::current_session;
use crate::web::layout::auth_page;
use crate::web::ui::role_label;
use crate::web::views::{flash, notice};
use crate::workflow::now_rfc3339;

fn view(title: &str, body: Markup) -> Html<String> {
    Html(auth_page(title, body).into_string())
}

// ---------------------------------------------------------------- recovery

pub async fn recover_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if current_session(&app, &headers).is_some() {
        return Redirect::to("/account").into_response();
    }
    let body = html! {
        h1 { "Recuperar el acceso" }
        p class="lede" {
            "Escribí tu usuario. Administración recibe el pedido, confirma que sos vos y te entrega un enlace de un solo uso "
            "para elegir una contraseña nueva."
        }
        form method="post" action="/recover" class="form-grid" data-once {
            div {
                label for="username" { "Usuario" }
                input type="text" id="username" name="username" required maxlength="32" autocomplete="username"
                    autocapitalize="none" spellcheck="false";
            }
            div { button class="button primary" type="submit" { "Pedir un enlace" } }
        }
        p { a href="/login" { "Volver a ingresar" } }
    };
    view("Recuperar el acceso", body).into_response()
}

#[derive(Deserialize)]
pub struct RecoverForm {
    #[serde(default)]
    username: String,
}

pub async fn recover(State(app): State<Arc<App>>, Form(form): Form<RecoverForm>) -> Response {
    let username = form.username.trim().to_ascii_lowercase();
    let exists = app.accounts().find(&username).is_some();
    // Only real accounts are recorded, so a password typed in the wrong box never reaches the log.
    if exists && app.desk().ask_recovery(&username, &now_rfc3339()) {
        app.core().record("public", "password_recovery_requested", json!({"username": username}));
    }
    let body = html! {
        h1 { "Pedido recibido" }
        p class="lede" {
            "Si el usuario existe, administración ya tiene el pedido. Te van a contactar por un canal oficial para "
            "entregarte un enlace de un solo uso, que vence a los " (LINK_TTL.as_secs() / 60) " minutos de generado."
        }
        p { "Nadie de Strack te va a pedir tu contraseña." }
        p { a href="/login" { "Volver a ingresar" } }
    };
    view("Pedido recibido", body).into_response()
}

// ---------------------------------------------------------------- access requests

#[derive(Deserialize, Default)]
pub struct AccessForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    organism: String,
    #[serde(default)]
    contact: String,
    #[serde(default)]
    reason: String,
}

fn parse_role(value: &str) -> Role {
    match value {
        "judge" => Role::Judge,
        "admin" => Role::Admin,
        "platform" => Role::Platform,
        _ => Role::Operator,
    }
}

/// The step of the access form that holds the field an error code is about.
fn error_step(code: Option<&str>) -> usize {
    match code {
        Some("organism_required") => 2,
        Some("contact_required") | Some("too_many_requests") | Some("internal") => 3,
        _ => 1,
    }
}

const ROLE_CHOICES: [(&str, Role, &str); 4] = [
    ("operator", Role::Operator, "Carga sitios piratas y sigue cada bloqueo en vivo."),
    ("judge", Role::Judge, "Revisa los pedidos y firma las órdenes durante su turno."),
    ("platform", Role::Platform, "Ve las cuentas de su servicio que aparecen en copias piratas."),
    ("admin", Role::Admin, "Gestiona cuentas, plataformas y el registro de proveedores."),
];

/// Asking for an account, one step at a time: who you are, your role, how to reach you. Without
/// script every step shows at once and the form works the same.
fn access_form(values: &AccessForm, error: Option<&str>) -> Markup {
    let role = parse_role(&values.role);
    let start = if error.is_some() { error_step(error) } else { 1 };
    html! {
        p class="eyebrow" { "Pedir acceso" }
        h1 { "Creá tu cuenta en Strack" }
        p class="lede" {
            "La administración revisa cada pedido. Si corresponde, crea la cuenta y te manda un enlace de un solo uso "
            "para que elijas tu contraseña."
        }
        ol class="stepper" aria-hidden="true" data-stepper {
            li { span { "1" } "Quién sos" }
            li { span { "2" } "Tu rol" }
            li { span { "3" } "Contacto" }
        }
        p class="visually-hidden" aria-live="polite" data-step-status {}
        (flash(error))
        form method="post" action="/access" class="form-grid wide steps" data-steps data-start=(start) data-once {
            fieldset class="step" data-step {
                legend { "Quién sos" }
                div class="form-row" {
                    div {
                        label for="ac-name" { "Nombre y apellido" }
                        input type="text" id="ac-name" name="name" required maxlength="300" value=(values.name) autocomplete="name";
                    }
                    div {
                        label for="ac-username" { "Usuario que querés" }
                        input type="text" id="ac-username" name="username" required maxlength="32" pattern="[a-z0-9][a-z0-9._\\-]{2,31}"
                            value=(values.username) autocomplete="off" autocapitalize="none" spellcheck="false"
                            aria-describedby="ac-username-hint";
                        p class="hint" id="ac-username-hint" { "Minúsculas, números, punto o guion; de 3 a 32 caracteres." }
                    }
                }
                div class="step-nav" hidden data-step-nav {
                    span {}
                    button class="button primary" type="button" data-step-next { "Siguiente" }
                }
            }
            fieldset class="step" data-step {
                legend { "Tu rol" }
                div class="role-options" role="radiogroup" aria-label="Rol" {
                    @for (value, r, text) in ROLE_CHOICES {
                        label class="role-option" {
                            input type="radio" name="role" value=(value) checked[r == role] required;
                            span class="role-name" { (role_label(r)) }
                            span class="role-text" { (text) }
                        }
                    }
                }
                div {
                    label for="ac-organism" { "Organismo o empresa" }
                    input type="text" id="ac-organism" name="organism" required maxlength="300" value=(values.organism)
                        autocomplete="organization" placeholder="Juzgado, fiscalía, regulador o plataforma";
                }
                div class="step-nav" hidden data-step-nav {
                    button class="button" type="button" data-step-back { "Atrás" }
                    button class="button primary" type="button" data-step-next { "Siguiente" }
                }
            }
            fieldset class="step" data-step {
                legend { "Contacto" }
                div {
                    label for="ac-contact" { "Cómo te contactamos" }
                    input type="text" id="ac-contact" name="contact" required maxlength="300" value=(values.contact)
                        aria-describedby="ac-contact-hint";
                    p class="hint" id="ac-contact-hint" { "Un correo o teléfono institucional: por ahí te llega el enlace." }
                }
                div {
                    label for="ac-reason" { "Para qué necesitás la cuenta (opcional)" }
                    textarea id="ac-reason" name="reason" rows="3" maxlength="300" { (values.reason) }
                }
                div class="step-nav" {
                    button class="button" type="button" hidden data-step-back { "Atrás" }
                    button class="button primary" type="submit" { "Enviar el pedido" }
                }
            }
        }
        p class="auth-alt" { "¿Ya tenés cuenta? " a href="/login" { "Ingresá" } }
    }
}

pub async fn access_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if current_session(&app, &headers).is_some() {
        return Redirect::to("/account").into_response();
    }
    view("Pedir acceso", access_form(&AccessForm::default(), None)).into_response()
}

pub async fn access(State(app): State<Arc<App>>, Form(form): Form<AccessForm>) -> Response {
    let accounts = app.accounts().clone();
    let new = NewRequest {
        name: &form.name,
        username: &form.username,
        role: parse_role(&form.role),
        organism: &form.organism,
        contact: &form.contact,
        reason: &form.reason,
    };
    let path = app.settings.access_requests_path();
    let submitted = {
        let mut desk = app.desk();
        let mut draft = desk.requests.clone();
        draft.submit(&accounts, new, &now_rfc3339()).and_then(|request| {
            draft.save(&path).map_err(|e| {
                tracing::error!(error = %e, "could not save the access requests");
                AccessError::Internal
            })?;
            desk.requests = draft;
            Ok(request)
        })
    };
    let request = match submitted {
        Ok(request) => request,
        Err(e) => {
            let body = access_form(&form, Some(e.code()));
            return (StatusCode::UNPROCESSABLE_ENTITY, view("Pedir acceso", body)).into_response();
        }
    };
    app.core().record(
        "public",
        "access_requested",
        json!({"request_id": request.id, "username": request.username, "role": request.role}),
    );
    let body = html! {
        h1 { "Pedido enviado" }
        p class="lede" {
            "Tu pedido " span class="mono" { (request.id) } " quedó en manos de administración. Si lo aprueban, te contactan por "
            "el medio que dejaste para entregarte un enlace de un solo uso: con él elegís tu contraseña."
        }
        p { a href="/login" { "Volver a ingresar" } }
    };
    view("Pedido enviado", body).into_response()
}

// ---------------------------------------------------------------- one-time password link

fn dead_link() -> Response {
    let body = html! {
        h1 { "El enlace ya no sirve" }
        p class="lede" { "Venció o ya se usó. Pedí otro con " a href="/recover" { "¿Olvidaste tu contraseña?" } "." }
    };
    (StatusCode::GONE, view("Enlace vencido", body)).into_response()
}

fn link_account(app: &App, token: &str) -> Option<Account> {
    let username = app.desk().peek(token)?;
    app.accounts().find(&username).cloned()
}

fn password_form(token: &str, account: &Account, error: Option<&str>) -> Markup {
    html! {
        h1 { "Elegí tu contraseña" }
        p class="lede" { "Para " strong { (account.display_name) } " (@" (account.username) "). Al guardarla se cierran tus sesiones abiertas." }
        @if account.disabled {
            (notice("La cuenta está deshabilitada: vas a poder ingresar cuando administración la habilite.", "warn"))
        }
        (flash(error))
        form method="post" action={ "/password/" (token) } class="form-grid" data-once {
            div {
                label for="pw-new" { "Contraseña nueva" }
                input type="password" id="pw-new" name="password" required minlength=(MIN_PASSWORD) autocomplete="new-password"
                    aria-describedby="pw-new-hint";
                p class="hint" id="pw-new-hint" { "Al menos " (MIN_PASSWORD) " caracteres." }
            }
            div {
                label for="pw-repeat" { "Repetir la contraseña" }
                input type="password" id="pw-repeat" name="repeat" required minlength=(MIN_PASSWORD) autocomplete="new-password";
            }
            @if account.role == Role::Judge {
                div {
                    label for="pw-key" { "Tu clave de firma" }
                    input type="password" id="pw-key" name="signing_key" required autocomplete="off" aria-describedby="pw-key-hint";
                    p class="hint" id="pw-key-hint" {
                        "La clave de firma de demostración que te entregó el juzgado. Se guarda cifrada con tu nueva contraseña: "
                        "solo se abre cuando ingresás."
                    }
                }
            }
            div class="form-actions" { button class="button primary" type="submit" { "Guardar la contraseña" } }
        }
    }
}

pub async fn password_page(State(app): State<Arc<App>>, Path(token): Path<String>) -> Response {
    match link_account(&app, &token) {
        Some(account) => view("Elegí tu contraseña", password_form(&token, &account, None)).into_response(),
        None => dead_link(),
    }
}

#[derive(Deserialize)]
pub struct LinkPasswordForm {
    #[serde(default)]
    password: String,
    #[serde(default)]
    repeat: String,
    signing_key: Option<String>,
}

pub async fn password(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    Form(form): Form<LinkPasswordForm>,
) -> Response {
    let Some(account) = link_account(&app, &token) else { return dead_link() };
    let retry = |code: &str| {
        let body = password_form(&token, &account, Some(code));
        (StatusCode::UNPROCESSABLE_ENTITY, view("Elegí tu contraseña", body)).into_response()
    };
    if form.password.chars().count() < MIN_PASSWORD {
        return retry("password_too_short");
    }
    if form.password != form.repeat {
        return retry("password_mismatch");
    }
    let username = account.username.clone();
    let key = form.signing_key.map(|k| k.trim().as_bytes().to_vec());
    let app2 = app.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut current = app2.accounts_mut();
        let mut draft = current.clone();
        admin::set_password(&mut draft, &username, &form.password, key.as_deref())?;
        draft.save(&app2.settings.accounts_path).map_err(|_| AdminError::Internal)?;
        *current = draft;
        Ok::<(), AdminError>(())
    })
    .await
    .unwrap_or(Err(AdminError::Internal));
    if let Err(e) = result {
        return retry(e.code());
    }
    {
        let mut desk = app.desk();
        desk.consume(&token);
        desk.clear_recovery(&account.username);
    }
    let closed = app.sessions().remove_user(&account.username, None);
    app.core().record(
        &format!("user:{}", account.username),
        "password_set_by_link",
        json!({"username": account.username, "sessions_closed": closed}),
    );
    Redirect::to("/login?msg=password_set").into_response()
}
