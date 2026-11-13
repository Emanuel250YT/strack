//! Administration: user accounts and the registry of licensed platforms (admin role only).
//!
//! Every change runs on a copy of the file, is saved to disk and only then replaces the copy in
//! memory, so memory and disk never disagree; every change is recorded in the audit log without
//! secrets.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use serde_json::json;

use crate::access::{AccessError, AccessRequest, LINK_TTL};
use crate::admin::{
    self, AdminError, JudgeRef, MIN_PASSWORD, NewAccount, PlatformInput, create_platform, delete_platform,
    update_platform,
};
use crate::app::App;
use crate::audit::read_entries;
use crate::crypto::random_token;
use crate::judges::{Account, AccountsFile, Role, Session};
use crate::leak::mark::platform_code;
use crate::leak::platforms::{PlatformEntry, PlatformsFile};
use crate::leak::trace::NoticeStatus;
use crate::web::labels::{self, Label};
use crate::web::layout::{Nav, page};
use crate::web::ui::{avatar, dialog, dialog_button, figure, figures, page_header, role_label, role_pill, when};
use crate::web::views::{flash, notice, status};
use crate::web::{csrf_ok, current_session, error_page};
use crate::workflow::now_rfc3339;

#[allow(clippy::result_large_err)]
fn admin_session(app: &App, headers: &HeaderMap) -> Result<Session, Response> {
    match current_session(app, headers) {
        None => Err(Redirect::to("/login").into_response()),
        Some(s) if s.role != Role::Admin => Err(error_page(
            StatusCode::FORBIDDEN,
            Some(&s),
            "Solo administración",
            "Esta sección es para cuentas con rol de administración.",
        )),
        Some(s) => Ok(s),
    }
}

fn actor(session: &Session) -> String {
    format!("user:{}", session.username)
}

/// Applies a change to a copy of the accounts, saves it and then publishes it.
async fn change_accounts<T: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&mut AccountsFile) -> Result<T, AdminError> + Send + 'static,
) -> Result<T, AdminError> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut current = app.accounts_mut();
        let mut draft = current.clone();
        let out = f(&mut draft)?;
        draft.save(&app.settings.accounts_path).map_err(|e| {
            tracing::error!(error = %e, "could not save the accounts file");
            AdminError::Internal
        })?;
        *current = draft;
        Ok(out)
    })
    .await
    .unwrap_or(Err(AdminError::Internal))
}

pub async fn change_platforms<T: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&mut PlatformsFile) -> Result<T, AdminError> + Send + 'static,
) -> Result<T, AdminError> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut current = app.platforms_mut();
        let mut draft = current.clone();
        let out = f(&mut draft)?;
        draft.save(&app.settings.platforms_path).map_err(|e| {
            tracing::error!(error = %e, "could not save the platforms file");
            AdminError::Internal
        })?;
        *current = draft;
        Ok(out)
    })
    .await
    .unwrap_or(Err(AdminError::Internal))
}

fn parse_role(value: &str) -> Option<Role> {
    match value {
        "judge" => Some(Role::Judge),
        "operator" => Some(Role::Operator),
        "admin" => Some(Role::Admin),
        "platform" => Some(Role::Platform),
        _ => None,
    }
}

fn role_value(role: Role) -> &'static str {
    match role {
        Role::Judge => "judge",
        Role::Operator => "operator",
        Role::Admin => "admin",
        Role::Platform => "platform",
    }
}

fn account_status(account: &Account) -> Label {
    if account.disabled {
        Label { text: "Deshabilitado", tone: "tone-muted" }
    } else {
        Label { text: "Activo", tone: "tone-ok" }
    }
}

/// Judges published by the simulator, with their court, and whether an account already uses them.
fn known_judges(app: &App) -> Vec<(JudgeRef, String, bool)> {
    let used: Vec<String> = app.accounts().accounts.iter().filter_map(|a| a.judge_id.clone()).collect();
    let core = app.core();
    let Some(courts) = core.store.courts.as_ref() else { return Vec::new() };
    courts
        .courts
        .iter()
        .flat_map(|court| {
            court.judges.iter().map(|j| {
                let r = JudgeRef { judge_id: j.id.clone(), court_id: court.id.clone(), name: j.name.clone() };
                (r, court.name.clone(), used.contains(&j.id))
            })
        })
        .collect()
}

fn court_name(app: &App, court_id: Option<&str>) -> String {
    let Some(court_id) = court_id else { return "—".into() };
    let core = app.core();
    core.store
        .courts
        .as_ref()
        .and_then(|c| c.courts.iter().find(|c| c.id == court_id))
        .map_or_else(|| court_id.to_string(), |c| c.name.clone())
}

// ---------------------------------------------------------------- users

#[derive(Deserialize, Default)]
pub struct UsersQuery {
    q: Option<String>,
    role: Option<String>,
    status: Option<String>,
    msg: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct NewUserForm {
    csrf: String,
    username: String,
    display_name: String,
    role: String,
    password: String,
    judge_id: Option<String>,
    signing_key: Option<String>,
    /// Registered platform, for `platform` accounts.
    platform_id: Option<String>,
    /// Access request this account answers (`AR-0001`).
    request: Option<String>,
}

fn new_user_form(app: &App, session: &Session, values: &NewUserForm) -> Markup {
    let judges = known_judges(app);
    let role = parse_role(&values.role).unwrap_or(Role::Operator);
    html! {
        form method="post" action="/admin/users" class="form-grid wide" data-once {
            input type="hidden" name="csrf" value=(session.csrf);
            @if let Some(request) = &values.request {
                input type="hidden" name="request" value=(request);
            }
            div class="form-row" {
                div {
                    label for="nu-username" { "Usuario" }
                    input type="text" id="nu-username" name="username" required maxlength="32" value=(values.username)
                        autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="nu-username-hint";
                    p class="hint" id="nu-username-hint" { "Minúsculas, números, punto o guion; de 3 a 32 caracteres." }
                }
                div {
                    label for="nu-role" { "Rol" }
                    select id="nu-role" name="role" data-role-select {
                        @for r in [Role::Operator, Role::Judge, Role::Admin, Role::Platform] {
                            option value=(role_value(r)) selected[r == role] { (role_label(r)) }
                        }
                    }
                }
            }
            div {
                label for="nu-name" { "Nombre visible" }
                input type="text" id="nu-name" name="display_name" maxlength="80" value=(values.display_name)
                    aria-describedby="nu-name-hint";
                p class="hint" id="nu-name-hint" { "En los jueces puede quedar vacío: se usa el nombre del juzgado." }
            }
            div {
                label for="nu-password" { "Contraseña inicial (opcional)" }
                input type="password" id="nu-password" name="password" minlength=(MIN_PASSWORD) autocomplete="new-password"
                    aria-describedby="nu-password-hint";
                p class="hint" id="nu-password-hint" {
                    "Dejala vacía y te damos un enlace de un solo uso: la persona elige su contraseña sin que nadie más la conozca. "
                    "Si la escribís, al menos " (MIN_PASSWORD) " caracteres."
                }
            }
            fieldset data-platform-only hidden[role != Role::Platform] {
                legend { "Plataforma con licencia" }
                @let platforms = app.platforms().platforms.clone();
                @if platforms.is_empty() {
                    p class="hint" { "Primero registrá la plataforma en Plataformas." }
                } @else {
                    div {
                        label for="nu-platform" { "Plataforma" }
                        select id="nu-platform" name="platform_id" aria-describedby="nu-platform-hint" {
                            option value="" { "Elegí una plataforma" }
                            @for p in &platforms {
                                option value=(p.id) selected[values.platform_id.as_deref() == Some(p.id.as_str())] { (p.name) }
                            }
                        }
                        p class="hint" id="nu-platform-hint" {
                            "La cuenta solo ve su portal: las filtraciones de sus streams, los avisos y su integración."
                        }
                    }
                }
            }
            fieldset data-judge-only hidden[role != Role::Judge] {
                legend { "Datos del juez" }
                @if judges.is_empty() {
                    p class="hint" { "Los jueces y sus turnos vienen del registro de juzgados. Todavía no hay conexión con ese registro." }
                } @else {
                    div {
                        label for="nu-judge" { "Juez" }
                        select id="nu-judge" name="judge_id" aria-describedby="nu-judge-hint" {
                            option value="" { "Elegí un juez" }
                            @for (j, court, used) in &judges {
                                option value=(j.judge_id) disabled[*used] selected[values.judge_id.as_deref() == Some(j.judge_id.as_str())] {
                                    (j.name) " · " (court) @if *used { " (ya tiene cuenta)" }
                                }
                            }
                        }
                        @if judges.iter().all(|(_, _, used)| *used) {
                            p class="hint" id="nu-judge-hint" { "Todos los jueces del registro ya tienen cuenta." }
                        } @else {
                            p class="hint" id="nu-judge-hint" { "Los jueces y sus turnos vienen del registro de juzgados." }
                        }
                    }
                    div {
                        label for="nu-key" { "Clave de firma de demostración" }
                        input type="password" id="nu-key" name="signing_key" autocomplete="off" aria-describedby="nu-key-hint";
                        p class="hint" id="nu-key-hint" {
                            "La clave_firma_demo del juez. Se guarda cifrada con su contraseña: solo se abre cuando el juez ingresa."
                        }
                    }
                }
            }
            div class="form-actions" {
                button class="button" type="button" data-dialog-close { "Cancelar" }
                button class="button primary" type="submit" { "Crear usuario" }
            }
        }
    }
}

fn users_table(app: &App, session: &Session, accounts: &[Account]) -> Markup {
    let sessions = app.sessions().counts();
    html! {
        div class="table-wrap" role="region" aria-label="Usuarios" tabindex="0" {
            table {
                caption { "Usuarios (" (accounts.len()) ")" }
                thead { tr {
                    th scope="col" { "Usuario" }
                    th scope="col" { "Rol" }
                    th scope="col" { "Juzgado" }
                    th scope="col" { "Estado" }
                    th scope="col" class="num" { "Sesiones" }
                    th scope="col" { span class="visually-hidden" { "Acciones" } }
                } }
                tbody {
                    @if accounts.is_empty() {
                        tr { td colspan="6" class="hint" { "Ningún usuario coincide con el filtro." } }
                    }
                    @for a in accounts {
                        tr {
                            th scope="row" {
                                a class="user-cell" href={ "/admin/users/" (a.username) } {
                                    (avatar(&a.display_name, true))
                                    span { span class="user-name" { (a.display_name) } span class="hint" { "@" (a.username) } }
                                }
                            }
                            td { (role_pill(a.role)) }
                            td class="wide-cell" { (court_name(app, a.court_id.as_deref())) }
                            td { (status(account_status(a))) }
                            td class="num" { (sessions.get(&a.username.to_ascii_lowercase()).copied().unwrap_or(0)) }
                            td class="row-actions" {
                                a class="button" href={ "/admin/users/" (a.username) } { "Editar" span class="visually-hidden" { " a " (a.display_name) } }
                                @if !a.username.eq_ignore_ascii_case(&session.username) {
                                    form method="post" action={ "/admin/users/" (a.username) "/status" } {
                                        input type="hidden" name="csrf" value=(session.csrf);
                                        input type="hidden" name="back" value="list";
                                        @if a.disabled {
                                            input type="hidden" name="disabled" value="false";
                                            button class="button" type="submit" { "Habilitar" span class="visually-hidden" { " a " (a.display_name) } }
                                        } @else {
                                            input type="hidden" name="disabled" value="true";
                                            button class="button" type="submit" { "Deshabilitar" span class="visually-hidden" { " a " (a.display_name) } }
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

pub async fn users_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<UsersQuery>) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let all = app.accounts().accounts.clone();
    let open_sessions: usize = app.sessions().counts().values().sum();
    let search = q.q.clone().unwrap_or_default().trim().to_lowercase();
    let role = q.role.as_deref().and_then(parse_role);
    let only = q.status.clone().unwrap_or_default();
    let shown: Vec<Account> = all
        .iter()
        .filter(|a| {
            search.is_empty()
                || a.username.contains(&search)
                || a.display_name.to_lowercase().contains(&search)
                || a.judge_id.as_deref().is_some_and(|j| j.contains(&search))
        })
        .filter(|a| role.is_none_or(|r| a.role == r))
        .filter(|a| match only.as_str() {
            "active" => !a.disabled,
            "disabled" => a.disabled,
            _ => true,
        })
        .cloned()
        .collect();
    let count = |r: Role| all.iter().filter(|a| a.role == r).count();
    let disabled = all.iter().filter(|a| a.disabled).count();
    let (pending, recoveries) = {
        let desk = app.desk();
        (desk.requests.pending().into_iter().cloned().collect::<Vec<_>>(), desk.recoveries().to_vec())
    };
    let body = html! {
        (page_header(
            "Usuarios",
            "Quién entra a Strack y con qué rol. Los jueces firman con su propia clave; operaciones sigue el partido; administración gestiona cuentas y plataformas.",
            dialog_button("new-user", "/admin/users/new", "Crear usuario"),
        ))
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        (figures(html! {
            (figure("Usuarios", all.len(), Some("/admin/users")))
            (figure("Jueces", count(Role::Judge), Some("/admin/users?role=judge")))
            (figure("Operadores", count(Role::Operator), Some("/admin/users?role=operator")))
            (figure("Administración", count(Role::Admin), Some("/admin/users?role=admin")))
            (figure("Deshabilitados", disabled, Some("/admin/users?status=disabled")))
            (figure("Sesiones abiertas", open_sessions, None))
            (figure("Pedidos pendientes", pending.len() + recoveries.len(), Some("/admin/users#requests")))
        }))
        (requests_panel(&session, &pending, &recoveries))
        form class="toolbar" method="get" action="/admin/users" role="search" {
            div class="toolbar-field grow" {
                label for="f-q" class="visually-hidden" { "Buscar usuarios" }
                input type="search" id="f-q" name="q" value=(q.q.clone().unwrap_or_default()) placeholder="Buscar por nombre o usuario";
            }
            div class="toolbar-field" {
                label for="f-role" class="visually-hidden" { "Rol" }
                select id="f-role" name="role" data-autosubmit {
                    option value="" { "Todos los roles" }
                    @for r in [Role::Judge, Role::Operator, Role::Admin, Role::Platform] {
                        option value=(role_value(r)) selected[role == Some(r)] { (role_label(r)) }
                    }
                }
            }
            div class="toolbar-field" {
                label for="f-status" class="visually-hidden" { "Estado" }
                select id="f-status" name="status" data-autosubmit {
                    option value="" { "Todos los estados" }
                    option value="active" selected[only == "active"] { "Activos" }
                    option value="disabled" selected[only == "disabled"] { "Deshabilitados" }
                }
            }
            button class="button" type="submit" { "Filtrar usuarios" }
            @if !search.is_empty() || role.is_some() || !only.is_empty() {
                a class="button ghost" href="/admin/users" { "Limpiar filtros" }
            }
        }
        (users_table(&app, &session, &shown))
        (dialog("new-user", "Crear usuario", new_user_form(&app, &session, &NewUserForm::default())))
    };
    Html(page("Usuarios", Some(&session), Nav::Users, body).into_string()).into_response()
}

fn requests_panel(session: &Session, pending: &[AccessRequest], recoveries: &[(String, String)]) -> Markup {
    html! {
        @if !pending.is_empty() || !recoveries.is_empty() {
            section class="panel" id="requests" aria-labelledby="requests-title" {
                h2 id="requests-title" { "Pedidos pendientes" }
                @if !pending.is_empty() {
                    div class="table-wrap" role="region" aria-label="Pedidos de acceso" tabindex="0" {
                        table {
                            caption { "Pedidos de acceso (" (pending.len()) ")" }
                            thead { tr {
                                th scope="col" { "Pedido" }
                                th scope="col" { "Persona" }
                                th scope="col" { "Rol" }
                                th scope="col" { "Organismo y contacto" }
                                th scope="col" { "Motivo" }
                                th scope="col" { span class="visually-hidden" { "Acciones" } }
                            } }
                            tbody {
                                @for r in pending {
                                    tr {
                                        th scope="row" { span class="mono" { (r.id) } br; span class="hint" { (when(&r.at)) } }
                                        td { (r.name) br; span class="hint" { "@" (r.username) } }
                                        td { (role_pill(r.role)) }
                                        td class="wide-cell" { (r.organism) br; span class="hint" { (r.contact) } }
                                        td class="wide-cell" { (r.reason) }
                                        td class="row-actions" {
                                            a class="button primary" href={ "/admin/users/new?request=" (r.id) } {
                                                "Crear la cuenta" span class="visually-hidden" { " de " (r.name) }
                                            }
                                            form method="post" action={ "/admin/access/" (r.id) "/reject" } {
                                                input type="hidden" name="csrf" value=(session.csrf);
                                                button class="button" type="submit" {
                                                    "Rechazar" span class="visually-hidden" { " el pedido de " (r.name) }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @if !recoveries.is_empty() {
                    div class="table-wrap" role="region" aria-label="Pedidos de recuperación" tabindex="0" {
                        table {
                            caption { "Pedidos de recuperación de acceso (" (recoveries.len()) ")" }
                            thead { tr {
                                th scope="col" { "Usuario" }
                                th scope="col" { "Cuándo" }
                                th scope="col" { span class="visually-hidden" { "Acciones" } }
                            } }
                            tbody {
                                @for (username, at) in recoveries {
                                    tr {
                                        th scope="row" { a href={ "/admin/users/" (username) } { "@" (username) } }
                                        td { (when(at)) }
                                        td class="row-actions" {
                                            a class="button" href={ "/admin/users/" (username) "#link-title" } {
                                                "Generar enlace" span class="visually-hidden" { " para " (username) }
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

/// The same form as a page: works without script and shows validation errors with the values kept.
fn new_user_page(app: &App, session: &Session, values: &NewUserForm, error: Option<AdminError>) -> Response {
    let body = html! {
        p class="breadcrumb" { a href="/admin/users" { "← Usuarios" } }
        (page_header("Crear usuario", "", html! {}))
        @if let Some(e) = error {
            @if let Some((text, tone)) = labels::message(e.code()) { (notice(text, tone)) }
        }
        section class="panel narrow" { (new_user_form(app, session, values)) }
    };
    let status = if error.is_some() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK };
    (status, Html(page("Crear usuario", Some(session), Nav::Users, body).into_string())).into_response()
}

#[derive(Deserialize)]
pub struct NewUserQuery {
    request: Option<String>,
}

pub async fn user_new_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<NewUserQuery>) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let request = q.request.as_deref().and_then(|id| app.desk().requests.find(id).cloned());
    let values = match request {
        Some(r) => NewUserForm {
            username: r.username,
            display_name: r.name,
            role: role_value(r.role).into(),
            request: Some(r.id),
            ..Default::default()
        },
        None => NewUserForm { role: "operator".into(), ..Default::default() },
    };
    new_user_page(&app, &session, &values, None)
}

pub async fn user_create(State(app): State<Arc<App>>, headers: HeaderMap, Form(form): Form<NewUserForm>) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/admin/users?error=csrf").into_response();
    }
    let Some(role) = parse_role(&form.role) else {
        return new_user_page(&app, &session, &form, Some(AdminError::NameRequired));
    };
    let judge = form
        .judge_id
        .as_deref()
        .and_then(|id| known_judges(&app).into_iter().find(|(j, _, _)| j.judge_id == id).map(|(j, _, _)| j));
    // Without a password the account gets an unusable random one and a one-time link to choose it.
    let link_mode = form.password.is_empty();
    let password = if link_mode { random_token(24) } else { form.password.clone() };
    let (username, display_name, signing_key) =
        (form.username.clone(), form.display_name.clone(), form.signing_key.clone());
    let platform = form.platform_id.clone().filter(|p| app.platforms().find(p).is_some());
    let result = change_accounts(&app, move |file| {
        admin::create_account(
            file,
            NewAccount {
                username: &username,
                display_name: &display_name,
                role,
                password: &password,
                judge: if role == Role::Judge { judge } else { None },
                signing_key: signing_key.as_deref(),
                platform: platform.as_deref(),
            },
        )
    })
    .await;
    match result {
        Ok(account) => {
            app.core().record(
                &actor(&session),
                "account_created",
                json!({"username": account.username, "role": account.role, "judge_id": account.judge_id,
                       "platform_id": account.platform_id, "request_id": form.request, "password_link": link_mode}),
            );
            if let Some(id) = &form.request
                && decide_request(&app, id, true, &session).is_ok()
            {
                app.core().record(
                    &actor(&session),
                    "access_request_approved",
                    json!({"request_id": id, "username": account.username}),
                );
            }
            if link_mode {
                let token = app.desk().issue(&account.username);
                app.core().record(&actor(&session), "password_link_issued", json!({"username": account.username}));
                return user_view(&app, &session, &headers, account, Some("user_created_link"), Some(&token));
            }
            Redirect::to(&format!("/admin/users/{}?msg=user_created", account.username)).into_response()
        }
        Err(e) => {
            let kept = NewUserForm { password: String::new(), signing_key: None, ..form };
            new_user_page(&app, &session, &kept, Some(e))
        }
    }
}

#[derive(Deserialize)]
pub struct FlashQuery {
    msg: Option<String>,
    error: Option<String>,
}

pub async fn user_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(account) = app.accounts().find(&username).cloned() else {
        return error_page(StatusCode::NOT_FOUND, Some(&session), "Usuario inexistente", "No existe ese usuario.");
    };
    user_view(&app, &session, &headers, account, q.msg.as_deref().or(q.error.as_deref()), None)
}

/// Full address of a one-time password link, from the Host the admin used.
fn link_url(app: &App, headers: &HeaderMap, token: &str) -> String {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("127.0.0.1:3000");
    let scheme = if app.settings.secure_cookies { "https" } else { "http" };
    format!("{scheme}://{host}/password/{token}")
}

/// The user's page; `link` is a one-time password link token just issued (shown once).
fn user_view(
    app: &App,
    session: &Session,
    headers: &HeaderMap,
    account: Account,
    message: Option<&str>,
    link: Option<&str>,
) -> Response {
    let recovery_at = app.desk().recovery_of(&account.username).map(str::to_string);
    let link = link.map(|token| link_url(app, headers, token));
    let is_self = account.username.eq_ignore_ascii_case(&session.username);
    let open = app.sessions().counts().get(&account.username.to_ascii_lowercase()).copied().unwrap_or(0);
    let activity: Vec<_> = read_entries(&app.settings.audit_path())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            e.data.get("username").and_then(|v| v.as_str()).is_some_and(|u| u.eq_ignore_ascii_case(&account.username))
        })
        .rev()
        .take(12)
        .collect();
    let court = court_name(app, account.court_id.as_deref());
    let path = format!("/admin/users/{}", account.username);
    let body = html! {
        p class="breadcrumb" { a href="/admin/users" { "← Usuarios" } }
        div class="page-header" {
            div class="page-title identity" {
                (avatar(&account.display_name, false))
                div {
                    h1 { (account.display_name) }
                    p class="lede" { "@" (account.username) " · " (role_pill(account.role)) " · " (status(account_status(&account))) }
                }
            }
        }
        (flash(message))
        div class="split" {
            div class="main-col" {
                section class="panel" aria-labelledby="profile-title" {
                    h2 id="profile-title" { "Perfil" }
                    form method="post" action={ (path) "/profile" } class="form-grid wide" data-once {
                        input type="hidden" name="csrf" value=(session.csrf);
                        div class="form-row" {
                            div {
                                label for="p-name" { "Nombre visible" }
                                input type="text" id="p-name" name="display_name" required maxlength="80" value=(account.display_name);
                            }
                            div {
                                label for="p-role" { "Rol" }
                                @if account.role == Role::Judge {
                                    input type="hidden" name="role" value="judge";
                                    input type="text" id="p-role" value="Juez" readonly aria-describedby="p-role-hint";
                                    p class="hint" id="p-role-hint" { "El rol de juez queda atado a su clave de firma." }
                                } @else if account.role == Role::Platform {
                                    input type="hidden" name="role" value="platform";
                                    input type="text" id="p-role" value="Plataforma" readonly aria-describedby="p-role-hint";
                                    p class="hint" id="p-role-hint" { "Queda atada a su plataforma." }
                                } @else {
                                    select id="p-role" name="role" disabled[is_self] aria-describedby="p-role-hint" {
                                        @for r in [Role::Operator, Role::Admin] {
                                            option value=(role_value(r)) selected[r == account.role] { (role_label(r)) }
                                        }
                                    }
                                    @if is_self {
                                        input type="hidden" name="role" value=(role_value(account.role));
                                        p class="hint" id="p-role-hint" { "No podés cambiar tu propio rol." }
                                    }
                                }
                            }
                        }
                        @if account.role == Role::Judge {
                            dl class="facts" {
                                dt { "Juez" } dd class="mono" { (account.judge_id.clone().unwrap_or_default()) }
                                dt { "Juzgado" } dd { (court) }
                            }
                        }
                        @if let Some(platform) = &account.platform_id {
                            dl class="facts" {
                                dt { "Plataforma" } dd {
                                    a href={ "/admin/platforms/" (platform) } {
                                        (app.platforms().find(platform).map_or(platform.clone(), |p| p.name.clone()))
                                    }
                                }
                            }
                        }
                        div class="form-actions" { button class="button primary" type="submit" { "Guardar perfil" } }
                    }
                }
                section class="panel" aria-labelledby="password-title" {
                    h2 id="password-title" { "Contraseña" }
                    form method="post" action={ (path) "/password" } class="form-grid wide" data-once {
                        input type="hidden" name="csrf" value=(session.csrf);
                        div class="form-row" {
                            div {
                                label for="pw-new" { "Nueva contraseña" }
                                input type="password" id="pw-new" name="password" required minlength=(MIN_PASSWORD) autocomplete="new-password";
                            }
                            div {
                                label for="pw-repeat" { "Repetir contraseña" }
                                input type="password" id="pw-repeat" name="repeat" required minlength=(MIN_PASSWORD) autocomplete="new-password";
                            }
                        }
                        @if account.role == Role::Judge {
                            div {
                                label for="pw-key" { "Clave de firma de demostración" }
                                input type="password" id="pw-key" name="signing_key" required autocomplete="off" aria-describedby="pw-key-hint";
                                p class="hint" id="pw-key-hint" { "Hace falta para volver a cifrar la clave del juez con la nueva contraseña." }
                            }
                        }
                        p class="hint" { "Cambiarla cierra las sesiones abiertas de este usuario." }
                        div class="form-actions" { button class="button primary" type="submit" { "Cambiar contraseña" } }
                    }
                }
                section class="panel" aria-labelledby="activity-title" {
                    h2 id="activity-title" { "Actividad reciente" }
                    @if activity.is_empty() {
                        p class="hint" { "Sin actividad registrada en esta corrida." }
                    } @else {
                        div class="table-wrap" role="region" aria-label="Actividad reciente" tabindex="0" {
                            table {
                                thead { tr { th scope="col" { "Cuándo" } th scope="col" { "Evento" } th scope="col" { "Por" } } }
                                tbody {
                                    @for e in &activity {
                                        tr {
                                            td { (when(&e.at)) }
                                            td { (labels::audit_event(&e.event)) }
                                            td class="mono" { (e.actor) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            aside class="side" {
                section class="panel" aria-labelledby="access-title" {
                    h2 id="access-title" { "Acceso" }
                    dl class="facts" {
                        dt { "Estado" } dd { (status(account_status(&account))) }
                        dt { "Sesiones abiertas" } dd { (open) }
                        dt { "Alta" } dd { (account.created_at.as_deref().map(when).unwrap_or_else(|| "—".into())) }
                    }
                    @if !is_self {
                        div class="stack" {
                            form method="post" action={ (path) "/status" } {
                                input type="hidden" name="csrf" value=(session.csrf);
                                @if account.disabled {
                                    input type="hidden" name="disabled" value="false";
                                    button class="button" type="submit" { "Habilitar usuario" }
                                } @else {
                                    input type="hidden" name="disabled" value="true";
                                    button class="button" type="submit" { "Deshabilitar usuario" }
                                }
                            }
                            @if open > 0 {
                                form method="post" action={ (path) "/sessions" } {
                                    input type="hidden" name="csrf" value=(session.csrf);
                                    button class="button" type="submit" { "Cerrar sus sesiones" }
                                }
                            }
                        }
                    }
                }
                section class="panel" aria-labelledby="link-title" {
                    h2 id="link-title" { "Enlace para elegir contraseña" }
                    @if let Some(at) = &recovery_at {
                        (notice(&format!("Pidió recuperar el acceso ({}). Confirmá que es la persona antes de entregarle el enlace.", when(at)), "warn"))
                    }
                    @if let Some(url) = &link {
                        div class="notice ok" role="status" {
                            p {
                                "Enlace de un solo uso: vence en " (LINK_TTL.as_secs() / 60) " minutos. "
                                "Entregalo por un canal oficial: no se vuelve a mostrar."
                            }
                            p class="mono link-out" { (url) }
                        }
                    }
                    p class="hint" {
                        "La persona elige su contraseña sin que nadie más la conozca"
                        @if account.role == Role::Judge { "; un juez vuelve a cargar su clave de firma" }
                        ". Generar otro anula el anterior."
                    }
                    form method="post" action={ (path) "/link" } {
                        input type="hidden" name="csrf" value=(session.csrf);
                        button class="button" type="submit" { "Generar enlace" }
                    }
                }
                @if !is_self {
                    section class="panel danger-zone" aria-labelledby="danger-title" {
                        h2 id="danger-title" { "Eliminar usuario" }
                        p class="hint" { "Se borra la cuenta y su clave cifrada. Lo que ya firmó queda en el registro de auditoría." }
                        form method="post" action={ (path) "/delete" } {
                            input type="hidden" name="csrf" value=(session.csrf);
                            label class="choice" {
                                input type="checkbox" name="confirm" value="yes" required;
                                span { "Entiendo que no se puede deshacer" }
                            }
                            button class="button danger" type="submit" { "Eliminar usuario" }
                        }
                    }
                }
            }
        }
    };
    let title = format!("Usuario {}", account.username);
    Html(page(&title, Some(session), Nav::Users, body).into_string()).into_response()
}

/// Approves or rejects an access request (saved before it replaces the copy in memory).
fn decide_request(app: &App, id: &str, approved: bool, session: &Session) -> Result<AccessRequest, AccessError> {
    let path = app.settings.access_requests_path();
    let mut desk = app.desk();
    let mut draft = desk.requests.clone();
    let request = draft.decide(id, approved, &session.username, &now_rfc3339())?;
    draft.save(&path).map_err(|e| {
        tracing::error!(error = %e, "could not save the access requests");
        AccessError::Internal
    })?;
    desk.requests = draft;
    Ok(request)
}

pub async fn user_link(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("/admin/users/{username}?error=csrf")).into_response();
    }
    let Some(account) = app.accounts().find(&username).cloned() else {
        return error_page(StatusCode::NOT_FOUND, Some(&session), "Usuario inexistente", "No existe ese usuario.");
    };
    let token = {
        let mut desk = app.desk();
        desk.clear_recovery(&account.username);
        desk.issue(&account.username)
    };
    app.core().record(&actor(&session), "password_link_issued", json!({"username": account.username}));
    user_view(&app, &session, &headers, account, Some("link_issued"), Some(&token))
}

pub async fn access_reject(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/admin/users?error=csrf").into_response();
    }
    match decide_request(&app, &id, false, &session) {
        Ok(request) => {
            app.core().record(
                &actor(&session),
                "access_request_rejected",
                json!({"request_id": request.id, "username": request.username}),
            );
            Redirect::to("/admin/users?msg=access_rejected#requests").into_response()
        }
        Err(e) => Redirect::to(&format!("/admin/users?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ProfileForm {
    csrf: String,
    display_name: String,
    role: String,
}

pub async fn user_profile(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<ProfileForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/users/{username}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    let Some(role) = parse_role(&form.role) else {
        return Redirect::to(&format!("{back}?error=internal")).into_response();
    };
    let (target, name, me) = (username.clone(), form.display_name.clone(), session.username.clone());
    match change_accounts(&app, move |file| admin::update_profile(file, &target, &name, role, &me)).await {
        Ok(account) => {
            app.sessions().rename(&account.username, &account.display_name);
            app.core().record(
                &actor(&session),
                "account_updated",
                json!({"username": account.username, "display_name": account.display_name, "role": account.role}),
            );
            Redirect::to(&format!("{back}?msg=user_updated")).into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    password: String,
    repeat: String,
    signing_key: Option<String>,
}

pub async fn user_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<PasswordForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/users/{username}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    if form.password != form.repeat {
        return Redirect::to(&format!("{back}?error=password_mismatch")).into_response();
    }
    let target = username.clone();
    let key = form.signing_key.map(|k| k.trim().as_bytes().to_vec());
    let password = form.password;
    match change_accounts(&app, move |file| admin::set_password(file, &target, &password, key.as_deref())).await {
        Ok(()) => {
            let keep = username.eq_ignore_ascii_case(&session.username).then_some(session.token.as_str());
            let closed = app.sessions().remove_user(&username, keep);
            app.core().record(
                &actor(&session),
                "account_password_changed",
                json!({"username": username, "sessions_closed": closed}),
            );
            Redirect::to(&format!("{back}?msg=password_changed")).into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct StatusForm {
    csrf: String,
    disabled: String,
    back: Option<String>,
}

pub async fn user_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<StatusForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = if form.back.as_deref() == Some("list") {
        "/admin/users".to_string()
    } else {
        format!("/admin/users/{username}")
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    let disabled = form.disabled == "true";
    let (target, me) = (username.clone(), session.username.clone());
    match change_accounts(&app, move |file| admin::set_disabled(file, &target, disabled, &me)).await {
        Ok(()) => {
            let closed = if disabled { app.sessions().remove_user(&username, None) } else { 0 };
            let event = if disabled { "account_disabled" } else { "account_enabled" };
            app.core().record(&actor(&session), event, json!({"username": username, "sessions_closed": closed}));
            let msg = if disabled { "user_disabled" } else { "user_enabled" };
            Redirect::to(&format!("{back}?msg={msg}")).into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn user_sessions(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/users/{username}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    if username.eq_ignore_ascii_case(&session.username) {
        return Redirect::to(&format!("{back}?error=self_action")).into_response();
    }
    let closed = app.sessions().remove_user(&username, None);
    app.core().record(
        &actor(&session),
        "account_sessions_closed",
        json!({"username": username, "sessions_closed": closed}),
    );
    Redirect::to(&format!("{back}?msg=sessions_closed")).into_response()
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf: String,
    confirm: Option<String>,
}

pub async fn user_delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/users/{username}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    if form.confirm.as_deref() != Some("yes") {
        return Redirect::to(&format!("{back}?error=confirm_required")).into_response();
    }
    let (target, me) = (username.clone(), session.username.clone());
    match change_accounts(&app, move |file| admin::delete_account(file, &target, &me)).await {
        Ok(account) => {
            let closed = app.sessions().remove_user(&account.username, None);
            app.core().record(
                &actor(&session),
                "account_deleted",
                json!({"username": account.username, "role": account.role, "sessions_closed": closed}),
            );
            Redirect::to("/admin/users?msg=user_deleted").into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}

// ---------------------------------------------------------------- platforms

#[derive(Deserialize, Default)]
pub struct PlatformForm {
    csrf: String,
    id: Option<String>,
    name: String,
    api_url: String,
    notice_token: Option<String>,
}

fn masked(token: &str) -> String {
    let tail: String = token.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("•••• {tail}")
}

/// Notices and suspensions per platform id, from the leak traces of this run.
fn notice_counts(app: &App) -> std::collections::HashMap<u16, (usize, usize)> {
    let core = app.core();
    let mut out = std::collections::HashMap::new();
    for leak in core.store.traces.iter().flat_map(|t| t.leaks.iter()) {
        let entry = out.entry(leak.mark.platform).or_insert((0, 0));
        if leak.notice.attempts > 0 {
            entry.0 += 1;
        }
        if leak.notice.status == NoticeStatus::Acknowledged {
            entry.1 += 1;
        }
    }
    out
}

fn platform_form(session: &Session, values: &PlatformForm, existing: Option<&PlatformEntry>) -> Markup {
    let action = existing.map_or_else(|| "/admin/platforms".to_string(), |p| format!("/admin/platforms/{}", p.id));
    html! {
        form method="post" action=(action) class="form-grid wide" data-once {
            input type="hidden" name="csrf" value=(session.csrf);
            div class="form-row" {
                div {
                    label for="pf-name" { "Nombre" }
                    input type="text" id="pf-name" name="name" required maxlength="80" value=(values.name);
                }
                div {
                    label for="pf-id" { "Identificador" }
                    @match existing {
                        Some(p) => {
                            input type="text" id="pf-id" value=(p.id) readonly aria-describedby="pf-id-hint";
                            p class="hint" id="pf-id-hint" { "Fijo: el código de marca sale de él (" span class="mono" { (format!("{:04x}", platform_code(&p.id))) } ")." }
                        }
                        None => {
                            input type="text" id="pf-id" name="id" required maxlength="32" value=(values.id.clone().unwrap_or_default())
                                autocapitalize="none" spellcheck="false" aria-describedby="pf-id-hint";
                            p class="hint" id="pf-id-hint" { "El mismo id que la plataforma graba en sus marcas. Minúsculas, números y guiones." }
                        }
                    }
                }
            }
            div {
                label for="pf-url" { "Dirección de su API de avisos" }
                input type="url" id="pf-url" name="api_url" required maxlength="300" value=(values.api_url) placeholder="https://avisos.plataforma.example";
            }
            div {
                label for="pf-token" { "Token de avisos" }
                input type="password" id="pf-token" name="notice_token" autocomplete="off" minlength="16" aria-describedby="pf-token-hint";
                p class="hint" id="pf-token-hint" {
                    @if existing.is_some() { "Vacío conserva el actual. " } @else { "Vacío genera uno al azar. " }
                    "Es la credencial con la que Strack se presenta ante la plataforma."
                }
            }
            div class="form-actions" {
                @if existing.is_none() { button class="button" type="button" data-dialog-close { "Cancelar" } }
                button class="button primary" type="submit" { @if existing.is_some() { "Guardar plataforma" } @else { "Registrar plataforma" } }
            }
        }
    }
}

pub async fn platforms_page(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<FlashQuery>) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let platforms = app.platforms().platforms.clone();
    let counts = notice_counts(&app);
    let traces = app.core().store.traces.len();
    let notices: usize = counts.values().map(|c| c.0).sum();
    let suspended: usize = counts.values().map(|c| c.1).sum();
    let body = html! {
        (page_header(
            "Plataformas licenciatarias",
            "Las plataformas que esconden una marca por sesión en su señal y reciben los avisos de filtración. Strack solo acepta marcas de las plataformas registradas acá.",
            dialog_button("new-platform", "/admin/platforms/new", "Registrar plataforma"),
        ))
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        (figures(html! {
            (figure("Plataformas", platforms.len(), None))
            (figure("Rastreos", traces, Some("/ops/traces")))
            (figure("Avisos enviados", notices, Some("/ops/traces")))
            (figure("Cuentas suspendidas", suspended, Some("/ops/traces")))
        }))
        div class="table-wrap" role="region" aria-label="Plataformas" tabindex="0" {
            table {
                caption { "Plataformas registradas (" (platforms.len()) ")" }
                thead { tr {
                    th scope="col" { "Plataforma" }
                    th scope="col" { "Código de marca" }
                    th scope="col" { "API de avisos" }
                    th scope="col" { "Token" }
                    th scope="col" class="num" { "Avisos" }
                    th scope="col" class="num" { "Suspendidas" }
                    th scope="col" { span class="visually-hidden" { "Acciones" } }
                } }
                tbody {
                    @if platforms.is_empty() {
                        tr { td colspan="7" class="hint" { "Todavía no hay plataformas: los rastreos identifican cuentas pero no pueden avisar." } }
                    }
                    @for p in &platforms {
                        @let code = platform_code(&p.id);
                        @let (sent, ok) = counts.get(&code).copied().unwrap_or((0, 0));
                        tr {
                            th scope="row" { a href={ "/admin/platforms/" (p.id) } { (p.name) } br; span class="hint mono" { (p.id) } }
                            td class="mono" { (format!("{code:04x}")) }
                            td class="mono" { (p.api_url) }
                            td class="mono" { (masked(&p.notice_token)) }
                            td class="num" { (sent) }
                            td class="num" { (ok) }
                            td class="row-actions" { a class="button" href={ "/admin/platforms/" (p.id) } { "Editar" span class="visually-hidden" { " " (p.name) } } }
                        }
                    }
                }
            }
        }
        (dialog("new-platform", "Registrar plataforma", platform_form(&session, &PlatformForm::default(), None)))
    };
    Html(page("Plataformas", Some(&session), Nav::Platforms, body).into_string()).into_response()
}

fn platform_new_view(session: &Session, values: &PlatformForm, error: Option<AdminError>) -> Response {
    let body = html! {
        p class="breadcrumb" { a href="/admin/platforms" { "← Plataformas" } }
        (page_header("Registrar plataforma", "", html! {}))
        @if let Some(e) = error {
            @if let Some((text, tone)) = labels::message(e.code()) { (notice(text, tone)) }
        }
        section class="panel narrow" { (platform_form(session, values, None)) }
    };
    let status = if error.is_some() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK };
    (status, Html(page("Registrar plataforma", Some(session), Nav::Platforms, body).into_string())).into_response()
}

pub async fn platform_new_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    match admin_session(&app, &headers) {
        Ok(session) => platform_new_view(&session, &PlatformForm::default(), None),
        Err(r) => r,
    }
}

pub async fn platform_create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<PlatformForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to("/admin/platforms?error=csrf").into_response();
    }
    let (id, name, url, token) = (
        form.id.clone().unwrap_or_default(),
        form.name.clone(),
        form.api_url.clone(),
        form.notice_token.clone().unwrap_or_default(),
    );
    let result = change_platforms(&app, move |file| {
        create_platform(file, PlatformInput { id: &id, name: &name, api_url: &url, notice_token: &token })
    })
    .await;
    match result {
        Ok(entry) => {
            app.core().record(
                &actor(&session),
                "platform_created",
                json!({"platform_id": entry.id, "name": entry.name, "api_url": entry.api_url}),
            );
            Redirect::to(&format!("/admin/platforms/{}?msg=platform_created", entry.id)).into_response()
        }
        Err(e) => platform_new_view(&session, &PlatformForm { notice_token: None, ..form }, Some(e)),
    }
}

pub async fn platform_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FlashQuery>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(entry) = app.platforms().find(&id).cloned() else {
        return error_page(
            StatusCode::NOT_FOUND,
            Some(&session),
            "Plataforma inexistente",
            "No existe esa plataforma.",
        );
    };
    let code = platform_code(&entry.id);
    let (sent, ok) = notice_counts(&app).get(&code).copied().unwrap_or((0, 0));
    let values = PlatformForm {
        csrf: String::new(),
        id: Some(entry.id.clone()),
        name: entry.name.clone(),
        api_url: entry.api_url.clone(),
        notice_token: None,
    };
    let body = html! {
        p class="breadcrumb" { a href="/admin/platforms" { "← Plataformas" } }
        (page_header(&entry.name, "Plataforma licenciataria registrada para recibir avisos de filtración.", html! {}))
        (flash(q.msg.as_deref().or(q.error.as_deref())))
        div class="split" {
            div class="main-col" {
                section class="panel" aria-labelledby="pf-title" {
                    h2 id="pf-title" { "Datos de la plataforma" }
                    (platform_form(&session, &values, Some(&entry)))
                }
            }
            aside class="side" {
                section class="panel" aria-labelledby="pf-facts" {
                    h2 id="pf-facts" { "En esta corrida" }
                    dl class="facts" {
                        dt { "Código de marca" } dd class="mono" { (format!("{code:04x}")) }
                        dt { "Token" } dd class="mono" { (masked(&entry.notice_token)) }
                        dt { "Avisos enviados" } dd { (sent) }
                        dt { "Cuentas suspendidas" } dd { (ok) }
                    }
                    p class="hint" { "Los cambios valen para los rastreos que empiecen desde ahora." }
                }
                section class="panel danger-zone" aria-labelledby="pf-danger" {
                    h2 id="pf-danger" { "Quitar del registro" }
                    p class="hint" { "Strack deja de aceptar sus marcas y de avisarle. Los avisos ya enviados quedan en la auditoría." }
                    form method="post" action={ "/admin/platforms/" (entry.id) "/delete" } {
                        input type="hidden" name="csrf" value=(session.csrf);
                        label class="choice" {
                            input type="checkbox" name="confirm" value="yes" required;
                            span { "Entiendo que no se puede deshacer" }
                        }
                        button class="button danger" type="submit" { "Quitar plataforma" }
                    }
                }
            }
        }
    };
    Html(page(&entry.name, Some(&session), Nav::Platforms, body).into_string()).into_response()
}

pub async fn platform_update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<PlatformForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/platforms/{id}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    let token = form.notice_token.clone().unwrap_or_default();
    let token_changed = !token.trim().is_empty();
    let (target, name, url) = (id.clone(), form.name.clone(), form.api_url.clone());
    let result = change_platforms(&app, move |file| {
        update_platform(file, PlatformInput { id: &target, name: &name, api_url: &url, notice_token: &token })
    })
    .await;
    match result {
        Ok(entry) => {
            app.core().record(
                &actor(&session),
                "platform_updated",
                json!({"platform_id": entry.id, "name": entry.name, "api_url": entry.api_url, "token_changed": token_changed}),
            );
            Redirect::to(&format!("{back}?msg=platform_updated")).into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}

pub async fn platform_delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let session = match admin_session(&app, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let back = format!("/admin/platforms/{id}");
    if !csrf_ok(&session, &form.csrf) {
        return Redirect::to(&format!("{back}?error=csrf")).into_response();
    }
    if form.confirm.as_deref() != Some("yes") {
        return Redirect::to(&format!("{back}?error=confirm_required")).into_response();
    }
    let target = id.clone();
    match change_platforms(&app, move |file| delete_platform(file, &target)).await {
        Ok(entry) => {
            app.core().record(
                &actor(&session),
                "platform_deleted",
                json!({"platform_id": entry.id, "name": entry.name}),
            );
            Redirect::to("/admin/platforms?msg=platform_deleted").into_response()
        }
        Err(e) => Redirect::to(&format!("{back}?error={}", e.code())).into_response(),
    }
}
