//! Demo licensed platform ("TV Ficticia Play"). Subscribers sign up, sign in and watch the match;
//! every viewing session carries its own hidden mark, and leak notices from Strack suspend the
//! subscriber and close their sessions at once.
//!
//! - `demo::accounts`: subscriber directory (a JSON file), browser sessions, password links and the
//!   demo mailbox that stands in for email.
//! - `demo::site`: the subscriber side (sign-up, sign-in, recovery, "Mi cuenta", the live player).
//! - `demo::staff`: the staff console (subscriber CRUD, viewing sessions, notices received).
//! - here: startup, shared state and page parts, the live streams and the JSON API (scripted sign-in
//!   for the demo pirate, leak notices from Strack).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use image::{Rgb, RgbImage};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{broadcast, mpsc};

use crate::crypto::{constant_time_eq, random_token};
use crate::demo::accounts::{
    DEMO_PASSWORD, Directory, LINK_TTL, Links, Mail, Mailbox, SESSION_TTL, WebSession, WebSessions, Who,
};
use crate::demo::encoder::{self, Audio, Input};
use crate::demo::video::VideoSource;
use crate::demo::{css, security_headers, site, staff};
use crate::judges::{hash_password, verify_password};
use crate::leak::jpeg::encode;
use crate::leak::mark::{SessionMark, client_label, platform_code};
use crate::leak::mjpeg::{self, part};
use crate::leak::platforms::{NoticeAck, NoticeRequest};
use crate::leak::raster::QrMatrix;
use crate::leak::scene::{overlay_mark, render_base, slate};
use crate::leak::watermark::{self, DEFAULT_STRENGTH};
use crate::workflow::now_rfc3339;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MarkMode {
    /// Invisible watermark (default): only software can read it.
    Invisible,
    /// Visible QR code with the subscriber number, to show what the mark carries.
    Visible,
}

#[derive(Args, Clone)]
pub struct PlatformArgs {
    #[arg(long, default_value = "127.0.0.1:8100")]
    pub listen: SocketAddr,
    /// Platform id; marks carry its 16-bit code (it must match `config/platforms.json` in Strack).
    #[arg(long, default_value = "tvf")]
    pub id: String,
    #[arg(long, default_value = "TV Ficticia Play")]
    pub name: String,
    /// How the session mark is drawn on the picture (the JPEG metadata copy is always written).
    #[arg(long, value_enum, default_value = "invisible")]
    pub mark: MarkMode,
    /// Peak brightness shift of the invisible watermark, in levels of 255.
    #[arg(long, default_value_t = DEFAULT_STRENGTH)]
    pub mark_strength: f32,
    /// Token Strack must present to send notices (demo value, also in `config/platforms.json`).
    #[arg(
        long,
        env = "STRACK_DEMO_NOTICE_TOKEN",
        default_value = "tvf-demo-notice-token-2026",
        hide_env_values = true
    )]
    pub notice_token: String,
    /// Frames per second of the synthetic match (with `--video` the file's own rate is used).
    #[arg(long, default_value_t = 25)]
    pub fps: u32,
    #[arg(long, default_value_t = 80)]
    pub quality: u8,
    /// Where subscriber accounts are saved. A missing file is created with `--subscribers` demo accounts.
    #[arg(long, default_value = "var/demo-platform/subscribers.json")]
    pub data: PathBuf,
    /// Demo subscribers (c-00041, c-00042, ...) seeded into a new `--data` file, all with the demo password.
    #[arg(long, default_value_t = 6)]
    pub subscribers: u32,
    /// Staff user for the subscriber console (`/admin`).
    #[arg(long, default_value = "personal")]
    pub staff_user: String,
    /// Staff password for the subscriber console (demo value, documented in the README).
    #[arg(long, env = "STRACK_DEMO_STAFF_PASSWORD", default_value = "personal-demo-2026", hide_env_values = true)]
    pub staff_password: String,
    /// Broadcast this video file instead of the synthetic match (decoded with ffmpeg at its own size and rate).
    #[arg(long)]
    pub video: Option<PathBuf>,
    /// Take the sound from this file instead of the `--video` file: another copy of the same video
    /// with the same timeline (e.g. a lower-quality download that has the audio track).
    #[arg(long, requires = "video")]
    pub audio: Option<PathBuf>,
    /// Second of the video to start from.
    #[arg(long, default_value_t = 0.0)]
    pub video_start: f64,
    /// ffmpeg executable used with `--video`.
    #[arg(long, default_value = "ffmpeg")]
    pub ffmpeg: String,
    /// Start the video again when it ends (by default the broadcast ends with the file).
    #[arg(long = "loop")]
    pub loop_video: bool,
}

/// One viewing session: what a subscriber is watching right now, with its own mark.
pub struct LiveSession {
    pub mark: SessionMark,
    pub qr: Option<Arc<QrMatrix>>,
    /// Bearer key in the stream address handed to scripted clients (`/live/<id>.mjpg?key=`).
    pub key: String,
    pub started_at: String,
    pub closed_at: Option<String>,
}

pub struct NoticeEntry {
    pub at: String,
    pub notice_id: String,
    pub client: String,
    pub session: String,
    pub result: &'static str,
    pub pirate_url: String,
}

pub struct PlatformState {
    pub directory: Directory,
    pub sessions: Vec<LiveSession>,
    pub notices: Vec<NoticeEntry>,
    pub web: WebSessions,
    pub links: Links,
    pub mailbox: Mailbox,
}

/// Why a password link is sent.
#[derive(Clone, Copy)]
pub enum LinkKind {
    /// The subscriber asked to recover the account, or the staff sent a new link.
    Recovery,
    /// The staff created the account without a password: the subscriber chooses it.
    Welcome,
}

impl PlatformState {
    /// Closes every open viewing session of a subscriber; returns how many.
    pub fn close_sessions(&mut self, number: u32, at: &str) -> u32 {
        let mut closed = 0;
        for live in self.sessions.iter_mut().filter(|s| s.mark.client == number && s.closed_at.is_none()) {
            live.closed_at = Some(at.to_string());
            closed += 1;
        }
        closed
    }

    /// Mails a one-time password link to the subscriber (to the demo mailbox). `false` if unknown.
    pub fn send_link(&mut self, brand: &str, number: u32, kind: LinkKind) -> bool {
        let Some(subscriber) = self.directory.find(number) else { return false };
        let (name, email, label) = (subscriber.name.clone(), subscriber.email.clone(), subscriber.label());
        let token = self.links.issue(number);
        let minutes = LINK_TTL.as_secs() / 60;
        let (subject, text) = match kind {
            LinkKind::Recovery => (
                "Elegí una contraseña nueva".to_string(),
                format!(
                    "Hola, {name}. Pediste recuperar tu cuenta de {brand} ({label}). Este enlace sirve una sola vez y \
                     vence en {minutes} minutos. Si no lo pediste vos, ignorá este correo: tu contraseña no cambia."
                ),
            ),
            LinkKind::Welcome => (
                format!("Tu cuenta en {brand}"),
                format!(
                    "Hola, {name}. El personal de {brand} te creó una cuenta ({label}). Elegí tu contraseña con este \
                     enlace: sirve una sola vez y vence en {minutes} minutos."
                ),
            ),
        };
        self.mailbox.send(Mail { at: now_rfc3339(), to: email, subject, text, link: Some(format!("/reset/{token}")) });
        true
    }
}

/// One picture of the shared broadcast, before any session mark; `t` is the broadcast clock in seconds.
pub struct Frame {
    pub t: f64,
    pub img: RgbImage,
    /// Second of the source video file this picture comes from (`None` for the synthetic match).
    pub pos: Option<f64>,
    /// The closing card: the file ended and so did the broadcast.
    pub last: bool,
}

/// Frames buffered per viewer before a slow one starts losing pictures (a little over half a second
/// of 720p; each frame is shared, not copied).
const FEED_CAPACITY: usize = 16;

pub struct Platform {
    pub id: String,
    pub name: String,
    pub mode: MarkMode,
    strength: f32,
    notice_token: String,
    quality: u8,
    state: Mutex<PlatformState>,
    /// Every frame of the broadcast, in order, to every viewer.
    feed: broadcast::Sender<Arc<Frame>>,
    /// Frame rate as a fraction: the file's own with `--video`, else `--fps`.
    rate: (u32, u32),
    /// Picture size: the file's own with `--video`, else the synthetic scene's.
    pub picture: (u32, u32),
    pub ended: Arc<AtomicBool>,
    ffmpeg: String,
    /// File the sound comes from: `--audio`, else the `--video` file itself.
    audio: Option<PathBuf>,
    data_path: PathBuf,
    pub staff_user: String,
    pub staff_password: String,
}

impl Platform {
    pub fn state(&self) -> MutexGuard<'_, PlatformState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Saves the subscriber directory; called with the state locked, after every change to it.
    pub fn save(&self, state: &PlatformState) -> bool {
        match state.directory.save(&self.data_path) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "could not save the subscriber directory");
                false
            }
        }
    }

    /// Back to the start of the demo: every account active again, every viewing session closed,
    /// no notices. Accounts themselves are kept.
    pub fn reset(&self) {
        let mut state = self.state();
        state.directory.reactivate_all();
        let at = now_rfc3339();
        for live in state.sessions.iter_mut().filter(|s| s.closed_at.is_none()) {
            live.closed_at = Some(at.clone());
        }
        state.notices.clear();
        self.save(&state);
    }

    /// Opens a viewing session for a subscriber: `(session id, stream key)`; `Err` is the API error code.
    pub fn open_session(&self, client: u32) -> Result<(String, String), &'static str> {
        let mut state = self.state();
        let subscriber = state.directory.find(client).ok_or("unknown_client")?;
        if subscriber.suspended.is_some() {
            return Err("suspended");
        }
        if self.ended.load(Ordering::Relaxed) {
            return Err("ended");
        }
        let mark = SessionMark::new(&self.id, client, u64::from(rand::random::<u32>().max(1)));
        let qr = match self.mode {
            MarkMode::Visible => Some(Arc::new(QrMatrix::new(&mark.text()).ok_or("mark_too_long")?)),
            MarkMode::Invisible => None,
        };
        let key = random_token(16);
        state.sessions.push(LiveSession { mark, qr, key: key.clone(), started_at: now_rfc3339(), closed_at: None });
        tracing::info!(client = %client_label(client), session = %mark.session_hex(), "session opened");
        Ok((mark.session_hex(), key))
    }

    pub fn session_closed(&self, session: u64) -> bool {
        self.state().sessions.iter().find(|s| s.mark.session == session).is_none_or(|s| s.closed_at.is_some())
    }
}

fn suspended_slate() -> RgbImage {
    slate("CUENTA SUSPENDIDA", "Retransmisión no autorizada de esta sesión", Rgb([120, 16, 24]))
}

pub fn end_slate() -> RgbImage {
    slate("FIN DEL PARTIDO", "La transmisión terminó", Rgb([16, 22, 38]))
}

pub async fn run(args: PlatformArgs) -> anyhow::Result<()> {
    let channel = args.name.to_uppercase();
    let (feed, _) = broadcast::channel::<Arc<Frame>>(FEED_CAPACITY);
    let source = match args.video.clone() {
        Some(path) => Some(VideoSource::new(path, args.ffmpeg.clone(), args.video_start, args.loop_video)?),
        None => None,
    };
    if let Some(audio) = &args.audio
        && !audio.is_file()
    {
        anyhow::bail!("audio file not found: {}", audio.display());
    }
    let directory = match Directory::load(&args.data)? {
        Some(directory) => {
            tracing::info!(file = %args.data.display(), subscribers = directory.subscribers.len(), "subscribers loaded");
            directory
        }
        None => {
            // Every demo subscriber shares the demo password, so it is hashed once.
            let hash = hash_password(DEMO_PASSWORD)?;
            let directory = Directory::seeded(args.subscribers.clamp(1, 1000), &hash, &now_rfc3339());
            directory.save(&args.data).with_context(|| format!("writing {}", args.data.display()))?;
            tracing::info!(file = %args.data.display(), subscribers = directory.subscribers.len(), "demo subscribers created");
            directory
        }
    };
    let rate = source.as_ref().map_or((args.fps.clamp(1, 30), 1), |s| s.rate);
    let picture =
        source.as_ref().map_or((crate::leak::scene::WIDTH, crate::leak::scene::HEIGHT), |s| (s.width, s.height));
    let ended = Arc::new(AtomicBool::new(false));
    let platform = Arc::new(Platform {
        id: args.id.clone(),
        name: args.name.clone(),
        mode: args.mark,
        strength: args.mark_strength.clamp(0.5, 8.0),
        notice_token: args.notice_token.clone(),
        quality: args.quality.clamp(30, 95),
        state: Mutex::new(PlatformState {
            directory,
            sessions: Vec::new(),
            notices: Vec::new(),
            web: WebSessions::default(),
            links: Links::default(),
            mailbox: Mailbox::default(),
        }),
        feed: feed.clone(),
        rate,
        picture,
        ended: ended.clone(),
        ffmpeg: args.ffmpeg.clone(),
        audio: args.audio.clone().or_else(|| args.video.clone()),
        data_path: args.data.clone(),
        staff_user: args.staff_user.clone(),
        staff_password: args.staff_password.clone(),
    });

    // One shared broadcast; each session only adds its mark. Nothing is decoded while nobody watches.
    match source {
        Some(source) => {
            tracing::info!(
                file = %source.path.display(),
                width = source.width,
                height = source.height,
                rate = format!("{}/{}", source.rate.0, source.rate.1),
                duration = ?source.duration,
                "broadcasting a video file"
            );
            let clock = Instant::now();
            std::thread::spawn(move || crate::demo::video::run(source, feed, channel, clock, ended));
        }
        None => {
            tokio::spawn(synthetic(feed, channel, rate.0));
        }
    }

    let app = Router::new()
        .route("/", get(site::home))
        .route("/signup", get(site::signup_page).post(site::signup))
        .route("/login", get(site::login_page).post(site::login))
        .route("/logout", post(site::logout))
        .route("/recover", get(site::recover_page).post(site::recover))
        .route("/reset/{token}", get(site::reset_page).post(site::reset))
        .route("/mailbox", get(site::mailbox_page).post(site::mailbox))
        .route("/account", get(site::account_page))
        .route("/account/profile", post(site::account_profile))
        .route("/account/password", post(site::account_password))
        .route("/account/delete", post(site::account_delete))
        .route("/watch", post(site::watch_start))
        .route("/watch/{session}", get(site::watch_page))
        .route("/live/{file}", get(live))
        .route("/admin", get(staff::console))
        .route("/admin/login", get(staff::login_page).post(staff::login))
        .route("/admin/subscribers", post(staff::create))
        .route("/admin/subscribers/{number}", get(staff::detail))
        .route("/admin/subscribers/{number}/profile", post(staff::update))
        .route("/admin/subscribers/{number}/{action}", post(staff::action))
        .route("/admin/reset", post(staff::reset))
        .route("/api/sessions", post(api_session))
        .route("/api/notices", post(api_notice))
        .route("/static/demo.css", get(css))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(platform);
    let listener =
        tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!("demo platform {} listening on http://{}", args.name, args.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// The synthetic match, rendered at `fps` while somebody watches.
async fn synthetic(tx: broadcast::Sender<Arc<Frame>>, channel: String, fps: u32) {
    let start = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(fps)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if tx.receiver_count() == 0 {
            continue;
        }
        let t = start.elapsed().as_secs_f64();
        let channel = channel.clone();
        let Ok(img) = tokio::task::spawn_blocking(move || render_base(t, &channel)).await else { break };
        let _ = tx.send(Arc::new(Frame { t, img, pos: None, last: false }));
    }
}

// ---------------------------------------------------------------------------------------------
// Shared web parts: browser session, passwords, page shell and messages.

pub const COOKIE: &str = "tvf_session";

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_string())
}

pub fn web_session(p: &Platform, headers: &HeaderMap) -> Option<WebSession> {
    let token = cookie_token(headers)?;
    p.state().web.get(&token)
}

pub fn sign_in_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}", SESSION_TTL.as_secs())
}

pub fn sign_out_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

pub fn csrf_ok(session: &WebSession, submitted: &str) -> bool {
    constant_time_eq(&session.csrf, submitted)
}

/// Argon2id off the async runtime.
pub async fn hash(password: String) -> Option<String> {
    tokio::task::spawn_blocking(move || hash_password(&password).ok()).await.ok().flatten()
}

/// Checks a password against a stored hash. Without one, a dummy hash is checked so that unknown
/// accounts take as long as known ones.
pub async fn verify(stored: Option<String>, password: String) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    tokio::task::spawn_blocking(move || match stored {
        Some(stored) => verify_password(&stored, &password),
        None => {
            let dummy = DUMMY.get_or_init(|| hash_password("timing-equaliser-password").unwrap_or_default());
            verify_password(dummy, &password);
            false
        }
    })
    .await
    .unwrap_or(false)
}

/// The page shell. The state is locked briefly for the subscriber's name: never call it with the
/// state locked.
pub fn page(p: &Platform, title: &str, session: Option<&WebSession>, body: Markup) -> Html<String> {
    let name = match session.map(|s| s.who) {
        Some(Who::Subscriber(number)) => p.state().directory.find(number).map(|s| s.name.clone()),
        _ => None,
    };
    let markup = html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · " (p.name) }
                link rel="stylesheet" href="/static/demo.css";
            }
            body class="platform" {
                a class="skip" href="#main" { "Saltar al contenido" }
                header class="bar" {
                    div class="wrap" {
                        a class="brand" href="/" { (p.name) }
                        span class="tag" { "Plataforma licenciataria · demo" }
                        nav class="site-nav" aria-label="Cuenta" {
                            @match session {
                                None => {
                                    a href="/login" { "Ingresar" }
                                    a class="button" href="/signup" { "Crear cuenta" }
                                }
                                Some(s) => {
                                    @if s.who == Who::Staff {
                                        a href="/admin" { "Abonados" }
                                        a href="/mailbox" { "Buzón de la demo" }
                                    } @else {
                                        a href="/" { "Partido" }
                                        a href="/account" {
                                            "Mi cuenta"
                                            @if let Some(name) = &name { span class="who" { " · " (name) } }
                                        }
                                    }
                                    form method="post" action="/logout" {
                                        input type="hidden" name="csrf" value=(s.csrf);
                                        button type="submit" class="secondary" { "Salir" }
                                    }
                                }
                            }
                        }
                    }
                }
                main id="main" class="wrap" { (body) }
                footer class="wrap foot" {
                    p {
                        "Plataforma ficticia para la demo de Strack: abonados, cuentas y partido son inventados. "
                        a href="/mailbox" { "Buzón de la demo" } " · " a href="/admin/login" { "Acceso del personal" }
                    }
                }
            }
        }
    };
    Html(markup.into_string())
}

/// Text and tone (`true` = done, `false` = problem) for a `?msg=` / `?error=` code.
pub fn message(code: &str) -> Option<(&'static str, bool)> {
    Some(match code {
        "welcome" => ("Tu cuenta está lista. Ya podés mirar el partido.", true),
        "signed_out" => ("Cerraste la sesión.", true),
        "password_reset" => ("Listo: tu contraseña cambió. Ingresá con la nueva.", true),
        "profile_saved" => ("Datos guardados.", true),
        "password_changed" => ("Contraseña cambiada. Cerramos tus otras sesiones.", true),
        "account_deleted" => ("Eliminamos tu cuenta y cerramos sus sesiones.", true),
        "created" => ("Abonado creado.", true),
        "created_link" => ("Abonado creado. Le mandamos un enlace para elegir su contraseña.", true),
        "link_sent" => ("Le mandamos un enlace para elegir una contraseña nueva.", true),
        "suspended" => ("Cuenta suspendida y sesiones cerradas.", true),
        "reactivated" => ("Cuenta reactivada.", true),
        "deleted" => ("Abonado eliminado.", true),
        "demo_reset" => ("Demo reiniciada: cuentas reactivadas y sesiones cerradas.", true),
        "name_required" => ("Falta el nombre.", false),
        "invalid_email" => ("El correo no es válido.", false),
        "email_taken" => ("Ya hay una cuenta con ese correo.", false),
        "invalid_plan" => ("Elegí uno de los planes.", false),
        "password_too_short" => ("La contraseña necesita al menos 10 caracteres.", false),
        "password_mismatch" => ("Las contraseñas no coinciden.", false),
        "wrong_password" => ("La contraseña no es correcta.", false),
        "not_found" => ("Ese abonado no existe.", false),
        "csrf" => ("El formulario venció. Volvé a intentarlo.", false),
        "confirm_required" => ("Marcá la casilla para confirmar.", false),
        "account_suspended" => ("Tu cuenta está suspendida: no puede abrir sesiones.", false),
        "sign_in" => ("Ingresá para seguir.", false),
        "ended" => ("La transmisión terminó.", false),
        "internal" => ("No pudimos guardar el cambio. Probá de nuevo.", false),
        "invalid_login" => ("Correo, número o contraseña incorrectos.", false),
        "invalid_staff" => ("Usuario o contraseña incorrectos.", false),
        "locked_out" => ("Demasiados intentos fallidos. Esperá 30 segundos y volvé a intentar.", false),
        _ => return None,
    })
}

pub fn flash(msg: Option<&str>, error: Option<&str>) -> Markup {
    html! {
        @if let Some((text, _)) = error.and_then(message) { p class="alert" role="alert" { (text) } }
        @if let Some((text, _)) = msg.and_then(message) { p class="ok-note" role="status" { (text) } }
    }
}

#[derive(Deserialize, Default)]
pub struct FlashQuery {
    pub msg: Option<String>,
    pub error: Option<String>,
    /// Search text (staff console).
    pub q: Option<String>,
}

pub fn mark_explanation(mode: MarkMode) -> &'static str {
    match mode {
        MarkMode::Invisible => {
            "Cada sesión transmite el partido con una marca de agua invisible: el brillo de pequeños bloques de la imagen \
             varía apenas (2 niveles sobre 255), lento y suave, con un patrón que identifica la plataforma, el abonado y la \
             sesión. A simple vista no se nota; un programa la lee comparando cuadros. Además va una copia como metadato \
             de cada cuadro. Si alguien retransmite la señal, Strack lee la marca y nos avisa: suspendemos la cuenta y \
             cortamos la sesión."
        }
        MarkMode::Visible => {
            "Modo de demostración: cada sesión muestra su marca como un código QR visible con el número de abonado. \
             Si alguien retransmite la señal, Strack lee la marca y nos avisa: suspendemos la cuenta y cortamos la sesión."
        }
    }
}

pub fn parse_session(hex: &str) -> Option<u64> {
    (hex.len() == 8).then(|| u64::from_str_radix(hex, 16).ok()).flatten()
}

async fn not_found(State(p): State<Arc<Platform>>, headers: HeaderMap) -> Response {
    let session = web_session(&p, &headers);
    let body = html! {
        h1 { "Página inexistente" }
        p class="lede" { "La dirección no corresponde a ninguna página." }
        p { a href="/" { "Ir al inicio" } }
    };
    (StatusCode::NOT_FOUND, page(&p, "Página inexistente", session.as_ref(), body)).into_response()
}

// ---------------------------------------------------------------------------------------------
// Live streams.

#[derive(Deserialize)]
struct StreamQuery {
    key: Option<String>,
}

/// A stream is served to the subscriber who opened it (browser session), to the staff, or to a
/// scripted client holding the key `/api/sessions` returned.
fn may_watch(live: &LiveSession, key: Option<&str>, viewer: Option<&WebSession>) -> bool {
    key.is_some_and(|k| constant_time_eq(k, &live.key))
        || viewer.is_some_and(|v| v.who == Who::Staff || v.who == Who::Subscriber(live.mark.client))
}

async fn live(
    State(p): State<Arc<Platform>>,
    Path(file): Path<String>,
    Query(q): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    let viewer = web_session(&p, &headers);
    let (session, video) = match (file.strip_suffix(".mp4"), file.strip_suffix(".mjpg")) {
        (Some(id), _) => (parse_session(id), true),
        (_, Some(id)) => (parse_session(id), false),
        _ => (None, false),
    };
    let Some(session) = session else { return StatusCode::NOT_FOUND.into_response() };
    let found = {
        let state = p.state();
        state
            .sessions
            .iter()
            .find(|s| s.mark.session == session)
            .map(|s| (s.mark, s.qr.clone(), s.closed_at.is_some(), may_watch(s, q.key.as_deref(), viewer.as_ref())))
    };
    let Some((mark, qr, closed, allowed)) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    if video {
        return live_video(p, session, mark, qr, closed).await;
    }
    let (tx, rx) = mpsc::channel::<Bytes>(2);
    let (quality, strength) = (p.quality, p.strength);
    let mut feed = p.feed.subscribe();
    tokio::spawn(async move {
        if !closed && !p.ended.load(Ordering::Relaxed) {
            let text = mark.text();
            let mut pattern: Option<Arc<watermark::Pattern>> = None;
            loop {
                let frame = match feed.recv().await {
                    Ok(frame) => frame,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if frame.last || p.session_closed(session) {
                    break;
                }
                let (w, h) = frame.img.dimensions();
                let pat = match &pattern {
                    Some(pat) if pat.size() == (w, h) => pat.clone(),
                    _ => {
                        let pat = Arc::new(watermark::Pattern::new(&mark, w, h));
                        pattern = Some(pat.clone());
                        pat
                    }
                };
                let (qr, text) = (qr.clone(), text.clone());
                let jpeg = tokio::task::spawn_blocking(move || {
                    let mut img = frame.img.clone();
                    match &qr {
                        Some(qr) => overlay_mark(&mut img, &mark, qr, frame.t),
                        None => pat.apply(&mut img, frame.t, strength),
                    }
                    encode(&img, quality, Some(&text))
                })
                .await;
                let Ok(Ok(jpeg)) = jpeg else { break };
                if tx.send(part(&jpeg)).await.is_err() {
                    return;
                }
            }
        }
        // A closed session ends with the suspension card, a finished broadcast with its closing card.
        let card =
            if p.ended.load(Ordering::Relaxed) && !p.session_closed(session) { end_slate() } else { suspended_slate() };
        if let Ok(Ok(jpeg)) = tokio::task::spawn_blocking(move || encode(&card, 80, None)).await {
            let _ = tx.send(part(&jpeg)).await;
        }
    });
    mjpeg::response(rx)
}

/// The session as real video for a person: every original frame at its own size and rate, with the
/// session's invisible mark, encoded to H.264 (with the file's sound when it has any) for a `<video>`
/// player. Ends with the suspension card if the account is cut, or the closing card with the file.
async fn live_video(
    p: Arc<Platform>,
    session: u64,
    mark: SessionMark,
    qr: Option<Arc<QrMatrix>>,
    closed: bool,
) -> Response {
    if closed || p.ended.load(Ordering::Relaxed) {
        return StatusCode::GONE.into_response();
    }
    let mut feed = p.feed.subscribe();
    // The first frame gives the picture size and where the file is, for the sound.
    let first = loop {
        match tokio::time::timeout(Duration::from_secs(10), feed.recv()).await {
            Ok(Ok(frame)) => break frame,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    };
    let (width, height) = first.img.dimensions();
    let audio = p.audio.clone().zip(first.pos).map(|(file, position)| Audio { file, position });
    let (encoder, response) = match encoder::start(&p.ffmpeg, p.rate, Input::Rgb { width, height }, audio) {
        Ok(started) => started,
        Err(e) => {
            tracing::warn!(error = %e, "could not start the video encoder (is ffmpeg installed?)");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let strength = p.strength;
    let closing_frames = 3 * p.rate.0 / p.rate.1.max(1);
    std::thread::spawn(move || {
        let pattern = watermark::Pattern::new(&mark, width, height);
        let mark_frame = |frame: &Frame| {
            let mut img = frame.img.clone();
            match &qr {
                Some(qr) => overlay_mark(&mut img, &mark, qr, frame.t),
                None => pattern.apply(&mut img, frame.t, strength),
            }
            img.into_raw()
        };
        let card = |img: RgbImage| {
            image::imageops::resize(&img, width, height, image::imageops::FilterType::Triangle).into_raw()
        };
        let mut pending = Some(first);
        let mut closing: Option<(Vec<u8>, u32)> = None;
        // The sound comes straight from the file and never skips, so a lost picture is replaced by
        // the previous one: the picture freezes for a moment instead of running ahead of the sound.
        let mut last_picture: Vec<u8> = Vec::new();
        let mut hold: u64 = 0;
        encoder.run_each(|| {
            if let Some((frame, left)) = closing.as_mut() {
                *left = left.checked_sub(1)?;
                std::thread::sleep(Duration::from_secs_f64(f64::from(p.rate.1) / f64::from(p.rate.0)));
                return Some(frame.clone());
            }
            if hold > 0 && !last_picture.is_empty() {
                hold -= 1;
                return Some(last_picture.clone());
            }
            let frame = match pending.take() {
                Some(frame) => frame,
                None => loop {
                    match feed.blocking_recv() {
                        Ok(frame) => break frame,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "a viewer's encoder fell behind: holding the last picture");
                            hold += skipped;
                            if !last_picture.is_empty() {
                                hold -= 1;
                                return Some(last_picture.clone());
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                },
            };
            if p.session_closed(session) || frame.last {
                let picture = if frame.last { card(end_slate()) } else { card(suspended_slate()) };
                closing = Some((picture.clone(), closing_frames));
                return Some(picture);
            }
            let picture =
                if frame.img.dimensions() != (width, height) { card(frame.img.clone()) } else { mark_frame(&frame) };
            last_picture.clone_from(&picture);
            Some(picture)
        });
    });
    response
}

// ---------------------------------------------------------------------------------------------
// JSON API.

#[derive(Deserialize)]
struct SessionRequest {
    /// Subscriber number (`c-00042`) or email.
    #[serde(alias = "email")]
    client_id: String,
    password: String,
}

fn api_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

/// Subscriber sign-in for scripted clients (the demo pirate uses it with the accounts it holds):
/// opens a viewing session and returns the stream address with its key.
async fn api_session(State(p): State<Arc<Platform>>, Json(req): Json<SessionRequest>) -> Response {
    let login = req.client_id.trim().to_string();
    if p.state().web.is_locked_out(&login) {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "locked_out");
    }
    let found = p.state().directory.find_login(&login).map(|s| (s.number, s.password_hash.clone()));
    let verified = verify(found.as_ref().map(|(_, hash)| hash.clone()), req.password).await;
    let Some((number, _)) = found.filter(|_| verified) else {
        p.state().web.record_failure(&login);
        return api_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    };
    p.state().web.clear_failures(&login);
    match p.open_session(number) {
        Ok((session, key)) => (
            StatusCode::CREATED,
            Json(json!({"session_id": session, "stream_path": format!("/live/{session}.mjpg?key={key}")})),
        )
            .into_response(),
        Err(code) => api_error(StatusCode::FORBIDDEN, code),
    }
}

/// Leak notice from Strack: check that we issued that session to that subscriber, suspend the
/// subscriber and close all their sessions.
async fn api_notice(State(p): State<Arc<Platform>>, headers: HeaderMap, Json(req): Json<NoticeRequest>) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_eq(token, &p.notice_token) {
        return api_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let mut state = p.state();
    let log = |state: &mut PlatformState, client: &str, session: &str, result: &'static str| {
        state.notices.push(NoticeEntry {
            at: now_rfc3339(),
            notice_id: req.notice_id.clone(),
            client: client.to_string(),
            session: session.to_string(),
            result,
            pirate_url: req.pirate_url.clone(),
        });
    };
    let mark = match SessionMark::parse(&req.mark) {
        Some(mark) if mark.platform == platform_code(&p.id) => mark,
        _ => {
            log(&mut state, "—", "—", "Rechazado: no es una marca de esta plataforma");
            tracing::warn!(notice = %req.notice_id, "notice with a malformed or foreign mark");
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_mark");
        }
    };
    let (client, session) = (mark.client_label(), mark.session_hex());
    let Some(owner) = state.sessions.iter().find(|s| s.mark.session == mark.session).map(|s| s.mark.client) else {
        log(&mut state, &client, &session, "Rechazado: sesión inexistente");
        return api_error(StatusCode::NOT_FOUND, "unknown_session");
    };
    if owner != mark.client {
        log(&mut state, &client, &session, "Rechazado: la sesión es de otro abonado");
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_mark");
    }
    let at = now_rfc3339();
    // A subscriber deleted since then has nothing left to suspend; their sessions still close.
    let already = state.directory.suspend(owner, &at, &req.notice_id).unwrap_or(false);
    let closed = state.close_sessions(owner, &at);
    p.save(&state);
    let result = if already { "Ya estaba suspendida" } else { "Cuenta suspendida y sesiones cerradas" };
    log(&mut state, &client, &session, result);
    tracing::info!(client = %client, session = %session, closed, notice = %req.notice_id, "subscriber suspended");
    Json(NoticeAck {
        status: if already { "already_suspended" } else { "suspended" }.to_string(),
        client_id: client,
        session_id: session,
        sessions_closed: closed,
        at,
    })
    .into_response()
}
