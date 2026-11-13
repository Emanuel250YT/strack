//! Demo pirate site: restreams the licensed platform with subscriber accounts. It re-encodes and
//! rescales the picture (the metadata copy of the mark is lost), covers the broadcaster's bug and one
//! corner with its own logo, and switches to the next account whenever the current one is cut.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router, middleware};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use image::{Rgb, RgbImage, imageops};
use maud::{DOCTYPE, html};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use crate::demo::encoder::{self, Input};
use crate::demo::{clock_time, css, security_headers};
use crate::leak::jpeg::{decode_rgb, encode};
use crate::leak::mark::{client_label, parse_client};
use crate::leak::mjpeg::{self, part};
use crate::leak::raster::{draw_text, draw_text_centered, fill_rect, text_width};
use crate::leak::scene::{Corner, slate};
use crate::workflow::now_rfc3339;

const PIRATE_RED: Rgb<u8> = Rgb([176, 18, 30]);
const PIRATE_INK: Rgb<u8> = Rgb([255, 236, 140]);

#[derive(Clone, Copy, ValueEnum)]
pub enum CoverArg {
    None,
    TopLeft,
    TopRight,
    BottomRight,
    BottomLeft,
}

impl CoverArg {
    fn corner(self) -> Option<Corner> {
        match self {
            CoverArg::None => None,
            CoverArg::TopLeft => Some(Corner::TopLeft),
            CoverArg::TopRight => Some(Corner::TopRight),
            CoverArg::BottomRight => Some(Corner::BottomRight),
            CoverArg::BottomLeft => Some(Corner::BottomLeft),
        }
    }
}

#[derive(Args, Clone)]
pub struct PirateArgs {
    #[arg(long, default_value = "127.0.0.1:8200")]
    pub listen: SocketAddr,
    /// Licensed platform the pirate watches with subscriber accounts.
    #[arg(long, default_value = "http://127.0.0.1:8100")]
    pub platform: String,
    /// Subscriber accounts the pirate holds, used one after another as each one is cut. Ranges work
    /// too: `c-00042..c-00120`.
    #[arg(long, value_delimiter = ',', default_value = "c-00042,c-00043,c-00044")]
    pub accounts: Vec<String>,
    /// Password of those accounts (the demo subscribers' shared demo password).
    #[arg(
        long,
        env = "STRACK_DEMO_SUBSCRIBER_PASSWORD",
        default_value = crate::demo::accounts::DEMO_PASSWORD,
        hide_env_values = true
    )]
    pub password: String,
    /// Name shown on the pirate overlay.
    #[arg(long, default_value = "pelotaya.test")]
    pub site: String,
    #[arg(long, default_value_t = 60)]
    pub quality: u8,
    /// Size of the restream relative to the original picture, in percent.
    #[arg(long, default_value_t = 80)]
    pub scale: u32,
    /// Seconds showing "no signal" before switching to the next account (how long it takes the pirate
    /// to get going again).
    #[arg(long, default_value_t = 6)]
    pub switch_secs: u64,
    /// Corner the pirate covers with its logo, trying to hide the mark.
    #[arg(long, value_enum, default_value = "top-left")]
    pub cover: CoverArg,
    /// ffmpeg executable for the video player on the pirate page.
    #[arg(long, default_value = "ffmpeg")]
    pub ffmpeg: String,
    /// Frames per second of the pirate page's video player (the source's rate, rounded up).
    #[arg(long, default_value_t = 30)]
    pub fps: u32,
}

/// One account's time on air: from the first relayed frame until the source was lost.
#[derive(Clone, serde::Serialize)]
struct Stint {
    account: String,
    started_at: String,
    ended_at: Option<String>,
    on_air_secs: Option<f64>,
}

#[derive(Clone, serde::Serialize)]
struct Status {
    state: &'static str,
    account: Option<String>,
    accounts_used: usize,
    accounts_total: usize,
    history: Vec<Stint>,
}

struct Pirate {
    args: PirateArgs,
    accounts: Vec<String>,
    frames: watch::Sender<Option<Bytes>>,
    status: Mutex<Status>,
}

impl Pirate {
    fn status(&self) -> MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_status(&self, state: &'static str, account: Option<&str>, used: usize) {
        let mut status = self.status();
        status.state = state;
        status.account = account.map(str::to_string);
        status.accounts_used = used;
    }
}

/// Expands `c-00042..c-00045` style ranges; other entries pass through.
fn expand_accounts(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in list {
        let range = item.split_once("..").and_then(|(a, b)| Some((parse_client(a)?, parse_client(b)?)));
        match range {
            Some((from, to)) if from <= to && to - from < 10_000 => out.extend((from..=to).map(client_label)),
            _ => out.push(item.trim().to_string()),
        }
    }
    out
}

pub async fn run(args: PirateArgs) -> anyhow::Result<()> {
    let (frames, _) = watch::channel(None);
    let accounts = expand_accounts(&args.accounts);
    let pirate = Arc::new(Pirate {
        args: args.clone(),
        frames,
        status: Mutex::new(Status {
            state: "starting",
            account: None,
            accounts_used: 0,
            accounts_total: accounts.len(),
            history: Vec::new(),
        }),
        accounts,
    });
    tokio::spawn(relay(pirate.clone()));
    let app = Router::new()
        .route("/", get(home))
        .route("/stream.mjpg", get(stream))
        .route("/stream.mp4", get(stream_video))
        .route("/status", get(status))
        .route("/history", get(history))
        .route("/static/demo.css", get(css))
        .layer(middleware::from_fn(security_headers))
        .with_state(pirate);
    let listener =
        tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!("demo pirate {} listening on http://{}", args.site, args.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn login(http: &reqwest::Client, platform: &str, account: &str, password: &str) -> anyhow::Result<String> {
    let base = platform.trim_end_matches('/');
    let response = http
        .post(format!("{base}/api/sessions"))
        .timeout(Duration::from_secs(5))
        .json(&json!({"client_id": account, "password": password}))
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!("login refused ({status}): {}", body["error"].as_str().unwrap_or("unknown")));
    }
    let path = body["stream_path"].as_str().ok_or_else(|| anyhow!("no stream_path in the login answer"))?;
    Ok(format!("{base}{path}"))
}

async fn relay(p: Arc<Pirate>) {
    let http = reqwest::Client::builder().connect_timeout(Duration::from_secs(5)).build().unwrap_or_default();
    let accounts = p.accounts.clone();
    for (i, account) in accounts.iter().enumerate() {
        p.set_status("connecting", Some(account), i + 1);
        match login(&http, &p.args.platform, account, &p.args.password).await {
            Ok(url) => {
                p.set_status("relaying", Some(account), i + 1);
                tracing::info!(account, "relaying the licensed stream");
                if let Err(e) = pipe(&p, &http, &url).await {
                    tracing::warn!(account, error = %e, "relay interrupted");
                }
                tracing::info!(account, "source lost");
            }
            Err(e) => tracing::warn!(account, error = %e, "could not log in"),
        }
        p.set_status("no_signal", Some(account), i + 1);
        no_signal(&p, Duration::from_secs(p.args.switch_secs)).await;
    }
    p.set_status("out_of_accounts", None, accounts.len());
    loop {
        no_signal(&p, Duration::from_secs(3600)).await;
    }
}

async fn pipe(p: &Arc<Pirate>, http: &reqwest::Client, url: &str) -> anyhow::Result<()> {
    let mut reader = mjpeg::open(http, url).await?;
    let mut on_air: Option<Instant> = None;
    let result = relay_frames(p, &mut reader, &mut on_air).await;
    if let Some(started) = on_air {
        let mut status = p.status();
        if let Some(stint) = status.history.last_mut() {
            stint.ended_at = Some(now_rfc3339());
            stint.on_air_secs = Some(started.elapsed().as_secs_f64());
        }
    }
    result
}

async fn relay_frames(
    p: &Arc<Pirate>,
    reader: &mut mjpeg::FrameReader<reqwest::Error>,
    on_air: &mut Option<Instant>,
) -> anyhow::Result<()> {
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(6), reader.next_frame()).await {
            Ok(frame) => frame?,
            Err(_) => return Err(anyhow!("no frame in 6 s")),
        };
        let Some(frame) = frame else { return Ok(()) };
        let args = p.args.clone();
        let jpeg = tokio::task::spawn_blocking(move || restream(&frame, &args)).await??;
        p.frames.send_replace(Some(Bytes::from(jpeg)));
        if on_air.is_none() {
            *on_air = Some(Instant::now());
            let mut status = p.status();
            let account = status.account.clone().unwrap_or_default();
            status.history.push(Stint { account, started_at: now_rfc3339(), ended_at: None, on_air_secs: None });
        }
    }
}

/// What a pirate does to the picture: rescale, cover the broadcaster's bug and a corner, re-encode.
fn restream(jpeg: &[u8], args: &PirateArgs) -> anyhow::Result<Vec<u8>> {
    let img = decode_rgb(jpeg)?;
    let scale = args.scale.clamp(40, 100);
    let mut out = imageops::thumbnail(&img, img.width() * scale / 100, img.height() * scale / 100);
    overlay(&mut out, args);
    encode(&out, args.quality.clamp(20, 95), None)
}

fn overlay(img: &mut RgbImage, args: &PirateArgs) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    let site = args.site.to_uppercase();
    // Over the broadcaster's bug, bottom centre.
    let banner = format!("{site} · FUTBOL GRATIS");
    let bw = text_width(&banner, 2) + 24;
    fill_rect(img, (w - bw) / 2, h - 34, bw, 30, PIRATE_RED);
    draw_text_centered(img, w / 2, h - 27, &banner, 2, PIRATE_INK);
    // A logo over one corner, sized to hide the mark when it passes there.
    if let Some(corner) = args.cover.corner() {
        let (lw, lh) = (w * 20 / 100, h * 38 / 100);
        let (x, y) = corner.place(w, h, lw, lh, 0);
        fill_rect(img, x, y, lw, lh, PIRATE_RED);
        let short = site.split('.').next().unwrap_or(&site).to_string();
        let tw = text_width(&short, 2);
        draw_text(img, x + (lw - tw).max(0) / 2, y + lh / 2 - 8, &short, 2, PIRATE_INK);
    }
}

async fn no_signal(p: &Arc<Pirate>, duration: Duration) {
    let scale = p.args.scale.clamp(40, 100);
    let quality = p.args.quality;
    let jpeg = tokio::task::spawn_blocking(move || {
        let card = slate("SIN SEÑAL", "Volvemos en unos segundos", Rgb([30, 30, 34]));
        let small = imageops::thumbnail(&card, card.width() * scale / 100, card.height() * scale / 100);
        encode(&small, quality, None)
    })
    .await;
    let Ok(Ok(jpeg)) = jpeg else { return };
    let jpeg = Bytes::from(jpeg);
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        p.frames.send_replace(Some(jpeg.clone()));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn home(State(p): State<Arc<Pirate>>) -> Html<String> {
    let site = p.args.site.clone();
    let status = p.status().clone();
    let state = match status.state {
        "relaying" => "Retransmitiendo",
        "connecting" => "Conectando",
        "no_signal" => "Sin señal: la cuenta dejó de funcionar",
        "out_of_accounts" => "Sin señal: no quedan cuentas",
        _ => "Arrancando",
    };
    let page = html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (site) " · fútbol gratis" }
                link rel="stylesheet" href="/static/demo.css";
            }
            body class="pirate" {
                header class="bar" { div class="wrap" { span class="brand" { (site) } span class="tag" { "Sitio pirata ficticio · demo" } } }
                main class="wrap" {
                    h1 { "Fútbol gratis en vivo" }
                    figure class="player" {
                        video src="/stream.mp4" width="768" height="432" controls autoplay muted playsinline preload="auto"
                            aria-label="Retransmisión pirata del partido (demo)" {
                            "Tu navegador no puede reproducir este video."
                        }
                        figcaption { "Retransmisión sin sonido: el pirata toma la imagen de la cuenta que usa." }
                    }
                    section class="backstage" aria-labelledby="backstage-title" {
                        h2 id="backstage-title" { "Detrás de escena (solo para la demo)" }
                        p { "Estado: " strong { (state) } }
                        p { "Cuenta usada: " span class="mono" { (status.account.as_deref().unwrap_or("—")) }
                            " · cuentas usadas: " (status.accounts_used) " de " (status.accounts_total) " · "
                            a href="/history" { "historial de cuentas" } }
                        p { "Origen: " span class="mono" { (p.args.platform) } ". Este sitio re-codifica y achica la imagen y tapa una esquina con su logo para esconder la marca." }
                        p { "Para rastrearlo en Strack: " span class="mono" { "http://" (p.args.listen) "/stream.mjpg" } }
                    }
                }
                footer class="wrap foot" { p { "Sitio inventado para la demo de Strack. No retransmite nada real." } }
            }
        }
    };
    Html(page.into_string())
}

async fn stream(State(p): State<Arc<Pirate>>) -> Response {
    let mut frames = p.frames.subscribe();
    let (tx, rx) = mpsc::channel::<Bytes>(2);
    tokio::spawn(async move {
        loop {
            let frame = frames.borrow_and_update().clone();
            if let Some(jpeg) = frame {
                if tx.send(part(&jpeg)).await.is_err() {
                    return;
                }
            }
            if frames.changed().await.is_err() {
                return;
            }
        }
    });
    mjpeg::response(rx)
}

async fn status(State(p): State<Arc<Pirate>>) -> Json<Status> {
    Json(p.status().clone())
}

/// Every account the pirate used and how long each stayed on air (refreshes itself every 5 s).
async fn history(State(p): State<Arc<Pirate>>) -> Html<String> {
    let site = p.args.site.clone();
    let status = p.status().clone();
    let ended: Vec<f64> = status.history.iter().filter_map(|s| s.on_air_secs).collect();
    let average = (!ended.is_empty()).then(|| ended.iter().sum::<f64>() / ended.len() as f64);
    let longest = ended.iter().copied().reduce(f64::max);
    let secs = |v: Option<f64>| v.map(|s| format!("{s:.1} s")).unwrap_or_else(|| "—".into());
    let page = html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta http-equiv="refresh" content="5";
                title { "Historial de cuentas · " (site) }
                link rel="stylesheet" href="/static/demo.css";
            }
            body class="pirate" {
                header class="bar" { div class="wrap" { a class="brand" href="/" { (site) } span class="tag" { "Detrás de escena · demo" } } }
                main class="wrap" {
                    h1 { "Historial de cuentas del pirata" }
                    p class="lede" {
                        "Cada cuenta de abonado que usó para retransmitir y cuánto duró al aire hasta que la plataforma la cortó. "
                        "Se actualiza cada 5 segundos."
                    }
                    p {
                        "Cuentas usadas: " strong { (status.accounts_used) " de " (status.accounts_total) }
                        " · cortadas: " strong { (ended.len()) }
                        " · tiempo al aire promedio: " strong { (secs(average)) }
                        " · la que más duró: " strong { (secs(longest)) }
                    }
                    div class="table-wrap" role="region" aria-label="Historial de cuentas" tabindex="0" {
                        table {
                            thead { tr {
                                th scope="col" { "#" }
                                th scope="col" { "Cuenta" }
                                th scope="col" { "Al aire desde" }
                                th scope="col" { "Cortada" }
                                th scope="col" { "Tiempo al aire" }
                            } }
                            tbody {
                                @for (i, stint) in status.history.iter().enumerate().rev() {
                                    tr {
                                        td { (i + 1) }
                                        th scope="row" class="mono" { (stint.account) }
                                        td { (clock_time(&stint.started_at)) }
                                        td { (stint.ended_at.as_deref().map(clock_time).unwrap_or_else(|| "sigue al aire".into())) }
                                        td { (secs(stint.on_air_secs)) }
                                    }
                                }
                            }
                        }
                    }
                }
                footer class="wrap foot" { p { "Sitio inventado para la demo de Strack. No retransmite nada real." } }
            }
        }
    };
    Html(page.into_string())
}

/// The restream as real video in a `<video>` player (H.264, no sound), from the same frames Strack reads.
async fn stream_video(State(p): State<Arc<Pirate>>) -> Response {
    let (encoder, response) = match encoder::start(&p.args.ffmpeg, (p.args.fps, 1), Input::Jpeg, None) {
        Ok(started) => started,
        Err(e) => {
            tracing::warn!(error = %e, "could not start the video encoder (is ffmpeg installed?)");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let frames = p.frames.subscribe();
    std::thread::spawn(move || {
        // Waits for the first picture, then repeats the latest one at a constant rate.
        encoder.run_paced(|| {
            loop {
                if let Some(jpeg) = frames.borrow().as_ref() {
                    return Some(jpeg.to_vec());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    });
    response
}

#[cfg(test)]
mod tests {
    use crate::demo::pirate::expand_accounts;

    #[test]
    fn expands_account_ranges() {
        let list = vec!["c-00042..c-00044".to_string(), "c-00100".to_string()];
        assert_eq!(expand_accounts(&list), vec!["c-00042", "c-00043", "c-00044", "c-00100"]);
    }
}
