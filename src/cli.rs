//! Command line: `serve`, `enroll`, `verify`, `export`, `trace` and the leak-tracing `demo` servers.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::access::{AccessRequests, Desk};
use crate::app::{App, Core, MatchRun, Settings, audit_path, match_state_dir, state_path};
use crate::audit::{AuditLog, verify_file};
use crate::clock::MatchClock;
use crate::crypto::{random_token, sha256_hex};
use crate::demo::pirate::PirateArgs;
use crate::demo::platform::PlatformArgs;
use crate::export::{export, load_store, verify_case_file};
use crate::judges::{Account, AccountsFile, Role, Sessions, hash_password, seal_key};
use crate::leak::extract::Scanner;
use crate::leak::mark::platform_code;
use crate::leak::platforms::PlatformsFile;
use crate::model::{OrderStatus, Store};
use crate::simulator::SimClient;
use crate::standalone::{MatchSource, Standalone, StandaloneConfig};

#[derive(Parser)]
#[command(name = "strack", version, about = "Federal platform for live blocking orders (hackathon MVP)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the platform against a simulator.
    Serve(ServeArgs),
    /// Create or update an account. Judges get their demo signing key sealed with their password.
    Enroll(EnrollArgs),
    /// Verify the audit log chain and, optionally, an exported case file.
    Verify(VerifyArgs),
    /// Export a case file, the audit log and the transparency registry for delivery.
    Export(ExportArgs),
    /// Read session marks from a stream or image URL, or a video file, and print them (no notice is sent).
    Trace(TraceArgs),
    /// Hide one viewing session's mark in a video file, as a licensed platform does per subscriber.
    Mark(crate::leak::marker::MarkArgs),
    /// Reference order receiver an internet provider runs to take Strack's blocking orders.
    Provider(crate::provider::ProviderArgs),
    /// Demo servers for leak tracing: a licensed platform and a pirate restream.
    #[command(subcommand)]
    Demo(DemoCommand),
}

#[derive(Subcommand)]
pub enum DemoCommand {
    /// Licensed streaming platform that marks every subscriber session and accepts leak notices.
    Platform(PlatformArgs),
    /// Pirate site that restreams the platform with subscriber accounts.
    Pirate(PirateArgs),
}

#[derive(Args)]
pub struct TraceArgs {
    /// MJPEG stream or JPEG image URL, or a local video file (read with ffmpeg).
    pub url: String,
    /// Stop reading after this many seconds.
    #[arg(long, default_value_t = 20)]
    pub seconds: u64,
    /// Registered platforms; only their marks are accepted (a missing file accepts any platform).
    #[arg(long, default_value = "config/platforms.json")]
    pub platforms: PathBuf,
    /// ffmpeg, for video files.
    #[arg(long, default_value = "ffmpeg")]
    pub ffmpeg: String,
}

#[derive(Args)]
pub struct ServeArgs {
    /// Simulator base URL, one per match followed at the same time (repeat the flag or separate
    /// with commas). The first match keeps its state in `--state-dir`, match n in `match-<n>/`.
    /// Without `--simulator` and `--config`, `http://localhost:8080`.
    #[arg(long = "simulator", env = "STRACK_SIMULATOR", value_delimiter = ',')]
    pub simulators: Vec<String>,
    /// A match to follow without a simulator: a config file with the match, its courts and duty
    /// shifts and the providers with their order APIs (see `config/match.example.json`). Repeatable;
    /// these matches come after the `--simulator` ones.
    #[arg(long = "config")]
    pub configs: Vec<PathBuf>,
    /// Address the web interface listens on.
    #[arg(long, env = "STRACK_LISTEN", default_value = "127.0.0.1:3000")]
    pub listen: SocketAddr,
    /// Accounts file created with `strack enroll`.
    #[arg(long, env = "STRACK_ACCOUNTS", default_value = "config/accounts.json")]
    pub accounts: PathBuf,
    /// Folder for the state snapshot and the audit log.
    #[arg(long, env = "STRACK_STATE_DIR", default_value = "var")]
    pub state_dir: PathBuf,
    /// Continue from the existing state and audit log instead of starting a new run.
    #[arg(long)]
    pub resume: bool,
    /// Simulator polling interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    pub poll_ms: u64,
    /// Match minutes a domain block lasts after the end of the match (IP blocks always end with it).
    #[arg(long, default_value_t = 0)]
    pub domain_extra_min: i64,
    /// A judge stops signing this many match minutes before the end of the shift.
    #[arg(long, default_value_t = 0.1)]
    pub shift_margin_min: f64,
    /// Mark the session cookie `Secure` (serve behind HTTPS).
    #[arg(long)]
    pub secure_cookies: bool,
    /// Licensed platforms that accept leak notices.
    #[arg(long, env = "STRACK_PLATFORMS", default_value = "config/platforms.json")]
    pub platforms: PathBuf,
    /// Token monitoring services send as `Authorization: Bearer <token>` to load detections through
    /// `POST /api/detections`; without it that API is off.
    #[arg(long, env = "STRACK_INTAKE_TOKEN", hide_env_values = true)]
    pub intake_token: Option<String>,
    /// ffmpeg, used by leak tracing to read HLS, DASH, MP4, MPEG-TS, WebM and RTMP streams.
    #[arg(long, env = "STRACK_FFMPEG", default_value = "ffmpeg")]
    pub ffmpeg: String,
    /// Let the stream reader reach local and private addresses (local demos only: by default it
    /// reads public internet addresses alone).
    #[arg(long, env = "STRACK_ALLOW_PRIVATE_STREAMS")]
    pub allow_private_streams: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RoleArg {
    Judge,
    Operator,
    Admin,
    /// A licensed platform's account (its portal only); needs `--platform-id`.
    Platform,
}

#[derive(Args)]
pub struct EnrollArgs {
    #[arg(long, default_value = "config/accounts.json")]
    pub accounts: PathBuf,
    #[arg(long)]
    pub username: String,
    #[arg(long, value_enum)]
    pub role: RoleArg,
    /// Password (prefer the STRACK_PASSWORD environment variable).
    #[arg(long, env = "STRACK_PASSWORD", hide_env_values = true)]
    pub password: String,
    /// Judge id from the courts file (judges only).
    #[arg(long)]
    pub judge_id: Option<String>,
    /// The challenge's `datos/juzgados.json`, which holds the demo signing keys (judges only).
    #[arg(long)]
    pub courts: Option<PathBuf>,
    /// Registered platform id (platform accounts only).
    #[arg(long)]
    pub platform_id: Option<String>,
    /// Display name (operators and admins; judges take it from the courts file).
    #[arg(long)]
    pub display_name: Option<String>,
}

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long, default_value = "var/audit.jsonl")]
    pub audit: PathBuf,
    /// Exported case file to check against the audit log.
    #[arg(long)]
    pub case: Option<PathBuf>,
}

#[derive(Args)]
pub struct ExportArgs {
    #[arg(long, default_value = "var")]
    pub state_dir: PathBuf,
    #[arg(long, default_value = "entrega")]
    pub out: PathBuf,
    /// Case id to export (defaults to the first approved case with an applied block).
    #[arg(long)]
    pub case: Option<String>,
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Enroll(args) => enroll(args),
        Command::Verify(args) => verify(args),
        Command::Export(args) => {
            for path in export(&args.state_dir, &args.out, args.case.as_deref())? {
                println!("wrote {}", path.display());
            }
            Ok(())
        }
        Command::Trace(args) => trace(args).await,
        Command::Mark(args) => mark(args).await,
        Command::Provider(args) => crate::provider::run(args).await,
        Command::Demo(DemoCommand::Platform(args)) => crate::demo::platform::run(args).await,
        Command::Demo(DemoCommand::Pirate(args)) => crate::demo::pirate::run(args).await,
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let mut simulators: Vec<String> =
        args.simulators.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if simulators.is_empty() && args.configs.is_empty() {
        simulators.push("http://localhost:8080".to_string());
    }
    let mut sources: Vec<MatchSource> = Vec::new();
    for url in &simulators {
        sources.push(MatchSource::Simulator(SimClient::new(url)?));
    }
    for path in &args.configs {
        let config = StandaloneConfig::load(path)?;
        sources.push(MatchSource::Standalone(Box::new(Standalone::new(config, &path.display().to_string())?)));
    }
    let settings = Settings {
        poll_interval: Duration::from_millis(args.poll_ms.max(100)),
        domain_extra_min: args.domain_extra_min,
        shift_margin_min: args.shift_margin_min.max(0.0),
        secure_cookies: args.secure_cookies,
        state_dir: args.state_dir.clone(),
        intake_token: args.intake_token.clone().filter(|t| !t.trim().is_empty()),
        ffmpeg: args.ffmpeg.clone(),
        allow_private_streams: args.allow_private_streams,
        accounts_path: args.accounts.clone(),
        platforms_path: args.platforms.clone(),
    };
    let accounts = AccountsFile::load(&args.accounts)?;
    if accounts.accounts.is_empty() {
        tracing::warn!(path = %args.accounts.display(), "no accounts: enroll judges with `strack enroll`");
    }
    let mut matches = Vec::with_capacity(simulators.len());
    for (i, source) in sources.into_iter().enumerate() {
        let n = i + 1;
        let dir = match_state_dir(&settings.state_dir, n);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let (store, audit) = if args.resume && state_path(&dir).exists() {
            let mut store = load_store(&dir)?;
            // Orders caught mid-send are sent again with the same id (a 409 then means delivered).
            for order in store.orders.iter_mut().filter(|o| o.status == OrderStatus::Sending) {
                order.status = OrderStatus::Signed;
            }
            (store, AuditLog::resume(&audit_path(&dir))?)
        } else {
            let mut store = Store::new(random_token(2));
            // Case ids never repeat across matches: match n numbers its cases from (n - 1) * 100000.
            store.case_seq = (n as u64 - 1) * 100_000;
            (store, AuditLog::create(&audit_path(&dir))?)
        };
        matches.push(Arc::new(MatchRun {
            key: n.to_string(),
            sim: source,
            state_dir: dir,
            core: Mutex::new(Core { store, audit, clock: MatchClock::default() }),
            dispatch: Notify::new(),
        }));
    }
    let platforms = PlatformsFile::load(&args.platforms)?;
    let requests = AccessRequests::load(&settings.access_requests_path())?;
    let http = crate::leak::source::reader_client(args.allow_private_streams)?;
    let app = Arc::new(App {
        settings,
        matches,
        accounts: RwLock::new(accounts),
        platforms: RwLock::new(platforms),
        http,
        sessions: Mutex::new(Sessions::default()),
        desk: Mutex::new(Desk::new(requests)),
    });
    for m in &app.matches {
        let mut core = m.core();
        let data = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "run_id": core.store.run_id,
            "resumed": args.resume,
            "match_key": m.key,
            "simulator": m.sim.base_url(),
            "domain_extra_min": app.settings.domain_extra_min,
            "shift_margin_min": app.settings.shift_margin_min,
        });
        core.record("system", "platform_started", data);
    }
    if args.resume {
        crate::leak::trace::close_interrupted(&app);
    }

    let engine = tokio::spawn(crate::engine::run(app.clone()));
    let listener =
        tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(matches = app.matches.len(), "Strack listening on http://{}", args.listen);
    axum::serve(listener, crate::web::router(app.clone())).with_graceful_shutdown(shutdown_signal()).await?;
    engine.abort();
    for m in &app.matches {
        let mut core = m.core();
        core.store.dirty = true;
        core.record("system", "platform_stopped", json!({}));
    }
    app.persist();
    Ok(())
}

async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "could not listen for Ctrl+C");
        std::future::pending::<()>().await;
    }
    tracing::info!("shutting down");
}

fn enroll(args: EnrollArgs) -> anyhow::Result<()> {
    if args.password.chars().count() < 10 {
        bail!("the password must have at least 10 characters");
    }
    let mut accounts = AccountsFile::load(&args.accounts)?;
    let account = match args.role {
        RoleArg::Platform => Account {
            username: args.username.clone(),
            role: Role::Platform,
            display_name: args.display_name.clone().unwrap_or_else(|| args.username.clone()),
            judge_id: None,
            court_id: None,
            platform_id: Some(
                args.platform_id.clone().ok_or_else(|| anyhow!("--platform-id is required for platform accounts"))?,
            ),
            password_hash: hash_password(&args.password)?,
            sealed_key: None,
            disabled: false,
            created_at: Some(crate::workflow::now_rfc3339()),
        },
        RoleArg::Operator | RoleArg::Admin => Account {
            username: args.username.clone(),
            role: if matches!(args.role, RoleArg::Admin) { Role::Admin } else { Role::Operator },
            display_name: args.display_name.clone().unwrap_or_else(|| args.username.clone()),
            judge_id: None,
            court_id: None,
            platform_id: None,
            password_hash: hash_password(&args.password)?,
            sealed_key: None,
            disabled: false,
            created_at: Some(crate::workflow::now_rfc3339()),
        },
        RoleArg::Judge => {
            let judge_id = args.judge_id.clone().ok_or_else(|| anyhow!("--judge-id is required for judges"))?;
            let courts_path = args.courts.clone().ok_or_else(|| anyhow!("--courts is required for judges"))?;
            let courts: Value = serde_json::from_str(
                &std::fs::read_to_string(&courts_path).with_context(|| format!("reading {}", courts_path.display()))?,
            )?;
            let (court_id, judge) = courts["juzgados"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|court| {
                    court["jueces"]
                        .as_array()?
                        .iter()
                        .find(|j| j["id"].as_str() == Some(judge_id.as_str()))
                        .map(|j| (court["id"].as_str().unwrap_or_default().to_string(), j.clone()))
                })
                .ok_or_else(|| anyhow!("judge {judge_id} is not in {}", courts_path.display()))?;
            let key = judge["clave_firma_demo"]
                .as_str()
                .ok_or_else(|| anyhow!("judge {judge_id} has no clave_firma_demo"))?;
            Account {
                username: args.username.clone(),
                role: Role::Judge,
                display_name: judge["nombre"].as_str().unwrap_or(&judge_id).to_string(),
                sealed_key: Some(seal_key(&args.password, &judge_id, key.as_bytes())?),
                judge_id: Some(judge_id),
                court_id: Some(court_id),
                platform_id: None,
                password_hash: hash_password(&args.password)?,
                disabled: false,
                created_at: Some(crate::workflow::now_rfc3339()),
            }
        }
    };
    println!("enrolled {} ({:?})", account.username, account.role);
    accounts.upsert(account);
    accounts.save(&args.accounts)?;
    Ok(())
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let report = verify_file(&args.audit)?;
    match &report.problem {
        None => println!("audit log OK: {} entries, head {}", report.entries, report.head),
        Some(problem) => println!("audit log BROKEN after {} valid entries: {problem}", report.entries),
    }
    let mut ok = report.problem.is_none();
    if let Some(case) = &args.case {
        let problems = verify_case_file(case, Some(&args.audit))?;
        if problems.is_empty() {
            println!("case file OK: {}", case.display());
        } else {
            ok = false;
            for p in problems {
                println!("case file problem: {p}");
            }
        }
    }
    if ok { Ok(()) } else { Err(anyhow!("verification failed")) }
}

/// Prints every distinct session mark read from `url` within `--seconds`, as JSON lines.
async fn mark(args: crate::leak::marker::MarkArgs) -> anyhow::Result<()> {
    use crate::leak::marker::{mark_file, session_id, session_mark};
    let client = crate::leak::mark::parse_client(&args.client)
        .ok_or_else(|| anyhow!("--client must be a subscriber number (42 or c-00042)"))?;
    let mark = session_mark(&args.platform, client, session_id(args.session.as_deref())?);
    eprintln!("marking {} with {}", args.input.display(), mark.text());
    let started = Instant::now();
    let done = tokio::task::spawn_blocking(move || {
        mark_file(&args.ffmpeg, &args.input, &args.output, mark, args.strength).map(|m| (m, args.output))
    })
    .await??;
    let (marked, output) = done;
    println!(
        "{}",
        json!({
            "mark": marked.mark.text(),
            "platform_code": marked.mark.platform_hex(),
            "client": marked.mark.client_label(),
            "session": marked.mark.session_hex(),
            "frames": marked.frames,
            "size": format!("{}x{}", marked.width, marked.height),
            "output": output.display().to_string(),
            "secs": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        })
    );
    Ok(())
}

/// Reads the marks of a local video file (decoded with ffmpeg at 10 frames per second).
async fn trace_file(args: TraceArgs) -> anyhow::Result<()> {
    let codes = PlatformsFile::load(&args.platforms)?.platforms.iter().map(|p| platform_code(&p.id)).collect();
    let path = PathBuf::from(&args.url);
    let (seconds, ffmpeg) = (args.seconds.max(1), args.ffmpeg.clone());
    let (frames, found) = tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, Vec<Value>)> {
        let frames = crate::leak::marker::file_frames(&ffmpeg, &path, 10, seconds)?;
        let mut scanner = Scanner::new(codes);
        let mut seen = HashSet::new();
        let mut found = Vec::new();
        for (at, jpeg) in &frames {
            for f in scanner.scan(jpeg, *at) {
                if seen.insert(f.mark) {
                    found.push(json!({
                        "mark": f.mark.text(),
                        "platform_code": f.mark.platform_hex(),
                        "client": f.mark.client_label(),
                        "session": f.mark.session_hex(),
                        "sources": f.sources,
                        "at_secs": at,
                    }));
                }
            }
        }
        Ok((frames.len(), found))
    })
    .await??;
    for line in &found {
        println!("{line}");
    }
    eprintln!("read {frames} frames from the file, found {} distinct marks", found.len());
    if found.is_empty() { Err(anyhow!("no session mark found")) } else { Ok(()) }
}

async fn trace(args: TraceArgs) -> anyhow::Result<()> {
    if std::path::Path::new(&args.url).is_file() {
        return trace_file(args).await;
    }
    use crate::leak::source::{FrameSource, Probe, probe};
    let http = reqwest::Client::builder().connect_timeout(Duration::from_secs(5)).build()?;
    let deadline = Instant::now() + Duration::from_secs(args.seconds.max(1));
    let mut url = args.url.clone();
    let format = loop {
        match probe(&http, &url).await? {
            Probe::Stream(format) => break format,
            Probe::Page => {
                let found = crate::leak::discover::discover(&http, &url, true).await?;
                for c in &found {
                    eprintln!("found in the page ({}): {}", c.via, c.url);
                }
                let best = found.into_iter().next().ok_or_else(|| anyhow!("no video found in the page"))?;
                url = best.url;
            }
        }
    };
    eprintln!("reading {url} as {}", format.label());
    let mut reader = FrameSource::open(&http, &url, format, &args.ffmpeg).await?;
    let mut seen = HashSet::new();
    let (mut frames, mut scanned) = (0u64, 0u64);
    let mut last_scan: Option<Instant> = None;
    let started = Instant::now();
    let codes = PlatformsFile::load(&args.platforms)?.platforms.iter().map(|p| platform_code(&p.id)).collect();
    let mut scanner: Option<Scanner> = Some(Scanner::new(codes));
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = match tokio::time::timeout(remaining, reader.next_frame()).await {
            Ok(frame) => frame?,
            Err(_) => break,
        };
        let Some(frame) = frame else { break };
        frames += 1;
        if last_scan.is_some_and(|t| t.elapsed() < Duration::from_millis(100)) {
            continue;
        }
        last_scan = Some(Instant::now());
        scanned += 1;
        let bytes = frame.clone();
        let at = started.elapsed().as_secs_f64();
        let mut current = scanner.take().unwrap_or_default();
        let (back, found) = tokio::task::spawn_blocking(move || {
            let found = current.scan(&bytes, at);
            (current, found)
        })
        .await?;
        scanner = Some(back);
        for found in found {
            if seen.insert(found.mark) {
                let line = json!({
                    "mark": found.mark.text(),
                    "platform_code": found.mark.platform_hex(),
                    "client": found.mark.client_label(),
                    "session": found.mark.session_hex(),
                    "sources": found.sources,
                    "frame_sha256": sha256_hex(&frame),
                    "after_secs": (started.elapsed().as_secs_f64() * 100.0).round() / 100.0,
                });
                println!("{line}");
            }
        }
    }
    eprintln!("read {frames} frames, scanned {scanned}, found {} distinct marks", seen.len());
    if seen.is_empty() { Err(anyhow!("no session mark found")) } else { Ok(()) }
}
