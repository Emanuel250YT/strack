//! Leak traces: watch a pirate stream, identify the leaking session from its mark, notify the licensed
//! platform and confirm that the source was cut. Every step goes to the audit log.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::App;
use crate::crypto::sha256_hex;
use crate::leak::discover;
use crate::leak::extract::{Found, MarkSource, Scanner};
use crate::leak::mark::{SessionMark, platform_code};
use crate::leak::platforms::{NoticeAck, NoticeError, NoticeRequest, PlatformEntry, send_notice};
use crate::leak::source::{FrameSource, Probe, probe};
use crate::leak::watermark::PERIOD_SECS;
use crate::workflow::now_rfc3339;

/// Frames are read at the stream's pace but scanned for marks at most this often.
/// Every frame of an 8 fps stream is scanned: the watermark detector uses all of them.
const SCAN_INTERVAL: Duration = Duration::from_millis(100);
const FRAME_TIMEOUT: Duration = Duration::from_secs(6);
const FFMPEG_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
const UNMARKED_AFTER: Duration = Duration::from_secs(4);
/// An acknowledged leak not seen for this long is confirmed cut. It is longer than the gaps between
/// watermark reads and than the time the visible mark spends in a corner a pirate logo may cover.
const CUT_AFTER: Duration = Duration::from_secs(12);
/// Frames already in flight when the platform closed the session may still show the mark.
const SEEN_AFTER_ACK_GRACE: Duration = Duration::from_secs(3);
const GIVE_UP_DOWN: Duration = Duration::from_secs(45);
/// Long enough for a whole match with extra time and the build-up.
const WATCH_LIMIT: Duration = Duration::from_secs(4 * 60 * 60);
const NOTICE_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Watching,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEnd {
    Stopped,
    StreamDown,
    TimeLimit,
    /// The platform restarted while the trace was running.
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Connecting,
    /// The last scanned frames carry a session mark.
    Marked,
    /// Frames arrive but no mark has been readable for a few seconds.
    Unmarked,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeStatus {
    /// The mark names a platform that is not in the registry.
    NotSent,
    Sending,
    Acknowledged,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notice {
    pub notice_id: String,
    pub status: NoticeStatus,
    pub attempts: u32,
    pub sent_at: Option<String>,
    pub answered_at: Option<String>,
    pub ack: Option<NoticeAck>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leak {
    pub n: u32,
    pub mark: SessionMark,
    pub mark_text: String,
    pub sources: Vec<MarkSource>,
    pub platform_name: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub sightings: u32,
    /// Evidence frame, stored next to the state as `traces/<trace id>/<frame_file>`.
    pub frame_file: String,
    pub frame_sha256: String,
    /// The earlier frame the watermark was read against (the mark is the difference between both).
    #[serde(default)]
    pub pair_frame_file: Option<String>,
    #[serde(default)]
    pub pair_frame_sha256: Option<String>,
    pub notice: Notice,
    /// Seconds from the first sighting to the platform's acknowledgement.
    pub ack_after_secs: Option<f64>,
    /// When the mark was confirmed gone from the pirate stream after the acknowledgement.
    pub cut_confirmed_at: Option<String>,
    pub cut_after_secs: Option<f64>,
    /// The mark kept appearing after the platform said it had closed the session.
    pub seen_after_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub id: String,
    pub url: String,
    /// The pirate page the stream was found in, when the trace started from a page.
    #[serde(default)]
    pub page_url: Option<String>,
    /// How the stream is read (`StreamFormat::label`), once connected.
    #[serde(default)]
    pub format: Option<String>,
    pub case_id: Option<String>,
    pub started_by: String,
    pub started_at: String,
    pub status: TraceStatus,
    pub end: Option<TraceEnd>,
    pub ended_at: Option<String>,
    pub stream: StreamState,
    pub frames_read: u64,
    pub frames_scanned: u64,
    pub leaks: Vec<Leak>,
    pub stop_requested: bool,
    pub last_error: Option<String>,
}

impl Trace {
    pub fn leak(&self, n: u32) -> Option<&Leak> {
        self.leaks.iter().find(|l| l.n == n)
    }
}

pub fn frames_dir(app: &App, trace_id: &str) -> PathBuf {
    app.settings.state_dir.join("traces").join(trace_id)
}

/// Why no trace could start from an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// The address is a page with no video we can read in it.
    NoVideoInPage,
}

/// Starts tracing whatever `url` holds: a stream of any format is traced as it is; a pirate page is
/// read for its video, and each stream found (at most `discover::MAX_STREAMS`) gets its own trace.
/// An address that does not answer now is traced anyway (it may come back). Returns the trace ids.
pub async fn start_from(
    app: &Arc<App>,
    url: String,
    case_id: Option<String>,
    actor: &str,
) -> Result<Vec<String>, StartError> {
    if let Ok(Probe::Page) = probe(&app.http, &url).await {
        let found = discover::discover(&app.http, &url).await.unwrap_or_default();
        if found.is_empty() {
            app.core().record(actor, "trace_page_without_video", json!({"page_url": url, "case_id": case_id}));
            return Err(StartError::NoVideoInPage);
        }
        return Ok(found
            .into_iter()
            .map(|c| start_with(app, c.url, Some(url.clone()), case_id.clone(), actor))
            .collect());
    }
    Ok(vec![start(app, url, case_id, actor)])
}

/// Opens a trace record and starts watching `url` in the background. Returns the trace id.
pub fn start(app: &Arc<App>, url: String, case_id: Option<String>, actor: &str) -> String {
    start_with(app, url, None, case_id, actor)
}

fn start_with(app: &Arc<App>, url: String, page_url: Option<String>, case_id: Option<String>, actor: &str) -> String {
    let id = {
        let mut core = app.core();
        core.store.trace_seq += 1;
        let id = format!("RAS-{:06}", core.store.trace_seq);
        core.store.traces.push(Trace {
            id: id.clone(),
            url: url.clone(),
            page_url: page_url.clone(),
            format: None,
            case_id: case_id.clone(),
            started_by: actor.to_string(),
            started_at: now_rfc3339(),
            status: TraceStatus::Watching,
            end: None,
            ended_at: None,
            stream: StreamState::Connecting,
            frames_read: 0,
            frames_scanned: 0,
            leaks: Vec::new(),
            stop_requested: false,
            last_error: None,
        });
        core.store.touch();
        core.record(
            actor,
            "trace_started",
            json!({"trace_id": id, "url": url, "page_url": page_url, "case_id": case_id}),
        );
        id
    };
    app.persist();
    tokio::spawn(run(app.clone(), id.clone(), url, case_id));
    id
}

/// Asks a running trace to stop; it finishes within a few seconds.
pub fn request_stop(app: &App, trace_id: &str, actor: &str) -> bool {
    let mut core = app.core();
    let Some(trace) = core.store.traces.iter_mut().find(|t| t.id == trace_id) else {
        return false;
    };
    if trace.status != TraceStatus::Watching || trace.stop_requested {
        return false;
    }
    trace.stop_requested = true;
    core.store.touch();
    core.record(actor, "trace_stop_requested", json!({"trace_id": trace_id}));
    true
}

/// Traces left running by a previous process cannot continue: close them as interrupted.
pub fn close_interrupted(app: &App) {
    let mut core = app.core();
    let ids: Vec<String> =
        core.store.traces.iter().filter(|t| t.status == TraceStatus::Watching).map(|t| t.id.clone()).collect();
    for id in ids {
        if let Some(trace) = core.store.traces.iter_mut().find(|t| t.id == id) {
            trace.status = TraceStatus::Finished;
            trace.end = Some(TraceEnd::Interrupted);
            trace.ended_at = Some(now_rfc3339());
            trace.stream = StreamState::Down;
        }
        core.store.touch();
        core.record("tracer", "trace_finished", json!({"trace_id": id, "end": TraceEnd::Interrupted}));
    }
}

struct Seen {
    n: u32,
    first: Instant,
    last: Instant,
    acked: Option<Instant>,
    cut: bool,
    warned: bool,
}

struct Tracer {
    app: Arc<App>,
    id: String,
    url: String,
    case_id: Option<String>,
    dir: PathBuf,
    seen: HashMap<String, Seen>,
    started: Instant,
    last_mark: Instant,
    scanner: Option<Scanner>,
    /// Recently scanned frames with their time, to keep the watermark's reference frame as evidence.
    recent: VecDeque<(f64, Bytes)>,
}

async fn run(app: Arc<App>, id: String, url: String, case_id: Option<String>) {
    let now = Instant::now();
    let dir = frames_dir(&app, &id);
    let platform_codes = app.platforms().platforms.iter().map(|p| platform_code(&p.id)).collect();
    let mut tracer = Tracer {
        app,
        id,
        url,
        case_id,
        dir,
        seen: HashMap::new(),
        started: now,
        last_mark: now,
        scanner: Some(Scanner::new(platform_codes)),
        recent: VecDeque::new(),
    };
    let end = tracer.watch().await;
    tracer.finish(end);
}

impl Tracer {
    fn stop_requested(&self) -> bool {
        self.app.core().store.traces.iter().find(|t| t.id == self.id).is_none_or(|t| t.stop_requested)
    }

    /// Applies `f` to this trace; `touch` marks the state changed for persistence and live views.
    fn with_trace(&self, touch: bool, f: impl FnOnce(&mut Trace)) {
        let mut core = self.app.core();
        if let Some(trace) = core.store.traces.iter_mut().find(|t| t.id == self.id) {
            f(trace);
        }
        if touch {
            core.store.touch();
        }
    }

    fn with_leak(&self, n: u32, f: impl FnOnce(&mut Leak)) {
        self.with_trace(true, |t| {
            if let Some(leak) = t.leaks.iter_mut().find(|l| l.n == n) {
                f(leak);
            }
        });
    }

    fn record(&self, event: &str, data: serde_json::Value) {
        self.app.core().record("tracer", event, data);
    }

    fn set_stream(&self, state: StreamState) {
        let changed = {
            let core = self.app.core();
            core.store.traces.iter().find(|t| t.id == self.id).is_some_and(|t| t.stream != state)
        };
        if changed {
            self.with_trace(true, |t| t.stream = state);
        }
    }

    fn note_error(&self, error: String) {
        self.with_trace(false, |t| t.last_error = Some(error));
    }

    async fn watch(&mut self) -> TraceEnd {
        let mut down_since: Option<Instant> = None;
        loop {
            if self.stop_requested() {
                return TraceEnd::Stopped;
            }
            if self.started.elapsed() > WATCH_LIMIT {
                return TraceEnd::TimeLimit;
            }
            match self.connect().await {
                Ok(mut reader) => {
                    down_since = None;
                    if let Some(end) = self.read(&mut reader).await {
                        return end;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    self.note_error(e.to_string());
                    self.set_stream(StreamState::Down);
                    self.confirm_cuts(&HashSet::new(), true);
                    let since = *down_since.get_or_insert_with(Instant::now);
                    if since.elapsed() > GIVE_UP_DOWN {
                        return TraceEnd::StreamDown;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Connects to the stream, natively for MJPEG and JPEG and through ffmpeg for everything else.
    async fn connect(&mut self) -> anyhow::Result<FrameSource> {
        let format = match probe(&self.app.http, &self.url).await? {
            Probe::Stream(format) => format,
            Probe::Page => anyhow::bail!("the address is a web page, not a stream"),
        };
        let label = format.label().to_string();
        let known = self.app.core().store.traces.iter().any(|t| t.id == self.id && t.format.as_deref() == Some(&label));
        if !known {
            self.with_trace(true, |t| t.format = Some(label));
        }
        FrameSource::open(&self.app.http, &self.url, format, &self.app.settings.ffmpeg).await
    }

    /// Reads one connection until it ends (`None`: reconnect) or the trace must end.
    async fn read(&mut self, reader: &mut FrameSource) -> Option<TraceEnd> {
        let mut last_scan: Option<Instant> = None;
        // ffmpeg needs a few seconds to start an HLS or DASH stream; MJPEG frames come at once.
        let timeout = if matches!(reader, FrameSource::Ffmpeg(_)) { FFMPEG_FRAME_TIMEOUT } else { FRAME_TIMEOUT };
        loop {
            if self.stop_requested() {
                return Some(TraceEnd::Stopped);
            }
            if self.started.elapsed() > WATCH_LIMIT {
                return Some(TraceEnd::TimeLimit);
            }
            let frame = match tokio::time::timeout(timeout, reader.next_frame()).await {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) => return None,
                Ok(Err(e)) => {
                    self.note_error(e.to_string());
                    return None;
                }
                Err(_) => {
                    self.note_error(format!("no frame in {} s", timeout.as_secs()));
                    return None;
                }
            };
            let scan = last_scan.is_none_or(|t| t.elapsed() >= SCAN_INTERVAL);
            self.with_trace(false, |t| {
                t.frames_read += 1;
                t.frames_scanned += u64::from(scan);
            });
            if !scan {
                continue;
            }
            last_scan = Some(Instant::now());
            let at = self.started.elapsed().as_secs_f64();
            let mut scanner = self.scanner.take().unwrap_or_default();
            let bytes = frame.clone();
            let (scanner, found) = tokio::task::spawn_blocking(move || {
                let found = scanner.scan(&bytes, at);
                (scanner, found)
            })
            .await
            .unwrap_or_default();
            self.scanner = Some(scanner);
            self.on_scan(found, &frame, at).await;
            self.recent.push_back((at, frame));
            while self.recent.front().is_some_and(|(t, _)| *t < at - PERIOD_SECS * 1.5) {
                self.recent.pop_front();
            }
        }
    }

    async fn on_scan(&mut self, found: Vec<Found>, frame: &Bytes, at: f64) {
        let now = Instant::now();
        if found.is_empty() {
            if self.last_mark.elapsed() >= UNMARKED_AFTER {
                self.set_stream(StreamState::Unmarked);
            }
        } else {
            self.last_mark = now;
            self.set_stream(StreamState::Marked);
        }
        for f in &found {
            let key = f.mark.session_key();
            match self.seen.get_mut(&key) {
                Some(seen) => {
                    seen.last = now;
                    let late = seen.acked.is_some_and(|a| now.duration_since(a) > SEEN_AFTER_ACK_GRACE);
                    let warn = late && !seen.warned;
                    seen.warned |= warn;
                    let n = seen.n;
                    let at = now_rfc3339();
                    self.with_trace(warn, |t| {
                        if let Some(leak) = t.leaks.iter_mut().find(|l| l.n == n) {
                            leak.last_seen_at = at;
                            leak.sightings += 1;
                            leak.seen_after_ack |= warn;
                        }
                    });
                    if warn {
                        self.record("leak_mark_still_on_air", json!({"trace_id": self.id, "leak": n}));
                    }
                }
                None => self.new_leak(f, frame, now, at).await,
            }
        }
        let current: HashSet<String> = found.iter().map(|f| f.mark.session_key()).collect();
        self.confirm_cuts(&current, false);
    }

    fn store_frame(&self, file: &str, bytes: &[u8]) {
        if let Err(e) = std::fs::create_dir_all(&self.dir).and_then(|_| std::fs::write(self.dir.join(file), bytes)) {
            tracing::warn!(error = %e, trace = %self.id, "could not store an evidence frame");
        }
    }

    async fn new_leak(&mut self, found: &Found, frame: &Bytes, now: Instant, at: f64) {
        let n = self.seen.len() as u32 + 1;
        let frame_file = format!("{n}.jpg");
        let frame_sha256 = sha256_hex(frame);
        self.store_frame(&frame_file, frame);
        // The watermark was read against a frame about half a period earlier: keep it too.
        let pair = found.sources.contains(&MarkSource::Watermark).then(|| {
            let target = at - PERIOD_SECS / 2.0;
            self.recent.iter().min_by(|a, b| (a.0 - target).abs().total_cmp(&(b.0 - target).abs())).cloned()
        });
        let (pair_frame_file, pair_frame_sha256) = match pair.flatten() {
            Some((_, bytes)) => {
                let file = format!("{n}-ref.jpg");
                self.store_frame(&file, &bytes);
                (Some(file), Some(sha256_hex(&bytes)))
            }
            None => (None, None),
        };
        let platform: Option<PlatformEntry> = self.app.platforms().find_by_code(found.mark.platform).cloned();
        let detected_at = now_rfc3339();
        let notice_id = format!("{}-{n}", self.id);
        let leak = Leak {
            n,
            mark: found.mark,
            mark_text: found.mark.text(),
            sources: found.sources.clone(),
            platform_name: platform.as_ref().map(|p| p.name.clone()),
            first_seen_at: detected_at.clone(),
            last_seen_at: detected_at.clone(),
            sightings: 1,
            frame_file,
            frame_sha256: frame_sha256.clone(),
            pair_frame_file,
            pair_frame_sha256: pair_frame_sha256.clone(),
            notice: Notice {
                notice_id: notice_id.clone(),
                status: if platform.is_some() { NoticeStatus::Sending } else { NoticeStatus::NotSent },
                attempts: 0,
                sent_at: None,
                answered_at: None,
                ack: None,
                error: platform.is_none().then(|| "platform not in the registry".to_string()),
            },
            ack_after_secs: None,
            cut_confirmed_at: None,
            cut_after_secs: None,
            seen_after_ack: false,
        };
        self.with_trace(true, |t| t.leaks.push(leak));
        self.record(
            "leak_identified",
            json!({
                "trace_id": self.id,
                "leak": n,
                "url": self.url,
                "case_id": self.case_id,
                "platform_code": found.mark.platform_hex(),
                "platform": platform.as_ref().map(|p| p.id.clone()),
                "client": found.mark.client_label(),
                "session": found.mark.session_hex(),
                "mark": found.mark.text(),
                "sources": found.sources,
                "frame_sha256": frame_sha256,
                "pair_frame_sha256": pair_frame_sha256,
            }),
        );
        self.seen.insert(
            found.mark.session_key(),
            Seen { n, first: now, last: now, acked: None, cut: false, warned: false },
        );
        self.app.persist();
        match platform {
            Some(platform) => {
                let request = NoticeRequest {
                    notice_id,
                    mark: found.mark.text(),
                    pirate_url: self.url.clone(),
                    frame_sha256,
                    detected_at,
                    case_id: self.case_id.clone(),
                    issuer: "Strack".to_string(),
                };
                self.notify(n, &found.mark, &platform, &request).await;
            }
            None => self.record(
                "leak_platform_unknown",
                json!({"trace_id": self.id, "leak": n, "platform_code": found.mark.platform_hex()}),
            ),
        }
        self.app.persist();
    }

    async fn notify(&mut self, n: u32, mark: &SessionMark, platform: &PlatformEntry, request: &NoticeRequest) {
        let key = mark.session_key();
        for attempt in 1..=NOTICE_ATTEMPTS {
            let sent_at = now_rfc3339();
            self.with_leak(n, |l| {
                l.notice.attempts = attempt;
                l.notice.sent_at = Some(sent_at);
            });
            self.record(
                "leak_notice_sent",
                json!({"trace_id": self.id, "leak": n, "notice_id": request.notice_id, "platform": platform.id, "attempt": attempt}),
            );
            match send_notice(&self.app.http, platform, request).await {
                Ok(ack) => {
                    let elapsed = self.seen.get(&key).map(|s| s.first.elapsed().as_secs_f64());
                    if let Some(seen) = self.seen.get_mut(&key) {
                        seen.acked = Some(Instant::now());
                    }
                    self.record(
                        "leak_notice_acknowledged",
                        json!({"trace_id": self.id, "leak": n, "notice_id": request.notice_id, "status": ack.status,
                               "client": ack.client_id, "session": ack.session_id, "sessions_closed": ack.sessions_closed,
                               "ack_after_secs": elapsed}),
                    );
                    let answered_at = now_rfc3339();
                    self.with_leak(n, |l| {
                        l.notice.status = NoticeStatus::Acknowledged;
                        l.notice.answered_at = Some(answered_at);
                        l.notice.ack = Some(ack);
                        l.notice.error = None;
                        l.ack_after_secs = elapsed;
                    });
                    return;
                }
                Err(NoticeError::Rejected { status, code }) => {
                    self.record(
                        "leak_notice_rejected",
                        json!({"trace_id": self.id, "leak": n, "notice_id": request.notice_id, "http_status": status, "code": code}),
                    );
                    let answered_at = now_rfc3339();
                    self.with_leak(n, |l| {
                        l.notice.status = NoticeStatus::Rejected;
                        l.notice.answered_at = Some(answered_at);
                        l.notice.error = Some(code);
                    });
                    return;
                }
                Err(NoticeError::Transport(error)) => {
                    let last = attempt == NOTICE_ATTEMPTS;
                    if last {
                        self.record(
                            "leak_notice_failed",
                            json!({"trace_id": self.id, "leak": n, "notice_id": request.notice_id, "error": error}),
                        );
                    }
                    self.with_leak(n, |l| {
                        l.notice.error = Some(error);
                        if last {
                            l.notice.status = NoticeStatus::Failed;
                        }
                    });
                    if !last {
                        tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
                    }
                }
            }
        }
    }

    /// Confirms the cut of acknowledged leaks: their mark is gone because the stream is down, another
    /// session took its place, or it has not been seen for `CUT_AFTER`.
    fn confirm_cuts(&mut self, current: &HashSet<String>, stream_down: bool) {
        let now = Instant::now();
        let mut confirmed = Vec::new();
        for (key, seen) in self.seen.iter_mut() {
            let Some(acked) = seen.acked else { continue };
            if seen.cut || current.contains(key) {
                continue;
            }
            let replaced = !current.is_empty();
            let quiet = now.duration_since(seen.last.max(acked)) >= CUT_AFTER;
            let reason = if stream_down {
                "stream_down"
            } else if replaced {
                "other_session_on_air"
            } else if quiet {
                "mark_gone"
            } else {
                continue;
            };
            seen.cut = true;
            confirmed.push((seen.n, now.duration_since(seen.first).as_secs_f64(), reason));
        }
        for (n, secs, reason) in confirmed {
            let at = now_rfc3339();
            self.with_leak(n, |l| {
                l.cut_confirmed_at = Some(at);
                l.cut_after_secs = Some(secs);
            });
            self.record(
                "leak_source_cut",
                json!({"trace_id": self.id, "leak": n, "reason": reason, "cut_after_secs": secs}),
            );
            self.app.persist();
        }
    }

    fn finish(&self, end: TraceEnd) {
        let leaks = {
            let mut core = self.app.core();
            let mut leaks = 0;
            if let Some(trace) = core.store.traces.iter_mut().find(|t| t.id == self.id) {
                trace.status = TraceStatus::Finished;
                trace.end = Some(end);
                trace.ended_at = Some(now_rfc3339());
                leaks = trace.leaks.len();
            }
            core.store.touch();
            leaks
        };
        self.record("trace_finished", json!({"trace_id": self.id, "end": end, "leaks": leaks}));
        self.app.persist();
    }
}
