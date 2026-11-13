//! Shared application state: settings, simulator client, accounts, sessions and the core state.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Notify;

use crate::access::Desk;
use crate::audit::{AuditEntry, AuditLog};
use crate::clock::MatchClock;
use crate::judges::{AccountsFile, Sessions};
use crate::leak::platforms::PlatformsFile;
use crate::model::Store;
use crate::simulator::Shift;
use crate::standalone::MatchSource;

#[derive(Debug, Clone)]
pub struct Settings {
    pub poll_interval: Duration,
    /// Extra match minutes a domain block lasts after the end of the match (IP blocks never do).
    pub domain_extra_min: i64,
    /// A judge stops signing this many match minutes before the end of the shift.
    pub shift_margin_min: f64,
    pub secure_cookies: bool,
    /// State of the first match and of the platform as a whole; match `n > 1` keeps its own in
    /// `match-<n>/` inside it.
    pub state_dir: PathBuf,
    /// Token monitoring services present to load detections through `POST /api/detections`
    /// (the API is off without one).
    pub intake_token: Option<String>,
    /// ffmpeg, which reads pirate streams that are not MJPEG (HLS, DASH, MP4, ...).
    pub ffmpeg: String,
    /// Let the stream reader (traces, Cargar sitios) reach local and private addresses. Off by
    /// default so nobody can point it at internal services; local demos turn it on.
    pub allow_private_streams: bool,
    /// Loopback proxy ffmpeg reaches the web through when private addresses are not allowed
    /// (`leak::egress`); `None` when they are.
    pub egress_proxy: Option<std::net::SocketAddr>,
    /// Where accounts and the platform registry are saved when edited from the web.
    pub accounts_path: PathBuf,
    pub platforms_path: PathBuf,
}

impl Settings {
    pub fn state_path(&self) -> PathBuf {
        state_path(&self.state_dir)
    }

    pub fn audit_path(&self) -> PathBuf {
        audit_path(&self.state_dir)
    }

    /// Access requests from people without an account (`access::AccessRequests`).
    pub fn access_requests_path(&self) -> PathBuf {
        self.state_dir.join("access-requests.json")
    }
}

pub fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

pub fn audit_path(dir: &Path) -> PathBuf {
    dir.join("audit.jsonl")
}

/// Everything that changes during a match, behind one lock.
pub struct Core {
    pub store: Store,
    pub audit: AuditLog,
    pub clock: MatchClock,
}

impl Core {
    pub fn now(&self) -> f64 {
        self.clock.now()
    }

    pub fn shifts(&self) -> Vec<Shift> {
        self.store.courts.as_ref().map(|c| c.shifts.clone()).unwrap_or_default()
    }

    pub fn record(&mut self, actor: &str, event: &str, data: Value) -> AuditEntry {
        let minute = self.clock.synced.then(|| self.clock.now());
        self.audit.record(minute, actor, event, data)
    }

    /// Writes the state snapshot when something changed (write to a temp file, then rename).
    pub fn persist(&mut self, path: &Path) {
        if !self.store.dirty {
            return;
        }
        let result = serde_json::to_vec(&self.store).map_err(anyhow::Error::from).and_then(|bytes| {
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, bytes)?;
            std::fs::rename(&tmp, path)?;
            Ok(())
        });
        match result {
            Ok(()) => self.store.dirty = false,
            // Keep the dirty flag so the next tick retries (e.g. a sync client holding the file).
            Err(e) => tracing::warn!(error = %e, "could not persist the state snapshot"),
        }
    }
}

/// One match followed live: its simulator (feed, providers, courts), its state and its audit chain.
pub struct MatchRun {
    /// Position among the matches (`--simulator`s first, then `--config`s), starting at 1; used in
    /// links and state folders.
    pub key: String,
    /// The challenge simulator, or a config file and the providers' own APIs.
    pub sim: MatchSource,
    pub state_dir: PathBuf,
    pub core: Mutex<Core>,
    /// Wakes this match's dispatcher as soon as there is something signed to send.
    pub dispatch: Notify,
}

impl MatchRun {
    pub fn core(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn state_path(&self) -> PathBuf {
        state_path(&self.state_dir)
    }

    pub fn audit_path(&self) -> PathBuf {
        audit_path(&self.state_dir)
    }

    pub fn persist(&self) {
        let path = self.state_path();
        self.core().persist(&path);
    }

    /// Teams as people say them (`Norte vs. Ejemplo`), before the match is known `Partido <n>`.
    pub fn label(&self) -> String {
        match_label(&self.key, self.core().store.match_info.as_ref().map(|m| m.name.as_str()))
    }
}

/// The teams part of a match name (`Partido de práctica — A vs. B` gives `A vs. B`).
pub fn match_label(key: &str, name: Option<&str>) -> String {
    match name {
        Some(name) => name.rsplit(" — ").next().unwrap_or(name).to_string(),
        None => format!("Partido {key}"),
    }
}

/// State folder of match `n` (1-based): the first match keeps the platform's folder.
pub fn match_state_dir(state_dir: &Path, n: usize) -> PathBuf {
    if n <= 1 { state_dir.to_path_buf() } else { state_dir.join(format!("match-{n}")) }
}

pub struct App {
    pub settings: Settings,
    /// Matches followed at the same time, in `--simulator` order. Never empty.
    pub matches: Vec<std::sync::Arc<MatchRun>>,
    pub accounts: RwLock<AccountsFile>,
    /// Licensed platforms that accept leak notices.
    pub platforms: RwLock<PlatformsFile>,
    /// HTTP client for leak tracing and notices (no overall timeout: streams stay open).
    pub http: reqwest::Client,
    pub sessions: Mutex<Sessions>,
    /// Access requests, recovery requests and one-time password links. Never held with another lock.
    pub desk: Mutex<Desk>,
}

impl App {
    /// The first match, which also carries the platform-wide records (sign-ins, administration,
    /// leak traces).
    pub fn primary(&self) -> &std::sync::Arc<MatchRun> {
        &self.matches[0]
    }

    /// Core of the first match (see [`App::primary`]).
    pub fn core(&self) -> MutexGuard<'_, Core> {
        self.primary().core()
    }

    pub fn match_run(&self, key: &str) -> Option<&std::sync::Arc<MatchRun>> {
        self.matches.iter().find(|m| m.key == key)
    }

    /// The match a `?partido=` value names, or the first one.
    pub fn match_or_primary(&self, key: Option<&str>) -> &std::sync::Arc<MatchRun> {
        key.and_then(|k| self.match_run(k)).unwrap_or_else(|| self.primary())
    }

    /// `(key, label)` of every match, for switchers and tables.
    pub fn match_list(&self) -> Vec<(String, String)> {
        self.matches.iter().map(|m| (m.key.clone(), m.label())).collect()
    }

    /// The match that holds a case (case ids never repeat across matches).
    pub fn match_of_case(&self, case_id: &str) -> Option<&std::sync::Arc<MatchRun>> {
        self.matches.iter().find(|m| m.core().store.case(case_id).is_some())
    }

    /// The match that holds a claim, preferring the one a link names (claim ids come from each
    /// match's feed and may repeat).
    pub fn match_of_claim(&self, claim_id: &str, preferred: Option<&str>) -> Option<&std::sync::Arc<MatchRun>> {
        let has = |m: &&std::sync::Arc<MatchRun>| m.core().store.claim(claim_id).is_some();
        preferred.and_then(|k| self.match_run(k)).filter(has).or_else(|| self.matches.iter().find(has))
    }

    pub fn sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn desk(&self) -> MutexGuard<'_, Desk> {
        self.desk.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn accounts(&self) -> RwLockReadGuard<'_, AccountsFile> {
        self.accounts.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn accounts_mut(&self) -> RwLockWriteGuard<'_, AccountsFile> {
        self.accounts.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn platforms(&self) -> RwLockReadGuard<'_, PlatformsFile> {
        self.platforms.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn platforms_mut(&self) -> RwLockWriteGuard<'_, PlatformsFile> {
        self.platforms.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Writes every match's snapshot that changed.
    pub fn persist(&self) {
        for m in &self.matches {
            m.persist();
        }
    }
}
