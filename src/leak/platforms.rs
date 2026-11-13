//! Registry of licensed platforms that accept leak notices, and the notice client.
//!
//! A notice tells the platform that one of its sessions is being restreamed. The platform checks that
//! it issued that session to that subscriber, suspends the subscriber and closes the session.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::leak::mark::platform_code;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformEntry {
    pub id: String,
    pub name: String,
    /// Base URL of the platform's notice API.
    pub api_url: String,
    /// Bearer token the platform issued to Strack (demo value in `config/platforms.json`).
    pub notice_token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformsFile {
    pub platforms: Vec<PlatformEntry>,
}

impl PlatformsFile {
    /// Loads the registry; a missing file means no platform can be notified (tracing still works).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::warn!(path = %path.display(), "no platforms file: leak notices are disabled");
            return Ok(PlatformsFile::default());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn find(&self, id: &str) -> Option<&PlatformEntry> {
        self.platforms.iter().find(|p| p.id == id)
    }

    /// The platform whose id hashes to the 16-bit code carried by a mark.
    pub fn find_by_code(&self, code: u16) -> Option<&PlatformEntry> {
        self.platforms.iter().find(|p| platform_code(&p.id) == code)
    }
}

/// Body of `POST {api_url}/api/notices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeRequest {
    pub notice_id: String,
    /// The mark exactly as read from the pirate stream.
    pub mark: String,
    pub pirate_url: String,
    pub frame_sha256: String,
    pub detected_at: String,
    pub case_id: Option<String>,
    pub issuer: String,
}

/// The platform's answer when it accepted the notice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeAck {
    /// `suspended` or `already_suspended`.
    pub status: String,
    pub client_id: String,
    pub session_id: String,
    pub sessions_closed: u32,
    pub at: String,
}

#[derive(Debug, Clone)]
pub enum NoticeError {
    /// The platform answered and refused (e.g. `invalid_mark`, `unknown_session`).
    Rejected { status: u16, code: String },
    /// No usable answer (network, timeout, unexpected body): worth retrying.
    Transport(String),
}

impl std::fmt::Display for NoticeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoticeError::Rejected { status, code } => write!(f, "rejected with HTTP {status}: {code}"),
            NoticeError::Transport(e) => write!(f, "{e}"),
        }
    }
}

pub const NOTICE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn send_notice(
    http: &reqwest::Client,
    platform: &PlatformEntry,
    notice: &NoticeRequest,
) -> Result<NoticeAck, NoticeError> {
    let url = format!("{}/api/notices", platform.api_url.trim_end_matches('/'));
    let response = http
        .post(&url)
        .bearer_auth(&platform.notice_token)
        .timeout(NOTICE_TIMEOUT)
        .json(notice)
        .send()
        .await
        .map_err(|e| NoticeError::Transport(e.to_string()))?;
    let status = response.status();
    if status.is_success() {
        return response.json::<NoticeAck>().await.map_err(|e| NoticeError::Transport(e.to_string()));
    }
    let code = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| status.to_string());
    if status.is_server_error() {
        Err(NoticeError::Transport(format!("HTTP {}: {code}", status.as_u16())))
    } else {
        Err(NoticeError::Rejected { status: status.as_u16(), code })
    }
}
