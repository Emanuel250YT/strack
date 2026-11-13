//! Registry of licensed platforms that accept leak notices, and the notice client.
//!
//! A notice tells the platform that one of its sessions is being restreamed. The platform checks that
//! it issued that session to that subscriber, suspends the subscriber and closes the session.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    /// The platform set `api_url` itself from its portal: notices then go only to public addresses,
    /// checked and pinned at send time. An address an admin set is trusted (it may be internal).
    #[serde(default)]
    pub api_url_from_platform: bool,
}

fn public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b)))
}

/// An address outside loopback, private, link-local, CGNAT and multicast ranges, also when an IPv4
/// address hides inside IPv6 (mapped, compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`).
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            if s[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified() {
                return public_v4(embedded(s[6], s[7]));
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return public_v4(embedded(s[6], s[7]));
            }
            if s[0] == 0x2002 {
                return public_v4(embedded(s[1], s[2]));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Resolves the URL's host; `Some` only when every address it resolves to is public.
pub async fn public_addrs(url: &str) -> Option<(String, Vec<SocketAddr>)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return None;
    }
    let port = parsed.port_or_known_default()?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.ok()?.collect();
    (!addrs.is_empty() && addrs.iter().all(|a| public_ip(a.ip()))).then_some((host, addrs))
}

/// True when every address the URL resolves to is public.
pub async fn reaches_only_public(url: &str) -> bool {
    public_addrs(url).await.is_some()
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

/// Sends a notice. Notices never follow redirects; when the platform chose its address, the host is
/// resolved now, every address must be public, and the connection goes to those very addresses (no
/// second lookup a DNS change could redirect inside the network).
pub async fn send_notice(platform: &PlatformEntry, notice: &NoticeRequest) -> Result<NoticeAck, NoticeError> {
    let url = format!("{}/api/notices", platform.api_url.trim_end_matches('/'));
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(NOTICE_TIMEOUT)
        .user_agent("strack");
    if platform.api_url_from_platform {
        let Some((host, addrs)) = public_addrs(&url).await else {
            return Err(NoticeError::Rejected { status: 0, code: "api_url_not_public".into() });
        };
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    let http = builder.build().map_err(|e| NoticeError::Transport(e.to_string()))?;
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
