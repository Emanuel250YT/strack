//! Getting into Strack without an account or without the password: access requests and account
//! recovery.
//!
//! Nothing is mailed. A person asks (for access, or to recover their account); an admin reviews the
//! request and hands over a one-time link to choose the password, through a channel they trust.
//! Links are kept hashed, in memory only, and work once within `LINK_TTL`. Access requests are saved
//! in the state directory; recovery requests live in memory.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::admin::valid_username;
use crate::crypto::{random_token, sha256_hex};
use crate::judges::{AccountsFile, Role};

pub const LINK_TTL: Duration = Duration::from_secs(30 * 60);
/// Pending access requests kept at most (the form is public).
const MAX_PENDING: usize = 50;
const MAX_TEXT: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    NameRequired,
    InvalidUsername,
    UsernameTaken,
    AlreadyRequested,
    OrganismRequired,
    ContactRequired,
    TooManyRequests,
    NotFound,
    AlreadyDecided,
    Internal,
}

impl AccessError {
    /// Code for `?error=` (mapped to Spanish text in `web::labels::message`).
    pub fn code(self) -> &'static str {
        match self {
            AccessError::NameRequired => "name_required",
            AccessError::InvalidUsername => "invalid_username",
            AccessError::UsernameTaken => "username_taken",
            AccessError::AlreadyRequested => "already_requested",
            AccessError::OrganismRequired => "organism_required",
            AccessError::ContactRequired => "contact_required",
            AccessError::TooManyRequests => "too_many_requests",
            AccessError::NotFound => "not_found",
            AccessError::AlreadyDecided => "already_decided",
            AccessError::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// `AR-0001`, ...
    pub id: String,
    pub at: String,
    pub name: String,
    pub username: String,
    pub role: Role,
    pub organism: String,
    /// How the admin reaches the person to hand over the link.
    pub contact: String,
    pub reason: String,
    pub status: RequestStatus,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_at: Option<String>,
}

pub struct NewRequest<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub role: Role,
    pub organism: &'a str,
    pub contact: &'a str,
    pub reason: &'a str,
}

fn clip(text: &str) -> String {
    text.trim().chars().take(MAX_TEXT).collect()
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AccessRequests {
    pub requests: Vec<AccessRequest>,
}

impl AccessRequests {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    /// Writes a temp file and renames it over the old one.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn pending(&self) -> Vec<&AccessRequest> {
        self.requests.iter().filter(|r| r.status == RequestStatus::Pending).collect()
    }

    pub fn find(&self, id: &str) -> Option<&AccessRequest> {
        self.requests.iter().find(|r| r.id == id)
    }

    pub fn submit(
        &mut self,
        accounts: &AccountsFile,
        new: NewRequest<'_>,
        at: &str,
    ) -> Result<AccessRequest, AccessError> {
        let name = clip(new.name);
        if name.is_empty() {
            return Err(AccessError::NameRequired);
        }
        let username = new.username.trim().to_ascii_lowercase();
        if !valid_username(&username) {
            return Err(AccessError::InvalidUsername);
        }
        if accounts.find(&username).is_some() {
            return Err(AccessError::UsernameTaken);
        }
        let pending = self.pending();
        if pending.iter().any(|r| r.username == username) {
            return Err(AccessError::AlreadyRequested);
        }
        if pending.len() >= MAX_PENDING {
            return Err(AccessError::TooManyRequests);
        }
        let organism = clip(new.organism);
        if organism.is_empty() {
            return Err(AccessError::OrganismRequired);
        }
        let contact = clip(new.contact);
        if contact.is_empty() {
            return Err(AccessError::ContactRequired);
        }
        let request = AccessRequest {
            id: format!("AR-{:04}", self.requests.len() + 1),
            at: at.to_string(),
            name,
            username,
            role: new.role,
            organism,
            contact,
            reason: clip(new.reason),
            status: RequestStatus::Pending,
            decided_by: None,
            decided_at: None,
        };
        self.requests.push(request.clone());
        Ok(request)
    }

    pub fn decide(&mut self, id: &str, approved: bool, by: &str, at: &str) -> Result<AccessRequest, AccessError> {
        let request = self.requests.iter_mut().find(|r| r.id == id).ok_or(AccessError::NotFound)?;
        if request.status != RequestStatus::Pending {
            return Err(AccessError::AlreadyDecided);
        }
        request.status = if approved { RequestStatus::Approved } else { RequestStatus::Rejected };
        request.decided_by = Some(by.to_string());
        request.decided_at = Some(at.to_string());
        Ok(request.clone())
    }
}

/// The admin's desk: one-time password links and recovery requests (memory only), plus the saved
/// access requests.
#[derive(Default)]
pub struct Desk {
    links: HashMap<String, (String, Instant)>,
    recoveries: Vec<(String, String)>,
    pub requests: AccessRequests,
}

impl Desk {
    pub fn new(requests: AccessRequests) -> Self {
        Desk { requests, ..Desk::default() }
    }

    fn purge(&mut self) {
        let now = Instant::now();
        self.links.retain(|_, (_, expires)| *expires > now);
    }

    /// A new one-time link token for a user; any earlier one stops working.
    pub fn issue(&mut self, username: &str) -> String {
        self.issue_for(username, LINK_TTL)
    }

    fn issue_for(&mut self, username: &str, ttl: Duration) -> String {
        self.purge();
        self.revoke(username);
        let token = random_token(32);
        self.links.insert(sha256_hex(token.as_bytes()), (username.to_ascii_lowercase(), Instant::now() + ttl));
        token
    }

    /// The user a live link belongs to, without using it up.
    pub fn peek(&mut self, token: &str) -> Option<String> {
        self.purge();
        self.links.get(&sha256_hex(token.as_bytes())).map(|(username, _)| username.clone())
    }

    pub fn consume(&mut self, token: &str) -> Option<String> {
        self.purge();
        self.links.remove(&sha256_hex(token.as_bytes())).map(|(username, _)| username)
    }

    pub fn revoke(&mut self, username: &str) {
        self.links.retain(|_, (u, _)| !u.eq_ignore_ascii_case(username));
    }

    /// Records that a user asked to recover their account; `false` if they already had.
    pub fn ask_recovery(&mut self, username: &str, at: &str) -> bool {
        let username = username.to_ascii_lowercase();
        if self.recoveries.iter().any(|(u, _)| *u == username) {
            return false;
        }
        self.recoveries.push((username, at.to_string()));
        true
    }

    /// `(username, when)` of every pending recovery request, oldest first.
    pub fn recoveries(&self) -> &[(String, String)] {
        &self.recoveries
    }

    pub fn recovery_of(&self, username: &str) -> Option<&str> {
        self.recoveries.iter().find(|(u, _)| u.eq_ignore_ascii_case(username)).map(|(_, at)| at.as_str())
    }

    pub fn clear_recovery(&mut self, username: &str) {
        self.recoveries.retain(|(u, _)| !u.eq_ignore_ascii_case(username));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::access::{AccessError, AccessRequests, Desk, NewRequest, RequestStatus};
    use crate::admin::{NewAccount, create_account};
    use crate::judges::{AccountsFile, Role};

    fn request<'a>(username: &'a str) -> NewRequest<'a> {
        NewRequest {
            name: "Ana Pérez",
            username,
            role: Role::Operator,
            organism: "ENACOM",
            contact: "ana@example.com",
            reason: "Operación del partido",
        }
    }

    #[test]
    fn access_requests() {
        let mut accounts = AccountsFile::default();
        let existing = NewAccount {
            username: "laura",
            display_name: "Laura",
            role: Role::Operator,
            password: "una-clave-larga",
            judge: None,
            signing_key: None,
            platform: None,
        };
        create_account(&mut accounts, existing).unwrap();
        let mut requests = AccessRequests::default();
        assert_eq!(requests.submit(&accounts, request("laura"), "t").unwrap_err(), AccessError::UsernameTaken);
        assert_eq!(requests.submit(&accounts, request("A B"), "t").unwrap_err(), AccessError::InvalidUsername);
        let first = requests.submit(&accounts, request(" Ana.Perez "), "t").unwrap();
        assert_eq!((first.id.as_str(), first.username.as_str()), ("AR-0001", "ana.perez"));
        assert_eq!(requests.submit(&accounts, request("ana.perez"), "t").unwrap_err(), AccessError::AlreadyRequested);
        let no_organism = NewRequest { organism: " ", ..request("beto") };
        assert_eq!(requests.submit(&accounts, no_organism, "t").unwrap_err(), AccessError::OrganismRequired);
        let decided = requests.decide("AR-0001", false, "admin", "t2").unwrap();
        assert_eq!(decided.status, RequestStatus::Rejected);
        assert_eq!(requests.decide("AR-0001", true, "admin", "t3").unwrap_err(), AccessError::AlreadyDecided);
        assert!(requests.pending().is_empty());
        // After a rejection the same username can ask again.
        assert_eq!(requests.submit(&accounts, request("ana.perez"), "t").unwrap().id, "AR-0002");
    }

    #[test]
    fn pending_requests_are_capped() {
        let accounts = AccountsFile::default();
        let mut requests = AccessRequests::default();
        for i in 0..50 {
            requests.submit(&accounts, request(&format!("persona{i}")), "t").unwrap();
        }
        assert_eq!(requests.submit(&accounts, request("una-mas"), "t").unwrap_err(), AccessError::TooManyRequests);
    }

    #[test]
    fn links_work_once() {
        let mut desk = Desk::default();
        let first = desk.issue("Laura");
        let second = desk.issue("laura");
        assert_eq!(desk.peek(&first), None);
        assert_eq!(desk.peek(&second).as_deref(), Some("laura"));
        assert_eq!(desk.consume(&second).as_deref(), Some("laura"));
        assert_eq!(desk.consume(&second), None);
        let expired = desk.issue_for("martin", Duration::ZERO);
        assert_eq!(desk.peek(&expired), None);
    }

    #[test]
    fn recovery_requests() {
        let mut desk = Desk::default();
        assert!(desk.ask_recovery("Laura", "t1"));
        assert!(!desk.ask_recovery("laura", "t2"));
        assert_eq!(desk.recovery_of("LAURA"), Some("t1"));
        desk.clear_recovery("laura");
        assert!(desk.recoveries().is_empty());
    }
}
