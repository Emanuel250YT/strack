//! Subscriber accounts of the demo platform: the directory (saved to a JSON file), browser sessions,
//! one-time password links and the demo mailbox that stands in for email.
//!
//! Pure over its own types: the web handlers in `demo::site` (subscribers) and `demo::staff`
//! (platform staff) check the session and the CSRF token, hash passwords off the async runtime, call
//! these functions and save the directory. Nothing here logs a password or a link.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::crypto::{random_token, sha256_hex};
use crate::leak::mark::{client_label, parse_client};

pub const MIN_PASSWORD: usize = 10;
/// Password of the seeded demo subscribers (documented in the README; the demo pirate uses it).
pub const DEMO_PASSWORD: &str = "abonado-demo-2026";
/// Seeded subscribers get `abonado41@tvficticia.test`, ... (`.test` is reserved, nothing is ever sent).
pub const DEMO_EMAIL_DOMAIN: &str = "tvficticia.test";
pub const PLANS: [&str; 3] = ["Fútbol", "Fútbol + series", "Premium"];
/// How long a password link (recovery or first password) works.
pub const LINK_TTL: Duration = Duration::from_secs(30 * 60);
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(30);
const MAILBOX_SIZE: usize = 500;
const FIRST_NUMBER: u32 = 41;
const MAX_NAME: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    NameRequired,
    InvalidEmail,
    EmailTaken,
    InvalidPlan,
    PasswordTooShort,
    PasswordMismatch,
    NotFound,
}

impl AccountError {
    /// Code for `?error=` (mapped to Spanish text in `demo::platform::message`).
    pub fn code(self) -> &'static str {
        match self {
            AccountError::NameRequired => "name_required",
            AccountError::InvalidEmail => "invalid_email",
            AccountError::EmailTaken => "email_taken",
            AccountError::InvalidPlan => "invalid_plan",
            AccountError::PasswordTooShort => "password_too_short",
            AccountError::PasswordMismatch => "password_mismatch",
            AccountError::NotFound => "not_found",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suspension {
    pub at: String,
    /// Strack's notice id, or `manual` when the staff suspended the account.
    pub notice_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscriber {
    pub number: u32,
    pub name: String,
    pub email: String,
    pub plan: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    pub created_at: String,
    #[serde(default)]
    pub suspended: Option<Suspension>,
}

impl Subscriber {
    pub fn label(&self) -> String {
        client_label(self.number)
    }
}

/// Name, email and plan as typed in a form.
pub struct Profile<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub plan: &'a str,
}

/// A profile that passed validation (trimmed, email lowercased, plan one of `PLANS`).
#[derive(Debug, Clone)]
pub struct CheckedProfile {
    pub name: String,
    pub email: String,
    pub plan: String,
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// `local@domain.tld`, no spaces, at most 254 characters.
pub fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.split('.').count() >= 2
                && domain.split('.').all(|part| !part.is_empty())
        })
}

pub fn check_password(password: &str, repeat: &str) -> Result<(), AccountError> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(AccountError::PasswordTooShort);
    }
    if password != repeat {
        return Err(AccountError::PasswordMismatch);
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Directory {
    pub subscribers: Vec<Subscriber>,
    /// Next subscriber number. Numbers are never reused: an old mark must never name a new person.
    #[serde(default)]
    next_number: u32,
}

impl Directory {
    /// `count` demo subscribers from `c-00041`, all with the same demo password hash.
    pub fn seeded(count: u32, password_hash: &str, at: &str) -> Self {
        let subscribers = (0..count)
            .map(|i| {
                let number = FIRST_NUMBER + i;
                Subscriber {
                    number,
                    name: format!("Abonado {number}"),
                    email: format!("abonado{number}@{DEMO_EMAIL_DOMAIN}"),
                    plan: PLANS[(i % 3) as usize].to_string(),
                    password_hash: password_hash.to_string(),
                    created_at: at.to_string(),
                    suspended: None,
                }
            })
            .collect();
        Directory { subscribers, next_number: FIRST_NUMBER + count }
    }

    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let directory = serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(directory))
    }

    /// Writes a temp file and renames it over the old one.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn find(&self, number: u32) -> Option<&Subscriber> {
        self.subscribers.iter().find(|s| s.number == number)
    }

    fn find_mut(&mut self, number: u32) -> Result<&mut Subscriber, AccountError> {
        self.subscribers.iter_mut().find(|s| s.number == number).ok_or(AccountError::NotFound)
    }

    pub fn find_by_email(&self, email: &str) -> Option<&Subscriber> {
        let email = normalize_email(email);
        self.subscribers.iter().find(|s| s.email == email)
    }

    /// What people sign in with: their email, or their subscriber number (`c-00042`).
    pub fn find_login(&self, login: &str) -> Option<&Subscriber> {
        if login.contains('@') {
            return self.find_by_email(login);
        }
        parse_client(login).and_then(|number| self.find(number))
    }

    /// Validates a profile; the email must not belong to anybody but `owner`.
    pub fn check_profile(&self, profile: &Profile<'_>, owner: Option<u32>) -> Result<CheckedProfile, AccountError> {
        let name: String = profile.name.trim().chars().take(MAX_NAME).collect();
        if name.is_empty() {
            return Err(AccountError::NameRequired);
        }
        let email = normalize_email(profile.email);
        if !valid_email(&email) {
            return Err(AccountError::InvalidEmail);
        }
        if self.find_by_email(&email).is_some_and(|s| Some(s.number) != owner) {
            return Err(AccountError::EmailTaken);
        }
        let plan = PLANS.iter().find(|p| **p == profile.plan.trim()).ok_or(AccountError::InvalidPlan)?;
        Ok(CheckedProfile { name, email, plan: (*plan).to_string() })
    }

    /// Adds a subscriber with the next free number and returns it.
    pub fn add(&mut self, profile: CheckedProfile, password_hash: String, at: &str) -> Result<u32, AccountError> {
        if self.find_by_email(&profile.email).is_some() {
            return Err(AccountError::EmailTaken);
        }
        let number = self.subscribers.iter().map(|s| s.number + 1).fold(self.next_number.max(FIRST_NUMBER), u32::max);
        self.next_number = number + 1;
        self.subscribers.push(Subscriber {
            number,
            name: profile.name,
            email: profile.email,
            plan: profile.plan,
            password_hash,
            created_at: at.to_string(),
            suspended: None,
        });
        Ok(number)
    }

    pub fn update(&mut self, number: u32, profile: CheckedProfile) -> Result<(), AccountError> {
        if self.find_by_email(&profile.email).is_some_and(|s| s.number != number) {
            return Err(AccountError::EmailTaken);
        }
        let subscriber = self.find_mut(number)?;
        subscriber.name = profile.name;
        subscriber.email = profile.email;
        subscriber.plan = profile.plan;
        Ok(())
    }

    pub fn set_password_hash(&mut self, number: u32, password_hash: String) -> Result<(), AccountError> {
        self.find_mut(number)?.password_hash = password_hash;
        Ok(())
    }

    pub fn remove(&mut self, number: u32) -> Result<Subscriber, AccountError> {
        let index = self.subscribers.iter().position(|s| s.number == number).ok_or(AccountError::NotFound)?;
        Ok(self.subscribers.remove(index))
    }

    /// Suspends the account; returns `true` when it already was (the first suspension is kept).
    pub fn suspend(&mut self, number: u32, at: &str, notice_id: &str) -> Result<bool, AccountError> {
        let subscriber = self.find_mut(number)?;
        if subscriber.suspended.is_some() {
            return Ok(true);
        }
        subscriber.suspended = Some(Suspension { at: at.to_string(), notice_id: notice_id.to_string() });
        Ok(false)
    }

    pub fn reactivate(&mut self, number: u32) -> Result<(), AccountError> {
        self.find_mut(number)?.suspended = None;
        Ok(())
    }

    pub fn reactivate_all(&mut self) {
        for subscriber in &mut self.subscribers {
            subscriber.suspended = None;
        }
    }
}

/// Who a browser session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Subscriber(u32),
    /// The platform's own staff (subscriber management and leak notices).
    Staff,
}

#[derive(Debug, Clone)]
pub struct WebSession {
    pub token: String,
    pub csrf: String,
    pub who: Who,
    expires_at: Instant,
}

/// Browser sessions plus failed sign-in counts (a short lockout after `MAX_FAILURES`).
#[derive(Default)]
pub struct WebSessions {
    by_token: HashMap<String, WebSession>,
    failures: HashMap<String, (u32, Instant)>,
}

impl WebSessions {
    fn purge(&mut self) {
        let now = Instant::now();
        self.by_token.retain(|_, s| s.expires_at > now);
    }

    pub fn create(&mut self, who: Who) -> WebSession {
        self.purge();
        let session = WebSession {
            token: random_token(32),
            csrf: random_token(16),
            who,
            expires_at: Instant::now() + SESSION_TTL,
        };
        self.by_token.insert(session.token.clone(), session.clone());
        session
    }

    pub fn get(&mut self, token: &str) -> Option<WebSession> {
        self.purge();
        self.by_token.get(token).cloned()
    }

    pub fn remove(&mut self, token: &str) {
        self.by_token.remove(token);
    }

    /// Signs a subscriber out everywhere except `keep`; returns how many sessions were closed.
    pub fn remove_subscriber(&mut self, number: u32, keep: Option<&str>) -> usize {
        let before = self.by_token.len();
        self.by_token.retain(|token, s| s.who != Who::Subscriber(number) || Some(token.as_str()) == keep);
        before - self.by_token.len()
    }

    pub fn is_locked_out(&self, login: &str) -> bool {
        self.failures
            .get(&login.trim().to_lowercase())
            .is_some_and(|(count, last)| *count >= MAX_FAILURES && last.elapsed() < LOCKOUT)
    }

    pub fn record_failure(&mut self, login: &str) {
        let entry = self.failures.entry(login.trim().to_lowercase()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= LOCKOUT {
            entry.0 = 0;
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn clear_failures(&mut self, login: &str) {
        self.failures.remove(&login.trim().to_lowercase());
    }
}

/// One-time password links. Only a hash of each token is kept; issuing a new link for a subscriber
/// voids the previous one.
#[derive(Default)]
pub struct Links {
    by_hash: HashMap<String, (u32, Instant)>,
}

impl Links {
    fn purge(&mut self) {
        let now = Instant::now();
        self.by_hash.retain(|_, (_, expires)| *expires > now);
    }

    pub fn issue(&mut self, number: u32) -> String {
        self.issue_for(number, LINK_TTL)
    }

    fn issue_for(&mut self, number: u32, ttl: Duration) -> String {
        self.purge();
        self.revoke(number);
        let token = random_token(32);
        self.by_hash.insert(sha256_hex(token.as_bytes()), (number, Instant::now() + ttl));
        token
    }

    /// The subscriber a live link belongs to, without using it up.
    pub fn peek(&mut self, token: &str) -> Option<u32> {
        self.purge();
        self.by_hash.get(&sha256_hex(token.as_bytes())).map(|(number, _)| *number)
    }

    pub fn consume(&mut self, token: &str) -> Option<u32> {
        self.purge();
        self.by_hash.remove(&sha256_hex(token.as_bytes())).map(|(number, _)| number)
    }

    pub fn revoke(&mut self, number: u32) {
        self.by_hash.retain(|_, (n, _)| *n != number);
    }
}

#[derive(Debug, Clone)]
pub struct Mail {
    pub at: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    /// Path of the one-time link the mail carries, if any.
    pub link: Option<String>,
}

/// Where the platform's emails land in the demo (nothing leaves the machine).
#[derive(Default)]
pub struct Mailbox {
    mails: Vec<Mail>,
}

impl Mailbox {
    pub fn send(&mut self, mail: Mail) {
        self.mails.push(mail);
        if self.mails.len() > MAILBOX_SIZE {
            self.mails.remove(0);
        }
    }

    /// Mails sent to `email`, newest first.
    pub fn to(&self, email: &str) -> Vec<&Mail> {
        let email = normalize_email(email);
        self.mails.iter().rev().filter(|m| m.to == email).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::demo::accounts::{
        AccountError, Directory, Links, Mail, Mailbox, Profile, WebSessions, Who, check_password, valid_email,
    };

    fn profile<'a>(name: &'a str, email: &'a str) -> Profile<'a> {
        Profile { name, email, plan: "Premium" }
    }

    #[test]
    fn emails() {
        assert!(valid_email("ana@example.com"));
        assert!(valid_email("abonado41@tvficticia.test"));
        assert!(!valid_email("ana"));
        assert!(!valid_email("ana@local"));
        assert!(!valid_email("ana @example.com"));
        assert!(!valid_email("@example.com"));
        assert!(!valid_email("ana@@example.com"));
        assert!(!valid_email("ana@example..com"));
    }

    #[test]
    fn passwords() {
        assert_eq!(check_password("corta", "corta").unwrap_err(), AccountError::PasswordTooShort);
        assert_eq!(check_password("una-clave-larga", "otra-clave-larga").unwrap_err(), AccountError::PasswordMismatch);
        check_password("una-clave-larga", "una-clave-larga").unwrap();
    }

    #[test]
    fn crud() {
        let mut dir = Directory::seeded(3, "hash", "2026-11-12T00:00:00Z");
        assert_eq!(dir.find_login("c-00042").unwrap().email, "abonado42@tvficticia.test");
        assert_eq!(dir.find_login(" ABONADO43@tvficticia.test ").unwrap().number, 43);
        assert!(dir.find_login("c-00099").is_none());

        let checked = dir.check_profile(&profile("  Ana Pérez ", "Ana@Example.com"), None).unwrap();
        assert_eq!((checked.name.as_str(), checked.email.as_str()), ("Ana Pérez", "ana@example.com"));
        let number = dir.add(checked, "h".into(), "now").unwrap();
        assert_eq!(number, 44);
        assert_eq!(dir.check_profile(&profile("Otra", "ana@example.com"), None).unwrap_err(), AccountError::EmailTaken);
        // Keeping your own email is fine.
        let same = dir.check_profile(&profile("Ana P.", "ana@example.com"), Some(number)).unwrap();
        dir.update(number, same).unwrap();
        assert_eq!(dir.find(number).unwrap().name, "Ana P.");
        assert_eq!(dir.check_profile(&profile("", "x@y.z"), None).unwrap_err(), AccountError::NameRequired);
        let bad_plan = Profile { name: "X", email: "x@y.z", plan: "Gratis" };
        assert_eq!(dir.check_profile(&bad_plan, None).unwrap_err(), AccountError::InvalidPlan);

        assert!(!dir.suspend(number, "t1", "RAS-1").unwrap());
        assert!(dir.suspend(number, "t2", "manual").unwrap());
        assert_eq!(dir.find(number).unwrap().suspended.as_ref().unwrap().notice_id, "RAS-1");
        dir.reactivate(number).unwrap();
        assert!(dir.find(number).unwrap().suspended.is_none());

        dir.remove(number).unwrap();
        assert_eq!(dir.remove(number).unwrap_err(), AccountError::NotFound);
        // Numbers are never reused.
        let again = dir.check_profile(&profile("Beto", "beto@example.com"), None).unwrap();
        assert_eq!(dir.add(again, "h".into(), "now").unwrap(), 45);
    }

    #[test]
    fn saves_and_loads() {
        let path = std::env::temp_dir().join(format!("strack-demo-dir-{}.json", rand::random::<u32>()));
        let dir = Directory::seeded(2, "hash", "now");
        dir.save(&path).unwrap();
        let loaded = Directory::load(&path).unwrap().unwrap();
        assert_eq!(loaded.subscribers.len(), 2);
        assert_eq!(loaded.subscribers[1].email, "abonado42@tvficticia.test");
        std::fs::remove_file(&path).unwrap();
        assert!(Directory::load(&path).unwrap().is_none());
    }

    #[test]
    fn links_work_once_and_a_new_one_voids_the_old() {
        let mut links = Links::default();
        let first = links.issue(41);
        let second = links.issue(41);
        assert_eq!(links.peek(&first), None);
        assert_eq!(links.peek(&second), Some(41));
        assert_eq!(links.consume(&second), Some(41));
        assert_eq!(links.consume(&second), None);
        let expired = links.issue_for(42, Duration::ZERO);
        assert_eq!(links.peek(&expired), None);
        let revoked = links.issue(43);
        links.revoke(43);
        assert_eq!(links.consume(&revoked), None);
    }

    #[test]
    fn sessions_and_lockout() {
        let mut sessions = WebSessions::default();
        let a = sessions.create(Who::Subscriber(41));
        let b = sessions.create(Who::Subscriber(41));
        let staff = sessions.create(Who::Staff);
        assert_eq!(sessions.remove_subscriber(41, Some(&a.token)), 1);
        assert!(sessions.get(&a.token).is_some());
        assert!(sessions.get(&b.token).is_none());
        assert_eq!(sessions.get(&staff.token).unwrap().who, Who::Staff);
        for _ in 0..5 {
            sessions.record_failure("Ana@example.com");
        }
        assert!(sessions.is_locked_out("ana@example.com"));
        sessions.clear_failures("ana@example.com");
        assert!(!sessions.is_locked_out("ana@example.com"));
    }

    #[test]
    fn mailbox_filters_by_address() {
        let mut mailbox = Mailbox::default();
        let mail =
            |to: &str| Mail { at: "now".into(), to: to.into(), subject: "s".into(), text: "t".into(), link: None };
        mailbox.send(mail("ana@example.com"));
        mailbox.send(mail("beto@example.com"));
        assert_eq!(mailbox.to("ANA@example.com").len(), 1);
        assert!(mailbox.to("otra@example.com").is_empty());
    }
}
