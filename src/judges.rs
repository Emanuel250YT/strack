//! Accounts, sealed signing keys, sessions and duty shifts.
//!
//! A judge's signing key is stored encrypted with a key derived from the judge's own password
//! (Argon2id + ChaCha20-Poly1305). The platform can only sign in a judge's name after that judge
//! logs in: the key is unsealed into the session's memory and dropped (zeroized) on logout or expiry.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::random_token;
use crate::simulator::Shift;

pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Judge,
    Operator,
    /// Manages accounts and the platform registry; sees the operations board.
    Admin,
    /// A licensed platform (a client of the service): only its own portal (`/platform`).
    Platform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub kdf: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub role: Role,
    pub display_name: String,
    #[serde(default)]
    pub judge_id: Option<String>,
    #[serde(default)]
    pub court_id: Option<String>,
    /// The registered platform a `platform` account belongs to.
    #[serde(default)]
    pub platform_id: Option<String>,
    /// Argon2id PHC string.
    pub password_hash: String,
    #[serde(default)]
    pub sealed_key: Option<SealedKey>,
    /// A disabled account cannot log in; its sessions are closed when it is disabled.
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountsFile {
    pub accounts: Vec<Account>,
}

impl AccountsFile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
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

    pub fn find(&self, username: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.username.eq_ignore_ascii_case(username))
    }

    pub fn find_mut(&mut self, username: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.username.eq_ignore_ascii_case(username))
    }

    pub fn upsert(&mut self, account: Account) {
        self.accounts.retain(|a| !a.username.eq_ignore_ascii_case(&account.username));
        self.accounts.push(account);
        self.accounts.sort_by(|a, b| a.username.cmp(&b.username));
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|e| anyhow!("salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("password hashing failed: {e}"))
}

pub fn verify_password(phc: &str, password: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

fn derive_wrapping_key(password: &str, salt: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(out)
}

/// Encrypts a signing key under the judge's password; the judge id is bound as associated data.
pub fn seal_key(password: &str, judge_id: &str, key: &[u8]) -> anyhow::Result<SealedKey> {
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let wrapping = derive_wrapping_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping[..]));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: key, aad: judge_id.as_bytes() })
        .map_err(|_| anyhow!("sealing the signing key failed"))?;
    Ok(SealedKey {
        kdf: "argon2id-v19-m19456-t2-p1+chacha20poly1305".into(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn unseal_key(password: &str, judge_id: &str, sealed: &SealedKey) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let salt = hex::decode(&sealed.salt_hex)?;
    let nonce = hex::decode(&sealed.nonce_hex)?;
    let ciphertext = hex::decode(&sealed.ciphertext_hex)?;
    if nonce.len() != 12 {
        return Err(anyhow!("invalid nonce length"));
    }
    let wrapping = derive_wrapping_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping[..]));
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: judge_id.as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("wrong password or tampered key"))
}

/// Checks the password and, for judges, unseals the signing key. Slow on purpose (Argon2id).
pub fn authenticate(account: &Account, password: &str) -> Option<Option<Zeroizing<Vec<u8>>>> {
    if !verify_password(&account.password_hash, password) || account.disabled {
        return None;
    }
    match (account.role, &account.judge_id, &account.sealed_key) {
        (Role::Judge, Some(judge_id), Some(sealed)) => unseal_key(password, judge_id, sealed).ok().map(Some),
        (Role::Judge, _, _) => None,
        (Role::Operator | Role::Admin | Role::Platform, _, _) => Some(None),
    }
}

#[derive(Clone)]
pub struct Session {
    pub token: String,
    pub username: String,
    pub role: Role,
    pub display_name: String,
    pub judge_id: Option<String>,
    pub court_id: Option<String>,
    pub platform_id: Option<String>,
    pub csrf: String,
    pub signing_key: Option<Zeroizing<Vec<u8>>>,
    pub expires_at: Instant,
}

#[derive(Default)]
pub struct Sessions {
    by_token: HashMap<String, Session>,
    failures: HashMap<String, (u32, Instant)>,
}

impl Sessions {
    fn purge(&mut self) {
        let now = Instant::now();
        self.by_token.retain(|_, s| s.expires_at > now);
    }

    pub fn create(&mut self, account: &Account, signing_key: Option<Zeroizing<Vec<u8>>>) -> Session {
        self.purge();
        let session = Session {
            token: random_token(32),
            username: account.username.clone(),
            role: account.role,
            display_name: account.display_name.clone(),
            judge_id: account.judge_id.clone(),
            court_id: account.court_id.clone(),
            platform_id: account.platform_id.clone(),
            csrf: random_token(16),
            signing_key,
            expires_at: Instant::now() + SESSION_TTL,
        };
        self.by_token.insert(session.token.clone(), session.clone());
        session
    }

    pub fn get(&mut self, token: &str) -> Option<Session> {
        self.purge();
        self.by_token.get(token).cloned()
    }

    pub fn remove(&mut self, token: &str) -> Option<Session> {
        self.by_token.remove(token)
    }

    /// Closes every session of a user (disabled, deleted or password changed); returns how many.
    pub fn remove_user(&mut self, username: &str, keep_token: Option<&str>) -> usize {
        let before = self.by_token.len();
        self.by_token
            .retain(|token, s| !s.username.eq_ignore_ascii_case(username) || Some(token.as_str()) == keep_token);
        before - self.by_token.len()
    }

    /// Live sessions per username.
    pub fn counts(&mut self) -> HashMap<String, usize> {
        self.purge();
        let mut out = HashMap::new();
        for s in self.by_token.values() {
            *out.entry(s.username.to_ascii_lowercase()).or_insert(0) += 1;
        }
        out
    }

    /// Keeps open sessions in step with an edited profile.
    pub fn rename(&mut self, username: &str, display_name: &str) {
        for s in self.by_token.values_mut().filter(|s| s.username.eq_ignore_ascii_case(username)) {
            s.display_name = display_name.to_string();
        }
    }

    /// Unsealed keys of judges with a live session, by judge id.
    pub fn signing_keys(&mut self) -> HashMap<String, Zeroizing<Vec<u8>>> {
        self.purge();
        self.by_token.values().filter_map(|s| Some((s.judge_id.clone()?, s.signing_key.clone()?))).collect()
    }

    pub fn is_locked_out(&self, username: &str) -> bool {
        self.failures
            .get(&username.to_ascii_lowercase())
            .is_some_and(|(count, last)| *count >= MAX_FAILURES && last.elapsed() < LOCKOUT)
    }

    pub fn record_failure(&mut self, username: &str) {
        let entry = self.failures.entry(username.to_ascii_lowercase()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= LOCKOUT {
            entry.0 = 0;
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn clear_failures(&mut self, username: &str) {
        self.failures.remove(&username.to_ascii_lowercase());
    }
}

/// Shift of `judge_id` that contains `minute`, if any.
pub fn shift_at<'a>(shifts: &'a [Shift], judge_id: &str, minute: f64) -> Option<&'a Shift> {
    shifts.iter().find(|s| s.judge_id == judge_id && s.from_min <= minute && minute < s.until_min)
}

/// A judge may sign while on duty, except in the last `margin` minutes of the shift, so the
/// order never reaches a provider after the shift ended.
pub fn can_sign(shifts: &[Shift], judge_id: &str, minute: f64, margin: f64) -> bool {
    shift_at(shifts, judge_id, minute).is_some_and(|s| minute + margin < s.until_min)
}

/// Judge who should hold pending work now: the one who can sign, or else the incoming judge.
pub fn duty_judge(shifts: &[Shift], minute: f64, margin: f64) -> Option<String> {
    shifts
        .iter()
        .find(|s| can_sign(shifts, &s.judge_id, minute, margin))
        .or_else(|| shifts.iter().find(|s| s.from_min <= minute + margin && minute + margin < s.until_min))
        .map(|s| s.judge_id.clone())
}

/// Next shift of `judge_id` starting after `minute`.
pub fn next_shift<'a>(shifts: &'a [Shift], judge_id: &str, minute: f64) -> Option<&'a Shift> {
    shifts
        .iter()
        .filter(|s| s.judge_id == judge_id && s.from_min > minute)
        .min_by(|a, b| a.from_min.total_cmp(&b.from_min))
}

#[cfg(test)]
mod tests {
    use crate::judges::{can_sign, duty_judge, seal_key, unseal_key};
    use crate::simulator::Shift;

    fn shifts() -> Vec<Shift> {
        vec![
            Shift { judge_id: "laura".into(), from_min: -60.0, until_min: 50.0 },
            Shift { judge_id: "martin".into(), from_min: 50.0, until_min: 240.0 },
        ]
    }

    #[test]
    fn signing_stops_before_the_shift_ends() {
        let s = shifts();
        assert!(can_sign(&s, "laura", 49.0, 0.1));
        assert!(!can_sign(&s, "laura", 49.95, 0.1));
        assert!(!can_sign(&s, "martin", 49.95, 0.1));
        assert!(can_sign(&s, "martin", 50.0, 0.1));
    }

    #[test]
    fn pending_work_moves_to_the_incoming_judge() {
        let s = shifts();
        assert_eq!(duty_judge(&s, 10.0, 0.1).as_deref(), Some("laura"));
        assert_eq!(duty_judge(&s, 49.95, 0.1).as_deref(), Some("martin"));
        assert_eq!(duty_judge(&s, 60.0, 0.1).as_deref(), Some("martin"));
        assert_eq!(duty_judge(&s, 300.0, 0.1), None);
    }

    #[test]
    fn sealed_keys_open_only_with_the_password_and_judge() {
        let sealed = seal_key("correct horse", "laura", b"demo-key").unwrap();
        assert_eq!(&unseal_key("correct horse", "laura", &sealed).unwrap()[..], b"demo-key");
        assert!(unseal_key("wrong", "laura", &sealed).is_err());
        assert!(unseal_key("correct horse", "martin", &sealed).is_err());
    }
}
