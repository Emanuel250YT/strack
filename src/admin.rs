//! Account and platform-registry management: validation, guards and the changes themselves.
//!
//! Web handlers check the session, the CSRF token and the admin role, call these functions, persist
//! the file and record the change in the audit log. Nothing here ever logs a password or a key.

use crate::crypto::random_token;
use crate::judges::{Account, AccountsFile, Role, hash_password, seal_key};
use crate::leak::platforms::{PlatformEntry, PlatformsFile};
use crate::workflow::now_rfc3339;

pub const MIN_PASSWORD: usize = 10;
pub const MIN_TOKEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    InvalidUsername,
    UsernameTaken,
    NameRequired,
    PasswordTooShort,
    JudgeRequired,
    JudgeTaken,
    SigningKeyRequired,
    NotFound,
    SelfAction,
    LastAdmin,
    JudgeRoleFixed,
    /// A `platform` account needs a registered platform.
    PlatformRequired,
    /// A platform account stays a platform account (and other accounts never become one).
    PlatformRoleFixed,
    InvalidPlatformId,
    PlatformTaken,
    InvalidUrl,
    TokenTooShort,
    Internal,
}

impl AdminError {
    /// Code for `?error=` (mapped to Spanish text in `web::labels::message`).
    pub fn code(self) -> &'static str {
        match self {
            AdminError::InvalidUsername => "invalid_username",
            AdminError::UsernameTaken => "username_taken",
            AdminError::NameRequired => "name_required",
            AdminError::PasswordTooShort => "password_too_short",
            AdminError::JudgeRequired => "judge_required",
            AdminError::JudgeTaken => "judge_taken",
            AdminError::SigningKeyRequired => "signing_key_required",
            AdminError::NotFound => "not_found",
            AdminError::SelfAction => "self_action",
            AdminError::LastAdmin => "last_admin",
            AdminError::JudgeRoleFixed => "judge_role_fixed",
            AdminError::PlatformRequired => "platform_required",
            AdminError::PlatformRoleFixed => "platform_role_fixed",
            AdminError::InvalidPlatformId => "invalid_platform_id",
            AdminError::PlatformTaken => "platform_taken",
            AdminError::InvalidUrl => "invalid_url",
            AdminError::TokenTooShort => "token_too_short",
            AdminError::Internal => "internal",
        }
    }
}

/// 3 to 32 characters: lowercase letters, digits, `.`, `_`, `-`; starts with a letter or digit.
pub fn valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// A judge known to the platform (from the courts the simulator publishes).
#[derive(Debug, Clone)]
pub struct JudgeRef {
    pub judge_id: String,
    pub court_id: String,
    pub name: String,
}

pub struct NewAccount<'a> {
    pub username: &'a str,
    pub display_name: &'a str,
    pub role: Role,
    pub password: &'a str,
    /// Required for judges.
    pub judge: Option<JudgeRef>,
    /// The judge's demo signing key (`clave_firma_demo`), sealed with the password. Required for judges.
    pub signing_key: Option<&'a str>,
    /// Registered platform id. Required for `platform` accounts (the caller checks it exists).
    pub platform: Option<&'a str>,
}

fn enabled_admins(file: &AccountsFile) -> usize {
    file.accounts.iter().filter(|a| a.role == Role::Admin && !a.disabled).count()
}

/// Validates and builds a new account (password hashed, judge key sealed). Slow: Argon2id.
pub fn create_account(file: &mut AccountsFile, new: NewAccount<'_>) -> Result<Account, AdminError> {
    let username = new.username.trim().to_ascii_lowercase();
    if !valid_username(&username) {
        return Err(AdminError::InvalidUsername);
    }
    if file.find(&username).is_some() {
        return Err(AdminError::UsernameTaken);
    }
    if new.password.chars().count() < MIN_PASSWORD {
        return Err(AdminError::PasswordTooShort);
    }
    let mut display_name = new.display_name.trim().to_string();
    let (judge_id, court_id, sealed_key) = match new.role {
        Role::Judge => {
            let judge = new.judge.ok_or(AdminError::JudgeRequired)?;
            if file.accounts.iter().any(|a| a.judge_id.as_deref() == Some(judge.judge_id.as_str())) {
                return Err(AdminError::JudgeTaken);
            }
            let key = new.signing_key.map(str::trim).filter(|k| !k.is_empty()).ok_or(AdminError::SigningKeyRequired)?;
            let sealed = seal_key(new.password, &judge.judge_id, key.as_bytes()).map_err(|_| AdminError::Internal)?;
            if display_name.is_empty() {
                display_name = judge.name.clone();
            }
            (Some(judge.judge_id), Some(judge.court_id), Some(sealed))
        }
        Role::Operator | Role::Admin | Role::Platform => (None, None, None),
    };
    let platform_id = match new.role {
        Role::Platform => {
            Some(new.platform.map(str::trim).filter(|p| !p.is_empty()).ok_or(AdminError::PlatformRequired)?.to_string())
        }
        _ => None,
    };
    if display_name.is_empty() {
        return Err(AdminError::NameRequired);
    }
    let account = Account {
        username,
        role: new.role,
        display_name,
        judge_id,
        court_id,
        platform_id,
        password_hash: hash_password(new.password).map_err(|_| AdminError::Internal)?,
        sealed_key,
        disabled: false,
        created_at: Some(now_rfc3339()),
    };
    file.upsert(account.clone());
    Ok(account)
}

/// Changes the display name and, for operators and admins, the role. A judge's role is bound to their
/// sealed key and cannot change; nobody can demote themselves or the last enabled admin.
pub fn update_profile(
    file: &mut AccountsFile,
    username: &str,
    display_name: &str,
    role: Role,
    actor: &str,
) -> Result<Account, AdminError> {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        return Err(AdminError::NameRequired);
    }
    let admins = enabled_admins(file);
    let account = file.find_mut(username).ok_or(AdminError::NotFound)?;
    if role != account.role {
        if account.role == Role::Judge || role == Role::Judge {
            return Err(AdminError::JudgeRoleFixed);
        }
        if account.role == Role::Platform || role == Role::Platform {
            return Err(AdminError::PlatformRoleFixed);
        }
        if account.username.eq_ignore_ascii_case(actor) {
            return Err(AdminError::SelfAction);
        }
        if account.role == Role::Admin && !account.disabled && admins <= 1 {
            return Err(AdminError::LastAdmin);
        }
    }
    account.display_name = display_name.to_string();
    account.role = role;
    Ok(account.clone())
}

/// Sets a new password. A judge's signing key is sealed again under it, so the key must be given:
/// the admin re-enters the demo key, or the judge's own session supplies it.
pub fn set_password(
    file: &mut AccountsFile,
    username: &str,
    password: &str,
    signing_key: Option<&[u8]>,
) -> Result<(), AdminError> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(AdminError::PasswordTooShort);
    }
    let account = file.find_mut(username).ok_or(AdminError::NotFound)?;
    if account.role == Role::Judge {
        let judge_id = account.judge_id.clone().ok_or(AdminError::JudgeRequired)?;
        let key = signing_key.filter(|k| !k.is_empty()).ok_or(AdminError::SigningKeyRequired)?;
        account.sealed_key = Some(seal_key(password, &judge_id, key).map_err(|_| AdminError::Internal)?);
    }
    account.password_hash = hash_password(password).map_err(|_| AdminError::Internal)?;
    Ok(())
}

pub fn set_disabled(file: &mut AccountsFile, username: &str, disabled: bool, actor: &str) -> Result<(), AdminError> {
    let admins = enabled_admins(file);
    let account = file.find_mut(username).ok_or(AdminError::NotFound)?;
    if disabled {
        if account.username.eq_ignore_ascii_case(actor) {
            return Err(AdminError::SelfAction);
        }
        if account.role == Role::Admin && !account.disabled && admins <= 1 {
            return Err(AdminError::LastAdmin);
        }
    }
    account.disabled = disabled;
    Ok(())
}

pub fn delete_account(file: &mut AccountsFile, username: &str, actor: &str) -> Result<Account, AdminError> {
    let admins = enabled_admins(file);
    let account = file.find(username).cloned().ok_or(AdminError::NotFound)?;
    if account.username.eq_ignore_ascii_case(actor) {
        return Err(AdminError::SelfAction);
    }
    if account.role == Role::Admin && !account.disabled && admins <= 1 {
        return Err(AdminError::LastAdmin);
    }
    file.accounts.retain(|a| !a.username.eq_ignore_ascii_case(username));
    Ok(account)
}

/// 2 to 32 characters: lowercase letters, digits and `-`.
pub fn valid_platform_id(id: &str) -> bool {
    (2..=32).contains(&id.len()) && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn valid_api_url(url: &str) -> bool {
    url.len() <= 300
        && reqwest::Url::parse(url).is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())
}

pub struct PlatformInput<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub api_url: &'a str,
    /// Blank: generate one (on create) or keep the current one (on update).
    pub notice_token: &'a str,
}

fn checked_token(token: &str) -> Result<Option<String>, AdminError> {
    let token = token.trim();
    match token.len() {
        0 => Ok(None),
        n if n < MIN_TOKEN => Err(AdminError::TokenTooShort),
        _ => Ok(Some(token.to_string())),
    }
}

pub fn create_platform(file: &mut PlatformsFile, input: PlatformInput<'_>) -> Result<PlatformEntry, AdminError> {
    let id = input.id.trim().to_ascii_lowercase();
    if !valid_platform_id(&id) {
        return Err(AdminError::InvalidPlatformId);
    }
    if file.find(&id).is_some() {
        return Err(AdminError::PlatformTaken);
    }
    let name = input.name.trim();
    if name.is_empty() {
        return Err(AdminError::NameRequired);
    }
    let api_url = input.api_url.trim().trim_end_matches('/').to_string();
    if !valid_api_url(&api_url) {
        return Err(AdminError::InvalidUrl);
    }
    let notice_token = checked_token(input.notice_token)?.unwrap_or_else(|| random_token(16));
    let entry = PlatformEntry { id, name: name.to_string(), api_url, notice_token };
    file.platforms.push(entry.clone());
    file.platforms.sort_by_key(|a| a.name.to_lowercase());
    Ok(entry)
}

pub fn update_platform(file: &mut PlatformsFile, input: PlatformInput<'_>) -> Result<PlatformEntry, AdminError> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(AdminError::NameRequired);
    }
    let api_url = input.api_url.trim().trim_end_matches('/').to_string();
    if !valid_api_url(&api_url) {
        return Err(AdminError::InvalidUrl);
    }
    let token = checked_token(input.notice_token)?;
    let entry = file.platforms.iter_mut().find(|p| p.id == input.id).ok_or(AdminError::NotFound)?;
    entry.name = name.to_string();
    entry.api_url = api_url;
    if let Some(token) = token {
        entry.notice_token = token;
    }
    Ok(entry.clone())
}

pub fn delete_platform(file: &mut PlatformsFile, id: &str) -> Result<PlatformEntry, AdminError> {
    let entry = file.find(id).cloned().ok_or(AdminError::NotFound)?;
    file.platforms.retain(|p| p.id != id);
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use crate::admin::{
        AdminError, JudgeRef, NewAccount, PlatformInput, create_account, create_platform, delete_account, set_disabled,
        set_password, update_profile, valid_username,
    };
    use crate::judges::{AccountsFile, Role, authenticate};
    use crate::leak::platforms::PlatformsFile;

    fn operator<'a>(username: &'a str, role: Role) -> NewAccount<'a> {
        NewAccount {
            username,
            display_name: "Persona",
            role,
            password: "una-clave-larga",
            judge: None,
            signing_key: None,
            platform: None,
        }
    }

    #[test]
    fn usernames() {
        assert!(valid_username("fiscalia"));
        assert!(valid_username("j.perez-2"));
        assert!(!valid_username("ab"));
        assert!(!valid_username("Mayus"));
        assert!(!valid_username("-guion"));
        assert!(!valid_username("con espacio"));
    }

    #[test]
    fn creates_judges_with_a_sealed_key_that_opens_at_login() {
        let mut file = AccountsFile::default();
        let judge = JudgeRef { judge_id: "jueza-x".into(), court_id: "jg-1".into(), name: "Dra. X".into() };
        let new = NewAccount {
            username: "jueza",
            display_name: "",
            role: Role::Judge,
            password: "clave-de-la-jueza",
            judge: Some(judge.clone()),
            signing_key: Some("demo-key"),
            platform: None,
        };
        let account = create_account(&mut file, new).unwrap();
        assert_eq!(account.display_name, "Dra. X");
        let key = authenticate(&account, "clave-de-la-jueza").unwrap().unwrap();
        assert_eq!(&key[..], b"demo-key");
        let again = NewAccount {
            username: "otra",
            display_name: "Otra",
            role: Role::Judge,
            password: "clave-de-la-jueza",
            judge: Some(judge),
            signing_key: Some("demo-key"),
            platform: None,
        };
        assert_eq!(create_account(&mut file, again).unwrap_err(), AdminError::JudgeTaken);
    }

    #[test]
    fn validation_errors() {
        let mut file = AccountsFile::default();
        create_account(&mut file, operator("ana", Role::Operator)).unwrap();
        assert_eq!(create_account(&mut file, operator("ana", Role::Operator)).unwrap_err(), AdminError::UsernameTaken);
        let short = NewAccount { password: "corta", ..operator("beto", Role::Operator) };
        assert_eq!(create_account(&mut file, short).unwrap_err(), AdminError::PasswordTooShort);
        let judge = NewAccount { ..operator("juez", Role::Judge) };
        assert_eq!(create_account(&mut file, judge).unwrap_err(), AdminError::JudgeRequired);
    }

    #[test]
    fn the_last_admin_and_yourself_are_protected() {
        let mut file = AccountsFile::default();
        create_account(&mut file, operator("admin", Role::Admin)).unwrap();
        create_account(&mut file, operator("ana", Role::Operator)).unwrap();
        assert_eq!(delete_account(&mut file, "admin", "ana").unwrap_err(), AdminError::LastAdmin);
        assert_eq!(delete_account(&mut file, "admin", "admin").unwrap_err(), AdminError::SelfAction);
        assert_eq!(set_disabled(&mut file, "admin", true, "ana").unwrap_err(), AdminError::LastAdmin);
        assert_eq!(
            update_profile(&mut file, "admin", "Admin", Role::Operator, "ana").unwrap_err(),
            AdminError::LastAdmin
        );
        assert_eq!(
            update_profile(&mut file, "ana", "Ana", Role::Judge, "admin").unwrap_err(),
            AdminError::JudgeRoleFixed
        );
        update_profile(&mut file, "ana", "Ana", Role::Admin, "admin").unwrap();
        set_disabled(&mut file, "admin", true, "ana").unwrap();
        let disabled = file.find("admin").unwrap().clone();
        assert!(authenticate(&disabled, "una-clave-larga").is_none());
        delete_account(&mut file, "admin", "ana").unwrap();
        assert!(file.find("admin").is_none());
    }

    #[test]
    fn a_judge_password_change_needs_the_key() {
        let mut file = AccountsFile::default();
        let judge = JudgeRef { judge_id: "j".into(), court_id: "c".into(), name: "J".into() };
        let new = NewAccount {
            username: "juez",
            display_name: "J",
            role: Role::Judge,
            password: "primera-clave",
            judge: Some(judge),
            signing_key: Some("k1"),
            platform: None,
        };
        create_account(&mut file, new).unwrap();
        assert_eq!(set_password(&mut file, "juez", "segunda-clave", None).unwrap_err(), AdminError::SigningKeyRequired);
        set_password(&mut file, "juez", "segunda-clave", Some(b"k1")).unwrap();
        let account = file.find("juez").unwrap().clone();
        assert!(authenticate(&account, "primera-clave").is_none());
        assert_eq!(&authenticate(&account, "segunda-clave").unwrap().unwrap()[..], b"k1");
    }

    #[test]
    fn platforms() {
        let mut file = PlatformsFile::default();
        let input = PlatformInput { id: "tvf", name: "TV", api_url: "http://127.0.0.1:8100/", notice_token: "" };
        let entry = create_platform(&mut file, input).unwrap();
        assert_eq!(entry.api_url, "http://127.0.0.1:8100");
        assert_eq!(entry.notice_token.len(), 32);
        let dup = PlatformInput { id: "tvf", name: "TV", api_url: "http://x.test", notice_token: "" };
        assert_eq!(create_platform(&mut file, dup).unwrap_err(), AdminError::PlatformTaken);
        let bad = PlatformInput { id: "otra", name: "O", api_url: "ftp://x", notice_token: "" };
        assert_eq!(create_platform(&mut file, bad).unwrap_err(), AdminError::InvalidUrl);
        let short = PlatformInput { id: "otra", name: "O", api_url: "http://x.test", notice_token: "corto" };
        assert_eq!(create_platform(&mut file, short).unwrap_err(), AdminError::TokenTooShort);
    }
}
