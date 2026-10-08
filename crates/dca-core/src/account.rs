//! The local sign-in account.
//!
//! A single operator account, created when Benchmark is installed, gates the
//! app. The password is never stored: only an Argon2id hash of it is kept, in
//! a per-user folder on this computer. Changing the password is done here too,
//! from Settings or from the separate `benchmark-password` tool.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::time;

const ACCOUNT_FILE: &str = "account.json";

/// Where the sign-in account is kept: per user, beside the assessments.
pub fn dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }?;
    Some(base.join("Benchmark").join("Account"))
}
/// The shortest password we accept. Short passwords are the one thing a local
/// hash cannot make safe, so we ask for length rather than character classes.
pub const MIN_PASSWORD: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    username: String,
    /// The Argon2id PHC string, e.g. `$argon2id$v=19$m=...$salt$hash`.
    hash: String,
    created: String,
    changed: String,
}

/// Whether an account has been created on this computer.
pub fn exists(dir: &Path) -> bool {
    read(dir).is_some()
}

/// The account's username, for showing who is signed in.
pub fn username(dir: &Path) -> Option<String> {
    read(dir).map(|a| a.username)
}

/// Creates the one account, at install time. Refuses if one already exists.
pub fn create(dir: &Path, username: &str, password: &str, now: i64) -> Result<(), String> {
    if exists(dir) {
        return Err("An account already exists on this computer.".into());
    }
    let name = username.trim();
    if name.is_empty() {
        return Err("Choose a username.".into());
    }
    check_strength(password)?;
    let now = time::iso(now);
    write(
        dir,
        &Account {
            username: name.to_string(),
            hash: hash_password(password)?,
            created: now.clone(),
            changed: now,
        },
    )
}

/// Confirms a username and password. The same message is returned whether the
/// username or the password is wrong, so neither can be probed.
pub fn verify(dir: &Path, username: &str, password: &str) -> Result<(), String> {
    let acct = read(dir).ok_or("No account yet. Create one to continue.")?;
    let wrong = || "Wrong username or password.".to_string();
    if !acct.username.eq_ignore_ascii_case(username.trim()) {
        return Err(wrong());
    }
    let parsed =
        PasswordHash::new(&acct.hash).map_err(|_| "The account record is damaged.".to_string())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| wrong())
}

/// Changes the password after checking the current one.
pub fn change(
    dir: &Path,
    username: &str,
    current: &str,
    new: &str,
    now: i64,
) -> Result<(), String> {
    verify(dir, username, current)?;
    check_strength(new)?;
    let mut acct = read(dir).ok_or("No account on this computer.")?;
    acct.hash = hash_password(new)?;
    acct.changed = time::iso(now);
    write(dir, &acct)
}

fn check_strength(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(format!("Use at least {MIN_PASSWORD} characters."));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("No randomness available: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| e.to_string())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn read(dir: &Path) -> Option<Account> {
    serde_json::from_str(&std::fs::read_to_string(dir.join(ACCOUNT_FILE)).ok()?).ok()
}

fn write(dir: &Path, acct: &Account) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join(ACCOUNT_FILE),
        serde_json::to_string_pretty(acct).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_791_000_000;

    #[test]
    fn create_then_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!exists(dir.path()));
        create(dir.path(), "operator", "corrects-horse-battery", NOW).unwrap();
        assert!(exists(dir.path()));
        assert_eq!(username(dir.path()).as_deref(), Some("operator"));

        verify(dir.path(), "operator", "corrects-horse-battery").unwrap();
        // Username match is case-insensitive.
        verify(dir.path(), "OPERATOR", "corrects-horse-battery").unwrap();
        // Wrong password and wrong username both fail with the same message.
        assert_eq!(
            verify(dir.path(), "operator", "nope").unwrap_err(),
            verify(dir.path(), "intruder", "corrects-horse-battery").unwrap_err()
        );
    }

    #[test]
    fn the_password_is_not_stored_in_the_clear() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "operator", "a-long-enough-secret", NOW).unwrap();
        let raw = std::fs::read_to_string(dir.path().join(ACCOUNT_FILE)).unwrap();
        assert!(!raw.contains("a-long-enough-secret"));
        assert!(raw.contains("$argon2id$"));
    }

    #[test]
    fn a_second_account_is_refused_and_short_passwords_too() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "operator", "a-long-enough-secret", NOW).unwrap();
        assert!(create(dir.path(), "other", "another-long-secret", NOW).is_err());
        let fresh = tempfile::tempdir().unwrap();
        assert!(create(fresh.path(), "operator", "short", NOW).is_err());
    }

    #[test]
    fn change_password_checks_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "operator", "the-first-password", NOW).unwrap();
        assert!(change(
            dir.path(),
            "operator",
            "wrong-old-one",
            "the-second-password",
            NOW
        )
        .is_err());
        change(
            dir.path(),
            "operator",
            "the-first-password",
            "the-second-password",
            NOW,
        )
        .unwrap();
        verify(dir.path(), "operator", "the-second-password").unwrap();
        assert!(verify(dir.path(), "operator", "the-first-password").is_err());
    }
}
