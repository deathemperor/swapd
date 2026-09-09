//! Where Claude Code keeps its config and its live credential, and the
//! keychain service names it derives for them.
//!
//! Port of cswap `paths.py:34-53` (`get_claude_config_home`,
//! `get_global_config_path`), `paths.py:80-82` (`get_credentials_path`),
//! `session.py:232-243` (`keychain_service_name`) and `credentials.py:47-107`
//! (`_active_profile_is_default`, `_active_oauth_keychain_services`).
//!
//! Every lookup goes through `Env` — never `std::env` — so tests build an
//! environment over a temp dir instead of mutating the process's.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::driver::{DriverError, Env};

/// Service name of Claude Code's *active* OAuth credential in the macOS
/// Keychain for the default profile (cswap `CLAUDE_CODE_KEYCHAIN_SERVICE`).
pub const DEFAULT_SERVICE: &str = "Claude Code-credentials";

/// The user's home directory, from `Env` rather than `std::env`.
///
/// `env.home` is *swapd's* own directory, not `$HOME`; Claude Code's paths
/// hang off `$HOME`. A missing/empty `HOME` is an error, never a panic.
fn home(env: &Env) -> Result<PathBuf, DriverError> {
    match env.vars.get("HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => Err(DriverError::Invalid("HOME is not set".to_string())),
    }
}

/// `$CLAUDE_CONFIG_DIR` when non-empty, else `~/.claude` (`paths.py:34-39`).
pub fn config_home(env: &Env) -> Result<PathBuf, DriverError> {
    match env.vars.get("CLAUDE_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => Ok(home(env)?.join(".claude")),
    }
}

/// Claude Code's global config file (`paths.py:42-53`): the legacy
/// `<config_home>/.config.json` when it exists, else
/// `($CLAUDE_CONFIG_DIR or $HOME)/.claude.json`.
pub fn config_json(env: &Env) -> Result<PathBuf, DriverError> {
    let legacy = config_home(env)?.join(".config.json");
    if legacy.exists() {
        return Ok(legacy);
    }
    let base = match env.vars.get("CLAUDE_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => home(env)?,
    };
    Ok(base.join(".claude.json"))
}

/// The plaintext credential file Claude Code falls back to, and the live store
/// on non-macOS (`paths.py:80-82`).
pub fn credentials_file(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(config_home(env)?.join(".credentials.json"))
}

/// Keychain service name Claude Code derives for a config dir
/// (`session.py:232-243`).
///
/// Claude hashes the *raw* `CLAUDE_CONFIG_DIR` string, NFC-normalized and
/// unresolved — never a canonicalized variant, which would drop a trailing
/// slash or a `./` and key a different item than Claude Code's.
pub fn keychain_service_name(config_dir: &str) -> String {
    let normalized: String = config_dir.nfc().collect();
    let digest = Sha256::digest(normalized.as_bytes());
    format!("Claude Code-credentials-{}", &hex::encode(digest)[..8])
}

/// Whether the active config home *is* the default profile's
/// (`credentials.py:47-66`).
///
/// Keys on where the path resolves, not on the variable being set, so
/// `CLAUDE_CONFIG_DIR` pointed at `~/.claude` (or a symlink to it) is still the
/// default profile. An unresolvable path answers `false`: treating an unknown
/// profile as the default is what would license reading another account's
/// credential.
fn active_profile_is_default(env: &Env) -> bool {
    fn resolved(path: Result<PathBuf, DriverError>) -> Option<PathBuf> {
        path.ok().and_then(|p| p.canonicalize().ok())
    }
    let active = resolved(config_home(env));
    let default = resolved(home(env).map(|h| h.join(".claude")));
    match (active, default) {
        (Some(a), Some(d)) => a == d,
        _ => false,
    }
}

/// Keychain services holding the OAuth credential for this environment, in
/// try-order (`credentials.py:69-107`).
///
/// Claude Code (2.1.220 `getMacOsKeychainStorageServiceName`) sources secure
/// storage from `CLAUDE_SECURESTORAGE_CONFIG_DIR` when that is *defined*, else
/// from `CLAUDE_CONFIG_DIR`; defined-but-empty selects the default store, whose
/// item is the unsuffixed one. The second entry exists for one case only: an
/// explicit `CLAUDE_CONFIG_DIR` naming the default profile, where Claude writes
/// the suffixed item but a long-time default-profile user may only have the
/// unsuffixed one. A defined `CLAUDE_SECURESTORAGE_CONFIG_DIR` gets no
/// fallback — it names the only store Claude will read here, so a miss means
/// Claude sees a logged-out profile.
pub fn live_services(env: &Env) -> Vec<String> {
    if let Some(secure) = env.vars.get("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
        // Defined-but-empty is meaningful; it is NOT the same as unset.
        if secure.is_empty() {
            return vec![DEFAULT_SERVICE.to_string()];
        }
        return vec![keychain_service_name(secure)];
    }

    let config_dir = match env.vars.get("CLAUDE_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => dir,
        _ => return vec![DEFAULT_SERVICE.to_string()],
    };

    let mut services = vec![keychain_service_name(config_dir)];
    if active_profile_is_default(env) {
        services.push(DEFAULT_SERVICE.to_string());
    }
    services
}

/// `<path>` with `.lock` appended to its file name — proper-lockfile's
/// artifact for `path` (`claude_locks.py` `credentials_lock_dir` /
/// `config_lock_dir`).
pub fn lock_dir_for(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::claude::tests::{env_with, temp_home};

    #[test]
    fn keychain_service_name_hashes_the_raw_string() {
        // printf '/Users/x/.claude' | shasum -a 256 -> 51a4d1d1…
        assert_eq!(
            keychain_service_name("/Users/x/.claude"),
            format!(
                "Claude Code-credentials-{}",
                &hex::encode(Sha256::digest(b"/Users/x/.claude"))[..8]
            )
        );
        // A trailing slash is a different string, hence a different item.
        assert_ne!(
            keychain_service_name("/Users/x/.claude"),
            keychain_service_name("/Users/x/.claude/")
        );
    }

    #[test]
    fn keychain_service_name_nfc_normalizes() {
        // "é" as U+0065 U+0301 (NFD) hashes as its NFC form U+00E9.
        assert_eq!(
            keychain_service_name("/tmp/e\u{0301}"),
            keychain_service_name("/tmp/\u{00e9}")
        );
    }

    #[test]
    fn config_home_defaults_to_dot_claude() {
        let home = temp_home();
        let env = env_with(&home, []);
        assert_eq!(config_home(&env).unwrap(), home.path().join(".claude"));
    }

    #[test]
    fn config_home_honours_config_dir() {
        let home = temp_home();
        let env = env_with(&home, [("CLAUDE_CONFIG_DIR", "/custom/profile")]);
        assert_eq!(config_home(&env).unwrap(), PathBuf::from("/custom/profile"));
    }

    #[test]
    fn missing_home_is_invalid_not_a_panic() {
        let env = Env {
            home: PathBuf::from("/nowhere"),
            vars: std::collections::HashMap::new(),
        };
        assert!(matches!(config_home(&env), Err(DriverError::Invalid(_))));
    }

    #[test]
    fn config_json_prefers_existing_legacy_file() {
        let home = temp_home();
        let env = env_with(&home, []);
        assert_eq!(config_json(&env).unwrap(), home.path().join(".claude.json"));

        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(home.path().join(".claude/.config.json"), "{}").unwrap();
        assert_eq!(
            config_json(&env).unwrap(),
            home.path().join(".claude/.config.json")
        );
    }

    #[test]
    fn live_services_default_profile_is_the_unsuffixed_item() {
        let home = temp_home();
        assert_eq!(live_services(&env_with(&home, [])), vec![DEFAULT_SERVICE]);
        // Empty CLAUDE_CONFIG_DIR is the same as unset.
        assert_eq!(
            live_services(&env_with(&home, [("CLAUDE_CONFIG_DIR", "")])),
            vec![DEFAULT_SERVICE]
        );
    }

    #[test]
    fn live_services_custom_profile_has_no_fallback() {
        let home = temp_home();
        let profile = home.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let env = env_with(&home, [("CLAUDE_CONFIG_DIR", profile.to_str().unwrap())]);
        assert_eq!(
            live_services(&env),
            vec![keychain_service_name(profile.to_str().unwrap())]
        );
    }

    #[test]
    fn live_services_config_dir_naming_the_default_profile_falls_back() {
        let home = temp_home();
        let default = home.path().join(".claude");
        std::fs::create_dir_all(&default).unwrap();
        let env = env_with(&home, [("CLAUDE_CONFIG_DIR", default.to_str().unwrap())]);
        assert_eq!(
            live_services(&env),
            vec![
                keychain_service_name(default.to_str().unwrap()),
                DEFAULT_SERVICE.to_string(),
            ]
        );
    }

    #[test]
    fn live_services_securestorage_defined_but_empty_selects_the_default_store() {
        let home = temp_home();
        let default = home.path().join(".claude");
        std::fs::create_dir_all(&default).unwrap();
        let env = env_with(
            &home,
            [
                ("CLAUDE_CONFIG_DIR", default.to_str().unwrap()),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
            ],
        );
        assert_eq!(live_services(&env), vec![DEFAULT_SERVICE]);
    }

    #[test]
    fn live_services_securestorage_set_wins_and_has_no_fallback() {
        let home = temp_home();
        let default = home.path().join(".claude");
        std::fs::create_dir_all(&default).unwrap();
        let env = env_with(
            &home,
            [
                ("CLAUDE_CONFIG_DIR", default.to_str().unwrap()),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/secure/dir"),
            ],
        );
        assert_eq!(
            live_services(&env),
            vec![keychain_service_name("/secure/dir")]
        );
    }
}
