//! Provider `Driver` trait and its supporting types. Task 6 adds the Claude
//! driver's paths/locks/live layer; Task 7 implements `Driver` for it and
//! registers it in `registry()`.

pub mod claude;

use std::collections::HashMap;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::errors::{ErrorCode, SwapdError};
use crate::paths::Home;

/// The CLI's credential blob, opaque to core.
pub struct Login {
    pub bytes: String,
}

impl Login {
    /// Port of oauth.py:40-58: sha256 of `claudeAiOauth.refreshToken` when
    /// present and non-empty, else sha256 of the raw bytes; empty bytes
    /// fingerprint to "".
    // Called by fingerprint tests below; Task 6's driver calls it on live logins.
    #[allow(dead_code)]
    pub fn fingerprint(&self) -> String {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&self.bytes) {
            if let Some(token) = value
                .pointer("/claudeAiOauth/refreshToken")
                .and_then(|v| v.as_str())
            {
                if !token.is_empty() {
                    return format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())));
                }
            }
        }
        if self.bytes.trim().is_empty() {
            return String::new();
        }
        format!(
            "sha256-full:{}",
            hex::encode(Sha256::digest(self.bytes.as_bytes()))
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub email: String,
    pub organization_uuid: String,
    pub organization_name: String,
    pub plan: Option<String>,
    pub uuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Usage {
    pub windows: Vec<crate::contract::Window>,
    pub fetched_at: f64,
}

// `Unsupported` has no producer yet: it is the answer a capability-gated verb
// gives, and the verbs are Task 8's.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("provider not installed")]
    NotInstalled,
    #[error("no login")]
    NoLogin,
    #[error("keychain unavailable")]
    KeychainUnavailable,
    #[error("token dead")]
    TokenDead,
    #[error("throttled")]
    Throttled { retry_after: Option<f64> },
    #[error("{0}")]
    Locked(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Http(String),
    #[error("{0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Invalid(String),
}

impl From<DriverError> for SwapdError {
    fn from(err: DriverError) -> Self {
        match err {
            DriverError::NotInstalled => {
                SwapdError::new(ErrorCode::ProviderNotInstalled, "provider not installed")
            }
            DriverError::NoLogin => SwapdError::new(ErrorCode::NoSuchSlot, "no login"),
            DriverError::KeychainUnavailable => {
                SwapdError::new(ErrorCode::KeychainUnavailable, "keychain unavailable")
            }
            DriverError::TokenDead => SwapdError::new(ErrorCode::TokenDead, "token dead"),
            DriverError::Throttled { .. } => SwapdError::new(ErrorCode::Http, "throttled"),
            DriverError::Locked(s) => SwapdError::new(ErrorCode::Locked, s),
            DriverError::Io(e) => SwapdError::new(ErrorCode::Io, e.to_string()),
            DriverError::Http(s) => SwapdError::new(ErrorCode::Http, s),
            DriverError::Unsupported(s) => SwapdError::new(ErrorCode::Unsupported, s),
            DriverError::Invalid(s) => SwapdError::new(ErrorCode::InvalidInput, s),
        }
    }
}

/// The process environment a driver operates under: swapd's home dir plus
/// the process env captured once at startup.
// Constructed by Task 6/8 call sites (`Env::current`); nothing calls it yet.
#[allow(dead_code)]
pub struct Env {
    pub home: PathBuf,
    pub vars: HashMap<String, String>,
}

impl Env {
    // Nothing calls this yet; Task 6/8 build an `Env` before invoking a driver.
    #[allow(dead_code)]
    pub fn current(home: &Home) -> Env {
        Env {
            home: home.root.clone(),
            vars: std::env::vars().collect(),
        }
    }
}

/// Per-slot environment for `run`/`ignite`: env overrides plus a working
/// dir, with a cleanup hook that runs on drop (e.g. removing a temp dir).
pub struct RunProfile {
    pub env: Vec<(String, String)>,
    pub dir: PathBuf,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl RunProfile {
    /// A profile that outlives the run: the Claude driver's per-slot profile
    /// directories persist (they hold the slot's credential and its copied
    /// customizations), so there is nothing to clean up. A driver whose profile
    /// is a temp dir sets `cleanup` instead.
    pub fn new(env: Vec<(String, String)>, dir: PathBuf) -> Self {
        Self {
            env,
            dir,
            cleanup: None,
        }
    }
}

impl Drop for RunProfile {
    fn drop(&mut self) {
        if let Some(f) = self.cleanup.take() {
            f()
        }
    }
}

/// What a driver supports, so callers can gate verbs on capability rather
/// than on provider identity.
#[derive(Debug, Clone, PartialEq)]
pub struct Caps {
    pub ignite: bool,
    pub add_token: bool,
    pub prefer: bool,
    pub refresh: bool,
    pub run: bool,
}

// The trait is fully implemented (`driver::claude`) but nothing *calls* it
// until Task 8's verbs; the allow seeds the dead-code analysis so the whole
// driver behind it counts as live.
#[allow(dead_code)]
pub trait Driver: Send + Sync {
    fn id(&self) -> &'static str; // "claude"
    fn installed(&self) -> Option<PathBuf>; // the CLI on this machine
    /// The CLI's live login for the current environment.
    fn read_live(&self, env: &Env) -> Result<Login, DriverError>;
    /// Replace it, under the CLI's own locks; preserve state the login
    /// does not own (Claude: MCP OAuth tokens, non-account config).
    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError>;
    fn identity(&self, login: &Login) -> Result<Identity, DriverError>; // email, org, plan
    fn refresh(&self, login: &Login) -> Result<Login, DriverError>; // TokenDead on invalid_grant
    fn usage(&self, login: &Login) -> Result<Usage, DriverError>; // windows[]; Throttled{retry_after}
    fn ignite(&self, env: &Env, slot: u32, login: &Login) -> Result<(), DriverError>; // one minimal request as this login
    fn run_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError>; // per-slot profile for `run`/`ignite`
    fn capabilities(&self) -> Caps; // ignite, add_token, prefer, refresh…
}

/// All known provider drivers.
// Consumed by Task 8's verbs; the tests below exercise it meanwhile.
#[allow(dead_code)]
pub fn registry() -> Vec<Box<dyn Driver>> {
    vec![Box::new(claude::live::ClaudeDriver::default_for_platform())]
}

// Consumed by Task 8's verbs.
#[allow(dead_code)]
pub fn by_id(id: &str) -> Option<Box<dyn Driver>> {
    registry().into_iter().find(|d| d.id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_uses_refresh_token_when_present() {
        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-abc"}}"#.to_string(),
        };
        // printf 'rt-abc' | shasum -a 256
        let expected = "sha256:27b93a106171df007491f79034d9e4b1bdc0ab5743e7494e84622e6b7616d0cb";
        assert_eq!(login.fingerprint(), expected);
    }

    #[test]
    fn fingerprint_full_hash_for_api_key() {
        let login = Login {
            bytes: "sk-ant-api03-fake-key".to_string(),
        };
        // printf 'sk-ant-api03-fake-key' | shasum -a 256
        let expected =
            "sha256-full:5d58c83a694002e693e2ba0c17e79804669133c1ef50a3c4269f5bed857d74fe";
        assert_eq!(login.fingerprint(), expected);
    }

    #[test]
    fn fingerprint_empty_for_empty() {
        let login = Login {
            bytes: String::new(),
        };
        assert_eq!(login.fingerprint(), "");
    }

    #[test]
    fn registry_holds_the_claude_driver() {
        let drivers = registry();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].id(), "claude");
        assert!(by_id("claude").is_some());
        assert!(by_id("codex").is_none());
    }

    #[test]
    fn claude_supports_every_verb() {
        let caps = by_id("claude").unwrap().capabilities();
        assert_eq!(
            caps,
            Caps {
                ignite: true,
                add_token: true,
                prefer: true,
                refresh: true,
                run: true,
            }
        );
    }
}
