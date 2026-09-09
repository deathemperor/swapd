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
    /// The access token is expired (or the server says so). A driver never
    /// refreshes on its own — a Claude refresh token is single-use, so a
    /// refresh whose result the caller cannot persist burns the lineage. The
    /// caller refreshes, persists, and retries.
    #[error("login needs refresh")]
    NeedsRefresh,
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
            DriverError::NeedsRefresh => {
                SwapdError::new(ErrorCode::RefreshDenied, "login needs refresh")
            }
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
#[derive(Clone)]
pub struct Env {
    pub home: PathBuf,
    pub vars: HashMap<String, String>,
}

impl Env {
    pub fn current(home: &Home) -> Env {
        Env {
            home: home.root.clone(),
            vars: std::env::vars().collect(),
        }
    }
}

/// Reads a run profile's credential back after the child exits (see
/// `RunProfile::read_back`).
pub type ReadBack = Box<dyn Fn() -> Result<Option<Login>, DriverError> + Send>;

/// What one `ignite` run produced.
///
/// The rotation and the exit code are independent: the CLI refreshes its token
/// early in a run and can still fail the request afterwards (no network, a
/// server error, a bad prompt), so a non-zero exit routinely carries a rotation.
/// Both are reported so the caller can persist the credential *first* and only
/// then decide what a failed run means — dropping the rotation would leave the
/// slot holding a refresh token the server has already spent, and the next
/// refresh of it comes back `invalid_grant`, which reads as a dead account.
pub struct IgniteOutcome {
    /// The child's exit status. Zero is a successful ignite; non-zero is the
    /// caller's to report, after it has persisted `rotated`.
    pub exit_code: i32,
    /// The credential the CLI rotated to while running, if it did.
    pub rotated: Option<Login>,
}

/// Per-slot environment for `run`/`ignite`: env overrides plus a working
/// dir, with a cleanup hook that runs on drop (e.g. removing a temp dir).
pub struct RunProfile {
    /// Variables to set on the child.
    pub env: Vec<(String, String)>,
    /// Variables to *remove* from the child. `env` can only add, and some
    /// variables are dangerous precisely when inherited — an exported API key
    /// makes the CLI bypass the account this profile selects (see the Claude
    /// driver's `AUTH_OVERRIDE_ENV_VARS`).
    pub unset: Vec<String>,
    /// The profile's own directory. Nothing *runs* in it — `ignite` uses an
    /// empty cwd of swapd's own and `run` inherits the user's — so it is what a
    /// caller reports rather than what it runs in: `run` names it when a
    /// rotation is stranded there.
    pub dir: PathBuf,
    /// Reads the profile's credential back after the child exits, answering
    /// `Some(login)` when the CLI rotated it in place.
    ///
    /// The CLI refreshes its own token as it runs and writes the new generation
    /// into the profile, where nothing else would ever see it: a caller that
    /// does not read it back leaves the slot's stored login one generation
    /// behind, and Claude refresh tokens are single-use, so the stale one is
    /// already spent.
    pub read_back: Option<ReadBack>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl RunProfile {
    /// A profile that outlives the run: the Claude driver's per-slot profile
    /// directories persist (they hold the slot's credential and its copied
    /// customizations), so there is nothing to clean up. A driver whose profile
    /// is a temp dir sets `cleanup` instead.
    pub fn new(env: Vec<(String, String)>, unset: Vec<String>, dir: PathBuf) -> Self {
        Self {
            env,
            unset,
            dir,
            read_back: None,
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

pub trait Driver: Send + Sync {
    fn id(&self) -> &'static str; // "claude"
    /// The CLI on this machine, as *this* environment would resolve it.
    ///
    /// Takes the `Env` rather than reading the process's, so the answer a
    /// status verb prints is the answer a run would get. The two used to be
    /// separate reads that agreed only because `Env::current` captures the
    /// process env.
    fn installed(&self, env: &Env) -> Option<PathBuf>;
    /// The CLI's live login for the current environment.
    fn read_live(&self, env: &Env) -> Result<Login, DriverError>;
    /// Replace it, under the CLI's own locks; preserve state the login
    /// does not own (Claude: MCP OAuth tokens, non-account config).
    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError>;
    fn identity(&self, login: &Login) -> Result<Identity, DriverError>; // email, org, plan
    /// Who this login belongs to, *without touching the network* — `None` when
    /// the credential does not say.
    ///
    /// The collector matches the live login against a slot on every pass, and
    /// `identity()`'s remote fallback would make a status verb issue a request
    /// outside the usage table's cadence, claims and backoff. This is the
    /// question a read path is allowed to ask.
    fn identity_offline(&self, login: &Login) -> Option<Identity>;
    /// When this login's access token expires, in unix seconds, or `None` when
    /// the credential does not say.
    ///
    /// Offline and unbuffered: it answers "which of these two credentials is
    /// the later generation" (a spent refresh token must never overwrite its
    /// successor) and "is the active login past its expiry" for a slot the
    /// fetch gate kept out of this pass. `usage()`'s own expiry check keeps its
    /// refresh buffer; this one reports the stated moment.
    fn expires_at(&self, login: &Login) -> Option<f64>;
    fn refresh(&self, login: &Login) -> Result<Login, DriverError>; // TokenDead on invalid_grant
    /// windows[]; `Throttled{retry_after}` when rate-limited, `NeedsRefresh`
    /// when the login's access token is expired or the server rejects it — a
    /// driver never refreshes behind the caller's back.
    fn usage(&self, login: &Login) -> Result<Usage, DriverError>;
    /// Make one minimal request as this login, in the slot's own run profile.
    ///
    /// `Ok` for any *normal* exit, zero or not, carrying both the exit code and
    /// any rotation the CLI made while running (see `IgniteOutcome`); the caller
    /// persists the rotation before reporting a non-zero code. Only a run that
    /// produced no exit status at all — a timeout, a signal — is `Err`.
    fn ignite(&self, env: &Env, slot: u32, login: &Login) -> Result<IgniteOutcome, DriverError>;
    fn run_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError>; // per-slot profile for `run`/`ignite`
    /// Delete whatever the slot's run profile left *outside* its directory, so
    /// `remove` can forget an account completely.
    ///
    /// A profile is not only its files: Claude Code migrates the seeded
    /// `.credentials.json` into a keychain item named after the config dir, and
    /// `remove_dir_all` never touches it. Only the driver knows that item
    /// exists, or how it is named. No default — an engine that quietly
    /// inherited "nothing to do" would leave a live credential behind for an
    /// account swapd has forgotten.
    fn forget_profile(&self, env: &Env, slot: u32) -> Result<(), DriverError>;
    /// The CLI's own config file for the live login, as text — `None` when the
    /// CLI keeps no such file or it is not there.
    ///
    /// `export --full` is a same-machine backup, and the config is the half of
    /// the login state that does not live in the credential (Claude Code's
    /// `~/.claude.json`). Where it is is the engine's business, so the question
    /// is asked here rather than by reaching into a driver's paths.
    fn live_config_text(&self, env: &Env) -> Result<Option<String>, DriverError>;
    fn capabilities(&self) -> Caps; // ignite, add_token, prefer, refresh…
    /// Whether this login can be made the live one at all, asked *before* any
    /// side effect.
    ///
    /// `write_live` refuses some credentials (Claude: anything that is not an
    /// OAuth object, because a managed key lives on a different axis). Learning
    /// that only from `write_live` would mean discovering it after the outgoing
    /// login had already been backed up or stashed, so `switch` asks first. No
    /// default: an engine that cannot answer would silently inherit "yes".
    fn can_activate(&self, login: &Login) -> Result<(), DriverError>;
    /// Whether this credential is a managed API key rather than a subscription
    /// login: one definition of the question for the collector's sentinel,
    /// `add`'s capture refusal, `add-token`'s kind detection and `import`'s
    /// validation, which had five spellings of it between them.
    fn is_api_key(&self, login: &Login) -> bool;
}

/// Whether `live` is provably an OLDER generation of a lineage than `stored`.
///
/// Claude's refresh tokens are single-use, so writing a spent generation over
/// its successor strands the successor: the next refresh POSTs a token the
/// endpoint has already consumed and the account reads as dead. Both the
/// collector's adopt (a `write_live` that failed after the rotation was
/// persisted) and `switch`'s back-up of the outgoing login have to ask this,
/// and one answer keeps them from drifting apart.
///
/// An unknown expiry on either side is no evidence of order, so it answers
/// `false`: the caller's normal rule (the live copy is the current one) stands
/// unless the credentials themselves say otherwise.
pub fn live_is_older(driver: &dyn Driver, live: &Login, stored: &Login) -> bool {
    match (driver.expires_at(live), driver.expires_at(stored)) {
        (Some(live), Some(stored)) => live < stored,
        _ => false,
    }
}

/// All known provider drivers.
pub fn registry() -> Vec<Box<dyn Driver>> {
    vec![Box::new(claude::live::ClaudeDriver::default_for_platform())]
}

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
