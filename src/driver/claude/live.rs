//! Reading and replacing Claude Code's live login.
//!
//! Port of cswap `credentials.py:108-140` (retry constants),
//! `credentials.py:536-563` (`_read_active_oauth_keychain` /
//! `_read_one_oauth_keychain`), `credentials.py:180-268`
//! (`looks_like_api_key`, `_credential_object`, `SHARED_CREDENTIAL_KEYS`,
//! `shared_credential_fields`, `merge_shared_credential_fields`),
//! `switcher.py:739-760` (`_prepare_credentials_for_activation`),
//! `switcher.py:7102-7126` (the `oauthAccount` config splice) and
//! `switcher.py:5236-5250` (`_plan_label`).
//!
//! **A `Login` here is an envelope**: the live credential blob's JSON object
//! with one extra top-level key, `oauthAccount`, copied from `~/.claude.json`
//! at read time. `write_live` splits it again — the credential store never
//! receives the `oauthAccount` key, and `~/.claude.json` receives nothing else.

use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::core::store::write_json_atomic;
use crate::driver::claude::oauth::Endpoints;
use crate::driver::claude::{locks, paths};
use crate::driver::{DriverError, Env, Identity, Login};
use crate::errors::ErrorCode;
#[cfg(target_os = "macos")]
use crate::security_cli::RealSecurity;
use crate::security_cli::SecurityCli;

/// Bounded retry for the live OAuth-credential keychain read
/// (`credentials.py:132-133`). A locked/contended login keychain can fail a
/// single `security` call transiently — e.g. just after wake, or under
/// contention with Claude Code's own statusline polling the same item — and a
/// second attempt a moment later usually succeeds. This is an I/O backoff
/// between retries of an external CLI, not a sleep papering over a race.
const ACTIVE_READ_ATTEMPTS: u32 = 2;
const ACTIVE_READ_RETRY_DELAY: Duration = Duration::from_millis(300);

/// Claude Code's *managed API key* keychain service (`credentials.py:124`) —
/// the other auth axis, cleared whenever an OAuth login is activated.
const MANAGED_KEY_SERVICE: &str = "Claude Code";

/// The siblings of `claudeAiOauth` that are machine-shared rather than
/// account-scoped (`credentials.py:199-206`): they hold OAuth integrations that
/// rotate independently of any slot, so on activation the live copy is
/// authoritative. Everything else — known or unknown — stays with the target
/// slot: a stale restore of an unlisted shared field merely re-prompts for
/// auth, while carrying a live account-bound field across a switch would
/// present one account's credential under another.
const SHARED_CREDENTIAL_KEYS: [&str; 5] = [
    "mcpOAuth",
    "mcpOAuthClientConfig",
    "mcpXaaIdp",
    "mcpXaaIdpConfig",
    "pluginSecrets",
];

/// Where Claude Code's live credential lives on this machine.
///
/// A value, not a `cfg`: tests build `Keychain(FakeSecurity)` on every OS so
/// Linux CI covers the keychain logic too — real construction is
/// `default_for_platform`'s `RealSecurity` on macOS, `FakeSecurity` (and its
/// variants) in the `live.rs`/`run.rs` test suites on every OS. `dead_code`
/// only sees the former, so it's suppressed off macOS alone; on macOS the
/// lint stays live.
pub enum LiveStore {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Keychain(Arc<dyn SecurityCli>),
    File,
}

impl Clone for LiveStore {
    /// Shares the one backend rather than duplicating it: `RunProfile`'s
    /// read-back closure has to own a driver, and a `security` CLI wrapper is
    /// stateless anyway.
    fn clone(&self) -> Self {
        match self {
            LiveStore::Keychain(cli) => LiveStore::Keychain(cli.clone()),
            LiveStore::File => LiveStore::File,
        }
    }
}

/// The Claude provider driver: where the live login lives on this machine, and
/// which upstreams to talk to. `impl Driver for ClaudeDriver` is in the module
/// root, over these inherent methods plus `oauth`/`usage`/`run`.
pub struct ClaudeDriver {
    pub store: LiveStore,
    /// Injected rather than looked up per request, so the driver reads no
    /// process environment and the suite can point it at a local mock server.
    pub endpoints: Endpoints,
}

impl ClaudeDriver {
    pub fn new(store: LiveStore, endpoints: Endpoints) -> Self {
        Self { store, endpoints }
    }

    /// macOS keeps the live credential in the login keychain; every other
    /// platform in `<config_home>/.credentials.json`. Endpoints are the
    /// production ones (`SWAPD_URL_*`-overridable), and `SWAPD_LIVE_STORE`
    /// overrides the store the same way.
    ///
    /// The one place either variable is read: a constructed driver holds
    /// values, never an environment.
    pub fn default_for_platform(env: &Env) -> Self {
        Self::new(live_store_from_env(env), Endpoints::from_env())
    }

    /// Claude Code's live login for this environment, as an envelope (see the
    /// module docs).
    ///
    /// `NoLogin` when every service is genuinely absent;
    /// `KeychainUnavailable` when the backend errored on every attempt for a
    /// service — an unreadable keychain stops the walk, since it is a property
    /// of the keychain and not of the item.
    pub fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        let raw = self.read_live_raw(env)?.ok_or(DriverError::NoLogin)?;
        Ok(Login {
            bytes: embed_oauth_account(env, raw),
        })
    }

    /// `read_live` under Claude Code's own locks, in the order `write_live`
    /// takes them (credentials, then config).
    ///
    /// The budget is `locks::READ_TIMEOUT`, not the 9s write budget: this is a
    /// status read, and a caller that waited out two write budgets would stall
    /// a `list` for ~18s behind a CLI that is merely busy. `Locked` on timeout,
    /// which the collector degrades on.
    ///
    /// NOT reentrant (the locks are mkdir mutexes), so it belongs only where no
    /// `write_live` can follow under the same guard.
    pub fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        let _locks = match self.read_locks(env) {
            Ok(held) => held,
            // The lock DIRECTORIES cannot be created here at all (a read-only
            // config dir). Claude Code takes the same directories in the same
            // place, so a machine where they cannot be made is one where its
            // own writes are not happening either — and failing every status
            // verb on it would be a worse answer than the unfenced read this
            // has always been. Narrowly the permission cases: a full disk or a
            // vanished home is a fault, and faults are reported.
            Err(DriverError::Io(e))
                if matches!(
                    e.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                return self.read_live(env)
            }
            Err(e) => return Err(e),
        };
        self.read_live(env)
    }

    /// Claude Code's credential locks, then its config lock — acquisition only,
    /// so `read_live_locked` can tell "held by the CLI" from "cannot be taken".
    fn read_locks(
        &self,
        env: &Env,
    ) -> Result<(Vec<locks::LockGuard>, locks::LockGuard), DriverError> {
        let credentials = locks::credentials_lock(env, locks::READ_TIMEOUT)?;
        let config = locks::config_lock(env, locks::READ_TIMEOUT)?;
        Ok((credentials, config))
    }

    /// Replace it, under Claude Code's own locks, with the 9s production
    /// per-lock budget.
    pub fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError> {
        self.write_live_with_timeout(env, login, locks::DEFAULT_TIMEOUT)
    }

    /// `write_live` with an explicit per-lock wait budget (the suite uses a
    /// few hundred ms; production uses `locks::DEFAULT_TIMEOUT`).
    ///
    /// Splits the envelope, takes the credential locks and then the config lock
    /// (Claude Code's order), composes the credential with the machine's live
    /// shared fields, writes the credential store, and splices `oauthAccount`
    /// into `~/.claude.json`. The live credential is read *under* the lock: that
    /// is the whole point of holding it, so a refresh landing mid-swap cannot
    /// hand us a superseded generation.
    ///
    /// **OAuth logins only.** A managed `sk-ant-api…` key lives on Claude
    /// Code's other auth axis (keychain service "Claude Code" /
    /// `primaryApiKey`, with the OAuth item cleared — cswap
    /// `_write_managed_credentials`); writing one into the OAuth item would
    /// replace the live login with something Claude Code will not read there.
    /// A non-OAuth blob is rejected before any lock is taken; making a
    /// managed key live is `add-token`'s axis, not this one.
    pub fn write_live_with_timeout(
        &self,
        env: &Env,
        login: &Login,
        timeout: Duration,
    ) -> Result<(), DriverError> {
        let (credential, oauth_account) = split_envelope(&login.bytes)?;
        // Checked on the target rather than on the composed result: composition
        // only swaps `SHARED_CREDENTIAL_KEYS`, so it can neither add nor remove
        // `claudeAiOauth`. Doing it here keeps a bad input from ever taking a
        // lock Claude Code may be waiting on.
        require_oauth_login(&credential)?;

        // Dropped in reverse declaration order: config lock first, then the
        // credential pair (legacy before primary).
        let _credentials = locks::credentials_lock(env, timeout)?;
        let _config = locks::config_lock(env, timeout)?;

        // An unreadable live credential is not fatal: with no live JSON object
        // to take shared fields from, the target activates unchanged, exactly
        // as cswap's `_prepare_credentials_for_activation` does.
        let live = self.read_live_raw(env).unwrap_or(None);
        let composed = prepare_for_activation(&credential, live.as_deref())?;

        // Read (and validate) the config BEFORE the credential store is
        // touched: a torn `~/.claude.json` must fail the whole write, not leave
        // the keychain holding the new account while the config names the old.
        let config = match oauth_account {
            Some(_) => Some(read_config(env)?),
            None => None,
        };

        self.write_credential(env, &composed)?;
        if let (Some(oauth_account), Some(config)) = (oauth_account, config) {
            if let Err(splice_error) = splice_oauth_account(env, config, oauth_account) {
                // The credential landed but the config could not follow. Put
                // the previous login back so the two halves agree; the kinds of
                // both failures go in the message, never any credential bytes.
                let rolled_back = live
                    .as_deref()
                    .map(|previous| self.write_credential(env, previous).is_ok())
                    .unwrap_or(false);
                return Err(DriverError::Invalid(format!(
                    "write_live: credential written but the config splice failed ({}); \
                     credential store {}",
                    error_kind(&splice_error),
                    if rolled_back {
                        "rolled back"
                    } else {
                        "left on the new login"
                    },
                )));
            }
        }
        // Both halves of the OAuth axis are in place; now make sure the other
        // axis cannot shadow them.
        self.clear_managed_key(env);
        Ok(())
    }

    /// The live credential exactly as the store holds it — no envelope.
    ///
    /// On the keychain store an absent item falls through to
    /// `<config_home>/.credentials.json`, Claude Code's own plaintext fallback
    /// (`credentials.py` `_read_active_credentials` step 2): a macOS login that
    /// only ever wrote the file — a container-shared `~/.claude`, a session that
    /// logged in while the keychain was unusable — is a real login, not an empty
    /// slot. A keychain *error* still propagates: that is a property of the
    /// keychain, and answering from a possibly-stale file would hide it.
    pub fn read_live_raw(&self, env: &Env) -> Result<Option<String>, DriverError> {
        match &self.store {
            LiveStore::Keychain(cli) => match read_keychain(cli.as_ref(), env)? {
                Some(value) => Ok(Some(value)),
                None => read_credentials_file(env),
            },
            LiveStore::File => read_credentials_file(env),
        }
    }

    fn write_credential(&self, env: &Env, value: &str) -> Result<(), DriverError> {
        match &self.store {
            LiveStore::Keychain(cli) => {
                // The item Claude Code reads for *this* environment: the first
                // service in try-order (the profile's own, hashed item when
                // `CLAUDE_CONFIG_DIR` names one).
                let service = paths::live_services(env)
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| paths::DEFAULT_SERVICE.to_string());
                cli.add(&service, &keychain_account(env), value)
                    .map_err(map_security_error)?;
                refresh_stale_credentials_file(env, value);
                Ok(())
            }
            LiveStore::File => write_credentials_file(env, value),
        }
    }

    /// Clear the *other* auth axis after activating an OAuth login
    /// (`credentials.py:797-818` `_write_credentials`, `credentials.py:894-930`
    /// `_clear_managed_key`).
    ///
    /// Claude Code's own `saveApiKey`/`removeApiKey` treat the managed
    /// `sk-ant-api…` key and the OAuth credential as mutually exclusive, and a
    /// managed key wins wherever it is still present — so a stale one left
    /// behind is a live cross-account key that a later shell would pick up over
    /// the account we just activated (and that bills per token while it lies).
    ///
    /// Best-effort, and deliberately last: it runs after the `oauthAccount`
    /// splice, because the splice writes a config snapshot read *before* the
    /// credential write and would otherwise resurrect the key it dropped.
    /// `customApiKeyResponses.approved` is left intact, as `removeApiKey` leaves
    /// it. An unreadable (as opposed to absent) config is left alone rather than
    /// overwritten unread.
    fn clear_managed_key(&self, env: &Env) {
        if let LiveStore::Keychain(cli) = &self.store {
            // A down keychain cannot be cleaned now; the OAuth write already
            // succeeded and must not be failed for this.
            let _ = cli.delete(MANAGED_KEY_SERVICE, &keychain_account(env));
        }
        let Ok(Some(Value::Object(mut config))) = read_config(env) else {
            return;
        };
        if config
            .get("primaryApiKey")
            .is_none_or(|value| value.is_null())
        {
            return;
        }
        config.remove("primaryApiKey");
        if let Ok(path) = paths::config_json(env) {
            let _ = write_json_atomic(&path, &Value::Object(config));
        }
    }
}

/// `SWAPD_LIVE_STORE` = `file` | `keychain` overrides the platform default;
/// unset (or anything else) is the platform's own. Read from the `Env` the
/// driver was built with, never from the process: what a verb does must be
/// decidable from the context it was handed.
///
/// The suite needs `file` for one reason: the assert_cmd tests drive the real
/// binary, and on macOS the platform default would run `security` against the
/// developer's own login keychain — reading a real credential the tests must
/// never touch. `keychain` off macOS has no backend and falls back to the file
/// store rather than pretending.
fn live_store_from_env(env: &Env) -> LiveStore {
    let mode = env.vars.get("SWAPD_LIVE_STORE");
    if mode.map(String::as_str) == Some("file") {
        return LiveStore::File;
    }
    #[cfg(target_os = "macos")]
    {
        LiveStore::Keychain(Arc::new(RealSecurity))
    }
    #[cfg(not(target_os = "macos"))]
    {
        LiveStore::File
    }
}

/// Rewrite an already-present `.credentials.json` after a keychain write
/// (`credentials.py:1012-1038` `_refresh_stale_credentials_file`).
///
/// Rewrite-when-present, never create. Claude Code invalidates its memoized
/// OAuth token only when this file's mtime changes or the file is absent, so a
/// keychain-only swap leaves a stale file's mtime frozen and a running session
/// serves the old account's token until it restarts. Keychain-only users keep
/// their fileless posture — their absent-file path already hot-reloads via the
/// ~30s keychain TTL — and never gain a plaintext credential on disk.
///
/// Best-effort: the keychain write is authoritative and already succeeded, so a
/// failure here only means a running session may lag until restart.
fn refresh_stale_credentials_file(env: &Env, value: &str) {
    let Ok(path) = paths::credentials_file(env) else {
        return;
    };
    if !path.exists() {
        return;
    }
    let _ = write_credentials_file(env, value);
}

/// Reject anything that is not an OAuth login object before it can reach
/// Claude Code's OAuth item (see `write_live_with_timeout`).
pub fn require_oauth_login(credential: &str) -> Result<(), DriverError> {
    let is_oauth = credential_object(Some(credential))
        .and_then(|map| map.get("claudeAiOauth").cloned())
        .map(|value| value.is_object())
        .unwrap_or(false);
    if is_oauth {
        Ok(())
    } else {
        Err(DriverError::Invalid(
            "write_live: oauth login required".to_string(),
        ))
    }
}

/// A one-word kind for an error, so a failure can be reported without echoing
/// anything the error's own message may carry.
fn error_kind(err: &DriverError) -> &'static str {
    match err {
        DriverError::Io(_) => "io",
        DriverError::Locked(_) => "locked",
        DriverError::Invalid(_) => "invalid",
        DriverError::KeychainUnavailable => "keychain unavailable",
        _ => "error",
    }
}

/// Account name for the live-credential keychain item, mirroring Claude Code's
/// `getUsername()` (`macos_keychain.py:76-93`): `$USER`, else a stable
/// fallback. Matching it exactly matters on headless/launchd hosts where
/// `$USER` is unset — a divergent default would key a *different* item than
/// Claude Code's.
pub fn keychain_account(env: &Env) -> String {
    for name in ["USER", "LOGNAME"] {
        if let Some(user) = env.vars.get(name) {
            if !user.is_empty() {
                return user.clone();
            }
        }
    }
    "claude-code-user".to_string()
}

pub fn map_security_error(err: crate::errors::SwapdError) -> DriverError {
    match err.code {
        ErrorCode::KeychainUnavailable => DriverError::KeychainUnavailable,
        _ => DriverError::Invalid(err.message),
    }
}

/// Walk the environment's services in order, first hit wins
/// (`credentials.py:536-548`).
fn read_keychain(cli: &dyn SecurityCli, env: &Env) -> Result<Option<String>, DriverError> {
    for service in paths::live_services(env) {
        if let Some(value) = read_one_service(cli, &service)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// One item, with a bounded retry (`credentials.py:550-563`). An absent item
/// (`Ok(None)`) is not retried; only a backend error is.
fn read_one_service(cli: &dyn SecurityCli, service: &str) -> Result<Option<String>, DriverError> {
    for attempt in 0..ACTIVE_READ_ATTEMPTS {
        match cli.find(service, None) {
            Ok(Some(value)) if !value.trim().is_empty() => return Ok(Some(value)),
            Ok(_) => return Ok(None),
            Err(_) => {
                if attempt + 1 < ACTIVE_READ_ATTEMPTS {
                    std::thread::sleep(ACTIVE_READ_RETRY_DELAY);
                }
            }
        }
    }
    Err(DriverError::KeychainUnavailable)
}

pub fn read_credentials_file(env: &Env) -> Result<Option<String>, DriverError> {
    let path = paths::credentials_file(env)?;
    match fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => Ok(Some(text)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write the plaintext credential file atomically, 0600 (port of
/// `credentials.py:751-772` `_write_active_credentials_file`). On Linux this is
/// *the* live store and Claude Code reads it without taking any lock, so a
/// truncate-then-write would give it a window to read a torn credential.
pub fn write_credentials_file(env: &Env, value: &str) -> Result<(), DriverError> {
    let path = paths::credentials_file(env)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;

    let tmp = dir.join(format!(".credentials.json.tmp.{}", rand::random::<u64>()));
    match write_private_file(&tmp, value).and_then(|()| Ok(fs::rename(&tmp, &path)?)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Create `path` with 0600 and write `value` to it.
pub fn write_private_file(path: &Path, value: &str) -> Result<(), DriverError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(value.as_bytes())?;
    // Durable before the rename, as `core::store::write_json_atomic` does.
    file.sync_all()?;
    Ok(())
}

/// The envelope's `oauthAccount` (from `~/.claude.json`) glued onto the raw
/// credential object. A credential that is not a JSON object (a managed
/// `sk-ant-api…` key, an opaque legacy blob) is returned unchanged.
pub fn embed_oauth_account(env: &Env, raw: String) -> String {
    let Some(oauth_account) = config_oauth_account(env) else {
        return raw;
    };
    let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(&raw) else {
        return raw;
    };
    map.insert("oauthAccount".to_string(), oauth_account);
    serde_json::to_string(&Value::Object(map)).unwrap_or(raw)
}

/// The reverse: the credential without `oauthAccount`, plus that value.
pub fn split_envelope(bytes: &str) -> Result<(String, Option<Value>), DriverError> {
    let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(bytes) else {
        return Ok((bytes.to_string(), None));
    };
    match map.remove("oauthAccount") {
        // Present but not an object: splicing it would put a `null` or a string
        // where Claude Code expects the account profile.
        Some(oauth_account) if !oauth_account.is_object() => Err(DriverError::Invalid(
            "invalid oauthAccount in login".to_string(),
        )),
        Some(oauth_account) => Ok((
            serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| bytes.to_string()),
            Some(oauth_account),
        )),
        None => Ok((bytes.to_string(), None)),
    }
}

pub fn read_config(env: &Env) -> Result<Option<Value>, DriverError> {
    let path = paths::config_json(env)?;
    match fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(value @ Value::Object(_)) => Ok(Some(value)),
            // Fail loud rather than clobber: a torn or foreign config is the
            // user's data, and rewriting it from scratch would lose it.
            _ => Err(DriverError::Invalid(format!(
                "{} is not a JSON object",
                path.display()
            ))),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn config_oauth_account(env: &Env) -> Option<Value> {
    let config = read_config(env).ok()??;
    config
        .get("oauthAccount")
        .filter(|v| v.is_object())
        .cloned()
}

/// Replace only `oauthAccount` in `~/.claude.json`, preserving every other key
/// (`switcher.py:7102-7126`). The file is created when absent.
fn splice_oauth_account(
    env: &Env,
    config: Option<Value>,
    oauth_account: Value,
) -> Result<(), DriverError> {
    let path = paths::config_json(env)?;
    let mut config = match config {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    config.insert("oauthAccount".to_string(), oauth_account);
    write_json_config(&path, &Value::Object(config))
}

/// Write a `.claude.json` atomically, 0600 (`write_json_atomic` creates its temp
/// with that mode and renames over the target). Shared with the run profile's
/// seed, which writes the same file with more than one key.
pub fn write_json_config(path: &Path, value: &Value) -> Result<(), DriverError> {
    write_json_atomic(path, value).map_err(|e| match e.code {
        ErrorCode::Io => DriverError::Io(std::io::Error::other(e.message)),
        _ => DriverError::Invalid(e.message),
    })
}

/// Whether a stored credential is a raw managed API key rather than OAuth JSON
/// (`credentials.py:166-178`). Strict on purpose: requiring the `sk-ant-api`
/// prefix (and that it isn't JSON) keeps a raw `sk-ant-oat…` setup token from
/// being misclassified.
pub fn looks_like_api_key(credentials: &str) -> bool {
    let text = credentials.trim();
    text.starts_with("sk-ant-api") && !text.starts_with('{')
}

/// Parse a JSON credential object, excluding managed API keys
/// (`credentials.py:181-189`).
fn credential_object(credentials: Option<&str>) -> Option<Map<String, Value>> {
    let credentials = credentials?;
    if credentials.is_empty() || looks_like_api_key(credentials) {
        return None;
    }
    match serde_json::from_str::<Value>(credentials) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// The machine-shared fields of a Claude credential object
/// (`credentials.py:216-241`). `None` means the input is not a JSON credential
/// object (missing, malformed, or a managed API key). A map — including an
/// empty one — is authoritative for every allowlisted key: a key absent here is
/// absent from the machine's current shared state.
fn shared_credential_fields(credentials: Option<&str>) -> Option<Map<String, Value>> {
    let data = credential_object(credentials)?;
    let mut shared = Map::new();
    for key in SHARED_CREDENTIAL_KEYS {
        if let Some(value) = data.get(key) {
            shared.insert(key.to_string(), value.clone());
        }
    }
    Some(shared)
}

/// Compose a target login with the machine's shared fields
/// (`credentials.py:244-268`). The allowlisted keys are wholly live-owned,
/// presence and absence alike; all other target fields pass through untouched.
/// A target that is not a JSON object carrying a Claude login (managed API
/// keys, opaque legacy shapes) stays activatable verbatim.
fn merge_shared_credential_fields(target: &str, shared: &Map<String, Value>) -> String {
    let Some(target_map) = credential_object(Some(target)) else {
        return target.to_string();
    };
    if !target_map.contains_key("claudeAiOauth") {
        return target.to_string();
    }
    let mut composed: Map<String, Value> = target_map
        .into_iter()
        .filter(|(key, _)| !SHARED_CREDENTIAL_KEYS.contains(&key.as_str()))
        .collect();
    for (key, value) in shared {
        composed.insert(key.clone(), value.clone());
    }
    serde_json::to_string(&Value::Object(composed)).unwrap_or_else(|_| target.to_string())
}

/// Compose the credential to activate from its two owners
/// (`switcher.py:739-760`).
///
/// The machine-shared OAuth integrations (`SHARED_CREDENTIAL_KEYS`, notably
/// `mcpOAuth`) are frozen in the slot at backup time and may hold rotated-out
/// tokens, while the live credential's copies are by definition the current
/// generation — so for those keys the live credential wins, absence included.
/// Every other field travels with the slot: account-bound state such as
/// `trustedDeviceToken`, and any field swapd does not recognize, must not leak
/// across an account switch.
pub fn prepare_for_activation(target: &str, live: Option<&str>) -> Result<String, DriverError> {
    match shared_credential_fields(live) {
        Some(shared) => Ok(merge_shared_credential_fields(target, &shared)),
        None => Ok(target.to_string()),
    }
}

/// An `Identity` from an `oauthAccount` object.
pub fn identity_from_oauth_account(value: &Value) -> Option<Identity> {
    let oauth = value.as_object()?;
    let text = |key: &str| {
        oauth
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Some(Identity {
        email: text("emailAddress"),
        organization_uuid: text("organizationUuid"),
        organization_name: text("organizationName"),
        plan: plan_label(oauth),
        uuid: Some(text("accountUuid")).filter(|s| !s.is_empty()),
    })
}

/// Human plan label from an `oauthAccount` profile (`switcher.py:5236-5250`),
/// `None` if unknown. Prefers the rate-limit tier
/// (`default_claude_max_20x` -> "Max 20x", seat tiers over org tiers), falling
/// back to the organization type (`claude_pro` -> "Pro").
fn plan_label(oauth: &Map<String, Value>) -> Option<String> {
    let raw = [
        "userRateLimitTier",
        "organizationRateLimitTier",
        "organizationType",
    ]
    .iter()
    .find_map(|key| {
        oauth
            .get(*key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    })
    .unwrap_or("");
    let raw = raw.strip_prefix("default_").unwrap_or(raw);
    let raw = raw.strip_prefix("claude_").unwrap_or(raw);
    if raw.is_empty() {
        return None;
    }
    let words: Vec<String> = raw
        .split('_')
        .map(|word| {
            // "20x" stays as it is; every other word is capitalized. Sliced by
            // char, never by byte: this runs on a user-written file.
            match word.strip_suffix('x') {
                Some(stem) if !stem.is_empty() && stem.chars().all(|c| c.is_ascii_digit()) => {
                    word.to_string()
                }
                _ => capitalize(word),
            }
        })
        .collect();
    Some(words.join(" "))
}

/// Python's `str.capitalize`: first character upper, the rest lower.
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::claude::tests::{endpoints, env_with, temp_home};
    use crate::errors::SwapdError;
    use crate::security_cli::FakeSecurity;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn fake_driver() -> (ClaudeDriver, Arc<FakeSecurity>) {
        let fake = Arc::new(FakeSecurity::default());
        (
            ClaudeDriver::new(LiveStore::Keychain(fake.clone()), endpoints()),
            fake,
        )
    }

    /// A default profile whose `~/.claude` exists, so `live_services` yields
    /// the hashed item *and* the unsuffixed fallback.
    fn default_profile_env(home: &TempDir) -> (Env, Vec<String>) {
        let config_home = home.path().join(".claude");
        fs::create_dir_all(&config_home).unwrap();
        let env = env_with(
            home,
            [
                ("CLAUDE_CONFIG_DIR", config_home.to_str().unwrap()),
                ("USER", "tester"),
            ],
        );
        let services = paths::live_services(&env);
        assert_eq!(
            services.len(),
            2,
            "expected hashed + fallback: {services:?}"
        );
        (env, services)
    }

    #[test]
    fn read_live_tries_services_in_order() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();

        fake.add(
            &services[0],
            "tester",
            r#"{"claudeAiOauth":{"refreshToken":"hashed"}}"#,
        )
        .unwrap();
        fake.add(
            &services[1],
            "tester",
            r#"{"claudeAiOauth":{"refreshToken":"unsuffixed"}}"#,
        )
        .unwrap();

        // First hit wins: the profile's own hashed item.
        assert!(driver.read_live(&env).unwrap().bytes.contains("hashed"));

        // With it gone, the walk falls through to the unsuffixed item.
        fake.delete(&services[0], "tester").unwrap();
        assert!(driver.read_live(&env).unwrap().bytes.contains("unsuffixed"));

        // With both gone, that is a genuine absence, not a backend failure.
        fake.delete(&services[1], "tester").unwrap();
        assert!(matches!(driver.read_live(&env), Err(DriverError::NoLogin)));
    }

    /// Fails `find` a fixed number of times, then answers `Ok(None)`.
    struct FlakySecurity {
        remaining_failures: Mutex<u32>,
    }

    impl SecurityCli for FlakySecurity {
        fn find(
            &self,
            _service: &str,
            _account: Option<&str>,
        ) -> crate::errors::Result<Option<String>> {
            let mut remaining = self.remaining_failures.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err(SwapdError::new(
                    ErrorCode::KeychainUnavailable,
                    "keychain unavailable",
                ));
            }
            Ok(None)
        }
        fn add(&self, _service: &str, _account: &str, _value: &str) -> crate::errors::Result<()> {
            Ok(())
        }
        fn delete(&self, _service: &str, _account: &str) -> crate::errors::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn read_live_retries_once_then_reports_keychain_unavailable() {
        let home = temp_home();
        let env = env_with(&home, []);

        // One transient failure is ridden out by the second attempt: the item
        // then reads as absent, which is NoLogin, not KeychainUnavailable.
        let flaky = Arc::new(FlakySecurity {
            remaining_failures: Mutex::new(1),
        });
        let driver = ClaudeDriver::new(LiveStore::Keychain(flaky), endpoints());
        assert!(matches!(driver.read_live(&env), Err(DriverError::NoLogin)));

        // Both attempts failing is a keychain problem, never "no login".
        let flaky = Arc::new(FlakySecurity {
            remaining_failures: Mutex::new(2),
        });
        let driver = ClaudeDriver::new(LiveStore::Keychain(flaky), endpoints());
        assert!(matches!(
            driver.read_live(&env),
            Err(DriverError::KeychainUnavailable)
        ));
    }

    #[test]
    fn read_live_embeds_oauth_account_and_write_live_strips_it() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();

        fs::write(
            paths::config_json(&env).unwrap(),
            r#"{"numStartups":7,"oauthAccount":{"emailAddress":"a@example.com"}}"#,
        )
        .unwrap();
        fake.add(
            &services[0],
            "tester",
            r#"{"claudeAiOauth":{"refreshToken":"rt-1"}}"#,
        )
        .unwrap();

        let login = driver.read_live(&env).unwrap();
        let envelope: Value = serde_json::from_str(&login.bytes).unwrap();
        assert_eq!(envelope["oauthAccount"]["emailAddress"], "a@example.com");
        assert_eq!(envelope["claudeAiOauth"]["refreshToken"], "rt-1");
        // The envelope key does not disturb the fingerprint.
        assert!(login.fingerprint().starts_with("sha256:"));

        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        let stored = fake.find(&services[0], None).unwrap().unwrap();
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert!(
            stored.get("oauthAccount").is_none(),
            "claude code's own item must not carry swapd's envelope key: {stored}"
        );
        assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-1");
    }

    #[test]
    fn write_live_preserves_mcp_oauth_from_live() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();

        // Live: a current mcpOAuth generation, no pluginSecrets.
        fake.add(
            &services[0],
            "tester",
            r#"{"claudeAiOauth":{"refreshToken":"live"},"mcpOAuth":{"srv":"live-token"}}"#,
        )
        .unwrap();

        // Target slot: a stale mcpOAuth, a stale pluginSecrets, and an
        // account-bound trustedDeviceToken that must travel with the slot.
        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-2"},"mcpOAuth":{"srv":"stale"},"pluginSecrets":{"p":"stale"},"trustedDeviceToken":"tdt-2"}"#
                .to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        let stored: Value =
            serde_json::from_str(&fake.find(&services[0], None).unwrap().unwrap()).unwrap();
        assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-2");
        // Shared key: the live generation wins.
        assert_eq!(stored["mcpOAuth"]["srv"], "live-token");
        // Shared key absent from the live credential: absence wins too — the
        // slot's stale copy is not resurrected.
        assert!(stored.get("pluginSecrets").is_none(), "stored: {stored}");
        // Account-scoped key: travels with the slot.
        assert_eq!(stored["trustedDeviceToken"], "tdt-2");
    }

    #[test]
    fn write_live_splices_only_oauth_account_into_config() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        let config_path = paths::config_json(&env).unwrap();
        fs::write(
            &config_path,
            r#"{"numStartups":7,"oauthAccount":{"emailAddress":"old@example.com"},"mcpServers":{"srv":{"url":"http://x"}}}"#,
        )
        .unwrap();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-3"},"oauthAccount":{"emailAddress":"new@example.com","organizationName":"Org"}}"#
                .to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        let config: Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(config["oauthAccount"]["emailAddress"], "new@example.com");
        assert_eq!(config["oauthAccount"]["organizationName"], "Org");
        // Everything else is preserved byte-for-byte in value terms.
        assert_eq!(config["numStartups"], 7);
        assert_eq!(config["mcpServers"]["srv"]["url"], "http://x");
        assert_eq!(config.as_object().unwrap().len(), 3);
    }

    #[test]
    fn write_live_without_an_envelope_leaves_the_config_alone() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        let config_path = paths::config_json(&env).unwrap();
        let before = r#"{"oauthAccount":{"emailAddress":"old@example.com"}}"#;
        fs::write(&config_path, before).unwrap();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-4"}}"#.to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        assert_eq!(fs::read_to_string(&config_path).unwrap(), before);
    }

    #[test]
    fn write_live_refuses_when_lock_held() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        // Claude Code holds its primary refresh lock, freshly touched.
        let held = home.path().join(".claude/.oauth_refresh.lock");
        fs::create_dir_all(&held).unwrap();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-5"}}"#.to_string(),
        };
        let err = driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(200))
            .unwrap_err();
        match err {
            DriverError::Locked(msg) => assert!(msg.contains(".oauth_refresh.lock"), "{msg}"),
            other => panic!("expected Locked, got {other:?}"),
        }
        assert!(
            held.is_dir(),
            "we must not have stolen a live holder's lock"
        );
    }

    #[test]
    fn write_live_uses_the_file_store_with_0600() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-6"}}"#.to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        let path = paths::credentials_file(&env).unwrap();
        let stored: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-6");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // And it round-trips through the file store's read path.
        assert!(driver.read_live(&env).unwrap().bytes.contains("rt-6"));
    }

    #[test]
    fn write_live_rejects_a_non_oauth_login() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();
        let live = r#"{"claudeAiOauth":{"refreshToken":"live"}}"#;
        fake.add(&services[0], "tester", live).unwrap();

        for bytes in [
            "sk-ant-api03-fake-key",           // the managed-key axis
            "",                                // an empty write would log the user out
            r#"{"trustedDeviceToken":"tdt"}"#, // JSON, but not a login
            r#"{"claudeAiOauth":"not-an-object"}"#,
        ] {
            let login = Login {
                bytes: bytes.to_string(),
            };
            let err = driver
                .write_live_with_timeout(&env, &login, Duration::from_millis(300))
                .unwrap_err();
            assert!(
                matches!(&err, DriverError::Invalid(m) if m == "write_live: oauth login required"),
                "{bytes:?} -> {err:?}"
            );
        }
        // The live login is untouched by every rejection.
        assert_eq!(
            fake.find(&services[0], None).unwrap().as_deref(),
            Some(live)
        );
        // And no lock was even taken.
        assert!(!home.path().join(".claude/.oauth_refresh.lock").exists());
    }

    #[test]
    fn write_live_rejects_a_non_object_oauth_account() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        for oauth_account in ["null", r#""a@example.com""#, "42"] {
            let login = Login {
                bytes: format!(
                    r#"{{"claudeAiOauth":{{"refreshToken":"rt"}},"oauthAccount":{oauth_account}}}"#
                ),
            };
            let err = driver
                .write_live_with_timeout(&env, &login, Duration::from_millis(300))
                .unwrap_err();
            assert!(
                matches!(&err, DriverError::Invalid(m) if m == "invalid oauthAccount in login"),
                "{oauth_account} -> {err:?}"
            );
        }
    }

    #[test]
    fn keychain_account_follows_claude_codes_chain() {
        let home = temp_home();
        assert_eq!(
            keychain_account(&env_with(&home, [("USER", "alice"), ("LOGNAME", "bob")])),
            "alice"
        );
        // $USER unset or empty on a launchd/cron host: LOGNAME is next.
        assert_eq!(
            keychain_account(&env_with(&home, [("USER", ""), ("LOGNAME", "bob")])),
            "bob"
        );
        // Neither: Claude Code's own final fallback, so both name one item.
        assert_eq!(keychain_account(&env_with(&home, [])), "claude-code-user");
    }

    /// Wraps `FakeSecurity` and, on its first `add`, makes `dir` unwritable —
    /// so the config splice that follows the credential write fails, with no
    /// threads and no timing window.
    struct BreakDirOnFirstWrite {
        inner: FakeSecurity,
        // Only the `#[cfg(unix)]` branch of `add` below reads this — chmod'ing
        // a directory unwritable has no Windows equivalent here.
        #[cfg(unix)]
        dir: std::path::PathBuf,
        broken: Mutex<bool>,
    }

    impl SecurityCli for BreakDirOnFirstWrite {
        fn find(
            &self,
            service: &str,
            account: Option<&str>,
        ) -> crate::errors::Result<Option<String>> {
            self.inner.find(service, account)
        }
        fn add(&self, service: &str, account: &str, value: &str) -> crate::errors::Result<()> {
            let mut broken = self.broken.lock().unwrap();
            if !*broken {
                *broken = true;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o500)).unwrap();
                }
            }
            drop(broken);
            self.inner.add(service, account, value)
        }
        fn delete(&self, service: &str, account: &str) -> crate::errors::Result<()> {
            self.inner.delete(service, account)
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_live_rolls_the_credential_back_when_the_config_splice_fails() {
        use std::os::unix::fs::PermissionsExt;
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let config_path = paths::config_json(&env).unwrap();
        let config_before = r#"{"oauthAccount":{"emailAddress":"old@example.com"}}"#;
        fs::write(&config_path, config_before).unwrap();

        let live = r#"{"claudeAiOauth":{"refreshToken":"live"}}"#;
        let breaker = Arc::new(BreakDirOnFirstWrite {
            inner: FakeSecurity::default(),
            dir: config_path.parent().unwrap().to_path_buf(),
            broken: Mutex::new(false),
        });
        breaker.inner.add(&services[0], "tester", live).unwrap();
        let driver = ClaudeDriver::new(LiveStore::Keychain(breaker.clone()), endpoints());

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"new"},"oauthAccount":{"emailAddress":"new@example.com"}}"#
                .to_string(),
        };
        let err = driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap_err();

        // Restore write permission first, so the temp dir can be cleaned up
        // even if an assertion below panics.
        fs::set_permissions(
            config_path.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        match &err {
            DriverError::Invalid(msg) => {
                assert!(msg.contains("config splice failed (io)"), "{msg}");
                assert!(msg.contains("rolled back"), "{msg}");
                assert!(!msg.contains("refreshToken"), "no credential bytes: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(
            breaker.find(&services[0], None).unwrap().as_deref(),
            Some(live),
            "the credential must be rolled back when the config cannot follow"
        );
        assert_eq!(fs::read_to_string(&config_path).unwrap(), config_before);
    }

    #[test]
    fn prepare_for_activation_passes_api_keys_and_missing_live_through() {
        let target = r#"{"claudeAiOauth":{"refreshToken":"rt"},"mcpOAuth":{"srv":"slot"}}"#;
        // No live credential at all: the slot's blob activates unchanged.
        assert_eq!(prepare_for_activation(target, None).unwrap(), target);
        // A live managed API key is not a credential object either.
        assert_eq!(
            prepare_for_activation(target, Some("sk-ant-api03-fake")).unwrap(),
            target
        );
        // A managed API key as the *target* stays activatable verbatim here —
        // composition is the OAuth-agnostic step. `write_live` is the one that
        // refuses it (see `write_live_rejects_a_non_oauth_login`), because the
        // managed key belongs on Claude Code's other auth axis.
        assert_eq!(
            prepare_for_activation("sk-ant-api03-fake", Some(target)).unwrap(),
            "sk-ant-api03-fake"
        );
        // So does a target with no claudeAiOauth.
        assert_eq!(
            prepare_for_activation(r#"{"other":1}"#, Some(target)).unwrap(),
            r#"{"other":1}"#
        );
    }

    #[test]
    fn an_oauth_account_object_reads_as_email_org_and_plan() {
        // The shape `~/.claude.json` advertises, which is what the envelope
        // carries and `identity_offline` answers from.
        let account: Value = serde_json::from_str(
            r#"{"emailAddress":"a@example.com","organizationUuid":"org-1","organizationName":"Acme","accountUuid":"acc-1","userRateLimitTier":"default_claude_max_20x"}"#,
        )
        .unwrap();
        assert!(identity_from_oauth_account(&Value::Null).is_none());
        assert_eq!(
            identity_from_oauth_account(&account).unwrap(),
            Identity {
                email: "a@example.com".to_string(),
                organization_uuid: "org-1".to_string(),
                organization_name: "Acme".to_string(),
                plan: Some("Max 20x".to_string()),
                uuid: Some("acc-1".to_string()),
            }
        );
    }

    #[test]
    fn plan_label_ports_the_tier_precedence() {
        let label = |json: &str| {
            let value: Value = serde_json::from_str(json).unwrap();
            plan_label(value.as_object().unwrap())
        };
        // Seat tier wins over org tier, which wins over the org type.
        assert_eq!(
            label(
                r#"{"userRateLimitTier":"default_claude_max_5x","organizationRateLimitTier":"default_claude_max_20x","organizationType":"claude_pro"}"#
            ),
            Some("Max 5x".to_string())
        );
        assert_eq!(
            label(r#"{"organizationRateLimitTier":"default_claude_max_20x"}"#),
            Some("Max 20x".to_string())
        );
        assert_eq!(
            label(r#"{"organizationType":"claude_pro"}"#),
            Some("Pro".to_string())
        );
        assert_eq!(label(r#"{"organizationType":""}"#), None);
        // Slicing a word by byte to test for the "20x" shape would panic here.
        assert_eq!(
            label(r#"{"organizationType":"claud\u00e9"}"#),
            Some("Claudé".to_string())
        );
        assert_eq!(label("{}"), None);
    }

    #[test]
    fn write_live_clears_the_managed_key_axis_and_bumps_a_present_shadow_file() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();

        // A machine that last logged in with a managed API key: the key sits in
        // the "Claude Code" item AND in the config, either of which Claude Code
        // would prefer over the OAuth login we are about to activate.
        fake.add(MANAGED_KEY_SERVICE, "tester", "sk-ant-api03-stale")
            .unwrap();
        let config_path = paths::config_json(&env).unwrap();
        fs::write(
            &config_path,
            r#"{"primaryApiKey":"sk-ant-api03-stale","customApiKeyResponses":{"approved":["api03-stale"]}}"#,
        )
        .unwrap();
        // A shadow .credentials.json from that era, holding a stale generation.
        let shadow = paths::credentials_file(&env).unwrap();
        fs::write(&shadow, r#"{"claudeAiOauth":{"refreshToken":"rt-old"}}"#).unwrap();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-new"},"oauthAccount":{"emailAddress":"you@example.com"}}"#
                .to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        // The OAuth item holds the new login...
        assert!(fake
            .find(&services[0], Some("tester"))
            .unwrap()
            .unwrap()
            .contains("rt-new"));
        // ...the managed key can no longer shadow it, on either axis...
        assert_eq!(
            fake.find(MANAGED_KEY_SERVICE, Some("tester")).unwrap(),
            None
        );
        let config: Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(config.get("primaryApiKey").is_none());
        // ...`approved` survives, as Claude Code's own removeApiKey leaves it...
        assert_eq!(
            config["customApiKeyResponses"]["approved"][0],
            "api03-stale"
        );
        // ...the config splice still landed...
        assert_eq!(config["oauthAccount"]["emailAddress"], "you@example.com");
        // ...and the present shadow file was rewritten (mtime bumped, #86) with
        // the same fresh credential, minus the envelope.
        let shadow_text = fs::read_to_string(&shadow).unwrap();
        assert!(shadow_text.contains("rt-new"));
        assert!(!shadow_text.contains("oauthAccount"));
    }

    #[test]
    fn write_live_never_creates_a_shadow_credentials_file() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-7"}}"#.to_string(),
        };
        driver
            .write_live_with_timeout(&env, &login, Duration::from_millis(300))
            .unwrap();

        // Keychain-only users keep their fileless posture: no plaintext
        // credential appears on disk.
        assert!(!paths::credentials_file(&env).unwrap().exists());
    }

    #[test]
    fn read_live_falls_back_to_the_credentials_file_when_the_keychain_is_empty() {
        let home = temp_home();
        let (env, _services) = default_profile_env(&home);
        let (driver, _fake) = fake_driver();

        // Nothing in any keychain service, but Claude Code's own plaintext
        // fallback holds a real login (container-shared ~/.claude, or a login
        // made while the keychain was unusable).
        fs::write(
            paths::credentials_file(&env).unwrap(),
            r#"{"claudeAiOauth":{"refreshToken":"rt-file"}}"#,
        )
        .unwrap();
        fs::write(
            paths::config_json(&env).unwrap(),
            r#"{"oauthAccount":{"emailAddress":"you@example.com"}}"#,
        )
        .unwrap();

        let login = driver.read_live(&env).unwrap();
        assert!(login.bytes.contains("rt-file"));
        // And it is a full envelope, exactly as a keychain hit would be.
        assert!(login.bytes.contains("you@example.com"));
    }

    #[test]
    fn write_live_refuses_to_clobber_a_torn_config() {
        let home = temp_home();
        let (env, services) = default_profile_env(&home);
        let (driver, fake) = fake_driver();

        let config_path = paths::config_json(&env).unwrap();
        fs::write(&config_path, "{\"numStartups\": 7,").unwrap();
        let before = r#"{"claudeAiOauth":{"refreshToken":"live"}}"#;
        fake.add(&services[0], "tester", before).unwrap();

        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-7"},"oauthAccount":{"emailAddress":"new@example.com"}}"#
                .to_string(),
        };
        assert!(matches!(
            driver.write_live_with_timeout(&env, &login, Duration::from_millis(300)),
            Err(DriverError::Invalid(_))
        ));
        assert_eq!(
            fs::read_to_string(&config_path).unwrap(),
            "{\"numStartups\": 7,",
            "the user's torn config must be left as it was"
        );
        // And the swap must not have half-landed: the credential store still
        // holds the account the (unwritable) config still names.
        assert_eq!(
            fake.find(&services[0], None).unwrap().as_deref(),
            Some(before),
            "the credential must not be written when the config splice cannot be"
        );
    }
}
