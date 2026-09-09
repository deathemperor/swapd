# swapd phase 1 — core + Claude driver + Infinitus adapter

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust `swapd` binary that lists, refreshes, switches, adds, imports and ignites Claude Code logins with the same measured behaviour as cswap, plus an Infinitus adapter that drives it beside cswap.

**Architecture:** One binary crate. `src/core` owns slots, the usage store, poll policy, switching and the auto loop; `src/driver/claude.rs` owns everything Claude-specific (keychain item, `~/.claude.json`, Claude Code's locks, OAuth endpoints); every verb prints one JSON object with `--json`. Infinitus gets `Sources/InfinitusCore/Engines/Swapd/` as a second `AccountEngine`.

**Tech Stack:** Rust stable (1.98), clap 4 (derive), serde/serde_json, ureq 3 (rustls), keyring 3, sha2, time 0.3, thiserror, fd-lock; dev: httpmock, assert_cmd, tempfile, insta (snapshots). Swift 6 / SwiftPM for the Infinitus side.

**Spec:** `docs/superpowers/specs/2026-09-09-swapd-design.md` (this repo). Read it first; every task below argues from it.

**Reference implementation:** `~/death/claude-swap/src/claude_swap/` (Python). Where a task says *port verbatim*, read the cited lines completely and reproduce the behaviour and constants exactly; do not redesign.

## Global Constraints

- Every verb accepts `--json`; with it stdout is exactly one JSON object (NDJSON for `auto`), human text goes to stderr. Errors: `{"schemaVersion":1,"error":{"code":"…","message":"…"}}`, exit 1. `schemaVersion` is `1` everywhere.
- Secrets never appear in argv, logs, error messages or test fixtures. Tokens travel over stdin (`add-token -`) or the keychain.
- Nothing under `~/.claude-swap-backup/` is ever read. cswap's data comes in only through its `export` envelope.
- Network is never performed while a Claude Code lock is held (`claude_locks.py` docstring).
- Every commit ends with `Co-Authored-By: Claude Code <noreply@anthropic.com>`.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` green before every commit.
- Rust edition 2021. No `unsafe`. No async runtime (blocking `ureq`, threads where needed).
- Timestamps in JSON are RFC 3339 UTC with `Z`. Internal clocks are `f64` epoch seconds injected through a `Clock` fn so tests are deterministic.

---

### Task 1: Crate scaffold, output envelope, `version` and `doctor`

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/output.rs`, `src/errors.rs`, `src/paths.rs`
- Test: `tests/cli_basics.rs`

**Interfaces:**
- Produces: `output::emit_json<T: Serialize>(value: &T)`, `output::emit_error(err: &SwapdError)`, `errors::SwapdError { code: ErrorCode, message: String }`, `ErrorCode` enum with `as_str()` (`no-such-slot`, `provider-not-installed`, `keychain-unavailable`, `refresh-denied`, `token-dead`, `locked`, `unsupported`, `io`, `http`, `invalid-input`), `paths::Home` (data dir resolution).

- [ ] **Step 1: Cargo.toml**

```toml
[package]
name = "swapd"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"
description = "Multi-provider account switcher for AI coding CLIs"
license = "MIT"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ureq = { version = "3", default-features = false, features = ["rustls", "json"] }
keyring = { version = "3", features = ["apple-native", "windows-native", "sync-secret-service"] }
sha2 = "0.10"
hex = "0.4"
time = { version = "0.3", features = ["formatting", "parsing", "macros"] }
thiserror = "2"
fd-lock = "4"
rand = "0.8"

[dev-dependencies]
assert_cmd = "2"
httpmock = "0.7"
tempfile = "3"
insta = { version = "1", features = ["json"] }
predicates = "3"
```

- [ ] **Step 2: errors.rs**

```rust
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    NoSuchSlot, ProviderNotInstalled, KeychainUnavailable, RefreshDenied,
    TokenDead, Locked, Unsupported, Io, Http, InvalidInput,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SwapdError { pub code: ErrorCode, pub message: String }

impl SwapdError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self { Self { code, message: message.into() } }
}
impl From<std::io::Error> for SwapdError {
    fn from(e: std::io::Error) -> Self { Self::new(ErrorCode::Io, e.to_string()) }
}
impl From<serde_json::Error> for SwapdError {
    fn from(e: serde_json::Error) -> Self { Self::new(ErrorCode::InvalidInput, e.to_string()) }
}
pub type Result<T> = std::result::Result<T, SwapdError>;
```

- [ ] **Step 3: output.rs**

```rust
use serde::Serialize;
use crate::errors::SwapdError;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct ErrorEnvelope<'a> { #[serde(rename = "schemaVersion")] schema_version: u32, error: ErrorBody<'a> }
#[derive(Serialize)]
struct ErrorBody<'a> { code: &'a crate::errors::ErrorCode, message: &'a str }

pub fn emit_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string(value).expect("serializable"));
}

pub fn emit_error(err: &SwapdError, json: bool) {
    if json {
        emit_json(&ErrorEnvelope { schema_version: SCHEMA_VERSION,
            error: ErrorBody { code: &err.code, message: &err.message } });
    } else {
        eprintln!("Error: {}", err.message);
    }
}
```

- [ ] **Step 4: paths.rs** — data dir: `$SWAPD_HOME` if set; else macOS `~/.swapd`, Linux `${XDG_DATA_HOME:-~/.local/share}/swapd`, Windows `%APPDATA%\swapd`. Provide `Home { root: PathBuf }` with `slots_file()`, `usage_file()`, `settings_file()`, `history_file()`, `auto_state_file()`, `credentials_dir()`, `profiles_dir()`, `log_file()`, `ensure()` (mkdir -p, 0700 on unix).

- [ ] **Step 5: main.rs** with clap: global `--json`, `--provider <name>` (default `claude`); subcommands `version`, `doctor` (this task), the rest added by later tasks as `todo!()`-free stubs that return `ErrorCode::Unsupported` until implemented. `version --json` → `{"schemaVersion":1,"version":"0.1.0"}`. `doctor --json` → `{"schemaVersion":1,"home":"…","providers":[{"provider":"claude","installed":bool,"path":"…"}]}` where installed = `claude` found on PATH or in `~/.claude/local/claude`, `~/.local/bin/claude`, `/opt/homebrew/bin/claude`, `/usr/local/bin/claude`.

- [ ] **Step 6: tests/cli_basics.rs**

```rust
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_json_has_schema_and_version() {
    let out = Command::cargo_bin("swapd").unwrap().args(["version", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn unknown_verb_is_a_json_error_with_exit_1() {
    Command::cargo_bin("swapd").unwrap().args(["frobnicate", "--json"])
        .assert().failure();
}

#[test]
fn doctor_reports_home_under_swapd_home() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("swapd").unwrap().env("SWAPD_HOME", tmp.path())
        .args(["doctor", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["home"], tmp.path().to_str().unwrap());
    assert!(v["providers"].as_array().unwrap().iter().any(|p| p["provider"] == "claude"));
}
```

- [ ] **Step 7:** `cargo test` → 3 pass. `cargo fmt`, `cargo clippy -- -D warnings`.
- [ ] **Step 8: Commit** `scaffold: crate, JSON envelope, version + doctor`.

---

### Task 2: Store primitives — atomic JSON files, file lock, slots

**Files:**
- Create: `src/core/mod.rs`, `src/core/store.rs`, `src/core/slots.rs`
- Test: unit tests in each file (temp `SWAPD_HOME`)

**Interfaces:**
- Produces: `store::read_json<T: DeserializeOwned + Default>(path) -> Result<T>` (missing file → default), `store::write_json_atomic<T: Serialize>(path, &T)` (tmp + rename, 0600 on unix), `store::FileLock::acquire(path, timeout: Duration) -> Result<FileLock>` (fd-lock on `<path>.lock`, `ErrorCode::Locked` on timeout), `slots::SlotsFile`, `slots::Slot`, `slots::ProviderSlots`.

- [ ] **Step 1: slots model** (`slots.json`)

```rust
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SlotsFile { pub schema_version: u32, #[serde(default)] pub providers: BTreeMap<String, ProviderSlots> }

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSlots {
    pub active_slot: Option<u32>,
    #[serde(default)] pub order: Vec<u32>,          // rotation order, every slot once
    #[serde(default)] pub slots: BTreeMap<u32, Slot>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slot {
    pub email: String,
    #[serde(default)] pub organization_uuid: String,
    #[serde(default)] pub organization_name: String,
    #[serde(default)] pub plan: Option<String>,
    #[serde(default)] pub alias: Option<String>,
    #[serde(default)] pub icon: Option<String>,
    #[serde(default)] pub disabled: bool,
    #[serde(default)] pub preferred: bool,
    #[serde(default)] pub added: Option<String>,     // RFC 3339
    #[serde(default)] pub fingerprint: Option<String>, // "sha256:…" of the stored login
}

impl ProviderSlots {
    pub fn next_free(&self) -> u32 { (1..).find(|n| !self.slots.contains_key(n)).unwrap() }
    pub fn resolve(&self, ident: &str) -> Option<u32> {
        // number, then exact email (case-insensitive), then alias
        if let Ok(n) = ident.parse::<u32>() { return self.slots.contains_key(&n).then_some(n); }
        let l = ident.to_lowercase();
        self.slots.iter().find(|(_, s)| s.email.to_lowercase() == l).map(|(n, _)| *n)
            .or_else(|| self.slots.iter().find(|(_, s)| s.alias.as_deref().map(|a| a.to_lowercase()) == Some(l.clone())).map(|(n, _)| *n))
    }
    pub fn insert(&mut self, n: u32, slot: Slot) { self.slots.insert(n, slot); if !self.order.contains(&n) { self.order.push(n); } }
    pub fn remove(&mut self, n: u32) { self.slots.remove(&n); self.order.retain(|x| *x != n); if self.active_slot == Some(n) { self.active_slot = None; } }
}
```

- [ ] **Step 2: tests** — `next_free_skips_taken`, `resolve_by_number_email_alias`, `write_then_read_roundtrip` (temp dir), `write_is_atomic_leaves_no_tmp`, `file_lock_times_out_with_locked_code` (spawn a thread holding the lock; second acquire with 100 ms timeout → `ErrorCode::Locked`).
- [ ] **Step 3:** run, green, fmt, clippy.
- [ ] **Step 4: Commit** `core: atomic JSON store, file lock, slots model`.

---

### Task 3: Secrets — keyring, file fallback, in-memory fake

**Files:**
- Create: `src/secrets.rs`
- Test: unit tests (fake + file backends; keyring backend is exercised only by an `#[ignore]` test run by hand on macOS)

**Interfaces:**
- Produces:

```rust
pub trait Secrets: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}
pub struct KeyringSecrets;                       // service "swapd", account = key
pub struct FileSecrets { dir: PathBuf }          // <credentials_dir>/<key with ':' → '_'>, mode 0600
pub struct MemorySecrets(Mutex<HashMap<String,String>>);
pub struct StickySecrets { primary: Box<dyn Secrets>, fallback: Box<dyn Secrets>, degraded: AtomicBool }
pub fn default_secrets(home: &Home) -> Box<dyn Secrets>; // macOS/Windows: Sticky(Keyring, File); Linux: Sticky(Keyring, File) too
pub fn slot_key(provider: &str, slot: u32) -> String { format!("{provider}:{slot}") }
```

- `StickySecrets`: after the primary fails once with a backend error, every later call in this process goes to the fallback (port of the sticky per-process fallback, `credentials.py:126-140`). A `None` from the primary is not a failure.

- [ ] **Step 1:** implement; `KeyringSecrets` maps `keyring::Error::NoEntry` → `Ok(None)`, other errors → `ErrorCode::KeychainUnavailable`.
- [ ] **Step 2: tests** — `memory_roundtrip`, `file_backend_writes_0600` (unix), `sticky_falls_back_after_primary_error` (a `FailingSecrets` fake that errors on every call), `sticky_stays_on_fallback_for_process_lifetime`.
- [ ] **Step 3:** green, fmt, clippy. **Commit** `secrets: keyring + 0600 file fallback, sticky degrade`.

---

### Task 4: Contract types for `list --json`

**Files:**
- Create: `src/contract.rs`
- Test: `tests/snapshots/contract__list_payload.snap` via insta

**Interfaces:**
- Produces (all `Serialize`, camelCase, `skip_serializing_if = "Option::is_none"` on every Option):

```rust
pub struct ListPayload { pub schema_version: u32, pub providers: Vec<ProviderView> }
pub struct ProviderView { pub provider: String, pub installed: bool, pub active_slot: Option<u32>,
    pub next_candidate: Option<u32>, pub next_recovery: Option<NextRecovery>, pub accounts: Vec<AccountView> }
pub struct NextRecovery { pub slot: u32, pub at: String }
pub struct AccountView { pub slot: u32, pub email: String, pub organization_name: String,
    pub organization_uuid: String, pub plan: Option<String>, pub alias: Option<String>, pub icon: Option<String>,
    pub active: bool, pub disabled: bool, pub preferred: bool, pub usage_status: UsageStatus,
    pub fetched_at: Option<String>, pub age_seconds: Option<f64>, pub windows: Vec<Window>,
    pub last_good: Option<LastGood> }
pub struct LastGood { pub fetched_at: String, pub age_seconds: f64, pub windows: Vec<Window> }
#[serde(rename_all = "kebab-case")]
pub enum UsageStatus { Ok, Stale, ReloginRequired, TokenExpired, NoCredentials, ApiKey, Unsupported }
pub struct Window { pub kind: WindowKind, pub name: Option<String>, pub pct: f64, pub resets_at: Option<String>,
    pub pace: Option<Pace>, pub used: Option<f64>, pub limit: Option<f64>, pub currency: Option<String> }
#[serde(rename_all = "lowercase")]
pub enum WindowKind { #[serde(rename="5h")] FiveHour, #[serde(rename="7d")] SevenDay, Daily, Monthly, Scoped, Spend }
pub struct Pace { pub expected_pct: f64, pub ahead: bool, pub exhausts_at: Option<String>, pub lasts_to_reset: bool }
```

- [ ] **Step 1:** write the types and one `insta::assert_json_snapshot!` test building the example payload from spec §4 verbatim (slot 1 with 5h, 7d+pace, scoped Fable). Run `cargo insta review`/accept.
- [ ] **Step 2: Commit** `contract: list payload types + snapshot`.

---

### Task 5: Driver trait, registry, `Login`, HTTP client

**Files:**
- Create: `src/driver/mod.rs`, `src/http.rs`
- Test: unit tests in `driver/mod.rs`

**Interfaces:**
- Produces:

```rust
pub struct Login { pub bytes: String }             // the CLI's credential blob, opaque to core
impl Login { pub fn fingerprint(&self) -> String }  // port of oauth.py:40-58: sha256 of claudeAiOauth.refreshToken → "sha256:<hex>", else "sha256-full:<hex>" of bytes; empty → "" 
pub struct Identity { pub email: String, pub organization_uuid: String, pub organization_name: String, pub plan: Option<String>, pub uuid: Option<String> }
pub struct Usage { pub windows: Vec<crate::contract::Window>, pub fetched_at: f64 }
#[derive(Debug, thiserror::Error)]
pub enum DriverError { NotInstalled, NoLogin, TokenDead, Throttled { retry_after: Option<f64> }, Locked(String), Io(#[from] std::io::Error), Http(String), Unsupported(&'static str), Invalid(String) }
pub struct Env { pub home: PathBuf, pub vars: HashMap<String,String> } // vars = process env at startup
pub struct RunProfile { pub env: Vec<(String,String)>, pub dir: PathBuf, cleanup: Option<Box<dyn FnOnce()>> } // Drop runs cleanup
bitflags-free Caps { pub ignite: bool, pub add_token: bool, pub prefer: bool, pub refresh: bool, pub run: bool }
pub trait Driver: Send + Sync { /* exactly the spec §5 trait: ignite(&self, env, slot, login), run_profile(&self, env, slot, login) */ }
pub fn registry() -> Vec<Box<dyn Driver>>;          // phase 1: [claude]
pub fn by_id(id: &str) -> Option<Box<dyn Driver>>;
```

- `http.rs`: `pub fn agent(timeout_s: u64) -> ureq::Agent` with `User-Agent: swapd/0.1`; `pub fn base_url(name: &str) -> String` reading `SWAPD_URL_<NAME>` env override (tests point `SWAPD_URL_ANTHROPIC_API`, `SWAPD_URL_PLATFORM` at httpmock).

- [ ] **Step 1:** implement; tests `fingerprint_uses_refresh_token_when_present`, `fingerprint_full_hash_for_api_key`, `fingerprint_empty_for_empty`.
- [ ] **Step 2: Commit** `driver: trait, Login fingerprint, registry, http agent`.

---

### Task 6: Claude driver A — paths, keychain item, config, locks, read/write live

**Files:**
- Create: `src/driver/claude/mod.rs`, `src/driver/claude/paths.rs`, `src/driver/claude/locks.rs`, `src/driver/claude/live.rs`
- Test: unit tests with a temp HOME and a `FakeSecurity` (the `security` CLI is behind a trait)

**Port verbatim from:** `session.py:232-243` (service name), `credentials.py:69-140` (service order, retries, sticky fallback), `claude_locks.py` (whole file), `switcher.py:739-760` + `credentials.py` `shared_credential_fields` / `merge_shared_credential_fields` (find with `grep -n "def shared_credential_fields\|def merge_shared_credential_fields\|SHARED_CREDENTIAL_KEYS" ~/death/claude-swap/src/claude_swap/*.py`).

- [ ] **Step 1: paths.rs**

```rust
pub fn config_home(env: &Env) -> PathBuf            // $CLAUDE_CONFIG_DIR or ~/.claude
pub fn config_json(env: &Env) -> PathBuf            // ~/.claude.json (sibling of config home's parent when default; cswap paths.py get_global_config_path — read it)
pub fn keychain_service_name(config_dir: &str) -> String {
    // NFC-normalize the raw string, sha256, first 8 hex chars
    let digest = Sha256::digest(config_dir.nfc().collect::<String>().as_bytes());
    format!("Claude Code-credentials-{}", &hex::encode(digest)[..8])
}
pub const DEFAULT_SERVICE: &str = "Claude Code-credentials";
pub fn live_services(env: &Env) -> Vec<String>       // exact port of credentials.py:69-107 (CLAUDE_SECURESTORAGE_CONFIG_DIR rules, default-profile fallback)
pub fn credentials_file(env: &Env) -> PathBuf        // <config_home>/.credentials.json (non-macOS live store)
```
Add `unicode-normalization = "0.1"` to Cargo.toml for `.nfc()`.

- [ ] **Step 2: locks.rs** — port `claude_locks.py`: `proper_lockfile(dir, staleness_s, timeout_s)` = mkdir mutex on `<path>.lock` directory with an mtime toucher thread every 3 s, steal only when mtime older than staleness; `CREDENTIALS_STALENESS_S = 60.0`, `CONFIG_STALENESS_S = 10.0`, `TOUCH_INTERVAL_S = 3.0`, per-lock wait budget 9 s with 1–2 s jittered sleeps; `credentials_lock(env)` takes `<config_home>/.oauth_refresh.lock` then `<config_home>.lock` in that order and releases in reverse; `config_lock(env)` takes `<config_json>.lock`. Return a guard whose `Drop` stops the toucher and removes the directory. Timeout → `DriverError::Locked("claude code holds <path>")`.
  Tests: `acquire_creates_dir_and_drop_removes_it`, `fresh_lock_is_not_stolen` (pre-create dir with mtime now → acquire with 300 ms timeout fails Locked), `stale_lock_is_stolen` (pre-create dir, set mtime 120 s ago → acquire succeeds).

- [ ] **Step 3: live.rs** — the `security` CLI behind `trait SecurityCli { fn find(&self, service: &str) -> Result<Option<String>, DriverError>; fn add(&self, service: &str, account: &str, value: &str) -> …; fn delete(…) }` with `RealSecurity` (`/usr/bin/security find-generic-password -s <service> -w`, `add-generic-password -U -s <service> -a <user> -w <value>`) and `FakeSecurity` for tests. On non-macOS the live store is `credentials_file` (0600). `read_live(env)`: services in order, first hit wins, 2 attempts 300 ms apart on backend error (`_ACTIVE_READ_ATTEMPTS`), then `NoLogin`. `write_live(env, login)`: compose with `prepare_for_activation(target, live)` (shared keys from the live credential win, absence included — port `SHARED_CREDENTIAL_KEYS`), take `credentials_lock` and `config_lock`, write the keychain item (or file), splice `oauthAccount` into `~/.claude.json` (only that key; everything else preserved), release. `read_config_identity(env) -> Option<Identity>` from `~/.claude.json` `oauthAccount` (`emailAddress`, `organizationUuid`, `organizationName`; plan label from `switcher.py:5239` `_plan_label`).
  Tests: `read_live_tries_services_in_order`, `write_live_preserves_mcp_oauth_from_live`, `write_live_splices_only_oauth_account_into_config`, `write_live_refuses_when_lock_held`.

- [ ] **Step 4: Commit** `claude driver: keychain item, config splice, Claude Code lock handshake`.

---

### Task 7: Claude driver B — identity, refresh, usage → windows, ignite, run profile

**Files:**
- Create: `src/driver/claude/oauth.rs`, `src/driver/claude/usage.rs`, `src/driver/claude/run.rs`
- Test: httpmock tests in `tests/claude_driver.rs`; fixtures under `tests/fixtures/claude/` (scrubbed JSON: usage with five_hour/seven_day/extra_usage/limits; token refresh success; invalid_grant; profile)

**Port verbatim from:** `oauth.py:16-19` (constants), `oauth.py:130-200` (refresh + error classification), `oauth.py:240-300` (profile), `oauth.py:366-380` (usage request), `oauth.py:440-520` (usage → windows incl. `extra_usage` spend and `limits[].weekly_scoped`), `oauth.py` `relevant_windows` / `account_headroom` (grep), pace fields from `json_output.py:60-80` + the pace module it calls (`pace.py`).

- [ ] **Step 1: oauth.rs**

```rust
pub const BETA_HEADER: &str = "oauth-2025-04-20";
pub const EXPIRY_BUFFER_MS: i64 = 5 * 60 * 1000;
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub fn token_url() -> String   { format!("{}/v1/oauth/token", http::base_url("PLATFORM")) }        // default https://platform.claude.com
pub fn profile_url() -> String { format!("{}/api/oauth/profile", http::base_url("ANTHROPIC_API")) } // default https://api.anthropic.com
pub fn usage_url() -> String   { format!("{}/api/oauth/usage", http::base_url("ANTHROPIC_API")) }
pub fn access_token(login: &Login) -> Option<String>;       // claudeAiOauth.accessToken
pub fn is_expired(login: &Login, now_ms: i64) -> bool;      // expiresAt - buffer <= now
pub fn refresh(login: &Login) -> Result<Login, DriverError>; // POST {grant_type, refresh_token, client_id}; on 400/401/403 with body.error == "invalid_grant" → TokenDead; "invalid_client" → Http("invalid_client") (no strike); else Http (transient)
pub fn profile(access_token: &str) -> Option<Identity>;      // None on any failure (fail-open, as cswap)
```

- [ ] **Step 2: usage.rs** — `pub fn fetch(access_token) -> Result<serde_json::Value, DriverError>` (429 → `Throttled{retry_after}` parsing `Retry-After` seconds; timeout 5 s) and `pub fn windows(raw: &Value) -> Vec<Window>`: `five_hour.utilization` → `5h`, `seven_day` → `7d`, `extra_usage` (only when `is_enabled` and all three of `used_credits`, `monthly_limit`, `utilization` non-null; used/limit ÷ 100) → `spend`, each `limits[]` entry with `scope.model.display_name` and numeric `percent` → `scoped` with `name`. `resets_at` copied verbatim. `pub fn headroom(windows, models: &[String]) -> Option<f64>` and `pub fn relevant(windows, models) -> Vec<&Window>` (5h, 7d, plus scoped whose name matches case-insensitively, or all when models contains `"all"`; spend excluded). Pace: port `pace.py` (`expected_pct`, `ahead`, `exhausts_at`, `lasts_to_reset`) onto 7d and scoped windows when the week is ≥ 1 day old.

- [ ] **Step 3: run.rs** — `run_profile(env, slot, login) -> RunProfile`: dir `profiles/claude/<slot>` under `Home`; write the login to keychain service `keychain_service_name(dir)` (macOS) or `<dir>/.credentials.json`; copy `settings.json`, `CLAUDE.md`, `keybindings.json` and the `skills/ commands/ agents/` dirs from the real config home if present (cswap's default share set, `session.py` — read it); env = `CLAUDE_CONFIG_DIR=<dir>`; no cleanup (profiles persist). `ignite(env, slot, login)`: spawn `claude -p . --max-turns 1` with that env, PATH widened with the four candidate dirs from Task 1, stdout/stderr discarded, 120 s timeout; non-zero exit → `DriverError::Http(format!("igniter exited {code}"))`.

- [ ] **Step 4: mod.rs** — `impl Driver for Claude` wiring the above; `identity()` = config identity, else `profile()`; `usage()` = refresh first when `is_expired`, then fetch → windows; `capabilities()` all true.

- [ ] **Step 5: tests** (httpmock): `usage_maps_five_hour_seven_day_scoped_spend`, `usage_429_is_throttled_with_retry_after`, `refresh_invalid_grant_is_token_dead`, `refresh_invalid_client_is_not_token_dead`, `refresh_transient_on_500`, `profile_none_on_401`, `expired_login_is_refreshed_before_usage`.

- [ ] **Step 6: Commit** `claude driver: oauth refresh, usage windows, ignite, run profile`.

---

### Task 8: Usage store + poll policy

**Files:**
- Create: `src/core/usage_store.rs`, `src/core/poll_policy.rs`
- Test: unit tests with an injected clock

**Port verbatim from:** `poll_policy.py:60-330` (every constant and `plan_after_fetch`), `usage_store.py:54-120, 240-400, 1013-1120` (row fields, `fresh/in_backoff/recent_429/claimed/token_dead`, `reserve`, record success/failure, `AUTH_DEAD_STRIKES`, backoff schedule, `STALE_OK_S`).

- [ ] **Step 1: poll_policy.rs** — the constants exactly (`SERVE_TTL_S 180, MIN_INTERVAL_S 180, URGENT_INTERVAL_S 60, ACTIVE_MAX 300, CANDIDATE_DEFAULT 300, CANDIDATE_MAX 600, EXHAUSTED 600, MOVEMENT_DELTA_PCT 1.0, JITTER_FRAC 0.1, EDGE_BACKOFF_S 300, POST_429_MIN_INTERVAL_S 360, RECENT_429_WINDOW_S 3600, POST_429_BACKOFF_MULT 1.5, POST_429_MAX_INTERVAL_S 1800, ESCALATION_MARGIN_PCT 15, RESET_SLACK_S 60`) and

```rust
pub struct PlanInput<'a> { pub prev_interval_s: Option<f64>, pub prev: Option<&'a [Window]>, pub new: &'a [Window],
    pub is_active: bool, pub threshold: f64, pub models: &'a [String], pub recent_429: bool, pub now: f64 }
pub fn plan_after_fetch(i: PlanInput, rng: impl FnMut() -> f64) -> (f64 /*next_poll_at*/, f64 /*interval_s*/);
pub fn binding_pct(w: &[Window], models: &[String]) -> Option<f64>;
pub fn limiting_reset_ts(w, models) -> Option<f64>;
pub fn earliest_future_reset_ts(w, now, models) -> Option<f64>;
pub fn parse_reset_ts(s: Option<&str>) -> Option<f64>;   // RFC 3339, "Z" accepted
```
Tests (`rng` returns 0.5 so jitter is zero): `movement_halves_interval_floored_at_min`, `no_movement_backs_off_1_5x_to_ceiling`, `active_moving_near_threshold_is_urgent`, `recent_429_floors_at_360_and_grows_1_5x`, `exhausted_polls_every_600_capped_at_reset_plus_slack`, `next_poll_never_after_next_reset_plus_slack`.

- [ ] **Step 2: usage_store.rs** — `usage.json` `{schemaVersion:2, rows:{"<provider>:<slot>": Row}}`

```rust
pub struct Row { pub email: String, pub org: String, pub last_good: Option<Vec<Window>>, pub last_good_at: Option<f64>,
    pub fetched_at: Option<f64>, pub last_attempt_at: Option<f64>, pub last_error: Option<String>, pub backoff_until: Option<f64>,
    pub last_429_at: Option<f64>, pub next_poll_at: Option<f64>, pub interval_s: Option<f64>, pub claim_until: Option<f64>,
    pub claim_id: Option<String>, pub auth_dead_strikes: u32, pub dead_fingerprint: Option<String> }
pub struct UsageStore { path: PathBuf, clock: Box<dyn Fn() -> f64 + Send + Sync> }
pub struct Entry { /* read model: row + age_s + fresh()/in_backoff()/recent_429()/claimed()/token_dead() */ }
impl UsageStore {
    pub fn entries(&self, keys: &[(String /*key*/, String /*email*/, String /*org*/)]) -> BTreeMap<String, Entry>; // identity mismatch → fresh empty row
    pub fn reserve(&self, keys: &[String], respect_plans: bool, force: bool) -> Result<BTreeMap<String, String /*claim id*/>>; // under FileLock; force = refresh --slot (ignores fresh/plan, still honours backoff+dead)
    pub fn record_success(&self, key: &str, claim: &str, windows: Vec<Window>, is_active: bool, threshold: f64, models: &[String]) -> Result<()>; // fencing: only if claim matches; sets fetched_at, last_good, plan via plan_after_fetch, clears error/backoff/strikes
    pub fn record_failure(&self, key: &str, claim: &str, kind: &str, retry_after: Option<f64>) -> Result<()>; // "http-429": last_429_at, backoff = max(retry_after, EDGE_BACKOFF_S when retry_after == 0); other kinds: 30 s, 60 s, 120 s… capped 600 s
    pub fn record_token_dead(&self, key: &str, fingerprint: &str) -> Result<()>;   // strikes += 1 (AUTH_DEAD_STRIKES = 1 → dead at once)
    pub fn clear_dead(&self, key: &str) -> Result<()>;
}
pub const CLAIM_TTL_S: f64 = 90.0;
pub const STALE_OK_S: f64 = 15.0 * 60.0; // read it from usage_store.py and copy the real value
```
Tests: `reserve_skips_fresh_rows_when_respecting_plans`, `reserve_force_takes_fresh_row`, `reserve_never_double_claims_within_ttl`, `record_success_with_stale_claim_is_ignored`, `failure_429_backoff_uses_retry_after_and_edge_floor`, `token_dead_after_one_strike_blocks_reserve`, `identity_mismatch_yields_empty_row`.

- [ ] **Step 3: Commit** `core: usage store with claim leases, poll policy port`.

---

### Task 9: Collector — `list` and `refresh`

**Files:**
- Create: `src/core/collect.rs`, `src/cmd/list.rs`, `src/cmd/refresh.rs` (and `src/cmd/mod.rs`)
- Test: `tests/list_refresh.rs` (assert_cmd + httpmock + temp HOME + `SWAPD_SECRETS=file` env to force the file backend in tests)

**Interfaces:**
- Produces: `collect::collect(ctx: &Ctx, provider: &dyn Driver, opts: CollectOpts{ force_slots: Vec<u32>, all_stale: bool }) -> Result<ProviderView>`; `Ctx { home: Home, secrets: Box<dyn Secrets>, clock: Box<dyn Fn() -> f64>, settings: Settings, env: Env, store: UsageStore }` (built once in `main.rs` by `Ctx::from_env()`; `Settings` is a placeholder struct with the defaults until Task 11 fills it); `cmd::list::run(ctx, provider_filter: Option<&str>) -> Result<ListPayload>`; `cmd::refresh::run(ctx, provider, slot: Option<u32>) -> Result<ListPayload>`.

- [ ] **Step 1: collect()** in this order (port of `switcher.py:4745-4830` `_collect_usage_entries` and the fetch path `switcher.py:3940-4100`, read them):
  1. slots for the provider; the active slot = the one whose stored fingerprint equals the live login's fingerprint (read once via `driver.read_live`; `NoLogin` → none active).
  2. static sentinels: slot with no stored login → `NoCredentials`; API-key login (`claudeAiOauth` absent and value starts with `sk-ant-`) → `ApiKey` with no fetch.
  3. `store.entries` → dead token → `ReloginRequired` (no fetch).
  4. `reserve` (respect_plans = true unless `all_stale`; `force` for `force_slots`).
  5. for each claim, in parallel threads (max 4): login from secrets (active slot: the live login); if expired → `driver.refresh` (TokenDead → `record_token_dead`, status `ReloginRequired`; transient → `record_failure("refresh")`); write the refreshed login back to secrets (and to the live store for the active slot, under locks); `driver.usage` → `record_success` / `record_failure`.
  6. build `AccountView`s: `Ok` with `windows` when `fetched_at` within `STALE_OK_S`; `Stale` with `last_good` older; `TokenExpired` for an active slot whose login is expired and could not be refreshed this pass (port of the sentinel at `switcher.py:4810-4830`).
  7. `next_candidate` = the rotation's next healthy slot after the active one (skip disabled, dead, `binding_pct >= threshold`); `next_recovery` = the earliest `limiting_reset_ts` among exhausted slots.
- [ ] **Step 2: verbs** — `list [--provider]`, `refresh [--slot n]` (returns the list payload after the fetch).
- [ ] **Step 3: tests** — seed a temp HOME with `slots.json` (two slots) and file secrets holding two scrubbed logins; httpmock usage endpoint. `list_serves_from_store_within_serve_ttl` (two `list` calls → one usage request), `refresh_slot_bypasses_serve_ttl` (list, then `refresh --slot 1` → second request), `dead_token_is_relogin_required_and_not_fetched`, `stale_on_error_keeps_last_good` (mock 500 after one success → status `stale`, `lastGood` present), `windows_in_payload_match_snapshot` (insta).
- [ ] **Step 4: Commit** `list + refresh: collector with serve floor, forced refresh, stale-on-error`.

---

### Task 10: `add`, `add-token`, `import`, `switch`, `rotate`, `history`

**Files:**
- Create: `src/core/switch.rs`, `src/core/history.rs`, `src/core/import.rs`, `src/cmd/{add,add_token,import,switch,rotate,history}.rs`
- Test: `tests/switch.rs`, `tests/import.rs`

**Interfaces:**
- Produces: `switch::perform(ctx, driver, target: u32, trigger: &str) -> Result<SwitchResult { switched: bool, reason: Option<String>, from: Option<SlotRef>, to: SlotRef, warnings: Vec<String> }>` (Task 12's auto loop calls it), `switch::rank(ctx, view: &ProviderView, strategy: Strategy, preferred: &[String]) -> Vec<u32>`, `history::append(home, SwitchRecord)`, `import::run(ctx, path, force) -> ImportResult`.

**Port verbatim from:** `switcher.py:3332-3560` (add), `switcher.py:3562-3660` (add-token), `switcher.py:6690-6830` (switch), `switcher.py:6519-6560` (`_stash_live_credential`), `transfer.py:300-420` (import + cswap envelope), `autoswitch.py:2016-2250` (`_rank_candidates`) for `rotate`.

- [ ] **Step 1: add** — `driver.read_live` → identity (config, else profile) → slot: existing slot with same (email, org) refreshes in place, else `--slot n` or next free; store login in secrets, fingerprint, `added` now; returns `{"schemaVersion":1,"slot":n,"email":…,"created":bool}`. Errors: `NoLogin` → `no-credentials`.
- [ ] **Step 2: add-token -** — read stdin, trim; `sk-ant-…` API key → login bytes as-is; a `claudeAiOauth` JSON → validated; identity via `profile` for OAuth, `email = "<key-prefix>@token.local"` for API keys (cswap's convention, `switcher.py:3169`).
- [ ] **Step 3: import** — detects `{"format":"swapd/1"}` (own envelope, Task 11 writes it) or cswap's `{"version":…,"accounts":[…]}`; each account → slot by number (`--force` overwrites an occupied different-identity slot, else `invalid-input` "slot n holds …; --force"), login = `credentials` (object → JSON string; string → API key), alias, org fields, `activeSlot` only recorded, never activated. Result `{"imported":[slots],"skipped":[…]}`.
- [ ] **Step 4: switch <ident>** — resolve slot; refuse when target has no login (`no-credentials`) or is the active one (`{"switched":false,"reason":"already-active"}`); `driver.refresh` target if expired (network BEFORE locks); then under `store::FileLock(home/engine.lock)`: read live login; if live fingerprint matches a slot → write it back into that slot's secret (rotated token kept), else stash it as `unclaimed/<ts>` in secrets and report a warning; `driver.write_live(env, target)`; on error restore the previous live login and re-raise; set `active_slot`; `history.append(SwitchRecord{ts, from, to, trigger:"manual"})`; emit `{"switched":true,"from":{slot,email},"to":{slot,email},"warnings":[]}`.
- [ ] **Step 5: rotate [--strategy]** — collect (respect plans), rank candidates (port `_rank_candidates`: strategy `consume-first` = soonest 7d reset among healthy, preferred first; `best` = most headroom; `next-available` = rotation order, first healthy), then `switch`. `{"switched":false,"reason":"no-candidate"}` when none.
- [ ] **Step 6: history [--limit n]** — `history.jsonl` newest last; payload `{"schemaVersion":1,"switches":[{ts, from, to, trigger}]}`.
- [ ] **Step 7: tests** — `add_captures_live_login_into_next_free_slot`, `add_refreshes_existing_slot_in_place`, `add_token_api_key_gets_token_local_email`, `import_cswap_envelope_two_accounts`, `import_refuses_occupied_slot_without_force`, `switch_writes_target_and_backs_up_live_into_its_slot` (FakeSecurity), `switch_preserves_mcp_oauth_from_live`, `switch_restores_live_on_write_failure`, `rotate_consume_first_picks_soonest_weekly_reset`.
- [ ] **Step 8: Commit** `add, add-token, import, switch, rotate, history`.

---

### Task 11: `export`, `config`, `remove`, `alias`, `icon`, `prefer`, `hold/unhold`, `reorder`, `notify`

**Files:**
- Create: `src/core/settings.rs`, `src/cmd/{export,config,remove,alias,icon,prefer,hold,reorder,notify}.rs`
- Test: `tests/small_verbs.rs`

- [ ] **Step 1: settings.rs** — `settings.json` `{ "<provider>": { enabled: bool (true), threshold: f64 (99.9), intervalSeconds: 60, cooldownSeconds: 300, hysteresisPct: 10, strategy: "consume-first"|"best"|"next-available", preferred: Vec<String> (emails or slot numbers), model: Vec<String> (scoped window names), unhealthyTicks: 3 } }` with defaults from cswap `settings.py` (read it for the exact defaults). `config list --json` → `{"schemaVersion":1,"settings":[{key:"claude.threshold", value, isSet, default}]}`; `get/set/unset <key>` with type validation.
- [ ] **Step 2:** the small verbs, each returning the list payload (or `{"ok":true}` for `remove`). `export <path|-> [--slot n] [--full]` writes the swapd envelope from spec §9 (login bytes as the `credentials` field; `--full` adds the `~/.claude.json` snapshot as `config`). `notify` returns `{"slackWebhookUrl":null,"telegramBotToken":null,"telegramChatId":null}` — masked status only, sending is out of scope.
- [ ] **Step 3: tests** — one per verb, plus `export_then_import_roundtrip`.
- [ ] **Step 4: Commit** `settings + the small verbs + export`.

---

### Task 12: `auto --json` — the switching daemon

**Files:**
- Create: `src/core/auto.rs`, `src/core/events.rs`, `src/cmd/auto.rs`
- Test: `tests/auto.rs` (drive `AutoEngine::tick` directly with a fake driver and clock; one assert_cmd test for the stdin-EOF exit)

**Port verbatim from:** `autoswitch.py:296-600` (event classes and their JSON fields), `autoswitch.py:596-730` (window helpers), `autoswitch.py:730-1000` (state, quarantine, `_freshen_target`), `autoswitch.py:1000-1620` (`_tick_inner` — the decision), `autoswitch.py:2016-2250` (ranking), `autoswitch.py:2249-2400` (`_collect_scheduled_usage`, `_perform`).

- [ ] **Step 1: events.rs** — one enum `Event` serialised as `{"schemaVersion":1,"event":"<kind>","ts":"…","provider":"claude", …fields}` with kinds and fields exactly: `poll{active, headroomPct, threshold}`, `switch{trigger, from, to, warnings, dryRun}`, `no-switch{reason, detail}`, `account-quarantined{number, email, reason}`, `account-unquarantined{…}`, `all-exhausted{earliestResetAt}`, `sleep{seconds, until}`, `error{message, transient}`, `engine-refused{message}`, `config-warning{message}`. (`number` keeps cswap's name for the app's existing decoder; `slot` is added alongside.)
- [ ] **Step 2: auto.rs** — `AutoEngine { ctx, driver, state: AutoState (cooldownUntil, quarantined: {slot: {reason, since}}, leftAtLimit) persisted in auto-state.json, on_event }`, `tick() -> TickOutcome`: engine mutex (`home/engine.lock`, `engine-refused` when held by another auto), `_collect_scheduled_usage` (respect_plans=false), decision: active headroom vs threshold with hysteresis, cooldown for proactive/consume-first triggers, quarantine on TokenDead, `all-exhausted` with earliest reset, candidate ranking per strategy with `preferred` first, `_freshen_target` (refresh before switching), perform switch via Task 10's `switch::perform(ctx, target, trigger)`. Loop: `sleep` event between ticks (`intervalSeconds`), `SWAPD_SUPERVISED=1` → a thread reads stdin and exits the process on EOF.
- [ ] **Step 3: tests** — `below_threshold_polls_and_no_switch`, `at_threshold_switches_to_ranked_candidate`, `cooldown_blocks_proactive_switch`, `dead_target_is_quarantined_and_skipped`, `all_exhausted_emits_earliest_reset`, `second_auto_is_refused`, `supervised_exits_on_stdin_eof` (assert_cmd, pipe closed → exit 0 within 2 s).
- [ ] **Step 4: Commit** `auto: switching daemon with NDJSON events`.

---

### Task 13: `ignite` and `run`

**Files:**
- Create: `src/cmd/ignite.rs`, `src/cmd/run.rs`
- Test: `tests/ignite.rs` with a fake `claude` script on PATH (`SWAPD_CLAUDE_CLI` env override in the driver's `installed()`)

- [ ] **Step 1: ignite <slot>** — login from secrets (refresh if expired); `driver.ignite`; then `collect` with `force_slots=[slot]`; return the list payload plus `"ignited": {slot, at}`. Error when the driver isn't installed → `provider-not-installed`.
- [ ] **Step 2: run <slot> -- <args>** — `driver.run_profile`; exec the CLI with that env, inheriting stdio; propagate exit code. No `--json`.
- [ ] **Step 3: tests** — `ignite_runs_igniter_then_forces_refresh` (fake claude records its args and `CLAUDE_CONFIG_DIR`; usage mock hit after), `ignite_without_cli_is_provider_not_installed`.
- [ ] **Step 4: Commit** `ignite + run`.

---

### Task 14: CI and release workflow

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `rustfmt.toml` (defaults), `CHANGELOG.md`

- [ ] **Step 1: ci.yml** — on push/PR: matrix `macos-14`, `ubuntu-24.04`, `windows-2022`; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- [ ] **Step 2: release.yml** — on tag `v*`: build `--release` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (cross via `cross`), `x86_64-pc-windows-msvc`; upload `swapd-<target>.tar.gz|zip` + `sha256` to the GitHub release; body from CHANGELOG's top section.
- [ ] **Step 3: Commit** `ci: fmt, clippy, test matrix; release binaries`.

---

### Task 15: Infinitus adapter (in `~/death/limitless`, stream branch `swapd-engine`)

**Files:**
- Create: `Sources/InfinitusCore/Engines/Swapd/SwapdCLI.swift`, `SwapdEngine.swift`, `SwapdMapping.swift`, `Tests/InfinitusCoreTests/SwapdEngineTests.swift`, `Tests/InfinitusCoreTests/Fixtures/swapd-list.json`
- Modify: `Sources/InfinitusCore/AccountEngine.swift` (capability `refreshAccount`, protocol method `refresh(fleet:number:)` with a default `unsupported`), `Sources/InfinitusCore/Models.swift` (`Account.windows: [UsageWindow]?` additive), `Sources/Infinitus/EngineRegistry.swift`, `Sources/Infinitus/EnginesPane.swift` (row: "swapd" toggle + binary path), `Sources/Infinitus/AppModel.swift` (`ignite` uses `engine.ignite` then `engine.refresh` when capable; the "resets" text from the returned fleet), `tools/e2e.sh` (`swapd` stub), CHANGELOG, README, `site/public/index.html`.

**Interfaces:**
- Consumes: `swapd list --json` (spec §4), `refresh --slot`, `switch`, `rotate`, `reorder`, `hold/unhold`, `alias`, `prefer`, `add`, `add-token -`, `remove --yes`, `import`, `ignite`, `history`, `notify`, `version`, `auto --json` (`SWAPD_SUPERVISED=1`).
- Produces: `SwapdEngine: AccountEngine` yielding one `EngineFleet` per provider (`Provider(rawValue:)`, unknown → `.other`), `capabilities = .all + .refreshAccount`.

- [ ] **Step 1: SwapdMapping (pure)** — `ListPayload` Codable mirror of spec §4; `func fleet(from provider: ProviderView) -> EngineFleet` mapping `windows` to `Usage.fiveHour/sevenDay/scoped/spend` for today's UI and phone (kind `5h` → fiveHour, `7d` → sevenDay, `scoped` → scoped[], `spend` → spend), `usageStatus` strings mapped to cswap's (`ok`, `stale` → ok with `lastGoodUsage`, `relogin-required`, `token-expired`, `no-credentials`, `api-key`), `slot` → `number`. Fixture test with `swapd-list.json` = spec §4 example.
- [ ] **Step 2: SwapdCLI** — same `run(_:stdin:environment:)` shape as `CswapCLI`; binary lookup `INFINITUS_SWAPD_CLI` → `/opt/homebrew/bin/swapd`, `/usr/local/bin/swapd`, `~/.cargo/bin/swapd`, `~/.local/bin/swapd`; every verb with `--json`; errors decode the envelope's `error.message`.
- [ ] **Step 3: SwapdEngine + supervisor** — `snapshot()` = one `list`; `refresh(fleet:number:)` = `refresh --slot`; `ignite` = `ignite <slot>`; supervisor = `CswapSupervisor` generalised with an `environmentFlag` parameter (`CSWAP_SUPERVISED` / `SWAPD_SUPERVISED`) and `arguments`; `EventFeed` unchanged (`provider` rides in `raw`).
- [ ] **Step 4: registry + pane + AppModel.ignite** — Engines pane row "swapd (preview)"; `ignite` path: `engine.ignite` → `engine.refresh` (when `.refreshAccount`) → publish the returned fleet → event text from the fresh `resetsAt`, fallback now+5h only when the engine cannot refresh.
- [ ] **Step 5: e2e stub** — `$SOCKDIR/swapd` shell script answering `version`, `doctor`, `list --json` (fixture), `refresh --slot n` (fixture with `resetsAt` filled), `ignite n`, `auto --json` (prints one `poll` line then sleeps until stdin EOF); e2e block: enable swapd, `infinitusctl ignite claude 1`, assert the reply carries the reset from the refresh fixture.
- [ ] **Step 6:** `swift build`, `swift test --filter Swapd`, `tools/e2e.sh` (with `INFINITUS_CONTROL_SOCKET=/tmp/swpd.sock`) → E2E PASS, idle CPU unchanged. CHANGELOG one line under Unreleased › Mac: "swapd engine (preview): the app can run the new multi-provider engine beside cswap; ignite refreshes the account at once."
- [ ] **Step 7: Commit** on `swapd-engine`, push, hand off "merge swapd-engine at <sha> — --squash".

---

### Task 16: Parity check on this Mac + docs

**Files:**
- Create: `tools/parity.py` (this repo), `README.md` sections (install, verbs, JSON, data locations, migration from cswap)

- [ ] **Step 1: parity.py** — runs `cswap export - ` is NOT used (the user runs `cswap export ~/swapd-import.json` by hand); the script runs `swapd import ~/swapd-import.json`, then `swapd list --json --provider claude` and `cswap list --json`, maps the swapd payload back to cswap's shape (slot→number, windows→fiveHour/sevenDay/scoped), and diffs `pct` (±1), `resetsAt`, `active`, `alias`, `usageStatus` per account; prints a table; exit 1 on a mismatch.
- [ ] **Step 2: README** — install (`cargo install --git`, release binaries), every verb, JSON contract summary linking the spec, data locations, "migrate from cswap" (export → import → set the app's Engines pane), isolation note for Infinitus.
- [ ] **Step 3: Commit** `parity script + README`; tag nothing yet — the week of parity starts when the user runs the import.
