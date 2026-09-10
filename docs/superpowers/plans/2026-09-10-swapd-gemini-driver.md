# swapd Gemini driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `swapd` manages Gemini CLI accounts (provider id `gemini`) through the same `Driver` trait and verbs the Claude driver uses: list, add, switch, refresh, ignite, run, auto.

**Architecture:** A new `src/driver/gemini/` module implements `Driver` over a plaintext file pair (`oauth_creds.json` + `google_accounts.json`) under `$GEMINI_CLI_HOME/.gemini` (or the OS home), fenced by a swapd-owned mkdir lock. Refresh and usage are two HTTPS endpoints (Google OAuth, cloudcode-pa); the igniter is the usage call. Run profiles are per-slot `GEMINI_CLI_HOME` directories. Core changes are minimal: the fingerprint honours the Gemini envelope key, the registry gains the driver, `doctor` iterates the registry.

**Tech Stack:** Rust 2021, `ureq` 3 (rustls), `serde_json`, `httpmock` 0.7 (tests), `tempfile`, `assert_cmd`. New dependency: `base64 = "0.22"` (id_token payload decoding).

**Spec:** `docs/superpowers/specs/2026-09-10-swapd-gemini-driver-design.md` (approved 2026-09-10), over `docs/superpowers/specs/2026-09-09-swapd-design.md` §5 (the `Driver` trait) and §13 (phase-1 rulings).

## Global Constraints

- Every fact about the CLI is pinned to `google-gemini/gemini-cli` tag `v0.46.0` = commit `85b0c55c126a4992b51d140e357ae9db5f9c2d7f`. Raw source: `https://raw.githubusercontent.com/google-gemini/gemini-cli/85b0c55c126a4992b51d140e357ae9db5f9c2d7f/<path>`.
- Tests never touch the real `~/.gemini`, `~/.claude*`, `~/.swapd`, the keychain, the real `gemini`/`claude` binaries or the network. Every path comes from a `TempDir`; every variable from `Env.vars` (`env_with`) or `Command::env`; HTTP goes to an `httpmock` server through `SWAPD_URL_GOOGLE_OAUTH` / `SWAPD_URL_CLOUDCODE`. Never `std::env::set_var` in tests.
- The OAuth client id and client secret are copied verbatim from `packages/core/src/code_assist/oauth2.ts` lines 76–85 at the pinned commit into `const`s; they are never logged, never part of an error message, never in a report or a commit message body. No error ever carries a token or a response body.
- Login bytes are an envelope swapd owns: `{"oauth_creds": <the file's JSON object>, "google_account": <email string or null>}`.
- Gates on every task, run from the worktree: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings`, `cargo test`. Windows compiles must not be broken (`Path::join`, no `/` string paths, `.cmd` stubs where a test spawns a script).
- Commit messages: one line, lower-case subject naming the behaviour, trailers `Co-Authored-By: Claude Code <noreply@anthropic.com>` and `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- CHANGELOG: one line per feature under `## Unreleased`, the same section the existing entries use.
- No `unwrap` outside tests; `DriverError` variants as the spec maps them (`NoLogin`, `Invalid`, `Locked`, `NeedsRefresh`, `TokenDead`, `Throttled { retry_after }`, `Http`, `Unsupported`, `Io`).

## File structure

| file | responsibility |
|---|---|
| `src/driver/mod.rs` | `Login::fingerprint` envelope keys; registry + `provider_ids` gain `gemini` |
| `src/driver/marker.rs` (new) | the `.swapd-seeded` marker helpers shared by both drivers' run profiles |
| `src/driver/claude/run.rs` | uses `driver::marker` instead of its private copies |
| `src/driver/gemini/mod.rs` (new) | `GeminiDriver`, `impl Driver` seam |
| `src/driver/gemini/paths.rs` (new) | home resolution, the two file paths, the lock path, the CLI resolver |
| `src/driver/gemini/live.rs` (new) | read/write the file pair, envelope, lock, settings check |
| `src/driver/gemini/identity.rs` (new) | identity from the pointer file or the id_token, `expires_at` |
| `src/driver/gemini/oauth.rs` (new) | `GeminiEndpoints`, refresh |
| `src/driver/gemini/usage.rs` (new) | `loadCodeAssist` project lookup (memoised), `retrieveUserQuota`, bucket → windows |
| `src/driver/gemini/run.rs` (new) | run profile, read-back, ignite, commit/forget profile |
| `src/driver/gemini/fixtures/*.json` (new) | synthetic response and file shapes |
| `src/driver/gemini/tests.rs` (new) | shared test helpers |
| `src/http.rs` | two default base URLs |
| `src/main.rs` | `doctor` iterates the registry, per-provider note |
| `tests/gemini.rs` (new) | end-to-end verbs over a temp `GEMINI_CLI_HOME` |
| `Cargo.toml`, `CHANGELOG.md` | dependency, release note |

---

### Task 1: The fingerprint honours the Gemini envelope

**Files:**
- Modify: `src/driver/mod.rs:15-42` (`Login::fingerprint`)
- Modify: `docs/superpowers/specs/2026-09-10-swapd-gemini-driver-design.md` §4 (amend the "move into the driver" paragraph)

**Interfaces:**
- Consumes: nothing.
- Produces: `Login::fingerprint(&self) -> String` unchanged in signature; a Gemini envelope `{"oauth_creds":{"refresh_token":"r"}}` fingerprints to `"sha256:" + hex(sha256("r"))`, stable across access-token-only refreshes.

Ruling (controller, 2026-09-10): the spec proposed moving the fingerprint into `Driver` (27 call sites, 11 files). Both envelopes are swapd's OWN formats, so core reading swapd's own envelope keys is not "core parsing provider tokens"; an ordered key list gives identical behaviour with a three-line change. The spec is amended in this task.

- [ ] **Step 1: Write the failing tests** in `src/driver/mod.rs`'s existing `mod tests` (next to `fingerprint_uses_refresh_token_when_present`):

```rust
    #[test]
    fn fingerprint_uses_the_gemini_envelope_refresh_token() {
        let login = Login {
            bytes: r#"{"oauth_creds":{"access_token":"a1","refresh_token":"r-gem","expiry_date":1},"google_account":"you@example.com"}"#.to_string(),
        };
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(b"r-gem")));
        assert_eq!(login.fingerprint(), expected);
        // An access-token-only refresh keeps the fingerprint.
        let rotated = Login {
            bytes: r#"{"oauth_creds":{"access_token":"a2","refresh_token":"r-gem","expiry_date":2},"google_account":"you@example.com"}"#.to_string(),
        };
        assert_eq!(rotated.fingerprint(), expected);
    }

    #[test]
    fn fingerprint_of_a_gemini_envelope_without_a_refresh_token_is_the_full_hash() {
        let login = Login {
            bytes: r#"{"oauth_creds":{"access_token":"a1"},"google_account":null}"#.to_string(),
        };
        assert!(login.fingerprint().starts_with("sha256-full:"));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test driver::tests::fingerprint_uses_the_gemini`
Expected: FAIL — the first assertion gets a `sha256-full:` value.

- [ ] **Step 3: Implement**

Replace the body of `Login::fingerprint` with:

```rust
    /// The refresh token's sha256 when the envelope carries one, else the
    /// sha256 of the raw bytes; empty bytes fingerprint to "".
    ///
    /// Both pointers name keys of envelopes swapd itself writes (the Claude
    /// envelope is Claude Code's blob plus `oauthAccount`; the Gemini envelope
    /// is `{oauth_creds, google_account}`), so this is core reading its own
    /// format, not a provider's token. A refresh token is the one member that
    /// survives an access-token refresh, which is what makes it the identity
    /// of a stored login across generations.
    pub fn fingerprint(&self) -> String {
        const REFRESH_TOKEN_POINTERS: [&str; 2] =
            ["/claudeAiOauth/refreshToken", "/oauth_creds/refresh_token"];
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&self.bytes) {
            for pointer in REFRESH_TOKEN_POINTERS {
                if let Some(token) = value.pointer(pointer).and_then(|v| v.as_str()) {
                    if !token.is_empty() {
                        return format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())));
                    }
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
```

- [ ] **Step 4: Run the tests**

Run: `cargo test driver::tests`
Expected: PASS, every pre-existing fingerprint test still green.

- [ ] **Step 5: Amend the spec** — in the sub-spec's §4 replace the paragraph beginning "**Fingerprint.** `Login::fingerprint` (driver/mod.rs:23) is Claude-shaped" with:

```
**Fingerprint.** `Login::fingerprint` reads the refresh token through an
ordered list of envelope pointers (`/claudeAiOauth/refreshToken`, then
`/oauth_creds/refresh_token`), so a Gemini envelope keeps its fingerprint
across access-token refreshes. Both envelopes are swapd's own formats, so
core reads its own keys, never a provider's token. (Ruling 2026-09-10,
replacing the earlier proposal to move the pointer into `Driver`: same
behaviour, three lines instead of 27 call sites.)
```

and in §8 change item 1 to "`Login::fingerprint` gains the Gemini envelope pointer (§4)".

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/driver/mod.rs docs/superpowers/specs/2026-09-10-swapd-gemini-driver-design.md
git commit -m "fingerprint: a gemini envelope keys on its refresh token"
```

---

### Task 2: Gemini paths, live store and the swapd-owned lock

**Files:**
- Create: `src/driver/gemini/mod.rs`, `src/driver/gemini/paths.rs`, `src/driver/gemini/live.rs`, `src/driver/gemini/tests.rs`
- Modify: `src/driver/mod.rs:4` (add `pub mod gemini;` — NOT yet in the registry)

**Interfaces:**
- Consumes: `crate::driver::claude::locks::{proper_lockfile, LockGuard, READ_TIMEOUT, DEFAULT_TIMEOUT}`; `crate::driver::claude::live::write_private_file(path, value)`; `crate::driver::{Driver, DriverError, Env, Login, Identity, Usage, Caps, IgniteOutcome, RunProfile}`.
- Produces:
  - `paths::home(env) -> Result<PathBuf, DriverError>`: `GEMINI_CLI_HOME` when non-empty, else `USERPROFILE` on Windows / `HOME` elsewhere, else `HOME` (both platforms), else `Invalid("HOME is not set")`.
  - `paths::gemini_dir(env) -> Result<PathBuf>` = `home/.gemini`; `paths::oauth_creds(env)`, `paths::google_accounts(env)`, `paths::settings(env)` = that dir joined with `oauth_creds.json` / `google_accounts.json` / `settings.json`; `paths::live_lock(env)` = that dir joined with `.swapd-live.lock`.
  - `live::Envelope { oauth_creds: serde_json::Map<String, Value>, google_account: Option<String> }` with `Envelope::parse(&str) -> Result<Envelope, DriverError>` and `Envelope::to_login(&self) -> Login`.
  - `GeminiDriver { pub endpoints: oauth::GeminiEndpoints, project_memo: Mutex<HashMap<String, String>> }` (the `endpoints` field is added in Task 4; in this task the struct has only `project_memo` — see Step 3) with `GeminiDriver::new()`, `read_live`, `read_live_locked`, `write_live`, `write_live_with_timeout`, `live_config_text`.
  - Constants: `pub const LIVE_LOCK_STALENESS: Duration = Duration::from_secs(60);`, `pub const OAUTH_PERSONAL: &str = "oauth-personal";`.

- [ ] **Step 1: Test helpers** — create `src/driver/gemini/tests.rs`:

```rust
//! Shared helpers for the Gemini driver's unit tests. Nothing here reads the
//! process environment or the real `~/.gemini`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use tempfile::TempDir;

use crate::driver::Env;

pub fn temp_home() -> TempDir {
    TempDir::new().expect("temp home")
}

/// An `Env` whose `GEMINI_CLI_HOME` is `home` and whose swapd home is
/// `home/swapd`. `HOME` is set to the same temp dir so a resolver that falls
/// back to it still lands inside the sandbox.
pub fn env_with<'a>(home: &TempDir, vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> Env {
    let root = home.path().to_str().expect("utf-8 temp path").to_string();
    let mut map = HashMap::new();
    map.insert("HOME".to_string(), root.clone());
    map.insert("USERPROFILE".to_string(), root.clone());
    map.insert("GEMINI_CLI_HOME".to_string(), root);
    for (key, value) in vars {
        map.insert(key.to_string(), value.to_string());
    }
    Env {
        home: home.path().join("swapd"),
        vars: map,
    }
}

pub const CREDS: &str = r#"{"access_token":"at-1","refresh_token":"rt-1","id_token":"","expiry_date":4102444800000,"scope":"openid","token_type":"Bearer"}"#;
pub const ACCOUNTS: &str = r#"{"active":"you@example.com","old":[]}"#;

/// Seed `home/.gemini/{oauth_creds.json,google_accounts.json,settings.json}`.
pub fn seed_live(home: &Path, creds: &str, accounts: Option<&str>) {
    let dir = home.join(".gemini");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("oauth_creds.json"), creds).unwrap();
    if let Some(accounts) = accounts {
        fs::write(dir.join("google_accounts.json"), accounts).unwrap();
    }
    fs::write(
        dir.join("settings.json"),
        r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
    )
    .unwrap();
}
```

- [ ] **Step 2: Write the failing tests** — `src/driver/gemini/live.rs` ends with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::gemini::tests::{env_with, seed_live, temp_home, ACCOUNTS, CREDS};
    use std::fs;

    #[test]
    fn read_live_builds_the_envelope_from_the_file_pair() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        let login = GeminiDriver::new().read_live(&env).unwrap();
        let value: serde_json::Value = serde_json::from_str(&login.bytes).unwrap();
        assert_eq!(value["oauth_creds"]["refresh_token"], "rt-1");
        assert_eq!(value["google_account"], "you@example.com");
    }

    #[test]
    fn read_live_without_the_pointer_file_has_a_null_account() {
        let home = temp_home();
        seed_live(home.path(), CREDS, None);
        let login = GeminiDriver::new().read_live(&env_with(&home, [])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&login.bytes).unwrap();
        assert!(value["google_account"].is_null());
    }

    #[test]
    fn read_live_without_credentials_is_no_login() {
        let home = temp_home();
        assert!(matches!(
            GeminiDriver::new().read_live(&env_with(&home, [])),
            Err(DriverError::NoLogin)
        ));
    }

    #[test]
    fn read_live_rejects_a_non_object_credential_file() {
        let home = temp_home();
        seed_live(home.path(), "[1,2]", Some(ACCOUNTS));
        assert!(matches!(
            GeminiDriver::new().read_live(&env_with(&home, [])),
            Err(DriverError::Invalid(_))
        ));
    }

    #[test]
    fn read_live_refuses_a_non_oauth_auth_type() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        fs::write(
            home.path().join(".gemini").join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
        )
        .unwrap();
        match GeminiDriver::new().read_live(&env_with(&home, [])) {
            Err(DriverError::Invalid(msg)) => assert_eq!(msg, "auth-type-not-oauth"),
            other => panic!("expected auth-type-not-oauth, got {:?}", other.err()),
        }
    }

    #[test]
    fn read_live_refuses_encrypted_storage() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, [("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", "true")]);
        assert!(matches!(
            GeminiDriver::new().read_live(&env),
            Err(DriverError::Unsupported(_))
        ));
    }

    #[test]
    fn write_live_replaces_the_pair_and_rotates_the_old_account() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        let next = Login {
            bytes: r#"{"oauth_creds":{"access_token":"at-2","refresh_token":"rt-2","expiry_date":4102444800000},"google_account":"other@example.com"}"#.to_string(),
        };
        GeminiDriver::new().write_live(&env, &next).unwrap();
        let creds: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(paths::oauth_creds(&env).unwrap()).unwrap()).unwrap();
        assert_eq!(creds["refresh_token"], "rt-2");
        let accounts: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(paths::google_accounts(&env).unwrap()).unwrap()).unwrap();
        assert_eq!(accounts["active"], "other@example.com");
        assert_eq!(accounts["old"], serde_json::json!(["you@example.com"]));
        assert!(!paths::live_lock(&env).unwrap().exists(), "the lock is released");
    }

    #[cfg(unix)]
    #[test]
    fn write_live_keeps_the_credential_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = temp_home();
        let env = env_with(&home, []);
        let login = Login {
            bytes: r#"{"oauth_creds":{"refresh_token":"rt-2"},"google_account":null}"#.to_string(),
        };
        GeminiDriver::new().write_live(&env, &login).unwrap();
        let mode = fs::metadata(paths::oauth_creds(&env).unwrap()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_held_live_lock_makes_the_locked_read_report_locked() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        fs::create_dir_all(paths::live_lock(&env).unwrap()).unwrap();
        assert!(matches!(
            GeminiDriver::new().read_live_locked_with_timeout(&env, Duration::from_millis(200)),
            Err(DriverError::Locked(_))
        ));
        // The unfenced read still answers.
        assert!(GeminiDriver::new().read_live(&env).is_ok());
    }

    #[test]
    fn live_config_text_is_the_pointer_file() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        assert_eq!(GeminiDriver::new().live_config_text(&env).unwrap().as_deref(), Some(ACCOUNTS));
        fs::remove_file(paths::google_accounts(&env).unwrap()).unwrap();
        assert_eq!(GeminiDriver::new().live_config_text(&env).unwrap(), None);
    }
}
```

and `src/driver/gemini/paths.rs` ends with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::gemini::tests::{env_with, temp_home};

    #[test]
    fn gemini_cli_home_wins_over_the_os_home() {
        let home = temp_home();
        let env = env_with(&home, [("GEMINI_CLI_HOME", "/elsewhere")]);
        assert_eq!(gemini_dir(&env).unwrap(), std::path::Path::new("/elsewhere").join(".gemini"));
    }

    #[test]
    fn an_empty_gemini_cli_home_falls_back_to_home() {
        let home = temp_home();
        let env = env_with(&home, [("GEMINI_CLI_HOME", "")]);
        assert_eq!(gemini_dir(&env).unwrap(), home.path().join(".gemini"));
    }

    #[test]
    fn no_home_at_all_is_invalid() {
        let home = temp_home();
        let mut env = env_with(&home, []);
        env.vars.remove("GEMINI_CLI_HOME");
        env.vars.remove("HOME");
        env.vars.remove("USERPROFILE");
        assert!(matches!(self::home(&env), Err(DriverError::Invalid(_))));
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test driver::gemini`
Expected: compile errors (module missing).

- [ ] **Step 4: Implement `paths.rs`**

```rust
//! Where the Gemini CLI keeps its login (gemini-cli v0.46.0,
//! `packages/core/src/utils/paths.ts:13-28`, `config/storage.ts:86-88,206-208`).

use std::path::PathBuf;

use crate::driver::{DriverError, Env};

/// `$GEMINI_CLI_HOME` when non-empty (the CLI's own isolation knob), else the
/// OS home the CLI's `os.homedir()` would return.
pub fn home(env: &Env) -> Result<PathBuf, DriverError> {
    if let Some(dir) = env.vars.get("GEMINI_CLI_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let os_home = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    for key in [os_home, "HOME"] {
        if let Some(dir) = env.vars.get(key).filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(dir));
        }
    }
    Err(DriverError::Invalid("HOME is not set".to_string()))
}

pub fn gemini_dir(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(home(env)?.join(".gemini"))
}

/// The tokens (`OAUTH_FILE`, mode 0600).
pub fn oauth_creds(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(gemini_dir(env)?.join("oauth_creds.json"))
}

/// The CLI's cached identity: `{active, old[]}`.
pub fn google_accounts(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(gemini_dir(env)?.join("google_accounts.json"))
}

/// User-scope settings; `security.auth.selectedType` says which auth mode is live.
pub fn settings(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(gemini_dir(env)?.join("settings.json"))
}

/// swapd's own fence around the pair. The CLI has no lock of its own on these
/// files; this one orders swapd's readers and writers (spec §3, #13 ruling 2).
pub fn live_lock(env: &Env) -> Result<PathBuf, DriverError> {
    Ok(gemini_dir(env)?.join(".swapd-live.lock"))
}
```

- [ ] **Step 5: Implement `live.rs`**

```rust
//! Reading and replacing the Gemini CLI's live login: the file pair under
//! `<home>/.gemini/`, fenced by swapd's own mkdir lock.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::driver::claude::live::write_private_file;
use crate::driver::claude::locks::{proper_lockfile, LockGuard, DEFAULT_TIMEOUT, READ_TIMEOUT};
use crate::driver::gemini::paths;
use crate::driver::gemini::GeminiDriver;
use crate::driver::{DriverError, Env, Login};

/// How long a swapd holder may go without touching the lock before another
/// swapd takes it over. Matches the Claude credential lock.
pub const LIVE_LOCK_STALENESS: Duration = Duration::from_secs(60);
/// The one auth mode this driver manages (`AuthType.LOGIN_WITH_GOOGLE`).
pub const OAUTH_PERSONAL: &str = "oauth-personal";

/// The login bytes swapd stores: the credential file's object plus the
/// CLI's cached email.
pub struct Envelope {
    pub oauth_creds: Map<String, Value>,
    pub google_account: Option<String>,
}

impl Envelope {
    pub fn parse(bytes: &str) -> Result<Envelope, DriverError> {
        let Ok(Value::Object(mut outer)) = serde_json::from_str::<Value>(bytes) else {
            return Err(DriverError::Invalid("malformed gemini envelope".to_string()));
        };
        let oauth_creds = match outer.remove("oauth_creds") {
            Some(Value::Object(m)) => m,
            _ => return Err(DriverError::Invalid("gemini envelope has no oauth_creds".to_string())),
        };
        let google_account = outer
            .get("google_account")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok(Envelope { oauth_creds, google_account })
    }

    pub fn to_login(&self) -> Login {
        let mut outer = Map::new();
        outer.insert("oauth_creds".to_string(), Value::Object(self.oauth_creds.clone()));
        outer.insert(
            "google_account".to_string(),
            self.google_account.clone().map(Value::from).unwrap_or(Value::Null),
        );
        Login { bytes: Value::Object(outer).to_string() }
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, DriverError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `security.auth.selectedType` from the user settings, when the file says.
fn selected_auth_type(env: &Env) -> Result<Option<String>, DriverError> {
    let Some(text) = read_optional(&paths::settings(env)?)? else { return Ok(None) };
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(value
        .pointer("/security/auth/selectedType")
        .and_then(Value::as_str)
        .map(str::to_string))
}

impl GeminiDriver {
    /// The pair as an envelope. `NoLogin` when there is no credential file;
    /// `Invalid("auth-type-not-oauth")` when the CLI is configured for another
    /// auth mode; `Unsupported` under the encrypted-storage flag (#13 ruling 5).
    pub fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        if env
            .vars
            .get("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE")
            .is_some_and(|v| !v.is_empty() && v != "false" && v != "0")
        {
            return Err(DriverError::Unsupported(
                "gemini encrypted credential storage (GEMINI_FORCE_ENCRYPTED_FILE_STORAGE)",
            ));
        }
        if let Some(kind) = selected_auth_type(env)? {
            if kind != OAUTH_PERSONAL {
                return Err(DriverError::Invalid("auth-type-not-oauth".to_string()));
            }
        }
        let Some(creds) = read_optional(&paths::oauth_creds(env)?)? else {
            return Err(DriverError::NoLogin);
        };
        if creds.trim().is_empty() {
            return Err(DriverError::NoLogin);
        }
        let Ok(Value::Object(oauth_creds)) = serde_json::from_str::<Value>(&creds) else {
            return Err(DriverError::Invalid("oauth_creds.json is not a JSON object".to_string()));
        };
        let google_account = match read_optional(&paths::google_accounts(env)?)? {
            Some(text) => serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("active").and_then(Value::as_str).map(str::to_string))
                .filter(|s| !s.is_empty()),
            None => None,
        };
        Ok(Envelope { oauth_creds, google_account }.to_login())
    }

    pub fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        self.read_live_locked_with_timeout(env, READ_TIMEOUT)
    }

    /// `read_live` under swapd's own live lock. `Locked` on timeout; a lock
    /// directory that cannot be created (read-only home) degrades to the
    /// unfenced read, as the Claude driver does.
    pub fn read_live_locked_with_timeout(&self, env: &Env, timeout: Duration) -> Result<Login, DriverError> {
        let _guard = match take_live_lock(env, timeout) {
            Ok(guard) => guard,
            Err(DriverError::Io(e))
                if matches!(e.kind(), ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem) =>
            {
                return self.read_live(env)
            }
            Err(e) => return Err(e),
        };
        self.read_live(env)
    }

    pub fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError> {
        self.write_live_with_timeout(env, login, DEFAULT_TIMEOUT)
    }

    /// Replace the pair under the live lock: the credential (tmp + rename,
    /// 0600) first, then the pointer file with the previous `active` rotated
    /// onto `old[]` (the CLI's own rule, `userAccountManager.ts:100-117`).
    /// Nothing else under `.gemini/` is touched.
    pub fn write_live_with_timeout(&self, env: &Env, login: &Login, timeout: Duration) -> Result<(), DriverError> {
        let envelope = Envelope::parse(&login.bytes)?;
        let dir = paths::gemini_dir(env)?;
        fs::create_dir_all(&dir)?;
        let _guard = take_live_lock(env, timeout)?;

        let creds_path = paths::oauth_creds(env)?;
        let tmp = dir.join(".oauth_creds.json.swapd-tmp");
        write_private_file(&tmp, &Value::Object(envelope.oauth_creds.clone()).to_string())?;
        fs::rename(&tmp, &creds_path)?;

        let accounts_path = paths::google_accounts(env)?;
        let mut accounts = read_optional(&accounts_path)?
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        let previous = accounts.get("active").and_then(Value::as_str).map(str::to_string);
        let mut old: Vec<String> = accounts
            .get("old")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        if let Some(previous) = previous {
            if envelope.google_account.as_deref() != Some(previous.as_str()) && !old.contains(&previous) {
                old.push(previous);
            }
        }
        accounts.insert(
            "active".to_string(),
            envelope.google_account.clone().map(Value::from).unwrap_or(Value::Null),
        );
        accounts.insert("old".to_string(), Value::from(old));
        fs::write(&accounts_path, Value::Object(accounts).to_string())?;
        Ok(())
    }

    /// The pointer file verbatim (the "config half" for `export --full`).
    pub fn live_config_text(&self, env: &Env) -> Result<Option<String>, DriverError> {
        read_optional(&paths::google_accounts(env)?)
    }
}

fn take_live_lock(env: &Env, timeout: Duration) -> Result<LockGuard, DriverError> {
    proper_lockfile(&paths::live_lock(env)?, LIVE_LOCK_STALENESS, timeout)
}
```

Note: `proper_lockfile`'s `Locked` message says "claude code holds …"; that wording is the Claude module's. Change `locks.rs:170-174` to `format!("held: {}", dir.display())`? NO — the Claude integration tests assert on `starts_with("claude code holds ")` (locks.rs test `fresh_lock_is_not_stolen`). Leave it; the Gemini caller maps it: wrap the `Locked(msg)` as `DriverError::Locked(format!("swapd holds {}", path.display()))` in `take_live_lock`:

```rust
fn take_live_lock(env: &Env, timeout: Duration) -> Result<LockGuard, DriverError> {
    let path = paths::live_lock(env)?;
    proper_lockfile(&path, LIVE_LOCK_STALENESS, timeout).map_err(|e| match e {
        DriverError::Locked(_) => DriverError::Locked(format!("swapd holds {}", path.display())),
        other => other,
    })
}
```

- [ ] **Step 6: Implement `mod.rs`** (the seam; unimplemented methods return `Unsupported` for now and are filled in by Tasks 3–6):

```rust
//! The Gemini CLI driver (google-gemini/gemini-cli, "oauth-personal" auth).
//!
//! `paths` says where the CLI keeps its login, `live` reads and replaces the
//! file pair under swapd's own lock, `identity` answers who a login is without
//! the network, `oauth` refreshes, `usage` asks Code Assist for quota (and is
//! the igniter), `run` builds per-slot `GEMINI_CLI_HOME` profiles.

pub mod identity;
pub mod live;
pub mod oauth;
pub mod paths;
pub mod run;
pub mod usage;

#[cfg(test)]
pub mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::driver::{Caps, Driver, DriverError, Env, Identity, IgniteOutcome, Login, RunProfile, Usage};

pub struct GeminiDriver {
    pub endpoints: oauth::GeminiEndpoints,
    /// `email -> cloudaicompanionProject`, learned from `loadCodeAssist` once
    /// per process (the daemon is long-lived; a status verb pays one extra
    /// request). Never persisted.
    pub(crate) project_memo: Mutex<HashMap<String, String>>,
}

impl GeminiDriver {
    pub fn new(endpoints: oauth::GeminiEndpoints) -> Self {
        Self { endpoints, project_memo: Mutex::new(HashMap::new()) }
    }

    pub fn default_for_platform(env: &Env) -> Self {
        Self::new(oauth::GeminiEndpoints::from_env(env))
    }
}

impl Driver for GeminiDriver {
    fn id(&self) -> &'static str {
        "gemini"
    }
    fn installed(&self, env: &Env) -> Option<PathBuf> {
        run::resolve_cli(env)
    }
    fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        GeminiDriver::read_live(self, env)
    }
    fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        GeminiDriver::read_live_locked(self, env)
    }
    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError> {
        GeminiDriver::write_live(self, env, login)
    }
    fn identity(&self, login: &Login) -> Result<Identity, DriverError> {
        self.identity_offline(login)
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
    }
    fn identity_offline(&self, login: &Login) -> Option<Identity> {
        identity::identity_offline(login)
    }
    fn expires_at(&self, login: &Login) -> Option<f64> {
        identity::expires_at(login)
    }
    fn refresh(&self, login: &Login) -> Result<Login, DriverError> {
        oauth::refresh(&self.endpoints, login)
    }
    fn usage(&self, login: &Login) -> Result<Usage, DriverError> {
        usage::usage(self, login)
    }
    fn ignite(&self, env: &Env, slot: u32, login: &Login) -> Result<IgniteOutcome, DriverError> {
        run::ignite(self, env, slot, login)
    }
    fn run_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError> {
        run::run_profile(env, slot, login)
    }
    fn commit_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<(), DriverError> {
        run::commit_profile(env, slot, login)
    }
    fn forget_profile(&self, env: &Env, slot: u32) -> Result<(), DriverError> {
        run::forget_profile(env, slot)
    }
    fn live_config_text(&self, env: &Env) -> Result<Option<String>, DriverError> {
        GeminiDriver::live_config_text(self, env)
    }
    fn capabilities(&self) -> Caps {
        Caps { ignite: true, add_token: false, prefer: true, refresh: true, run: true }
    }
    /// Anything with a refresh token can be made live; there is no other axis.
    fn can_activate(&self, login: &Login) -> Result<(), DriverError> {
        let envelope = live::Envelope::parse(&login.bytes)?;
        match envelope.oauth_creds.get("refresh_token").and_then(serde_json::Value::as_str) {
            Some(t) if !t.is_empty() => Ok(()),
            _ => Err(DriverError::Invalid("gemini login has no refresh token".to_string())),
        }
    }
    /// API keys never live in `oauth_creds.json`.
    fn is_api_key(&self, _login: &Login) -> bool {
        false
    }
}
```

For THIS task only, so the crate compiles before Tasks 3–6 land, create the four sibling modules as stubs whose functions return `Err(DriverError::Unsupported("gemini: not yet implemented"))` (or `None`) with the exact signatures named in the later tasks' "Produces" blocks; each later task replaces its stub. Add `pub mod gemini;` to `src/driver/mod.rs`. Do NOT add the driver to `registry`/`provider_ids` yet (Task 7).

- [ ] **Step 7: Run the tests**

Run: `cargo test driver::gemini`
Expected: PASS (paths + live tests).

- [ ] **Step 8: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/driver/mod.rs src/driver/gemini
git commit -m "gemini: the live login is the file pair under .gemini, fenced by a swapd lock"
```

---

### Task 3: Identity and expiry without the network

**Files:**
- Create/replace: `src/driver/gemini/identity.rs`
- Modify: `Cargo.toml` (`base64 = "0.22"` under `[dependencies]`)

**Interfaces:**
- Consumes: `live::Envelope::parse`.
- Produces: `identity::identity_offline(login: &Login) -> Option<Identity>`; `identity::expires_at(login: &Login) -> Option<f64>` (unix seconds = `expiry_date` ms / 1000); `identity::jwt_payload(token: &str) -> Option<serde_json::Value>` (base64url-decoded second segment, NO signature check).

- [ ] **Step 1: Write the failing tests** at the end of `identity.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// A structurally valid, unsigned JWT: `header.payload.sig` with the
    /// payload base64url-encoded without padding.
    fn jwt(payload: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}.{}.{}", b64.encode(r#"{"alg":"none"}"#), b64.encode(payload), b64.encode("sig"))
    }

    fn login(creds: &str, account: &str) -> Login {
        Login { bytes: format!(r#"{{"oauth_creds":{creds},"google_account":{account}}}"#) }
    }

    #[test]
    fn identity_prefers_the_pointer_file_email() {
        let id_token = jwt(r#"{"email":"jwt@example.com","sub":"123"}"#);
        let login = login(&format!(r#"{{"id_token":"{id_token}"}}"#), r#""cached@example.com""#);
        let identity = identity_offline(&login).unwrap();
        assert_eq!(identity.email, "cached@example.com");
        assert_eq!(identity.uuid.as_deref(), Some("123"));
        assert_eq!(identity.organization_uuid, "");
    }

    #[test]
    fn identity_falls_back_to_the_id_token_claims() {
        let id_token = jwt(r#"{"email":"jwt@example.com","sub":"123","hd":"example.com"}"#);
        let login = login(&format!(r#"{{"id_token":"{id_token}"}}"#), "null");
        let identity = identity_offline(&login).unwrap();
        assert_eq!(identity.email, "jwt@example.com");
        assert_eq!(identity.organization_name, "example.com");
        assert_eq!(identity.plan, None);
    }

    #[test]
    fn identity_is_none_without_either() {
        assert!(identity_offline(&login(r#"{"access_token":"a"}"#, "null")).is_none());
        assert!(identity_offline(&login(r#"{"id_token":"not-a-jwt"}"#, "null")).is_none());
    }

    #[test]
    fn expires_at_is_expiry_date_in_seconds() {
        let login = login(r#"{"expiry_date":1772074235302}"#, "null");
        assert_eq!(expires_at(&login), Some(1772074235.302));
        assert_eq!(expires_at(&self::login(r#"{}"#, "null")), None);
    }
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo test driver::gemini::identity` → FAIL/compile error.

- [ ] **Step 3: Implement**

```rust
//! Who a Gemini login belongs to, without the network: the CLI's own cached
//! email (`google_accounts.json`, what `/about` shows) or the `id_token`'s
//! claims. The JWT is decoded, never verified: it was written by the CLI
//! after Google issued it, and this is a read-only peek at its subject.

use base64::Engine as _;
use serde_json::Value;

use crate::driver::gemini::live::Envelope;
use crate::driver::{Identity, Login};

/// The payload object of a JWT, or `None` when the token is not three
/// base64url segments around a JSON object.
pub fn jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        v @ Value::Object(_) => Some(v),
        _ => None,
    }
}

pub fn identity_offline(login: &Login) -> Option<Identity> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    let claims = envelope
        .oauth_creds
        .get("id_token")
        .and_then(Value::as_str)
        .and_then(jwt_payload);
    let claim = |name: &str| {
        claims
            .as_ref()
            .and_then(|c| c.get(name))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let email = envelope.google_account.clone().or_else(|| claim("email"))?;
    Some(Identity {
        email,
        organization_uuid: String::new(),
        organization_name: claim("hd").unwrap_or_default(),
        plan: None,
        uuid: claim("sub"),
    })
}

/// `expiry_date` is epoch milliseconds (google-auth-library computes
/// `Date.now() + expires_in * 1000` and drops `expires_in`).
pub fn expires_at(login: &Login) -> Option<f64> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    envelope
        .oauth_creds
        .get("expiry_date")
        .and_then(Value::as_f64)
        .map(|ms| ms / 1000.0)
}
```

- [ ] **Step 4: Run the tests** — `cargo test driver::gemini` → PASS.

- [ ] **Step 5: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add Cargo.toml Cargo.lock src/driver/gemini/identity.rs
git commit -m "gemini: identity from the cached account or the id_token, expiry from expiry_date"
```

---

### Task 4: Refresh against Google's token endpoint

**Files:**
- Create/replace: `src/driver/gemini/oauth.rs`
- Create: `src/driver/gemini/fixtures/token_refresh.json`, `src/driver/gemini/fixtures/token_invalid_grant.json`
- Modify: `src/http.rs:22-26` (two defaults)

**Interfaces:**
- Consumes: `http::agent`, `http::base_url_from`, `live::Envelope`.
- Produces: `oauth::GeminiEndpoints { pub oauth: String, pub cloudcode: String }` with `GeminiEndpoints::from_env(env)` (names `google-oauth` → `https://oauth2.googleapis.com`, `cloudcode` → `https://cloudcode-pa.googleapis.com`); `oauth::token_url(ep) -> String` = `{oauth}/token`; `oauth::refresh(ep, login) -> Result<Login, DriverError>`; `oauth::now_ms() -> i64`; `oauth::is_expired(login, now_ms: i64) -> bool` (true when `expiry_date` is absent or within `REFRESH_BUFFER_MS = 5 * 60 * 1000`, the CLI's own clock-skew buffer); `oauth::access_token(login) -> Option<String>`; `pub const REFRESH_TIMEOUT_S: u64 = 20; pub const READ_TIMEOUT_S: u64 = 15;`.

- [ ] **Step 1: Fixtures**

`token_refresh.json`:
```json
{"access_token":"at-2","expires_in":3599,"scope":"openid https://www.googleapis.com/auth/userinfo.email","id_token":"h.e30.s"}
```
`token_invalid_grant.json`:
```json
{"error":"invalid_grant","error_description":"Token has been expired or revoked."}
```

- [ ] **Step 2: Write the failing tests** at the end of `oauth.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn endpoints(server: &MockServer) -> GeminiEndpoints {
        GeminiEndpoints { oauth: server.base_url(), cloudcode: server.base_url() }
    }

    fn login() -> Login {
        Login { bytes: r#"{"oauth_creds":{"access_token":"at-1","refresh_token":"rt-1","expiry_date":1000,"scope":"openid","token_type":"Bearer"},"google_account":"you@example.com"}"#.to_string() }
    }

    #[test]
    fn refresh_posts_the_form_and_keeps_the_old_refresh_token_when_the_reply_omits_it() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body_contains("grant_type=refresh_token")
                .body_contains("refresh_token=rt-1")
                .body_contains("client_id=");
            then.status(200).body(include_str!("fixtures/token_refresh.json"));
        });
        let before = now_ms();
        let rotated = refresh(&endpoints(&server), &login()).unwrap();
        mock.assert();
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["access_token"], "at-2");
        assert_eq!(v["oauth_creds"]["refresh_token"], "rt-1", "kept from the input");
        assert_eq!(v["oauth_creds"]["id_token"], "h.e30.s");
        assert_eq!(v["oauth_creds"]["scope"], "openid https://www.googleapis.com/auth/userinfo.email", "the reply's scope is adopted");
        assert_eq!(v["oauth_creds"]["token_type"], "Bearer", "a member the reply never mentions survives");
        assert_eq!(v["google_account"], "you@example.com");
        let expiry = v["oauth_creds"]["expiry_date"].as_i64().unwrap();
        assert!(expiry >= before + 3_599_000 && expiry <= now_ms() + 3_599_000);
    }

    #[test]
    fn refresh_adopts_a_rotated_refresh_token() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200).body(r#"{"access_token":"at-2","expires_in":10,"refresh_token":"rt-2"}"#);
        });
        let rotated = refresh(&endpoints(&server), &login()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["refresh_token"], "rt-2");
    }

    #[test]
    fn invalid_grant_is_token_dead() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400).body(include_str!("fixtures/token_invalid_grant.json"));
        });
        assert!(matches!(refresh(&endpoints(&server), &login()), Err(DriverError::TokenDead)));
    }

    #[test]
    fn a_429_is_throttled_and_a_500_is_transient() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(429).header("Retry-After", "7");
        });
        match refresh(&endpoints(&server), &login()) {
            Err(DriverError::Throttled { retry_after }) => assert_eq!(retry_after, Some(7.0)),
            other => panic!("{:?}", other.err()),
        }
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(500);
        });
        assert!(matches!(refresh(&endpoints(&server), &login()), Err(DriverError::Http(_))));
    }

    #[test]
    fn a_login_without_a_refresh_token_is_token_dead_without_a_request() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200);
        });
        let login = Login { bytes: r#"{"oauth_creds":{"access_token":"a"},"google_account":null}"#.to_string() };
        assert!(matches!(refresh(&endpoints(&server), &login), Err(DriverError::TokenDead)));
        mock.assert_hits(0);
    }

    #[test]
    fn expiry_uses_the_five_minute_buffer() {
        let l = |ms: i64| Login { bytes: format!(r#"{{"oauth_creds":{{"expiry_date":{ms}}},"google_account":null}}"#) };
        assert!(is_expired(&l(1_000_000), 1_000_000 - REFRESH_BUFFER_MS + 1));
        assert!(!is_expired(&l(1_000_000), 1_000_000 - REFRESH_BUFFER_MS - 1));
        assert!(is_expired(&Login { bytes: r#"{"oauth_creds":{},"google_account":null}"#.to_string() }, 0));
    }

    #[test]
    fn endpoints_from_env_honour_the_overrides() {
        let home = crate::driver::gemini::tests::temp_home();
        let env = crate::driver::gemini::tests::env_with(&home, [("SWAPD_URL_GOOGLE_OAUTH", "http://127.0.0.1:1"), ("SWAPD_URL_CLOUDCODE", "http://127.0.0.1:2")]);
        let ep = GeminiEndpoints::from_env(&env);
        assert_eq!(ep.oauth, "http://127.0.0.1:1");
        assert_eq!(ep.cloudcode, "http://127.0.0.1:2");
        let plain = GeminiEndpoints::from_env(&crate::driver::gemini::tests::env_with(&home, []));
        assert_eq!(plain.oauth, "https://oauth2.googleapis.com");
        assert_eq!(plain.cloudcode, "https://cloudcode-pa.googleapis.com");
    }
}
```

- [ ] **Step 3: Run to verify they fail** — `cargo test driver::gemini::oauth` → FAIL.

- [ ] **Step 4: Implement** — `src/http.rs` `base_url_from` match gains:

```rust
        "SWAPD_URL_GOOGLE_OAUTH" => "https://oauth2.googleapis.com".to_string(),
        "SWAPD_URL_CLOUDCODE" => "https://cloudcode-pa.googleapis.com".to_string(),
```

and `oauth.rs`:

```rust
//! Google OAuth for the Gemini CLI's "oauth-personal" login: the token
//! endpoint the CLI's `google-auth-library` client uses, with the CLI's own
//! installed-app client (gemini-cli v0.46.0 `code_assist/oauth2.ts:76-92`).
//! The client secret is public by Google's installed-app model; it is still
//! never logged, printed or exported.

use serde_json::Value;

use crate::driver::gemini::live::Envelope;
use crate::driver::{DriverError, Env, Login};
use crate::http;

/// `OAUTH_CLIENT_ID` from oauth2.ts:76-77 at the pinned commit.
const CLIENT_ID: &str = "<copy verbatim from the source>";
/// `OAUTH_CLIENT_SECRET` from oauth2.ts:85 at the pinned commit.
const CLIENT_SECRET: &str = "<copy verbatim from the source>";

pub const REFRESH_TIMEOUT_S: u64 = 20;
pub const READ_TIMEOUT_S: u64 = 15;
/// google-auth-library's `CLOCK_SKEW_SECS_ = 300`: a token this close to
/// expiry is treated as expired.
pub const REFRESH_BUFFER_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct GeminiEndpoints {
    pub oauth: String,
    pub cloudcode: String,
}

impl GeminiEndpoints {
    pub fn from_env(env: &Env) -> Self {
        Self {
            oauth: http::base_url_from("google-oauth", |k| env.vars.get(k).cloned()),
            cloudcode: http::base_url_from("cloudcode", |k| env.vars.get(k).cloned()),
        }
    }
}

pub fn token_url(ep: &GeminiEndpoints) -> String {
    format!("{}/token", ep.oauth.trim_end_matches('/'))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn access_token(login: &Login) -> Option<String> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    envelope.oauth_creds.get("access_token").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Expired, or within the CLI's own skew buffer of it; a missing
/// `expiry_date` counts as expired (the CLI would refresh too).
pub fn is_expired(login: &Login, now_ms: i64) -> bool {
    let Ok(envelope) = Envelope::parse(&login.bytes) else { return true };
    match envelope.oauth_creds.get("expiry_date").and_then(Value::as_i64) {
        Some(expiry) => expiry - REFRESH_BUFFER_MS <= now_ms,
        None => true,
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

/// `POST {oauth}/token`, form-encoded, as `refreshTokenNoCache` does.
/// `invalid_grant` → `TokenDead`; 429 → `Throttled`; other non-200 → `Http`.
/// A reply without `refresh_token` keeps the stored one (rotation is not
/// guaranteed — gemini-cli PR #26924). Untouched members of `oauth_creds`
/// survive; `google_account` is carried over.
pub fn refresh(ep: &GeminiEndpoints, login: &Login) -> Result<Login, DriverError> {
    let mut envelope = Envelope::parse(&login.bytes).map_err(|_| DriverError::Http("refresh: malformed credential".to_string()))?;
    let refresh_token = envelope
        .oauth_creds
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or(DriverError::TokenDead)?
        .to_string();
    let body = form_encode(&[
        ("refresh_token", refresh_token.as_str()),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
        ("grant_type", "refresh_token"),
    ]);
    let response = http::agent(REFRESH_TIMEOUT_S)
        .post(token_url(ep))
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;
    let status = response.status().as_u16();
    if status == 429 {
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v.max(0.0));
        return Err(DriverError::Throttled { retry_after });
    }
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;
    if status != 200 {
        let error = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        return Err(match (status, error.as_str()) {
            (400 | 401, "invalid_grant") => DriverError::TokenDead,
            _ => DriverError::Http(format!("refresh: http {status}")),
        });
    }
    let Ok(Value::Object(resp)) = serde_json::from_str::<Value>(&text) else {
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };
    let (Some(access_token), Some(expires_in)) = (
        resp.get("access_token").and_then(Value::as_str),
        resp.get("expires_in").and_then(Value::as_f64),
    ) else {
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };
    envelope.oauth_creds.insert("access_token".to_string(), Value::from(access_token));
    envelope.oauth_creds.insert("expiry_date".to_string(), Value::from(now_ms() + (expires_in * 1000.0) as i64));
    for key in ["refresh_token", "id_token", "scope", "token_type"] {
        if let Some(v) = resp.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            envelope.oauth_creds.insert(key.to_string(), Value::from(v));
        }
    }
    Ok(envelope.to_login())
}
```

Replace the two `<copy verbatim from the source>` placeholders by fetching `https://raw.githubusercontent.com/google-gemini/gemini-cli/85b0c55c126a4992b51d140e357ae9db5f9c2d7f/packages/core/src/code_assist/oauth2.ts` (read-only, one `curl`) and copying `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`. Do not paste either value anywhere but the two `const`s.

- [ ] **Step 5: Run the tests** — `cargo test driver::gemini` and `cargo test http` → PASS.

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/http.rs src/driver/gemini/oauth.rs src/driver/gemini/fixtures
git commit -m "gemini: refresh against google's token endpoint, keeping the stored refresh token when the reply omits it"
```

---

### Task 5: Usage from Code Assist quota buckets

**Files:**
- Create/replace: `src/driver/gemini/usage.rs`
- Create: `src/driver/gemini/fixtures/load_code_assist.json`, `src/driver/gemini/fixtures/quota.json`
- Modify: `docs/superpowers/specs/2026-09-10-swapd-gemini-driver-design.md` §5 (`project` is memoised in-process, not stored in the slot row)

**Interfaces:**
- Consumes: `oauth::{access_token, is_expired, now_ms, READ_TIMEOUT_S}`, `GeminiDriver.project_memo`, `identity::identity_offline`.
- Produces: `usage::usage(driver: &GeminiDriver, login: &Login) -> Result<Usage, DriverError>`; `usage::load_project(ep, access_token) -> Result<String, DriverError>`; `usage::fetch_quota(ep, access_token, project) -> Result<Value, DriverError>`; `usage::windows_at(raw: &Value) -> Vec<Window>`; `usage::load_url(ep)`, `usage::quota_url(ep)` = `{cloudcode}/v1internal:loadCodeAssist` / `{cloudcode}/v1internal:retrieveUserQuota`.

Request shapes (types.ts:67-71, 250-253 at the pinned commit; setup.ts:177-183):
- `loadCodeAssist` body: `{"metadata":{"ideType":"IDE_UNSPECIFIED","platform":"PLATFORM_UNSPECIFIED","pluginType":"GEMINI"}}`; response `cloudaicompanionProject` (string) is the project. Absent/empty → `Invalid("gemini: no code assist project for this account")`.
- `retrieveUserQuota` body: `{"project":"<id>","userAgent":"swapd/0.1"}`; response `{"buckets":[{remainingAmount?,remainingFraction?,resetTime?,tokenType?,modelId?}]}`.
- Both POST, `Content-Type: application/json`, `Authorization: Bearer <access_token>`.

Ruling: the project id is memoised per email in `project_memo` for the process lifetime (the spec's §5 said the slot row; a status verb pays one extra request, the daemon none — and the slot row stays provider-neutral). Amend the spec §5 paragraph "**`project`.**" accordingly and §8 item "slots.json gains…" (delete it).

- [ ] **Step 1: Fixtures**

`load_code_assist.json`:
```json
{"currentTier":{"id":"free-tier","name":"Gemini Code Assist for individuals"},"cloudaicompanionProject":"projects-123","allowedTiers":[]}
```
`quota.json`:
```json
{"buckets":[{"modelId":"gemini-2.5-pro","remainingFraction":0.25,"resetTime":"2026-09-11T00:00:00Z","tokenType":"REQUESTS"},{"modelId":"gemini-2.5-flash","remainingAmount":"180","remainingFraction":0.9,"resetTime":"2026-09-11T00:00:00Z"},{"tokenType":"CREDITS","remainingFraction":1.0},{"modelId":"","remainingFraction":0.5}]}
```

- [ ] **Step 2: Write the failing tests** at the end of `usage.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::WindowKind;
    use crate::driver::gemini::oauth::GeminiEndpoints;
    use httpmock::prelude::*;

    fn driver(server: &MockServer) -> GeminiDriver {
        GeminiDriver::new(GeminiEndpoints { oauth: server.base_url(), cloudcode: server.base_url() })
    }

    fn login(expiry_ms: i64) -> Login {
        Login { bytes: format!(r#"{{"oauth_creds":{{"access_token":"at-1","refresh_token":"rt-1","expiry_date":{expiry_ms}}},"google_account":"you@example.com"}}"#) }
    }
    const FRESH: i64 = 4_102_444_800_000;

    #[test]
    fn buckets_become_scoped_windows_named_by_model() {
        let raw: serde_json::Value = serde_json::from_str(include_str!("fixtures/quota.json")).unwrap();
        let windows = windows_at(&raw);
        assert_eq!(windows.len(), 3, "the unnamed bucket is dropped");
        let pro = &windows[0];
        assert_eq!(pro.kind, WindowKind::Scoped);
        assert_eq!(pro.name.as_deref(), Some("gemini-2.5-pro"));
        assert!((pro.pct - 75.0).abs() < 1e-9);
        assert_eq!(pro.resets_at.as_deref(), Some("2026-09-11T00:00:00Z"));
        assert_eq!(pro.pace, None);
        assert_eq!(pro.used, None);
        let flash = &windows[1];
        assert!((flash.pct - 10.0).abs() < 1e-9);
        assert_eq!(flash.limit, Some(200.0), "remainingAmount / remainingFraction");
        assert_eq!(flash.used, Some(20.0));
        assert_eq!(windows[2].name.as_deref(), Some("CREDITS"), "tokenType names an unnamed-model bucket");
        assert!((windows[2].pct - 0.0).abs() < 1e-9);
    }

    #[test]
    fn usage_loads_the_project_once_then_asks_for_quota() {
        let server = MockServer::start();
        let load = server.mock(|when, then| {
            when.method(POST)
                .path("/v1internal:loadCodeAssist")
                .header("authorization", "Bearer at-1")
                .json_body_partial(r#"{"metadata":{"pluginType":"GEMINI"}}"#);
            then.status(200).body(include_str!("fixtures/load_code_assist.json"));
        });
        let quota = server.mock(|when, then| {
            when.method(POST)
                .path("/v1internal:retrieveUserQuota")
                .header("authorization", "Bearer at-1")
                .json_body_partial(r#"{"project":"projects-123"}"#);
            then.status(200).body(include_str!("fixtures/quota.json"));
        });
        let driver = driver(&server);
        let usage = usage(&driver, &login(FRESH)).unwrap();
        assert_eq!(usage.windows.len(), 3);
        assert!(usage.fetched_at > 0.0);
        let _ = usage(&driver, &login(FRESH)).unwrap();
        load.assert_hits(1);
        quota.assert_hits(2);
    }

    #[test]
    fn an_expired_token_needs_a_refresh_without_a_request() {
        let server = MockServer::start();
        let any = server.mock(|when, then| {
            when.method(POST);
            then.status(200);
        });
        assert!(matches!(usage(&driver(&server), &login(1_000)), Err(DriverError::NeedsRefresh)));
        any.assert_hits(0);
    }

    #[test]
    fn a_401_needs_a_refresh_and_a_429_is_throttled_from_retry_info() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(401);
        });
        assert!(matches!(usage(&driver(&server), &login(FRESH)), Err(DriverError::NeedsRefresh)));

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(429).body(r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"40s"}]}}"#);
        });
        match usage(&driver(&server), &login(FRESH)) {
            Err(DriverError::Throttled { retry_after }) => assert_eq!(retry_after, Some(40.0)),
            other => panic!("{:?}", other.err()),
        }
    }

    #[test]
    fn a_reply_without_a_project_is_invalid() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(200).body(r#"{"currentTier":{"id":"free-tier"}}"#);
        });
        assert!(matches!(usage(&driver(&server), &login(FRESH)), Err(DriverError::Invalid(_))));
    }
}
```

- [ ] **Step 3: Run to verify they fail** — `cargo test driver::gemini::usage` → FAIL.

- [ ] **Step 4: Implement**

```rust
//! Quota for a Gemini login: Code Assist's `retrieveUserQuota`, one bucket
//! per model with a server-chosen `resetTime` (gemini-cli v0.46.0
//! `code_assist/server.ts:363-370`, `types.ts:250-265`). The project the
//! call needs comes from `loadCodeAssist` (`setup.ts:177-183`), memoised per
//! account for the process. Never refreshes: an expired token is
//! `NeedsRefresh`, the caller's to fix.

use serde_json::{json, Value};

use crate::contract::{Window, WindowKind};
use crate::driver::gemini::oauth::{self, GeminiEndpoints};
use crate::driver::gemini::{identity, GeminiDriver};
use crate::driver::{DriverError, Login, Usage};
use crate::http;

pub fn load_url(ep: &GeminiEndpoints) -> String {
    format!("{}/v1internal:loadCodeAssist", ep.cloudcode.trim_end_matches('/'))
}

pub fn quota_url(ep: &GeminiEndpoints) -> String {
    format!("{}/v1internal:retrieveUserQuota", ep.cloudcode.trim_end_matches('/'))
}

/// One authenticated POST; non-2xx classified here. 401/403 → `NeedsRefresh`
/// (the caller refreshes and retries), 429 → `Throttled` with the
/// `RetryInfo.retryDelay` seconds when the body carries one.
fn post(url: String, access_token: &str, body: &Value, what: &str) -> Result<Value, DriverError> {
    let response = http::agent(oauth::READ_TIMEOUT_S)
        .post(url)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => DriverError::Http(format!("{what}: timeout")),
            _ => DriverError::Http(format!("{what}: network")),
        })?;
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().map_err(|_| DriverError::Http(format!("{what}: network")))?;
    match status {
        200..=299 => serde_json::from_str::<Value>(&text).map_err(|_| DriverError::Http(format!("{what}: malformed response"))),
        401 | 403 => Err(DriverError::NeedsRefresh),
        429 => Err(DriverError::Throttled { retry_after: retry_delay_seconds(&text) }),
        _ => Err(DriverError::Http(format!("{what}: http {status}"))),
    }
}

/// `error.details[].retryDelay` like `"40s"` (google.rpc.RetryInfo).
fn retry_delay_seconds(body: &str) -> Option<f64> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .pointer("/error/details")?
        .as_array()?
        .iter()
        .find_map(|d| d.get("retryDelay").and_then(Value::as_str))
        .and_then(|s| s.trim_end_matches('s').parse::<f64>().ok())
}

pub fn load_project(ep: &GeminiEndpoints, access_token: &str) -> Result<String, DriverError> {
    let body = json!({"metadata": {"ideType": "IDE_UNSPECIFIED", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"}});
    let reply = post(load_url(ep), access_token, &body, "loadCodeAssist")?;
    reply
        .get("cloudaicompanionProject")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| DriverError::Invalid("gemini: no code assist project for this account".to_string()))
}

pub fn fetch_quota(ep: &GeminiEndpoints, access_token: &str, project: &str) -> Result<Value, DriverError> {
    post(quota_url(ep), access_token, &json!({"project": project, "userAgent": "swapd/0.1"}), "retrieveUserQuota")
}

/// One `Scoped` window per named bucket. `pct` is used, not remaining;
/// `used`/`limit` only when the server sent an amount to derive them from;
/// no pace (a bucket has no start).
pub fn windows_at(raw: &Value) -> Vec<Window> {
    let mut out = Vec::new();
    let Some(buckets) = raw.get("buckets").and_then(Value::as_array) else { return out };
    for bucket in buckets {
        let name = bucket
            .get("modelId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| bucket.get("tokenType").and_then(Value::as_str).filter(|s| !s.is_empty()));
        let Some(name) = name else { continue };
        let fraction = bucket.get("remainingFraction").and_then(Value::as_f64);
        let amount = bucket.get("remainingAmount").and_then(Value::as_str).and_then(|s| s.parse::<f64>().ok());
        let Some(remaining) = fraction else { continue };
        let pct = ((1.0 - remaining.clamp(0.0, 1.0)) * 100.0).clamp(0.0, 100.0);
        let (used, limit) = match amount {
            Some(amount) if remaining > 0.0 => {
                let limit = (amount / remaining).round();
                (Some(limit - amount), Some(limit))
            }
            _ => (None, None),
        };
        out.push(Window {
            kind: WindowKind::Scoped,
            name: Some(name.to_string()),
            pct,
            resets_at: bucket.get("resetTime").and_then(Value::as_str).map(str::to_string),
            pace: None,
            used,
            limit,
            currency: None,
        });
    }
    out
}

pub fn usage(driver: &GeminiDriver, login: &Login) -> Result<Usage, DriverError> {
    if oauth::is_expired(login, oauth::now_ms()) {
        return Err(DriverError::NeedsRefresh);
    }
    let access_token = oauth::access_token(login).ok_or_else(|| DriverError::Invalid("no access token".to_string()))?;
    let key = identity::identity_offline(login).map(|i| i.email).unwrap_or_default();
    let memoised = driver.project_memo.lock().ok().and_then(|m| m.get(&key).cloned());
    let project = match memoised {
        Some(p) => p,
        None => {
            let p = load_project(&driver.endpoints, &access_token)?;
            if let Ok(mut m) = driver.project_memo.lock() {
                m.insert(key, p.clone());
            }
            p
        }
    };
    let raw = fetch_quota(&driver.endpoints, &access_token, &project)?;
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    Ok(Usage { windows: windows_at(&raw), fetched_at })
}
```

- [ ] **Step 5: Run the tests** — `cargo test driver::gemini` → PASS (`remainingAmount 180 / remainingFraction 0.9 = limit 200`, `used 20`).

- [ ] **Step 6: Amend the spec §5** — replace the "**`project`.**" paragraph with: "`project` comes from one `loadCodeAssist` call per account, memoised in the driver for the process lifetime (`project_memo`); it is never persisted, so the slot row stays provider-neutral." Delete §8's mention of `slots.json` gaining a field (there is none).

- [ ] **Step 7: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/driver/gemini/usage.rs src/driver/gemini/fixtures docs/superpowers/specs/2026-09-10-swapd-gemini-driver-design.md
git commit -m "gemini: usage is code assist's quota buckets, one scoped window per model"
```

---

### Task 6: Run profiles, the igniter, and the shared seed marker

**Files:**
- Create: `src/driver/marker.rs`
- Modify: `src/driver/mod.rs` (add `pub mod marker;`), `src/driver/claude/run.rs:396-412` (use `marker::{read, write}`; delete the private copies)
- Create/replace: `src/driver/gemini/run.rs`

**Interfaces:**
- Consumes: `RunProfile::new(env: Vec<(String,String)>, unset: Vec<String>, dir: PathBuf)`, `RunProfile.read_back: Option<ReadBack>`, `live::Envelope`, `identity::expires_at`, `usage::usage`, `write_private_file`.
- Produces:
  - `marker::MARKER = ".swapd-seeded"`, `marker::read(dir: &Path) -> Option<String>`, `marker::write(dir: &Path, fingerprint: &str) -> Result<(), DriverError>`.
  - `run::CLI_OVERRIDE_ENV = "SWAPD_GEMINI_CLI"`, `run::resolve_cli(env) -> Option<PathBuf>` (the override when it names an executable file, else the first executable `gemini` / `gemini.cmd` on `PATH`).
  - `run::profile_dir(env, slot) = <swapd home>/profiles/gemini/<slot>`.
  - `run::run_profile(env, slot, login) -> Result<RunProfile, DriverError>`: seeds `<dir>/.gemini/{oauth_creds.json (0600), google_accounts.json, settings.json}` when the marker is absent or names another fingerprint; env `[("GEMINI_CLI_HOME", dir)]`; unset `["GEMINI_API_KEY","GOOGLE_API_KEY","GOOGLE_APPLICATION_CREDENTIALS","GOOGLE_GENAI_USE_VERTEXAI","GOOGLE_CLOUD_PROJECT","GEMINI_FORCE_ENCRYPTED_FILE_STORAGE"]`; `read_back` returns the profile's pair as a rotation when its `expiry_date` is later than the seeded login's.
  - `run::commit_profile(env, slot, login)` writes the marker; `run::forget_profile(env, slot)` removes the profile dir (absent is fine).
  - `run::ignite(driver, env, slot, login) -> Result<IgniteOutcome, DriverError>`: the usage call. `Ok(_)` → `exit_code 0`; `Err(TokenDead | NeedsRefresh)` → `exit_code 41` (the CLI's `FatalAuthenticationError`); any other `Err` propagates. `rotated: None`. No process is spawned.

- [ ] **Step 1: Lift the marker** — create `src/driver/marker.rs`:

```rust
//! The `.swapd-seeded` marker a run profile carries: the fingerprint of the
//! credential swapd last seeded into it, so a later launch can tell "never
//! seeded" and "seeded something else" from "seeded this". Shared by every
//! driver with per-slot profiles.

use std::fs;
use std::path::{Path, PathBuf};

use crate::driver::claude::live::write_private_file;
use crate::driver::DriverError;

pub const MARKER: &str = ".swapd-seeded";

fn path(dir: &Path) -> PathBuf {
    dir.join(MARKER)
}

pub fn read(dir: &Path) -> Option<String> {
    fs::read_to_string(path(dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn write(dir: &Path, fingerprint: &str) -> Result<(), DriverError> {
    write_private_file(&path(dir), fingerprint)
}
```

In `src/driver/claude/run.rs` delete `SEED_MARKER`, `marker_path`, `read_marker`, `write_marker` and replace their uses with `crate::driver::marker::{read, write}` (keep the call sites' semantics: `read_marker(&dir)` → `marker::read(&dir)`, `write_marker(&dir, fp)` → `marker::write(&dir, fp)`). Confirm `read_marker`'s previous body did the same trim/filter (lines 400-407) — if it did not filter empty, keep the new behaviour and note it in the report. Run `cargo test driver::claude::run` → PASS before going on.

- [ ] **Step 2: Write the failing tests** at the end of `gemini/run.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::gemini::oauth::GeminiEndpoints;
    use crate::driver::gemini::tests::{env_with, temp_home};
    use std::fs;

    fn login(expiry_ms: i64) -> Login {
        Login { bytes: format!(r#"{{"oauth_creds":{{"access_token":"at-1","refresh_token":"rt-1","expiry_date":{expiry_ms}}},"google_account":"you@example.com"}}"#) }
    }

    #[test]
    fn a_profile_is_seeded_once_and_points_gemini_cli_home_at_itself() {
        let home = temp_home();
        let env = env_with(&home, []);
        let profile = run_profile(&env, 3, &login(1_000)).unwrap();
        let dir = profile_dir(&env, 3);
        assert_eq!(profile.dir, dir);
        assert_eq!(profile.env, vec![("GEMINI_CLI_HOME".to_string(), dir.to_str().unwrap().to_string())]);
        assert!(profile.unset.contains(&"GEMINI_API_KEY".to_string()));
        let creds: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap()).unwrap();
        assert_eq!(creds["refresh_token"], "rt-1");
        let accounts: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(".gemini").join("google_accounts.json")).unwrap()).unwrap();
        assert_eq!(accounts["active"], "you@example.com");
        let settings: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(".gemini").join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["security"]["auth"]["selectedType"], "oauth-personal");
        assert_eq!(crate::driver::marker::read(&dir).as_deref(), Some(login(1_000).fingerprint().as_str()));

        // The CLI rotates in place; a second run_profile with the SAME login must not re-seed over it.
        fs::write(dir.join(".gemini").join("oauth_creds.json"), r#"{"access_token":"at-9","refresh_token":"rt-1","expiry_date":2000}"#).unwrap();
        let _ = run_profile(&env, 3, &login(1_000)).unwrap();
        let creds: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap()).unwrap();
        assert_eq!(creds["access_token"], "at-9", "not re-seeded");
    }

    #[test]
    fn a_different_login_re_seeds_the_profile() {
        let home = temp_home();
        let env = env_with(&home, []);
        let _ = run_profile(&env, 1, &login(1_000)).unwrap();
        let other = Login { bytes: r#"{"oauth_creds":{"access_token":"b","refresh_token":"rt-other","expiry_date":5},"google_account":"other@example.com"}"#.to_string() };
        let _ = run_profile(&env, 1, &other).unwrap();
        let dir = profile_dir(&env, 1);
        let creds: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap()).unwrap();
        assert_eq!(creds["refresh_token"], "rt-other");
        assert_eq!(crate::driver::marker::read(&dir).as_deref(), Some(other.fingerprint().as_str()));
    }

    #[test]
    fn read_back_reports_a_later_generation_and_nothing_otherwise() {
        let home = temp_home();
        let env = env_with(&home, []);
        let profile = run_profile(&env, 2, &login(1_000)).unwrap();
        let read_back = profile.read_back.as_ref().unwrap();
        assert!(read_back().unwrap().is_none(), "unchanged profile: no rotation");
        let dir = profile_dir(&env, 2);
        fs::write(dir.join(".gemini").join("oauth_creds.json"), r#"{"access_token":"at-2","refresh_token":"rt-1","expiry_date":9000}"#).unwrap();
        let rotated = read_back().unwrap().expect("a later expiry is a rotation");
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["access_token"], "at-2");
        assert_eq!(v["google_account"], "you@example.com");
    }

    #[test]
    fn commit_and_forget_profile() {
        let home = temp_home();
        let env = env_with(&home, []);
        let _ = run_profile(&env, 4, &login(1_000)).unwrap();
        let rotated = login(9_000);
        commit_profile(&env, 4, &rotated).unwrap();
        assert_eq!(crate::driver::marker::read(&profile_dir(&env, 4)).as_deref(), Some(rotated.fingerprint().as_str()));
        forget_profile(&env, 4).unwrap();
        assert!(!profile_dir(&env, 4).exists());
        forget_profile(&env, 4).unwrap();
    }

    #[test]
    fn ignite_is_the_usage_call() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(200).body(include_str!("fixtures/load_code_assist.json"));
        });
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:retrieveUserQuota");
            then.status(200).body(include_str!("fixtures/quota.json"));
        });
        let driver = GeminiDriver::new(GeminiEndpoints { oauth: server.base_url(), cloudcode: server.base_url() });
        let home = temp_home();
        let env = env_with(&home, []);
        let outcome = ignite(&driver, &env, 1, &login(4_102_444_800_000)).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.rotated.is_none());
        // An expired login: 41, the CLI's FatalAuthenticationError code.
        let outcome = ignite(&driver, &env, 1, &login(1_000)).unwrap();
        assert_eq!(outcome.exit_code, 41);
    }

    #[test]
    fn resolve_cli_honours_the_override_then_path() {
        let home = temp_home();
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let exe = bin.join(if cfg!(windows) { "gemini.cmd" } else { "gemini" });
        fs::write(&exe, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_var = std::env::join_paths([bin.as_path()]).unwrap();
        let env = env_with(&home, [("PATH", path_var.to_str().unwrap())]);
        assert_eq!(resolve_cli(&env), Some(exe.clone()));
        let env = env_with(&home, [("PATH", path_var.to_str().unwrap()), (CLI_OVERRIDE_ENV, exe.to_str().unwrap())]);
        assert_eq!(resolve_cli(&env), Some(exe));
        let env = env_with(&home, [(CLI_OVERRIDE_ENV, home.path().join("missing").to_str().unwrap())]);
        assert_eq!(resolve_cli(&env), None);
    }
}
```

- [ ] **Step 3: Run to verify they fail** — `cargo test driver::gemini::run` → FAIL.

- [ ] **Step 4: Implement `gemini/run.rs`**

```rust
//! Per-slot run profiles for the Gemini CLI, and the igniter.
//!
//! A profile is a `GEMINI_CLI_HOME` of its own: the CLI keeps everything
//! under `<home>/.gemini/`, so pointing that variable at
//! `<swapd home>/profiles/gemini/<slot>` gives the slot a private login. The
//! profile is seeded once per credential generation (`driver::marker`); the
//! CLI refreshes in place, and the read-back carries a later generation
//! home. The igniter is the usage call (#13 ruling 1): it exercises the same
//! bearer token as a real turn, costs no model tokens, and answers quota.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::driver::claude::live::write_private_file;
use crate::driver::gemini::live::{Envelope, OAUTH_PERSONAL};
use crate::driver::gemini::{identity, usage, GeminiDriver};
use crate::driver::marker;
use crate::driver::{DriverError, Env, IgniteOutcome, Login, RunProfile};

pub const CLI_OVERRIDE_ENV: &str = "SWAPD_GEMINI_CLI";

/// Variables that make the CLI bypass the OAuth login a profile selects.
pub const AUTH_OVERRIDE_ENV_VARS: [&str; 6] = [
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE",
];

fn binary_names() -> &'static [&'static str] {
    if cfg!(windows) { &["gemini.cmd", "gemini.exe", "gemini"] } else { &["gemini"] }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else { return false };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `SWAPD_GEMINI_CLI` when it names an executable file, else the first
/// executable `gemini` on `PATH`. Nothing else: the CLI has no well-known
/// install location swapd should guess at.
pub fn resolve_cli(env: &Env) -> Option<PathBuf> {
    if let Some(explicit) = env.vars.get(CLI_OVERRIDE_ENV).filter(|s| !s.is_empty()) {
        let path = PathBuf::from(explicit);
        return is_executable(&path).then_some(path);
    }
    let path_var = env.vars.get("PATH")?;
    for dir in std::env::split_paths(path_var) {
        for name in binary_names() {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn profile_dir(env: &Env, slot: u32) -> PathBuf {
    env.home.join("profiles").join("gemini").join(slot.to_string())
}

fn create_private_dir_all(dir: &Path) -> Result<(), DriverError> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn seed(dir: &Path, envelope: &Envelope) -> Result<(), DriverError> {
    let gemini = dir.join(".gemini");
    create_private_dir_all(&gemini)?;
    write_private_file(&gemini.join("oauth_creds.json"), &Value::Object(envelope.oauth_creds.clone()).to_string())?;
    let accounts = json!({"active": envelope.google_account.clone(), "old": []});
    fs::write(gemini.join("google_accounts.json"), accounts.to_string())?;
    // The auth picker never opens for a profile: the mode is decided.
    let settings_path = gemini.join("settings.json");
    let mut settings = fs::read_to_string(&settings_path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v { Value::Object(m) => Some(m), _ => None })
        .unwrap_or_default();
    let security = settings.entry("security").or_insert_with(|| json!({}));
    if let Value::Object(security) = security {
        let auth = security.entry("auth").or_insert_with(|| json!({}));
        if let Value::Object(auth) = auth {
            auth.insert("selectedType".to_string(), Value::from(OAUTH_PERSONAL));
        }
    }
    fs::write(&settings_path, Value::Object(settings).to_string())?;
    Ok(())
}

/// The profile's current pair as a login, `None` when it holds no credential.
fn read_profile_login(dir: &Path) -> Result<Option<Login>, DriverError> {
    let gemini = dir.join(".gemini");
    let creds = match fs::read_to_string(gemini.join("oauth_creds.json")) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let Ok(Value::Object(oauth_creds)) = serde_json::from_str::<Value>(&creds) else {
        return Err(DriverError::Invalid("profile oauth_creds.json is not a JSON object".to_string()));
    };
    let google_account = fs::read_to_string(gemini.join("google_accounts.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get("active").and_then(Value::as_str).map(str::to_string))
        .filter(|s| !s.is_empty());
    Ok(Some(Envelope { oauth_creds, google_account }.to_login()))
}

pub fn run_profile(env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError> {
    let envelope = Envelope::parse(&login.bytes)?;
    let dir = profile_dir(env, slot);
    create_private_dir_all(&dir)?;
    let dir_str = dir
        .to_str()
        .ok_or_else(|| DriverError::Invalid("profile dir is not valid UTF-8".to_string()))?
        .to_string();

    let seeded = login.fingerprint();
    let needs_seeding = match marker::read(&dir) {
        Some(previous) => previous != seeded,
        None => true,
    };
    if needs_seeding {
        seed(&dir, &envelope)?;
        marker::write(&dir, &seeded)?;
    }
    let baseline_expiry = identity::expires_at(login);

    let mut profile = RunProfile::new(
        vec![("GEMINI_CLI_HOME".to_string(), dir_str)],
        AUTH_OVERRIDE_ENV_VARS.iter().map(|v| v.to_string()).collect(),
        dir.clone(),
    );
    profile.read_back = Some(Box::new(move || {
        let Some(current) = read_profile_login(&dir)? else { return Ok(None) };
        let later = match (identity::expires_at(&current), baseline_expiry) {
            (Some(now), Some(then)) => now > then,
            (Some(_), None) => true,
            _ => false,
        };
        Ok(later.then_some(current))
    }));
    Ok(profile)
}

pub fn commit_profile(env: &Env, slot: u32, login: &Login) -> Result<(), DriverError> {
    let dir = profile_dir(env, slot);
    create_private_dir_all(&dir)?;
    marker::write(&dir, &login.fingerprint())
}

/// Nothing lives outside the directory (no keychain migration on this store).
pub fn forget_profile(env: &Env, slot: u32) -> Result<(), DriverError> {
    match fs::remove_dir_all(profile_dir(env, slot)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The CLI's `FatalAuthenticationError` exit code (`utils/errors.ts:71-124`),
/// synthesised so `auto`'s dead-strike logic needs no Gemini branch.
const EXIT_AUTH_FAILED: i32 = 41;

pub fn ignite(driver: &GeminiDriver, _env: &Env, _slot: u32, login: &Login) -> Result<IgniteOutcome, DriverError> {
    match usage::usage(driver, login) {
        Ok(_) => Ok(IgniteOutcome { exit_code: 0, rotated: None }),
        Err(DriverError::TokenDead | DriverError::NeedsRefresh) => Ok(IgniteOutcome { exit_code: EXIT_AUTH_FAILED, rotated: None }),
        Err(e) => Err(e),
    }
}
```

- [ ] **Step 5: Run the tests** — `cargo test driver::gemini` and `cargo test driver::claude::run` → PASS.

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/driver/marker.rs src/driver/mod.rs src/driver/claude/run.rs src/driver/gemini/run.rs
git commit -m "gemini: per-slot GEMINI_CLI_HOME profiles, the usage call as igniter, one seed marker for both drivers"
```

---

### Task 7: Registry, doctor, end-to-end verbs, release note

**Files:**
- Modify: `src/driver/mod.rs:354-370` (`registry`, `provider_ids`), its tests (`registry_holds_the_claude_driver`, `provider_ids_name_the_registry`)
- Modify: `src/main.rs:521-560` (`doctor` iterates the registry) and `ProviderStatus` (+ `note: Option<String>`), `src/main.rs:712-717` (`locate_claude` removed)
- Create: `tests/gemini.rs`
- Modify: `CHANGELOG.md`, `README.md` (the providers table / sentence, if one exists — otherwise nothing)

**Interfaces:**
- Consumes: `GeminiDriver::default_for_platform(env)`, `Driver::installed`, `cli_version(path)`.
- Produces: `driver::provider_ids() == ["claude", "gemini"]`; `doctor --json` `providers[]` has one entry per registry driver with `note` = `"GEMINI_FORCE_ENCRYPTED_FILE_STORAGE is set; encrypted credential storage is not supported"` for gemini when that variable is non-empty, else absent.

- [ ] **Step 1: Registry tests** — in `src/driver/mod.rs` tests, change `provider_ids_name_the_registry` / `registry_holds_the_claude_driver` to assert both ids in order `["claude", "gemini"]` and `by_id("gemini", …).is_some()`; add:

```rust
    #[test]
    fn gemini_supports_every_verb_but_add_token() {
        let home = tempfile::TempDir::new().unwrap();
        let env = Env { home: home.path().to_path_buf(), vars: Default::default() };
        let caps = by_id("gemini", &env).unwrap().capabilities();
        assert_eq!(caps, Caps { ignite: true, add_token: false, prefer: true, refresh: true, run: true });
    }
```

- [ ] **Step 2: Integration test** — `tests/gemini.rs`:

```rust
//! The verbs over a Gemini login in a throwaway GEMINI_CLI_HOME. No network:
//! nothing here fetches usage (the list is served from an empty store), and
//! the URL overrides point at an unroutable address so an accidental request
//! fails at once.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const CREDS_A: &str = r#"{"access_token":"at-a","refresh_token":"rt-a","expiry_date":4102444800000,"token_type":"Bearer"}"#;
const CREDS_B: &str = r#"{"access_token":"at-b","refresh_token":"rt-b","expiry_date":4102444800000,"token_type":"Bearer"}"#;

fn seed(home: &Path, creds: &str, email: &str) {
    let dir = home.join(".gemini");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("oauth_creds.json"), creds).unwrap();
    fs::write(dir.join("google_accounts.json"), format!(r#"{{"active":"{email}","old":[]}}"#)).unwrap();
    fs::write(dir.join("settings.json"), r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#).unwrap();
}

fn swapd(home: &TempDir, gemini_home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("swapd").unwrap();
    cmd.env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("SWAPD_HOME", home.path().join("swapd"))
        .env("SWAPD_SECRETS", "file")
        .env("SWAPD_LIVE_STORE", "file")
        .env("GEMINI_CLI_HOME", gemini_home.path())
        .env("SWAPD_URL_GOOGLE_OAUTH", "http://127.0.0.1:1")
        .env("SWAPD_URL_CLOUDCODE", "http://127.0.0.1:1")
        .env("SWAPD_URL_ANTHROPIC_API", "http://127.0.0.1:1")
        .env("SWAPD_URL_PLATFORM", "http://127.0.0.1:1");
    cmd
}

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).expect("json output")
}

#[test]
fn add_captures_the_live_gemini_login_and_list_shows_it() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    seed(gh.path(), CREDS_A, "a@example.com");
    let out = swapd(&home, &gh).args(["--provider", "gemini", "add", "--json"]).assert().success();
    let added = json(&out.get_output().stdout);
    assert_eq!(added["slot"], 1);
    let out = swapd(&home, &gh).args(["--provider", "gemini", "list", "--json"]).assert().success();
    let list = json(&out.get_output().stdout);
    let provider = &list["providers"][0];
    assert_eq!(provider["provider"], "gemini");
    assert_eq!(provider["activeSlot"], 1);
    assert_eq!(provider["accounts"][0]["email"], "a@example.com");
}

#[test]
fn switch_replaces_the_pair_and_rotates_the_old_email() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    seed(gh.path(), CREDS_A, "a@example.com");
    swapd(&home, &gh).args(["--provider", "gemini", "add", "--json"]).assert().success();
    seed(gh.path(), CREDS_B, "b@example.com");
    swapd(&home, &gh).args(["--provider", "gemini", "add", "--json"]).assert().success();
    swapd(&home, &gh).args(["--provider", "gemini", "switch", "1", "--json"]).assert().success();
    let creds: Value = serde_json::from_str(&fs::read_to_string(gh.path().join(".gemini").join("oauth_creds.json")).unwrap()).unwrap();
    assert_eq!(creds["refresh_token"], "rt-a");
    let accounts: Value = serde_json::from_str(&fs::read_to_string(gh.path().join(".gemini").join("google_accounts.json")).unwrap()).unwrap();
    assert_eq!(accounts["active"], "a@example.com");
    assert_eq!(accounts["old"][0], "b@example.com");
    assert!(!gh.path().join(".gemini").join(".swapd-live.lock").exists());
}

#[test]
fn doctor_lists_gemini_and_flags_encrypted_storage() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    let out = swapd(&home, &gh).env("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", "true").args(["doctor", "--json"]).assert().success();
    let doc = json(&out.get_output().stdout);
    let gemini = doc["providers"].as_array().unwrap().iter().find(|p| p["provider"] == "gemini").expect("gemini row");
    assert_eq!(gemini["installed"], false);
    assert!(gemini["note"].as_str().unwrap().contains("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE"));
    let claude = doc["providers"].as_array().unwrap().iter().find(|p| p["provider"] == "claude").expect("claude row");
    assert!(claude.get("note").is_none() || claude["note"].is_null());
}

#[test]
fn add_token_is_refused_for_gemini() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    swapd(&home, &gh)
        .args(["--provider", "gemini", "add-token", "-", "--json"])
        .write_stdin("anything")
        .assert()
        .failure();
}
```

If `add`'s JSON output names the slot differently from `"slot"`, read `src/cmd/add.rs`'s `AddOutput` and use its field. If `list --json` nests differently, read `tests/list_refresh.rs` for the shape the Claude tests assert and mirror it.

- [ ] **Step 3: Run to verify they fail** — `cargo test --test gemini` → FAIL (`unknown provider: gemini`).

- [ ] **Step 4: Implement**

`src/driver/mod.rs`:
```rust
pub fn registry(env: &Env) -> Vec<Box<dyn Driver>> {
    vec![
        Box::new(claude::live::ClaudeDriver::default_for_platform(env)),
        Box::new(gemini::GeminiDriver::default_for_platform(env)),
    ]
}

pub fn provider_ids() -> &'static [&'static str] {
    &["claude", "gemini"]
}
```

`src/main.rs` doctor: replace the `locate_claude` block with

```rust
    let providers = driver::registry(&env)
        .iter()
        .map(|d| {
            let path = d.installed(&env).map(|p| p.to_string_lossy().into_owned());
            let version = path.as_deref().and_then(cli_version);
            let note = match d.id() {
                "gemini"
                    if env
                        .vars
                        .get("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE")
                        .is_some_and(|v| !v.is_empty()) =>
                {
                    Some("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE is set; encrypted credential storage is not supported".to_string())
                }
                _ => None,
            };
            ProviderStatus { provider: d.id().to_string(), installed: path.is_some(), path, version, note }
        })
        .collect();
```

add `#[serde(skip_serializing_if = "Option::is_none")] note: Option<String>` to `ProviderStatus`, print the note in the text branch (`println!("  note: {note}")` after the provider line when present), and delete `locate_claude`. Check `tests/cli_basics.rs`'s doctor test still passes (it may assert `providers.len() == 1` — update it to find the `claude` row instead).

`CHANGELOG.md`, under `## Unreleased` in the section the other entries use:
```
- Gemini CLI accounts: `--provider gemini` for list, add, switch, refresh, ignite, run and auto, over the CLI's oauth-personal login.
```

- [ ] **Step 5: Run everything** — `cargo test` → PASS; `cargo run -q -- doctor --json | python3 -m json.tool | grep -A4 gemini` on the dev machine prints the row (this touches the real `PATH` only, never `~/.gemini`).

- [ ] **Step 6: Gates and commit**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings && cargo test
git add src/driver/mod.rs src/main.rs tests/gemini.rs tests/cli_basics.rs CHANGELOG.md README.md
git commit -m "gemini: the driver joins the registry; doctor reports every provider"
```

---

### Task 8: Infinitus shows the Gemini fleet (separate repo, separate PR)

**Files (in `~/death/limitless`, worktree `~/death/limitless-gemini`, branch `swapd-gemini-fleet` off `origin/main`):**
- Modify: `Sources/InfinitusCore/Engines/Swapd/SwapdEngine.swift` — `addCurrent()` / `addToken` currently hard-code `provider: .claude`; `addCurrent` gains no new API (the app's add flow is Claude-only today) — nothing to change unless the engine protocol already carries a provider.
- Test: `Tests/InfinitusCoreTests/SwapdEngineTests.swift`

`SwapdMapping.provider(for: "gemini")` already yields `.gemini` and `fleets(from:)` builds one `EngineFleet` per provider, so a swapd list with a gemini provider renders without code. The task is a **test** proving it plus the CHANGELOG line:

- [ ] **Step 1: Test** — add to `SwapdMappingTests`:

```swift
    func testAGeminiProviderBecomesItsOwnFleet() throws {
        let json = """
        {"schemaVersion":1,"providers":[
          {"provider":"claude","installed":true,"activeSlot":1,"accounts":[{"slot":1,"email":"a@x","organizationName":"","organizationUuid":"","active":true,"usageStatus":"ok","windows":[]}]},
          {"provider":"gemini","installed":true,"activeSlot":2,"accounts":[{"slot":2,"email":"g@x","organizationName":"","organizationUuid":"","active":true,"usageStatus":"ok","windows":[{"kind":"scoped","name":"gemini-2.5-pro","pct":75,"resetsAt":"2026-09-11T00:00:00Z"}]}]}
        ]}
        """
        let list = try JSONDecoder().decode(SwapdList.self, from: Data(json.utf8))
        let fleets = SwapdMapping.fleets(from: list)
        XCTAssertEqual(fleets.map(\.provider), [.claude, .gemini])
        XCTAssertEqual(fleets[1].activeNumber, 2)
        XCTAssertEqual(fleets[1].accounts.first?.email, "g@x")
    }
```

Mirror the exact JSON field names the existing `SwapdMappingTests` fixtures use (read one first; the `windows` element shape above is the swapd `contract::Window` in camelCase).

- [ ] **Step 2: Run** — `swift test --filter SwapdMappingTests` → PASS (or fix the fixture names until it does; if it fails on a real gap, that gap is the task).
- [ ] **Step 3: CHANGELOG** (Infinitus, `### Mac` under `## Unreleased`): `- swapd engine: a Gemini CLI fleet shows beside the Claude one when swapd reports it.`
- [ ] **Step 4: Commit** (trailer `Co-Authored-By: Claude Code <noreply@anthropic.com>`), push `swapd-gemini-fleet`, hand off to Infi: "merge swapd-gemini-fleet at <sha> — --squash".

---

## Self-review

- **Spec coverage:** §2 givens → Tasks 2–6 cite them; §3 live login (envelope, NoLogin/Invalid/Unsupported, lock, write order, config text, can_activate, is_api_key) → Task 2; §4 identity/fingerprint → Tasks 1, 3; §5 usage (NeedsRefresh, 401/403, 429 RetryInfo, project, bucket mapping, no pace) → Task 5; §6 refresh (form body, kept refresh token, invalid_grant, expires_at) → Task 4; §7 profiles/igniter/forget/capabilities → Task 6; §8 core touchpoints (registry, endpoints, doctor, Infinitus) → Tasks 4, 7, 8; §9 testing (unit, live-store, httpmock, stub CLI — the stub CLI is not needed since ignite spawns nothing; `resolve_cli` is unit-tested instead) → each task; §10 rulings → Tasks 5, 6.
- **Placeholders:** the two `<copy verbatim from the source>` in Task 4 are deliberate (the secret must not live in this file) with the exact fetch instruction.
- **Type consistency:** `GeminiEndpoints { oauth, cloudcode }` (Task 4) is what Tasks 2, 5, 6 construct; `Envelope::parse/to_login` (Task 2) used by 3–6; `marker::{read, write}` (Task 6) used by both drivers; `run::{resolve_cli, profile_dir, run_profile, commit_profile, forget_profile, ignite}` match `gemini/mod.rs`'s seam (Task 2).
