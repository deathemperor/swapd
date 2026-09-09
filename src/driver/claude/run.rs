//! Per-slot run profiles and the igniter.
//!
//! A run profile is a `CLAUDE_CONFIG_DIR` of its own: Claude Code reads its
//! whole config — credential item, `.claude.json`, settings, skills — relative
//! to that directory, so a slot can be *run* without touching the live login at
//! all. Port of cswap `session.py:76-83` (the default share set) and
//! `session.py:232-243` (the keychain item a config dir derives, already in
//! `paths::keychain_service_name`).
//!
//! Profiles persist, and swapd seeds them **once**: a profile that has already
//! run holds the *newest* generation of the account's token family, because
//! Claude Code rotates in place and nothing syncs that back. Re-seeding on every
//! launch would overwrite it with the older stored copy — whose refresh token
//! the server has already spent. Hence the `.swapd-seeded` fingerprint marker,
//! and the read-back that hands a rotation to the caller.
//!
//! Seeding writes a plaintext 0600 `.credentials.json` and **never** the
//! profile's hashed keychain item — deliberately, including on macOS
//! (`session.py`'s module docstring). The plaintext fallback is Claude Code's
//! only credential mechanism on Linux, a stable contract, and it migrates the
//! seed into its hashed item on first write. Writing that item ourselves would
//! couple swapd to Claude Code's internal storage format and naming, where a
//! mismatch is a hard "logged out" rather than a harmless stale entry.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::driver::claude::live::{self, ClaudeDriver};
use crate::driver::claude::paths;
use crate::driver::{DriverError, Env, Login, RunProfile};

/// The user customizations that follow an account into its profile
/// (`session.py:76-83`, cswap's default share set). Files and directories
/// alike; anything absent is simply skipped.
const SHARED_ITEMS: [&str; 6] = [
    "settings.json",
    "keybindings.json",
    "CLAUDE.md",
    "skills",
    "commands",
    "agents",
];

/// Well-known install locations for the `claude` binary, in the order swapd's
/// doctor probes them, relative to `$HOME`.
const CANDIDATES: [&str; 4] = [
    ".claude/local/claude",
    ".local/bin/claude",
    "/opt/homebrew/bin/claude",
    "/usr/local/bin/claude",
];

/// Variables that make Claude Code bypass account OAuth entirely
/// (`session.py:191-199`, verified against claude 2.1.175).
///
/// Scrubbed from the child's environment: running slot N is an explicit request
/// for *that account*, so letting an exported API key silently hijack the run
/// would defeat the command — and worse, would report the wrong account's usage
/// as this slot's.
pub const AUTH_OVERRIDE_ENV_VARS: [&str; 5] = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
];

/// Records the fingerprint of the credential swapd last seeded into a profile,
/// so a later launch can tell "never seeded" and "seeded something else" from
/// "already holds this login, possibly rotated past it".
const SEED_MARKER: &str = ".swapd-seeded";

/// One `claude -p` run is a real model turn: it can sit in a queue, so the
/// budget is generous. It is bounded all the same — an igniter that never
/// returns would wedge the verb that called it.
const IGNITE_TIMEOUT: Duration = Duration::from_secs(120);

/// The `claude` binary for this machine: `PATH` first, then the well-known
/// install locations.
///
/// `path_var` and `home` are passed in rather than read from the process
/// environment, so `ignite` can resolve against the environment its child will
/// actually run under while `doctor` resolves against the process's.
pub fn find_claude(path_var: Option<&str>, home: &Path) -> Option<PathBuf> {
    if let Some(path_var) = path_var {
        for dir in std::env::split_paths(path_var) {
            let candidate = dir.join(binary_name());
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    candidate_paths(home).into_iter().find(|p| is_executable(p))
}

/// An existing file we could actually exec. A non-executable `claude` on `PATH`
/// (a stray text file, a half-finished install, a `claude` *directory*) must not
/// shadow a real one further along it — reporting "installed" for something that
/// cannot run turns every later failure into a mystery.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(windows)]
fn binary_name() -> &'static str {
    "claude.exe"
}

#[cfg(not(windows))]
fn binary_name() -> &'static str {
    "claude"
}

/// The well-known install locations as absolute paths ($HOME-relative entries
/// resolved against `home`).
fn candidate_paths(home: &Path) -> Vec<PathBuf> {
    CANDIDATES
        .iter()
        .map(|c| {
            let path = Path::new(c);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                home.join(path)
            }
        })
        .collect()
}

/// `path_var` with the candidates' directories appended, so a `claude` that
/// only exists in a well-known location can still be found by anything the
/// igniter's child spawns in turn (Claude Code re-execs itself).
fn widen_path(path_var: Option<&str>, home: &Path) -> std::ffi::OsString {
    let mut dirs: Vec<PathBuf> = path_var
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    for candidate in candidate_paths(home) {
        if let Some(parent) = candidate.parent() {
            if !dirs.iter().any(|d| d == parent) {
                dirs.push(parent.to_path_buf());
            }
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

/// The per-slot profile directory: `<swapd home>/profiles/claude/<slot>`.
fn profile_dir(env: &Env, slot: u32) -> PathBuf {
    env.home
        .join("profiles")
        .join("claude")
        .join(slot.to_string())
}

/// Build (or reuse) slot `slot`'s run profile and return the environment that
/// selects it.
///
/// Seeds a 0600 `<dir>/.credentials.json` and splices the envelope's
/// `oauthAccount` into `<dir>/.claude.json`, which is where Claude Code reads
/// its config from when `CLAUDE_CONFIG_DIR` is set (`paths::config_json`). The
/// live login is never touched, and neither is the profile's hashed keychain
/// item (see the module docs).
///
/// **Seeds at most once per credential generation.** A profile that already
/// holds a credential is left alone unless the marker says it was seeded from a
/// *different* login: after a run, the profile — not swapd's store — holds the
/// newest generation of the token family, and overwriting it would install a
/// refresh token the server has already spent.
pub fn run_profile(
    driver: &ClaudeDriver,
    env: &Env,
    slot: u32,
    login: &Login,
) -> Result<RunProfile, DriverError> {
    let dir = profile_dir(env, slot);
    // 0700 all the way down: the tree holds credentials, and a mode set only on
    // the leaf leaves `profiles/claude/` itself world-listable.
    create_private_dir_all(&dir)?;
    // The keychain service name hashes this exact string, so Claude Code and
    // swapd must agree on it byte for byte — a non-UTF-8 path has no such
    // string, and guessing one would key a different item.
    let dir_str = dir
        .to_str()
        .ok_or_else(|| DriverError::Invalid("profile dir is not valid UTF-8".to_string()))?
        .to_string();

    copy_share_set(env, &dir)?;

    // The environment the profile *is*: same process env, but pointed at the
    // profile — on BOTH axes.
    //
    // `CLAUDE_SECURESTORAGE_CONFIG_DIR` is set rather than merely unset:
    // `RunProfile.env` is a list of overrides a caller layers over the process
    // environment, and such a list can add a variable but never remove one. A
    // user whose shell exports that variable would otherwise have the child
    // resolve secure storage to the *live* item while `CLAUDE_CONFIG_DIR` named
    // the profile — succeeding as the wrong account. Pointed at the profile dir
    // it names exactly the item Claude Code migrates the seed into, so the two
    // axes cannot disagree.
    let overrides = [
        ("CLAUDE_CONFIG_DIR".to_string(), dir_str.clone()),
        ("CLAUDE_SECURESTORAGE_CONFIG_DIR".to_string(), dir_str),
    ];
    let mut vars = env.vars.clone();
    for (key, value) in &overrides {
        vars.insert(key.clone(), value.clone());
    }
    let profile_env = Env {
        home: env.home.clone(),
        vars,
    };

    let (credential, oauth_account) = live::split_envelope(&login.bytes)?;
    // Session mode is OAuth-shaped: it seeds `.credentials.json`, which a
    // managed `sk-ant-api…` key does not live in (`session.py`
    // `_ensure_not_api_key`). Fail with the reason rather than seeding
    // something Claude Code will not read.
    live::require_oauth_login(&credential)
        .map_err(|_| DriverError::Unsupported("api-key logins cannot run"))?;

    let seeded = login.fingerprint();
    if needs_seeding(driver, &profile_env, &dir, &seeded)? {
        live::write_credentials_file(&profile_env, &credential)?;
        if let Some(oauth_account) = oauth_account {
            let config = live::read_config(&profile_env)?;
            live::splice_oauth_account(&profile_env, config, oauth_account)?;
        }
        write_marker(&dir, &seeded)?;
    }

    // What the profile is known to hold going in. The marker wins when it
    // disagrees with the passed login: the profile may have rotated past it, and
    // that rotation is what the read-back is for.
    let baseline = read_marker(&dir).unwrap_or(seeded);

    let read_driver = ClaudeDriver::new(driver.store.clone(), driver.endpoints.clone());
    let read_env = env.clone();
    let mut profile = RunProfile::new(
        overrides.to_vec(),
        AUTH_OVERRIDE_ENV_VARS
            .iter()
            .map(|v| v.to_string())
            .collect(),
        dir,
    );
    profile.read_back = Some(Box::new(move || {
        rotated_login(&read_driver, &read_env, slot, &baseline)
    }));
    Ok(profile)
}

/// Whether the profile has to be seeded (`session.py`'s reuse check).
///
/// Not when it already holds credential material that this login put there:
/// after one run that material is the *newer* generation. Seeded when the
/// profile has none at all, or when the marker records a different login —
/// which is a slot being re-pointed at another account, not a rotation.
fn needs_seeding(
    driver: &ClaudeDriver,
    profile_env: &Env,
    dir: &Path,
    seeded: &str,
) -> Result<bool, DriverError> {
    // Marker from another credential lineage: whatever the profile holds is not
    // this login's, so it is not a rotation of it — it is a slot re-pointed at a
    // different account, and the profile has to follow.
    if read_marker(dir).is_some_and(|previous| previous != seeded) {
        return Ok(true);
    }
    // An unreadable keychain answers "has material": re-seeding over a profile
    // that may hold the freshest generation is the one irreversible mistake here
    // (`_may_have_credential_material`).
    let has_material = match driver.read_profile_credential(profile_env) {
        Ok(material) => material.is_some(),
        Err(_) => true,
    };
    Ok(!has_material)
}

fn marker_path(dir: &Path) -> PathBuf {
    dir.join(SEED_MARKER)
}

fn read_marker(dir: &Path) -> Option<String> {
    fs::read_to_string(marker_path(dir))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// Record what the profile now holds. A fingerprint is a hash, not a secret, but
/// it sits beside the credential and inherits its mode.
fn write_marker(dir: &Path, fingerprint: &str) -> Result<(), DriverError> {
    live::write_private_file(&marker_path(dir), fingerprint)
}

/// The profile's credential if Claude Code rotated past `baseline`, else `None`.
fn rotated_login(
    driver: &ClaudeDriver,
    env: &Env,
    slot: u32,
    baseline: &str,
) -> Result<Option<Login>, DriverError> {
    let Some(login) = driver.read_profile_login(env, slot)? else {
        return Ok(None);
    };
    let fingerprint = login.fingerprint();
    if fingerprint == baseline {
        return Ok(None);
    }
    write_marker(&profile_dir(env, slot), &fingerprint)?;
    Ok(Some(login))
}

impl ClaudeDriver {
    /// Slot `slot`'s profile login as the profile currently holds it, envelope
    /// and all (`session.py:272-285` `read_session_credentials`).
    ///
    /// Read-only by design: the hashed keychain item — which shadows the
    /// plaintext seed from the moment Claude Code first writes it — is *read*
    /// here and never written. `None` when the profile has no readable
    /// credential material.
    pub fn read_profile_login(&self, env: &Env, slot: u32) -> Result<Option<Login>, DriverError> {
        let profile_env = profile_env(env, slot)?;
        let Some(raw) = self.read_profile_credential(&profile_env)? else {
            return Ok(None);
        };
        Ok(Some(Login {
            bytes: live::embed_oauth_account(&profile_env, raw),
        }))
    }

    /// The same read without the envelope, against an already-built profile
    /// environment: the hashed keychain item first (when this driver has a
    /// keychain at all), then `<dir>/.credentials.json`.
    fn read_profile_credential(&self, profile_env: &Env) -> Result<Option<String>, DriverError> {
        self.read_live_raw(profile_env)
    }
}

/// The environment that selects slot `slot`'s profile, without creating or
/// seeding anything.
fn profile_env(env: &Env, slot: u32) -> Result<Env, DriverError> {
    let dir = profile_dir(env, slot);
    let dir_str = dir
        .to_str()
        .ok_or_else(|| DriverError::Invalid("profile dir is not valid UTF-8".to_string()))?
        .to_string();
    let mut vars = env.vars.clone();
    vars.insert("CLAUDE_CONFIG_DIR".to_string(), dir_str.clone());
    vars.insert("CLAUDE_SECURESTORAGE_CONFIG_DIR".to_string(), dir_str);
    Ok(Env {
        home: env.home.clone(),
        vars,
    })
}

/// `mkdir -p` with 0700 on every component swapd creates.
fn create_private_dir_all(dir: &Path) -> Result<(), DriverError> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_private_dir_all(parent)?;
    }
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Mirror the share set from the user's real config home into the profile
/// (`session.py` `_sync_sharing`, share=True). Missing entries are skipped;
/// present ones are overwritten, so a profile picks up edits to the user's
/// settings on the next run.
///
/// The source is always the DEFAULT profile, `$HOME/.claude`, never
/// `CLAUDE_CONFIG_DIR` (`paths.py:56-77` `get_default_claude_config_home` /
/// `get_default_global_config_path`): swapd invoked from inside one run profile
/// must mirror the user's own customizations, not another slot's copies of them.
fn copy_share_set(env: &Env, dir: &Path) -> Result<(), DriverError> {
    let source = paths::home(env)?.join(".claude");
    for item in SHARED_ITEMS {
        let from = source.join(item);
        if from.exists() {
            copy_tree(&from, &dir.join(item))?;
        }
    }
    Ok(())
}

/// `cp -R` for one entry of the share set.
fn copy_tree(from: &Path, to: &Path) -> Result<(), DriverError> {
    if from.is_dir() {
        fs::create_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(from, to)?;
    }
    Ok(())
}

/// Make one minimal request as this login, so the account's usage window and
/// its rate-limit state reflect it (`claude -p . --max-turns 1`).
///
/// Runs in the slot's own profile, so the live login is untouched, and with a
/// `PATH` widened by the well-known install dirs — Claude Code re-execs itself
/// and a child that cannot find `claude` fails in a way that looks like the
/// account's problem. Output is discarded: it is a warm-up, not a query.
///
/// Answers `Some(login)` when Claude Code rotated the profile's credential while
/// running. That rotation exists only inside the profile, and the token it
/// replaced is already spent, so a caller that drops it leaves the slot holding
/// a dead refresh token.
pub fn ignite(
    driver: &ClaudeDriver,
    env: &Env,
    slot: u32,
    login: &Login,
) -> Result<Option<Login>, DriverError> {
    let profile = run_profile(driver, env, slot, login)?;
    let path_var = env.vars.get("PATH").map(String::as_str);
    let home = paths::home(env)?;
    let binary = find_claude(path_var, &home).ok_or(DriverError::NotInstalled)?;

    // An empty directory of swapd's own: `claude` scans its working directory
    // for project files (and records the run against that project), and the
    // igniter must not attach itself to whatever the user happened to be in.
    let cwd = env.home.join("ignite-cwd");
    create_private_dir_all(&cwd)?;

    let mut command = Command::new(binary);
    command
        .arg("-p")
        .arg(".")
        .arg("--max-turns")
        .arg("1")
        .current_dir(&cwd)
        // Exactly the environment swapd was started with, plus the profile's
        // overrides — never the ambient process env of whatever spawned us.
        .env_clear()
        .envs(&env.vars)
        .envs(profile.env.iter().cloned())
        .env("PATH", widen_path(path_var, &home))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Applied last: an exported API key would otherwise make the child bypass
    // the account this profile selects, and report its usage as this slot's.
    for key in &profile.unset {
        command.env_remove(key);
    }

    let mut child = command.spawn()?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= IGNITE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(DriverError::Http("igniter timed out".to_string()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    match status.code() {
        Some(0) => match &profile.read_back {
            Some(read_back) => read_back(),
            None => Ok(None),
        },
        Some(code) => Err(DriverError::Http(format!("igniter exited {code}"))),
        // Killed by a signal: no exit code to report, and it is not a success.
        None => Err(DriverError::Http("igniter killed by a signal".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::claude::live::LiveStore;
    use crate::driver::claude::tests::{endpoints, env_with, temp_home};
    use crate::security_cli::SecurityCli as _;

    fn login() -> Login {
        Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-1","accessToken":"at-1"},"oauthAccount":{"emailAddress":"you@example.com"}}"#
                .to_string(),
        }
    }

    /// `Result::unwrap_err` needs `T: Debug`, which neither `Login` (it holds
    /// the credential) nor `RunProfile` (it holds a closure) has.
    fn expect_err<T>(result: Result<T, DriverError>) -> DriverError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    /// An executable file `find_claude` will accept as the binary.
    fn write_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// A `claude` that does nothing but succeed.
    fn write_noop_claude(path: &Path) {
        write_script(path, "#!/bin/sh\nexit 0\n");
    }

    #[test]
    fn find_claude_prefers_path_then_the_well_known_locations() {
        let home = temp_home();
        let local = home.path().join(".claude/local");
        fs::create_dir_all(&local).unwrap();
        write_noop_claude(&local.join(binary_name()));

        // Nothing on PATH: the well-known location answers.
        assert_eq!(
            find_claude(None, home.path()),
            Some(local.join(binary_name()))
        );

        // A `claude` on PATH wins over it.
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        write_noop_claude(&bin.join(binary_name()));
        assert_eq!(
            find_claude(Some(bin.to_str().unwrap()), home.path()),
            Some(bin.join(binary_name()))
        );

        // Neither: not installed.
        let empty = temp_home();
        assert_eq!(find_claude(Some(""), empty.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn find_claude_skips_a_non_executable_candidate() {
        let home = temp_home();
        let dead = home.path().join("dead");
        let live = home.path().join("live");
        fs::create_dir_all(&dead).unwrap();
        fs::create_dir_all(&live).unwrap();
        // A `claude` that cannot be exec'd (a stray file, a half-finished
        // install) must not shadow the real one further along PATH.
        fs::write(dead.join("claude"), "not a program").unwrap();
        write_noop_claude(&live.join("claude"));
        // ...nor may a `claude` DIRECTORY.
        fs::create_dir_all(dead.join("claude.d")).unwrap();

        let path_var = format!("{}:{}", dead.display(), live.display());
        assert_eq!(
            find_claude(Some(&path_var), home.path()),
            Some(live.join("claude"))
        );
    }

    #[test]
    fn widen_path_appends_the_candidate_dirs_once() {
        let home = temp_home();
        let widened = widen_path(Some("/usr/bin:/usr/local/bin"), home.path());
        let dirs: Vec<PathBuf> = std::env::split_paths(&widened).collect();
        assert_eq!(dirs[0], PathBuf::from("/usr/bin"));
        assert_eq!(dirs[1], PathBuf::from("/usr/local/bin"));
        assert!(dirs.contains(&home.path().join(".claude/local")));
        assert!(dirs.contains(&home.path().join(".local/bin")));
        assert!(dirs.contains(&PathBuf::from("/opt/homebrew/bin")));
        // Already present, so it is not appended a second time.
        assert_eq!(
            dirs.iter()
                .filter(|d| *d == &PathBuf::from("/usr/local/bin"))
                .count(),
            1
        );
    }

    #[test]
    fn run_profile_writes_the_login_and_copies_the_share_set() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        // The user's real config home, with two share-set entries and one file
        // that is NOT in the set.
        let config_home = home.path().join(".claude");
        fs::create_dir_all(config_home.join("skills/deep")).unwrap();
        fs::write(config_home.join("settings.json"), r#"{"theme":"dark"}"#).unwrap();
        fs::write(config_home.join("skills/deep/skill.md"), "# skill").unwrap();
        fs::write(config_home.join("history.jsonl"), "{}").unwrap();

        let profile = run_profile(&driver, &env, 3, &login()).unwrap();
        let dir = env.home.join("profiles/claude/3");
        assert_eq!(profile.dir, dir);
        // Both axes point at the profile: a caller layering these over its
        // environment cannot leave an exported securestorage var naming the
        // live item.
        assert_eq!(
            profile.env,
            vec![
                (
                    "CLAUDE_CONFIG_DIR".to_string(),
                    dir.to_str().unwrap().to_string()
                ),
                (
                    "CLAUDE_SECURESTORAGE_CONFIG_DIR".to_string(),
                    dir.to_str().unwrap().to_string()
                ),
            ]
        );

        // The share set followed the account in; nothing else did.
        assert_eq!(
            fs::read_to_string(dir.join("settings.json")).unwrap(),
            r#"{"theme":"dark"}"#
        );
        assert_eq!(
            fs::read_to_string(dir.join("skills/deep/skill.md")).unwrap(),
            "# skill"
        );
        assert!(!dir.join("history.jsonl").exists());

        // The credential landed in the profile, without the envelope key...
        let stored = fs::read_to_string(dir.join(".credentials.json")).unwrap();
        assert!(stored.contains("rt-1"));
        assert!(!stored.contains("oauthAccount"));
        // ...and the identity in the profile's own config.
        let config: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join(".claude.json")).unwrap()).unwrap();
        assert_eq!(config["oauthAccount"]["emailAddress"], "you@example.com");

        // The live login is untouched: nothing was written to ~/.claude.
        assert!(!config_home.join(".credentials.json").exists());

        // The tree that holds it is private all the way down, and the seed is
        // recorded so the next launch does not overwrite a rotation.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                &dir,
                &env.home.join("profiles/claude"),
                &env.home.join("profiles"),
            ] {
                let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{}", path.display());
            }
            let mode = fs::metadata(dir.join(".credentials.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(
            fs::read_to_string(dir.join(SEED_MARKER)).unwrap(),
            login().fingerprint()
        );
    }

    #[test]
    fn run_profile_does_not_reseed_a_rotated_profile() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        run_profile(&driver, &env, 4, &login()).unwrap();
        let creds = env.home.join("profiles/claude/4/.credentials.json");

        // Claude Code rotated the token in place while running: the profile now
        // holds the NEWEST generation of this family, and the login swapd stores
        // is one behind (its refresh token is already spent).
        let rotated =
            r#"{"claudeAiOauth":{"refreshToken":"rt-rotated","accessToken":"at-rotated"}}"#;
        fs::write(&creds, rotated).unwrap();

        run_profile(&driver, &env, 4, &login()).unwrap();
        assert_eq!(fs::read_to_string(&creds).unwrap(), rotated);

        // A DIFFERENT login is a slot being re-pointed, not a rotation, so it
        // does re-seed.
        let other = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-other"}}"#.to_string(),
        };
        run_profile(&driver, &env, 4, &other).unwrap();
        assert!(fs::read_to_string(&creds).unwrap().contains("rt-other"));
    }

    #[test]
    fn run_profile_refuses_an_api_key_login() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());
        let api_key = Login {
            bytes: "sk-ant-api03-fake-key".to_string(),
        };
        let err = expect_err(run_profile(&driver, &env, 1, &api_key));
        assert!(matches!(err, DriverError::Unsupported(m) if m == "api-key logins cannot run"));
        // Nothing was seeded.
        assert!(!env
            .home
            .join("profiles/claude/1/.credentials.json")
            .exists());
    }

    #[test]
    fn share_set_comes_from_the_default_profile_not_the_active_one() {
        let home = temp_home();
        // swapd invoked from INSIDE another run profile: the share set must
        // still come from the user's own ~/.claude, not that profile's copies.
        let other_profile = home.path().join("other-profile");
        fs::create_dir_all(&other_profile).unwrap();
        fs::write(other_profile.join("settings.json"), r#"{"theme":"copy"}"#).unwrap();
        let default_home = home.path().join(".claude");
        fs::create_dir_all(&default_home).unwrap();
        fs::write(default_home.join("settings.json"), r#"{"theme":"mine"}"#).unwrap();

        let env = env_with(
            &home,
            [
                ("USER", "tester"),
                ("CLAUDE_CONFIG_DIR", other_profile.to_str().unwrap()),
            ],
        );
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());
        let profile = run_profile(&driver, &env, 9, &login()).unwrap();
        assert_eq!(
            fs::read_to_string(profile.dir.join("settings.json")).unwrap(),
            r#"{"theme":"mine"}"#
        );
    }

    #[test]
    fn run_profile_never_writes_the_profiles_keychain_item() {
        let home = temp_home();
        // An exported securestorage var pointed at the LIVE store: the profile
        // must not inherit it.
        let env = env_with(
            &home,
            [
                ("USER", "tester"),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/live/secure"),
            ],
        );
        let fake = std::sync::Arc::new(crate::security_cli::FakeSecurity::default());
        let driver = ClaudeDriver::new(LiveStore::Keychain(fake.clone()), endpoints());

        let profile = run_profile(&driver, &env, 5, &login()).unwrap();
        let dir_str = profile.dir.to_str().unwrap().to_string();

        // Seeding is plaintext-only, on every platform: writing Claude Code's
        // hashed item ourselves would couple swapd to its internal storage
        // format, where a mismatch reads as "logged out" (session.py docstring).
        // Claude Code migrates the seed into that item on its first write.
        assert_eq!(
            fake.find(&paths::keychain_service_name(&dir_str), None)
                .unwrap(),
            None
        );
        assert_eq!(
            fake.find(&paths::keychain_service_name("/live/secure"), None)
                .unwrap(),
            None
        );
        assert_eq!(fake.find(paths::DEFAULT_SERVICE, None).unwrap(), None);
        assert!(fs::read_to_string(profile.dir.join(".credentials.json"))
            .unwrap()
            .contains("rt-1"));
    }

    #[test]
    fn read_profile_login_prefers_the_hashed_keychain_item_over_the_seed() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester")]);
        let fake = std::sync::Arc::new(crate::security_cli::FakeSecurity::default());
        let driver = ClaudeDriver::new(LiveStore::Keychain(fake.clone()), endpoints());

        let profile = run_profile(&driver, &env, 6, &login()).unwrap();
        let dir_str = profile.dir.to_str().unwrap().to_string();

        // Only the plaintext seed exists so far.
        let read = driver.read_profile_login(&env, 6).unwrap().unwrap();
        assert!(read.bytes.contains("rt-1"));
        // The envelope is re-attached from the profile's own config.
        assert!(read.bytes.contains("you@example.com"));

        // Once Claude Code migrates the seed into its hashed item, that item
        // shadows the (now stale) file — and holds the newer generation.
        fake.add(
            &paths::keychain_service_name(&dir_str),
            "tester",
            r#"{"claudeAiOauth":{"refreshToken":"rt-migrated"}}"#,
        )
        .unwrap();
        let read = driver.read_profile_login(&env, 6).unwrap().unwrap();
        assert!(read.bytes.contains("rt-migrated"));

        // A profile that was never seeded has nothing to read.
        assert!(driver.read_profile_login(&env, 7).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn ignite_runs_claude_in_the_profile_and_reports_a_non_zero_exit() {
        let home = temp_home();
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let witness = home.path().join("witness");

        let write_fake = |exit: u32| {
            let script = format!(
                "#!/bin/sh\nprintf '%s %s %s [%s]' \
                 \"$CLAUDE_CONFIG_DIR\" \"$CLAUDE_SECURESTORAGE_CONFIG_DIR\" \
                 \"$PWD\" \"$ANTHROPIC_API_KEY\" > {}\nexit {}\n",
                witness.display(),
                exit
            );
            write_script(&bin.join("claude"), &script);
        };

        // An exported API key: claude would bypass account OAuth entirely and
        // the run would report the wrong account's usage as this slot's.
        let env = env_with(
            &home,
            [
                ("USER", "tester"),
                ("PATH", bin.to_str().unwrap()),
                ("ANTHROPIC_API_KEY", "sk-ant-api03-exported"),
            ],
        );
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        write_fake(0);
        // Nothing rotated, so there is nothing to hand back.
        assert!(ignite(&driver, &env, 2, &login()).unwrap().is_none());

        let profile_dir = env.home.join("profiles/claude/2");
        let seen = fs::read_to_string(&witness).unwrap();
        // `$PWD` is what the shell resolved, which on macOS is the temp dir's
        // /private prefix — compare against the same resolution.
        let cwd = fs::canonicalize(env.home.join("ignite-cwd")).unwrap();
        // The child ran under the slot's profile on both axes, in swapd's own
        // empty cwd, with the auth override scrubbed.
        assert_eq!(
            seen,
            format!(
                "{} {} {} []",
                profile_dir.to_str().unwrap(),
                profile_dir.to_str().unwrap(),
                cwd.to_str().unwrap(),
            )
        );

        write_fake(3);
        let err = expect_err(ignite(&driver, &env, 2, &login()));
        assert!(matches!(err, DriverError::Http(m) if m == "igniter exited 3"));
    }

    #[cfg(unix)]
    #[test]
    fn ignite_returns_the_rotated_login() {
        let home = temp_home();
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();

        // A claude that refreshes its token while running, as the real one does:
        // it rewrites the profile's credential in place and tells no one.
        write_script(
            &bin.join("claude"),
            "#!/bin/sh\nprintf '%s' \
             '{\"claudeAiOauth\":{\"refreshToken\":\"rt-rotated\"}}' \
             > \"$CLAUDE_CONFIG_DIR/.credentials.json\"\nexit 0\n",
        );

        let env = env_with(&home, [("USER", "tester"), ("PATH", bin.to_str().unwrap())]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        let rotated = ignite(&driver, &env, 8, &login())
            .unwrap()
            .expect("rotated");
        assert!(rotated.bytes.contains("rt-rotated"));
        // The marker moved with it, so the next launch does not overwrite the
        // new generation with the stored (spent) one.
        let dir = env.home.join("profiles/claude/8");
        assert_eq!(
            fs::read_to_string(dir.join(SEED_MARKER)).unwrap(),
            rotated.fingerprint()
        );

        // The caller persists what it was handed and igniting again with it
        // rotates nothing — and, crucially, does not re-seed over the profile.
        write_noop_claude(&bin.join("claude"));
        assert!(ignite(&driver, &env, 8, &rotated).unwrap().is_none());
        assert!(fs::read_to_string(dir.join(".credentials.json"))
            .unwrap()
            .contains("rt-rotated"));

        // Handing back the SUPERSEDED login instead is a slot being re-pointed
        // as far as the profile can tell, so it is re-seeded — which is why
        // `ignite`'s answer has to be persisted.
        assert!(ignite(&driver, &env, 8, &login()).unwrap().is_none());
        assert!(fs::read_to_string(dir.join(".credentials.json"))
            .unwrap()
            .contains("rt-1"));
    }

    #[cfg(unix)]
    #[test]
    fn ignite_without_a_claude_binary_is_not_installed() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester"), ("PATH", "")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());
        let err = expect_err(ignite(&driver, &env, 1, &login()));
        assert!(matches!(err, DriverError::NotInstalled));
    }
}
