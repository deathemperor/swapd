//! Per-slot run profiles and the igniter.
//!
//! A run profile is a `CLAUDE_CONFIG_DIR` of its own: Claude Code reads its
//! whole config — credential item, `.claude.json`, settings, skills — relative
//! to that directory, so a slot can be *run* without touching the live login at
//! all. Port of cswap `session.py:76-83` (the default share set) and
//! `session.py:232-243` (the keychain item a config dir derives, already in
//! `paths::keychain_service_name`).
//!
//! Profiles persist: they hold the slot's credential and its copied
//! customizations, and re-creating them on every run would re-prompt for
//! keychain access and re-copy the share set for nothing. Hence `RunProfile`'s
//! cleanup hook stays empty here.

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
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    candidate_paths(home).into_iter().find(|p| p.is_file())
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

/// Build (or refresh) slot `slot`'s run profile and return the environment that
/// selects it.
///
/// The login is written through the driver's own `LiveStore` — the keychain
/// item the profile dir hashes to on macOS (`keychain_service_name(dir)`, the
/// name Claude Code itself derives), a 0600 `<dir>/.credentials.json`
/// elsewhere — and the envelope's `oauthAccount` is spliced into
/// `<dir>/.claude.json`, which is where Claude Code reads its config from when
/// `CLAUDE_CONFIG_DIR` is set (`paths::config_json`). The live login is never
/// touched.
pub fn run_profile(
    driver: &ClaudeDriver,
    env: &Env,
    slot: u32,
    login: &Login,
) -> Result<RunProfile, DriverError> {
    let dir = profile_dir(env, slot);
    fs::create_dir_all(&dir)?;
    // The keychain service name hashes this exact string, so Claude Code and
    // swapd must agree on it byte for byte — a non-UTF-8 path has no such
    // string, and guessing one would key a different item.
    let dir_str = dir
        .to_str()
        .ok_or_else(|| DriverError::Invalid("profile dir is not valid UTF-8".to_string()))?
        .to_string();

    copy_share_set(env, &dir)?;

    // The environment the profile *is*: same process env, but pointed at the
    // profile. `CLAUDE_SECURESTORAGE_CONFIG_DIR` is dropped — if it survived, it
    // would keep naming the live secure store and the credential below would
    // land where Claude Code will not look for this profile.
    let mut vars = env.vars.clone();
    vars.insert("CLAUDE_CONFIG_DIR".to_string(), dir_str.clone());
    vars.remove("CLAUDE_SECURESTORAGE_CONFIG_DIR");
    let profile_env = Env {
        home: env.home.clone(),
        vars,
    };

    let (credential, oauth_account) = live::split_envelope(&login.bytes)?;
    driver.write_credential(&profile_env, &credential)?;
    if let Some(oauth_account) = oauth_account {
        let config = live::read_config(&profile_env)?;
        live::splice_oauth_account(&profile_env, config, oauth_account)?;
    }

    Ok(RunProfile::new(
        vec![("CLAUDE_CONFIG_DIR".to_string(), dir_str)],
        dir,
    ))
}

/// Mirror the share set from the real config home into the profile
/// (`session.py` `_sync_sharing`, share=True). Missing entries are skipped;
/// present ones are overwritten, so a profile picks up edits to the user's
/// settings on the next run.
fn copy_share_set(env: &Env, dir: &Path) -> Result<(), DriverError> {
    let source = paths::config_home(env)?;
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
pub fn ignite(
    driver: &ClaudeDriver,
    env: &Env,
    slot: u32,
    login: &Login,
) -> Result<(), DriverError> {
    let profile = run_profile(driver, env, slot, login)?;
    let path_var = env.vars.get("PATH").map(String::as_str);
    let home = paths::home(env)?;
    let binary = find_claude(path_var, &home).ok_or(DriverError::NotInstalled)?;

    let mut command = Command::new(binary);
    command
        .arg("-p")
        .arg(".")
        .arg("--max-turns")
        .arg("1")
        .current_dir(&profile.dir)
        // Exactly the environment swapd was started with, plus the profile's
        // overrides — never the ambient process env of whatever spawned us.
        .env_clear()
        .envs(&env.vars)
        .envs(profile.env.iter().cloned())
        .env("PATH", widen_path(path_var, &home))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

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
        Some(0) => Ok(()),
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

    fn login() -> Login {
        Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-1","accessToken":"at-1"},"oauthAccount":{"emailAddress":"you@example.com"}}"#
                .to_string(),
        }
    }

    #[test]
    fn find_claude_prefers_path_then_the_well_known_locations() {
        let home = temp_home();
        let local = home.path().join(".claude/local");
        fs::create_dir_all(&local).unwrap();
        fs::write(local.join(binary_name()), "#!/bin/sh\n").unwrap();

        // Nothing on PATH: the well-known location answers.
        assert_eq!(
            find_claude(None, home.path()),
            Some(local.join(binary_name()))
        );

        // A `claude` on PATH wins over it.
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join(binary_name()), "#!/bin/sh\n").unwrap();
        assert_eq!(
            find_claude(Some(bin.to_str().unwrap()), home.path()),
            Some(bin.join(binary_name()))
        );

        // Neither: not installed.
        let empty = temp_home();
        assert_eq!(find_claude(Some(""), empty.path()), None);
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
        assert_eq!(
            profile.env,
            vec![(
                "CLAUDE_CONFIG_DIR".to_string(),
                dir.to_str().unwrap().to_string()
            )]
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
    }

    #[cfg(unix)]
    #[test]
    fn ignite_runs_claude_in_the_profile_and_reports_a_non_zero_exit() {
        use std::os::unix::fs::PermissionsExt;

        let home = temp_home();
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let witness = home.path().join("witness");

        let write_fake = |exit: u32| {
            let script = format!(
                "#!/bin/sh\nprintf '%s' \"$CLAUDE_CONFIG_DIR\" > {}\nexit {}\n",
                witness.display(),
                exit
            );
            fs::write(bin.join("claude"), script).unwrap();
            fs::set_permissions(bin.join("claude"), fs::Permissions::from_mode(0o755)).unwrap();
        };

        let env = env_with(&home, [("USER", "tester"), ("PATH", bin.to_str().unwrap())]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());

        write_fake(0);
        assert!(ignite(&driver, &env, 2, &login()).is_ok());
        // The child ran under the slot's profile, not the live config home.
        assert_eq!(
            fs::read_to_string(&witness).unwrap(),
            env.home.join("profiles/claude/2").to_str().unwrap()
        );

        write_fake(3);
        let err = ignite(&driver, &env, 2, &login()).unwrap_err();
        assert!(matches!(err, DriverError::Http(m) if m == "igniter exited 3"));
    }

    #[cfg(unix)]
    #[test]
    fn ignite_without_a_claude_binary_is_not_installed() {
        let home = temp_home();
        let env = env_with(&home, [("USER", "tester"), ("PATH", "")]);
        let driver = ClaudeDriver::new(LiveStore::File, endpoints());
        let err = ignite(&driver, &env, 1, &login()).unwrap_err();
        assert!(matches!(err, DriverError::NotInstalled));
    }
}
