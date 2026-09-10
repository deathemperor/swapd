use assert_cmd::Command;

/// A `doctor --json` invocation with the same hermetic contract every other
/// suite uses: a fresh `SWAPD_HOME`, `SWAPD_SECRETS=file`,
/// `SWAPD_LIVE_STORE=file`, `HOME` pointed at a temp dir so a real
/// `~/.claude*` is never read, `CLAUDE_CONFIG_DIR` removed so a developer's
/// own override can't leak in either, and `SWAPD_GEMINI_CLI` pointed at a
/// path that doesn't exist so `doctor` never finds and runs a real `gemini`
/// on a dev machine's PATH.
fn doctor_cmd(home: &std::path::Path, claude_home: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("swapd").unwrap();
    cmd.env("SWAPD_HOME", home)
        .env("SWAPD_SECRETS", "file")
        .env("SWAPD_LIVE_STORE", "file")
        .env("HOME", claude_home)
        .env("SWAPD_GEMINI_CLI", home.join("no-such-gemini"))
        .env_remove("CLAUDE_CONFIG_DIR")
        .args(["doctor", "--json"]);
    cmd
}

#[test]
fn version_json_has_schema_and_version() {
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .args(["version", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn unknown_verb_is_a_json_error_with_exit_1() {
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .args(["frobnicate", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["error"]["code"], "invalid-input");
}

#[test]
fn doctor_reports_home_under_swapd_home() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .env("SWAPD_HOME", tmp.path())
        // `doctor` now runs `<cli> --version`; naming paths that don't exist
        // keeps this test from finding and running a real `claude` or
        // `gemini` on a dev machine's PATH.
        .env("SWAPD_CLAUDE_CLI", tmp.path().join("no-such-claude"))
        .env("SWAPD_GEMINI_CLI", tmp.path().join("no-such-gemini"))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["home"], tmp.path().to_str().unwrap());
    assert!(v["providers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["provider"] == "claude"));
}

#[test]
fn doctor_without_home_or_swapd_home_is_a_json_error_not_a_panic() {
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .env_remove("HOME")
        // The platform defaults: %APPDATA%\swapd on Windows, $XDG_DATA_HOME
        // on Linux — every route to a data dir is closed, not only $HOME.
        .env_remove("APPDATA")
        .env_remove("XDG_DATA_HOME")
        .env_remove("SWAPD_HOME")
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["error"]["code"], "io");
}

/// Belt-and-braces for the CI macOS runner: `default_secrets` must honour
/// `SWAPD_SECRETS=file` (the CI job sets it too) so a run through the real
/// binary never falls through to the platform default and touches the
/// developer's login keychain. Every other suite already relies on this
/// same wiring; this test names the guard explicitly. Same hermetic contract
/// as the other suites (`SWAPD_LIVE_STORE=file`, a temp `HOME`,
/// `CLAUDE_CONFIG_DIR` removed) even though `add-token` never reaches the
/// live store today — so a later change that makes it do so fails loud here
/// instead of quietly hitting the real keychain.
#[test]
fn add_token_with_swapd_secrets_file_never_touches_the_login_keychain() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .env("SWAPD_HOME", tmp.path())
        .env("SWAPD_SECRETS", "file")
        .env("SWAPD_LIVE_STORE", "file")
        .env("HOME", claude_home.path())
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .args(["add-token", "-", "--json"])
        .write_stdin("sk-ant-api03-secret-key\n")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("credentials/claude_1")).unwrap(),
        "sk-ant-api03-secret-key"
    );
}

#[test]
fn missing_subcommand_is_a_json_error_with_fixed_message() {
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .args(["--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["error"]["message"], "missing subcommand");
}

#[test]
fn doctor_reports_stores_and_free_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();
    let out = doctor_cmd(tmp.path(), claude_home.path()).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["liveStore"], "file");
    assert_eq!(v["secrets"], "file");
    assert_eq!(v["locks"]["engine"]["held"], false);
    assert_eq!(v["locks"]["auto"]["held"], false);
    assert_eq!(v["profiles"], serde_json::json!([]));

    // A read verb must never create the lock files it merely inspects.
    assert!(!tmp.path().join("engine.lock").exists());
    assert!(!tmp.path().join("auto.lock").exists());
}

#[test]
fn doctor_reports_a_held_auto_lock_with_its_pid() {
    use std::io::Write as _;

    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();

    let lock_path = tmp.path().join("auto.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    let mut rw = fd_lock::RwLock::new(file);
    let mut guard = rw.try_write().unwrap();
    guard.write_all(br#"{"pid":12345}"#).unwrap();
    guard.flush().unwrap();

    let out = doctor_cmd(tmp.path(), claude_home.path()).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["locks"]["auto"]["held"], true);
    // Windows locks are mandatory: the holder's breadcrumb is unreadable from
    // another handle until the lock is released, so the pid arrives late there.
    #[cfg(unix)]
    assert_eq!(v["locks"]["auto"]["pid"], 12345);

    drop(guard);
    let out = doctor_cmd(tmp.path(), claude_home.path()).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["locks"]["auto"]["held"], false);
}

#[test]
fn doctor_lists_existing_profile_dirs_sorted() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("profiles/claude/7")).unwrap();
    std::fs::create_dir_all(tmp.path().join("profiles/claude/3")).unwrap();
    std::fs::create_dir_all(tmp.path().join("profiles/claude/junk")).unwrap();

    let out = doctor_cmd(tmp.path(), claude_home.path()).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let profiles = v["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2, "profiles: {profiles:?}");
    assert_eq!(profiles[0]["provider"], "claude");
    assert_eq!(profiles[0]["slot"], 3);
    assert_eq!(profiles[1]["provider"], "claude");
    assert_eq!(profiles[1]["slot"], 7);
}

/// A stub `claude` on disk, named by `SWAPD_CLAUDE_CLI` so the real CLI is
/// never touched.
#[cfg(unix)]
fn write_stub(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
    let path = dir.join("claude");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn doctor_reports_the_cli_version_from_the_stub() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();

    let stub = write_stub(bin.path(), "echo '2.1.0 (Claude Code)'\nexit 0");
    let out = doctor_cmd(tmp.path(), claude_home.path())
        .env("SWAPD_CLAUDE_CLI", &stub)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["providers"][0]["installed"], true);
    assert_eq!(v["providers"][0]["version"], "2.1.0 (Claude Code)");

    let slow_stub = write_stub(bin.path(), "sleep 30");
    let start = std::time::Instant::now();
    let out = doctor_cmd(tmp.path(), claude_home.path())
        .env("SWAPD_CLAUDE_CLI", &slow_stub)
        .output()
        .unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "doctor must give up on a hung --version well before 10s: took {:?}",
        start.elapsed()
    );
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["providers"][0]["version"], serde_json::Value::Null);
}

#[test]
fn doctor_refuses_an_unknown_secrets_backend() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();
    let out = doctor_cmd(tmp.path(), claude_home.path())
        .env("SWAPD_SECRETS", "keychan")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid-input");
}
