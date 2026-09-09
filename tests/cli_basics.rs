use assert_cmd::Command;

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
