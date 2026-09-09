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
    Command::cargo_bin("swapd")
        .unwrap()
        .args(["frobnicate", "--json"])
        .assert()
        .failure();
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
