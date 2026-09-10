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
    fs::write(
        dir.join("google_accounts.json"),
        format!(r#"{{"active":"{email}","old":[]}}"#),
    )
    .unwrap();
    fs::write(
        dir.join("settings.json"),
        r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
    )
    .unwrap();
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
    let out = swapd(&home, &gh)
        .args(["--provider", "gemini", "add", "--json"])
        .assert()
        .success();
    let added = json(&out.get_output().stdout);
    assert_eq!(added["slot"], 1);
    let out = swapd(&home, &gh)
        .args(["--provider", "gemini", "list", "--json"])
        .assert()
        .success();
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
    swapd(&home, &gh)
        .args(["--provider", "gemini", "add", "--json"])
        .assert()
        .success();
    seed(gh.path(), CREDS_B, "b@example.com");
    swapd(&home, &gh)
        .args(["--provider", "gemini", "add", "--json"])
        .assert()
        .success();
    swapd(&home, &gh)
        .args(["--provider", "gemini", "switch", "1", "--json"])
        .assert()
        .success();
    let creds: Value = serde_json::from_str(
        &fs::read_to_string(gh.path().join(".gemini").join("oauth_creds.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(creds["refresh_token"], "rt-a");
    let accounts: Value = serde_json::from_str(
        &fs::read_to_string(gh.path().join(".gemini").join("google_accounts.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(accounts["active"], "a@example.com");
    assert_eq!(accounts["old"][0], "b@example.com");
    assert!(!gh.path().join(".gemini").join(".swapd-live.lock").exists());
}

#[test]
fn doctor_lists_gemini_and_flags_encrypted_storage() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    let out = swapd(&home, &gh)
        .env("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", "true")
        .args(["doctor", "--json"])
        .assert()
        .success();
    let doc = json(&out.get_output().stdout);
    let gemini = doc["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["provider"] == "gemini")
        .expect("gemini row");
    assert_eq!(gemini["installed"], false);
    assert!(gemini["note"]
        .as_str()
        .unwrap()
        .contains("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE"));
    let claude = doc["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["provider"] == "claude")
        .expect("claude row");
    assert!(claude.get("note").is_none() || claude["note"].is_null());
}

/// A machine whose Gemini CLI is on an API key has no login swapd manages —
/// but `list` without `--provider` fans out over every driver, so anything
/// harsher than `NoLogin` would take the Claude row down with it (B1).
#[test]
fn list_without_a_provider_survives_an_api_key_gemini() {
    let home = TempDir::new().unwrap();
    let gh = TempDir::new().unwrap();
    let dir = gh.path().join(".gemini");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
    )
    .unwrap();
    let out = swapd(&home, &gh)
        .args(["list", "--json"])
        .assert()
        .success();
    let list = json(&out.get_output().stdout);
    let providers = list["providers"].as_array().unwrap();
    assert!(
        providers.iter().any(|p| p["provider"] == "claude"),
        "the claude row survives"
    );
    let gemini = providers
        .iter()
        .find(|p| p["provider"] == "gemini")
        .expect("gemini row");
    assert!(
        gemini.get("activeSlot").is_none() || gemini["activeSlot"].is_null(),
        "no login swapd manages"
    );

    // `doctor` is where the reason surfaces.
    let out = swapd(&home, &gh)
        .args(["doctor", "--json"])
        .assert()
        .success();
    let doc = json(&out.get_output().stdout);
    let note = doc["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["provider"] == "gemini")
        .expect("gemini row")["note"]
        .as_str()
        .expect("a note naming the auth type")
        .to_string();
    assert!(note.contains("gemini-api-key"), "unexpected note: {note}");
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
