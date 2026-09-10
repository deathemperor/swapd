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
