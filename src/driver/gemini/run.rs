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
    if cfg!(windows) {
        &["gemini.cmd", "gemini.exe", "gemini"]
    } else {
        &["gemini"]
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
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
    env.home
        .join("profiles")
        .join("gemini")
        .join(slot.to_string())
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
    write_private_file(
        &gemini.join("oauth_creds.json"),
        &Value::Object(envelope.oauth_creds.clone()).to_string(),
    )?;
    let accounts = json!({"active": envelope.google_account.clone(), "old": []});
    fs::write(gemini.join("google_accounts.json"), accounts.to_string())?;
    // The auth picker never opens for a profile: the mode is decided.
    let settings_path = gemini.join("settings.json");
    let mut settings = fs::read_to_string(&settings_path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
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
        return Err(DriverError::Invalid(
            "profile oauth_creds.json is not a JSON object".to_string(),
        ));
    };
    let google_account = fs::read_to_string(gemini.join("google_accounts.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get("active").and_then(Value::as_str).map(str::to_string))
        .filter(|s| !s.is_empty());
    Ok(Some(
        Envelope {
            oauth_creds,
            google_account,
        }
        .to_login(),
    ))
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
        AUTH_OVERRIDE_ENV_VARS
            .iter()
            .map(|v| v.to_string())
            .collect(),
        dir.clone(),
    );
    profile.read_back = Some(Box::new(move || {
        let Some(current) = read_profile_login(&dir)? else {
            return Ok(None);
        };
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

pub fn ignite(
    driver: &GeminiDriver,
    _env: &Env,
    _slot: u32,
    login: &Login,
) -> Result<IgniteOutcome, DriverError> {
    match usage::usage(driver, login) {
        Ok(_) => Ok(IgniteOutcome {
            exit_code: 0,
            rotated: None,
        }),
        Err(DriverError::TokenDead | DriverError::NeedsRefresh) => Ok(IgniteOutcome {
            exit_code: EXIT_AUTH_FAILED,
            rotated: None,
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::gemini::oauth::GeminiEndpoints;
    use crate::driver::gemini::tests::{env_with, temp_home};
    use std::fs;

    fn login(expiry_ms: i64) -> Login {
        Login {
            bytes: format!(
                r#"{{"oauth_creds":{{"access_token":"at-1","refresh_token":"rt-1","expiry_date":{expiry_ms}}},"google_account":"you@example.com"}}"#
            ),
        }
    }

    #[test]
    fn a_profile_is_seeded_once_and_points_gemini_cli_home_at_itself() {
        let home = temp_home();
        let env = env_with(&home, []);
        let profile = run_profile(&env, 3, &login(1_000)).unwrap();
        let dir = profile_dir(&env, 3);
        assert_eq!(profile.dir, dir);
        assert_eq!(
            profile.env,
            vec![(
                "GEMINI_CLI_HOME".to_string(),
                dir.to_str().unwrap().to_string()
            )]
        );
        assert!(profile.unset.contains(&"GEMINI_API_KEY".to_string()));
        let creds: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(creds["refresh_token"], "rt-1");
        let accounts: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(".gemini").join("google_accounts.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(accounts["active"], "you@example.com");
        let settings: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(".gemini").join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings["security"]["auth"]["selectedType"],
            "oauth-personal"
        );
        assert_eq!(
            crate::driver::marker::read(&dir).as_deref(),
            Some(login(1_000).fingerprint().as_str())
        );

        // The CLI rotates in place; a second run_profile with the SAME login must not re-seed over it.
        fs::write(
            dir.join(".gemini").join("oauth_creds.json"),
            r#"{"access_token":"at-9","refresh_token":"rt-1","expiry_date":2000}"#,
        )
        .unwrap();
        let _ = run_profile(&env, 3, &login(1_000)).unwrap();
        let creds: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap(),
        )
        .unwrap();
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
        let creds: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(".gemini").join("oauth_creds.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(creds["refresh_token"], "rt-other");
        assert_eq!(
            crate::driver::marker::read(&dir).as_deref(),
            Some(other.fingerprint().as_str())
        );
    }

    #[test]
    fn read_back_reports_a_later_generation_and_nothing_otherwise() {
        let home = temp_home();
        let env = env_with(&home, []);
        let profile = run_profile(&env, 2, &login(1_000)).unwrap();
        let read_back = profile.read_back.as_ref().unwrap();
        assert!(
            read_back().unwrap().is_none(),
            "unchanged profile: no rotation"
        );
        let dir = profile_dir(&env, 2);
        fs::write(
            dir.join(".gemini").join("oauth_creds.json"),
            r#"{"access_token":"at-2","refresh_token":"rt-1","expiry_date":9000}"#,
        )
        .unwrap();
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
        assert_eq!(
            crate::driver::marker::read(&profile_dir(&env, 4)).as_deref(),
            Some(rotated.fingerprint().as_str())
        );
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
            then.status(200)
                .body(include_str!("fixtures/load_code_assist.json"));
        });
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:retrieveUserQuota");
            then.status(200).body(include_str!("fixtures/quota.json"));
        });
        let driver = GeminiDriver::new(GeminiEndpoints {
            oauth: server.base_url(),
            cloudcode: server.base_url(),
        });
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
        let exe = bin.join(if cfg!(windows) {
            "gemini.cmd"
        } else {
            "gemini"
        });
        fs::write(&exe, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_var = std::env::join_paths([bin.as_path()]).unwrap();
        let env = env_with(&home, [("PATH", path_var.to_str().unwrap())]);
        assert_eq!(resolve_cli(&env), Some(exe.clone()));
        let env = env_with(
            &home,
            [
                ("PATH", path_var.to_str().unwrap()),
                (CLI_OVERRIDE_ENV, exe.to_str().unwrap()),
            ],
        );
        assert_eq!(resolve_cli(&env), Some(exe));
        let env = env_with(
            &home,
            [(
                CLI_OVERRIDE_ENV,
                home.path().join("missing").to_str().unwrap(),
            )],
        );
        assert_eq!(resolve_cli(&env), None);
    }
}
