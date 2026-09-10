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
            return Err(DriverError::Invalid(
                "malformed gemini envelope".to_string(),
            ));
        };
        let oauth_creds = match outer.remove("oauth_creds") {
            Some(Value::Object(m)) => m,
            _ => {
                return Err(DriverError::Invalid(
                    "gemini envelope has no oauth_creds".to_string(),
                ))
            }
        };
        let google_account = outer
            .get("google_account")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok(Envelope {
            oauth_creds,
            google_account,
        })
    }

    pub fn to_login(&self) -> Login {
        let mut outer = Map::new();
        outer.insert(
            "oauth_creds".to_string(),
            Value::Object(self.oauth_creds.clone()),
        );
        outer.insert(
            "google_account".to_string(),
            self.google_account
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        Login {
            bytes: Value::Object(outer).to_string(),
        }
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
    let Some(text) = read_optional(&paths::settings(env)?)? else {
        return Ok(None);
    };
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
            return Err(DriverError::Invalid(
                "oauth_creds.json is not a JSON object".to_string(),
            ));
        };
        let google_account = match read_optional(&paths::google_accounts(env)?)? {
            Some(text) => serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("active").and_then(Value::as_str).map(str::to_string))
                .filter(|s| !s.is_empty()),
            None => None,
        };
        Ok(Envelope {
            oauth_creds,
            google_account,
        }
        .to_login())
    }

    pub fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        self.read_live_locked_with_timeout(env, READ_TIMEOUT)
    }

    /// `read_live` under swapd's own live lock. `Locked` on timeout; a lock
    /// directory that cannot be created (read-only home) degrades to the
    /// unfenced read, as the Claude driver does.
    pub fn read_live_locked_with_timeout(
        &self,
        env: &Env,
        timeout: Duration,
    ) -> Result<Login, DriverError> {
        let _guard = match take_live_lock(env, timeout) {
            Ok(guard) => guard,
            Err(DriverError::Io(e))
                if matches!(
                    e.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
                ) =>
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
    pub fn write_live_with_timeout(
        &self,
        env: &Env,
        login: &Login,
        timeout: Duration,
    ) -> Result<(), DriverError> {
        let envelope = Envelope::parse(&login.bytes)?;
        let dir = paths::gemini_dir(env)?;
        fs::create_dir_all(&dir)?;
        let _guard = take_live_lock(env, timeout)?;

        let creds_path = paths::oauth_creds(env)?;
        let tmp = dir.join(".oauth_creds.json.swapd-tmp");
        write_private_file(
            &tmp,
            &Value::Object(envelope.oauth_creds.clone()).to_string(),
        )?;
        fs::rename(&tmp, &creds_path)?;

        let accounts_path = paths::google_accounts(env)?;
        let mut accounts = read_optional(&accounts_path)?
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        let previous = accounts
            .get("active")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut old: Vec<String> = accounts
            .get("old")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(previous) = previous {
            if envelope.google_account.as_deref() != Some(previous.as_str())
                && !old.contains(&previous)
            {
                old.push(previous);
            }
        }
        accounts.insert(
            "active".to_string(),
            envelope
                .google_account
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
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

/// Takes swapd's own lock around the pair, wrapping the message so it reads
/// as swapd's rather than Claude Code's (`proper_lockfile`'s wording belongs
/// to the Claude module; its integration test pins it, so it is left alone).
fn take_live_lock(env: &Env, timeout: Duration) -> Result<LockGuard, DriverError> {
    let path = paths::live_lock(env)?;
    proper_lockfile(&path, LIVE_LOCK_STALENESS, timeout).map_err(|e| match e {
        DriverError::Locked(_) => DriverError::Locked(format!("swapd holds {}", path.display())),
        other => other,
    })
}

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
        let login = GeminiDriver::for_tests().read_live(&env).unwrap();
        let value: serde_json::Value = serde_json::from_str(&login.bytes).unwrap();
        assert_eq!(value["oauth_creds"]["refresh_token"], "rt-1");
        assert_eq!(value["google_account"], "you@example.com");
    }

    #[test]
    fn read_live_without_the_pointer_file_has_a_null_account() {
        let home = temp_home();
        seed_live(home.path(), CREDS, None);
        let login = GeminiDriver::for_tests()
            .read_live(&env_with(&home, []))
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&login.bytes).unwrap();
        assert!(value["google_account"].is_null());
    }

    #[test]
    fn read_live_without_credentials_is_no_login() {
        let home = temp_home();
        assert!(matches!(
            GeminiDriver::for_tests().read_live(&env_with(&home, [])),
            Err(DriverError::NoLogin)
        ));
    }

    #[test]
    fn read_live_rejects_a_non_object_credential_file() {
        let home = temp_home();
        seed_live(home.path(), "[1,2]", Some(ACCOUNTS));
        assert!(matches!(
            GeminiDriver::for_tests().read_live(&env_with(&home, [])),
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
        match GeminiDriver::for_tests().read_live(&env_with(&home, [])) {
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
            GeminiDriver::for_tests().read_live(&env),
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
        GeminiDriver::for_tests().write_live(&env, &next).unwrap();
        let creds: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(paths::oauth_creds(&env).unwrap()).unwrap())
                .unwrap();
        assert_eq!(creds["refresh_token"], "rt-2");
        let accounts: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(paths::google_accounts(&env).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(accounts["active"], "other@example.com");
        assert_eq!(accounts["old"], serde_json::json!(["you@example.com"]));
        assert!(
            !paths::live_lock(&env).unwrap().exists(),
            "the lock is released"
        );
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
        GeminiDriver::for_tests().write_live(&env, &login).unwrap();
        let mode = fs::metadata(paths::oauth_creds(&env).unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_held_live_lock_makes_the_locked_read_report_locked() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        fs::create_dir_all(paths::live_lock(&env).unwrap()).unwrap();
        assert!(matches!(
            GeminiDriver::for_tests()
                .read_live_locked_with_timeout(&env, Duration::from_millis(200)),
            Err(DriverError::Locked(_))
        ));
        // The unfenced read still answers.
        assert!(GeminiDriver::for_tests().read_live(&env).is_ok());
    }

    #[test]
    fn live_config_text_is_the_pointer_file() {
        let home = temp_home();
        seed_live(home.path(), CREDS, Some(ACCOUNTS));
        let env = env_with(&home, []);
        assert_eq!(
            GeminiDriver::for_tests()
                .live_config_text(&env)
                .unwrap()
                .as_deref(),
            Some(ACCOUNTS)
        );
        fs::remove_file(paths::google_accounts(&env).unwrap()).unwrap();
        assert_eq!(
            GeminiDriver::for_tests().live_config_text(&env).unwrap(),
            None
        );
    }
}
