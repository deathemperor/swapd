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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::gemini::tests::{env_with, temp_home};

    #[test]
    fn gemini_cli_home_wins_over_the_os_home() {
        let home = temp_home();
        let env = env_with(&home, [("GEMINI_CLI_HOME", "/elsewhere")]);
        assert_eq!(
            gemini_dir(&env).unwrap(),
            std::path::Path::new("/elsewhere").join(".gemini")
        );
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
