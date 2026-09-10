//! The Gemini CLI driver (google-gemini/gemini-cli, "oauth-personal" auth).
//!
//! `paths` says where the CLI keeps its login, `live` reads and replaces the
//! file pair under swapd's own lock, `identity` answers who a login is without
//! the network, `oauth` refreshes, `usage` asks Code Assist for quota (and is
//! the igniter), `run` builds per-slot `GEMINI_CLI_HOME` profiles.

pub mod identity;
pub mod live;
pub mod oauth;
pub mod paths;
pub mod run;
pub mod usage;

#[cfg(test)]
pub mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::driver::{
    Caps, Driver, DriverError, Env, Identity, IgniteOutcome, Login, RunProfile, Usage,
};

pub struct GeminiDriver {
    pub endpoints: oauth::GeminiEndpoints,
    /// Where the OAuth client comes from; resolved on first refresh and kept
    /// for the driver's lifetime (`client_memo`).
    pub client_source: oauth::ClientSource,
    pub(crate) client_memo: Mutex<Option<oauth::OauthClient>>,
    /// `email -> cloudaicompanionProject`, learned from `loadCodeAssist` once
    /// per process (the daemon is long-lived; a status verb pays one extra
    /// request). Never persisted.
    pub(crate) project_memo: Mutex<HashMap<String, String>>,
}

impl GeminiDriver {
    pub fn new(endpoints: oauth::GeminiEndpoints, client_source: oauth::ClientSource) -> Self {
        Self {
            endpoints,
            client_source,
            client_memo: Mutex::new(None),
            project_memo: Mutex::new(HashMap::new()),
        }
    }

    pub fn default_for_platform(env: &Env) -> Self {
        Self::new(
            oauth::GeminiEndpoints::from_env(env),
            oauth::ClientSource::from_env(env),
        )
    }

    /// The OAuth client a refresh sends, found once per driver.
    pub fn oauth_client(&self) -> Result<oauth::OauthClient, DriverError> {
        if let Some(client) = self.client_memo.lock().ok().and_then(|m| m.clone()) {
            return Ok(client);
        }
        let client = self.client_source.resolve()?;
        if let Ok(mut memo) = self.client_memo.lock() {
            *memo = Some(client.clone());
        }
        Ok(client)
    }

    /// A driver whose endpoints are unreachable loopback addresses: for tests
    /// that only exercise `paths`/`live` and never make a request.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self::new(
            oauth::GeminiEndpoints {
                oauth: "http://127.0.0.1:1".into(),
                cloudcode: "http://127.0.0.1:1".into(),
            },
            oauth::ClientSource::for_tests(),
        )
    }
}

impl Driver for GeminiDriver {
    fn id(&self) -> &'static str {
        "gemini"
    }
    fn installed(&self, env: &Env) -> Option<PathBuf> {
        run::resolve_cli(env)
    }
    fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        GeminiDriver::read_live(self, env)
    }
    fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        GeminiDriver::read_live_locked(self, env)
    }
    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError> {
        GeminiDriver::write_live(self, env, login)
    }
    fn identity(&self, login: &Login) -> Result<Identity, DriverError> {
        self.identity_offline(login)
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
    }
    fn identity_offline(&self, login: &Login) -> Option<Identity> {
        identity::identity_offline(login)
    }
    fn expires_at(&self, login: &Login) -> Option<f64> {
        identity::expires_at(login)
    }
    fn refresh(&self, login: &Login) -> Result<Login, DriverError> {
        oauth::refresh(&self.endpoints, &self.oauth_client()?, login)
    }
    fn usage(&self, login: &Login) -> Result<Usage, DriverError> {
        usage::usage(self, login)
    }
    fn ignite(&self, env: &Env, slot: u32, login: &Login) -> Result<IgniteOutcome, DriverError> {
        run::ignite(self, env, slot, login)
    }
    fn run_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError> {
        run::run_profile(env, slot, login)
    }
    fn commit_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<(), DriverError> {
        run::commit_profile(env, slot, login)
    }
    fn forget_profile(&self, env: &Env, slot: u32) -> Result<(), DriverError> {
        run::forget_profile(env, slot)
    }
    fn live_config_text(&self, env: &Env) -> Result<Option<String>, DriverError> {
        GeminiDriver::live_config_text(self, env)
    }
    fn capabilities(&self) -> Caps {
        Caps {
            ignite: true,
            add_token: false,
            prefer: true,
            refresh: true,
            run: true,
        }
    }
    /// Anything with a refresh token can be made live; there is no other axis.
    fn can_activate(&self, login: &Login) -> Result<(), DriverError> {
        let envelope = live::Envelope::parse(&login.bytes)?;
        match envelope
            .oauth_creds
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
        {
            Some(t) if !t.is_empty() => Ok(()),
            _ => Err(DriverError::Invalid(
                "gemini login has no refresh token".to_string(),
            )),
        }
    }
    /// API keys never live in `oauth_creds.json`.
    fn is_api_key(&self, _login: &Login) -> bool {
        false
    }
}
