//! The Claude Code driver.
//!
//! The environment-facing half is `paths` (where Claude Code keeps its config
//! and credential), `locks` (the port of its `proper-lockfile` handshake) and
//! `live` (reading/replacing the live login). The network- and process-facing
//! half is `oauth` (refresh, the profile oracle), `usage` (usage → windows with
//! pace) and `run` (per-slot profiles, the igniter). This file is the seam: the
//! `Driver` impl that puts them together.

pub mod live;
pub mod locks;
pub mod oauth;
pub mod paths;
pub mod run;
pub mod usage;

#[cfg(test)]
pub mod tests;

use std::path::PathBuf;

use crate::driver::claude::live::ClaudeDriver;
use crate::driver::{
    Caps, Driver, DriverError, Env, Identity, IgniteOutcome, Login, RunProfile, Usage,
};

impl Driver for ClaudeDriver {
    fn id(&self) -> &'static str {
        "claude"
    }

    /// The `claude` binary, if this environment has one — the same lookup the
    /// igniter makes, from the same `Env`.
    fn installed(&self, env: &Env) -> Option<PathBuf> {
        run::resolve_cli(env)
    }

    fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        ClaudeDriver::read_live(self, env)
    }

    fn read_live_locked(&self, env: &Env) -> Result<Login, DriverError> {
        ClaudeDriver::read_live_locked(self, env)
    }

    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError> {
        ClaudeDriver::write_live(self, env, login)
    }

    /// Who this login belongs to.
    ///
    /// The envelope's own `oauthAccount` first — it is the copy Claude Code
    /// itself advertises for this credential, it carries the organization name
    /// and the plan, and reading it costs no network. Only when the envelope has
    /// none does the profile endpoint get asked, and that answer is thinner (no
    /// org name, no plan). Neither yielding one is an error, not a blank
    /// identity: a caller must not present an account it cannot name.
    fn identity(&self, login: &Login) -> Result<Identity, DriverError> {
        if let Some(identity) = self.identity_offline(login) {
            return Ok(identity);
        }
        oauth::access_token(login)
            .and_then(|token| oauth::profile(&self.endpoints, &token))
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
    }

    /// The envelope's own `oauthAccount` and nothing else — the copy Claude
    /// Code advertises for this credential, carrying the organization name and
    /// the plan.
    fn identity_offline(&self, login: &Login) -> Option<Identity> {
        serde_json::from_str::<serde_json::Value>(&login.bytes)
            .ok()?
            .get("oauthAccount")
            .and_then(live::identity_from_oauth_account)
    }

    /// `claudeAiOauth.expiresAt`, which Claude Code stores in milliseconds.
    fn expires_at(&self, login: &Login) -> Option<f64> {
        serde_json::from_str::<serde_json::Value>(&login.bytes)
            .ok()?
            .pointer("/claudeAiOauth/expiresAt")
            .and_then(serde_json::Value::as_f64)
            .map(|ms| ms / 1000.0)
    }

    fn refresh(&self, login: &Login) -> Result<Login, DriverError> {
        oauth::refresh(&self.endpoints, login)
    }

    /// This login's usage windows.
    ///
    /// An expired (or nearly expired) access token is reported as
    /// `NeedsRefresh`, never refreshed here. A Claude refresh token is
    /// single-use: a refresh performed inside `usage()` would rotate the
    /// lineage into a `Login` the caller never receives, so the next call would
    /// POST a token the server has already spent and earn `invalid_grant` on a
    /// live account. The caller refreshes, persists, and calls again.
    ///
    /// `fetched_at` is read once and used both for the pace baseline and for the
    /// snapshot's own timestamp, so the two cannot drift apart.
    fn usage(&self, login: &Login) -> Result<Usage, DriverError> {
        if oauth::is_expired(login, oauth::now_ms()) {
            return Err(DriverError::NeedsRefresh);
        }
        let access_token = oauth::access_token(login)
            .ok_or_else(|| DriverError::Invalid("no access token".to_string()))?;
        let raw = usage::fetch(&self.endpoints, &access_token)?;
        let fetched_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        Ok(Usage {
            windows: usage::windows_at(&raw, fetched_at),
            fetched_at,
        })
    }

    fn ignite(&self, env: &Env, slot: u32, login: &Login) -> Result<IgniteOutcome, DriverError> {
        run::ignite(self, env, slot, login)
    }

    fn run_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<RunProfile, DriverError> {
        run::run_profile(self, env, slot, login)
    }

    fn commit_profile(&self, env: &Env, slot: u32, login: &Login) -> Result<(), DriverError> {
        run::commit_profile(env, slot, login)
    }

    fn forget_profile(&self, env: &Env, slot: u32) -> Result<(), DriverError> {
        run::forget_profile(self, env, slot)
    }

    fn relocate_profile(&self, env: &Env, from: u32, to: u32) -> Result<(), DriverError> {
        run::relocate_profile(self, env, from, to)
    }

    /// `~/.claude.json` (or the legacy `<config dir>/.config.json`), through
    /// the same resolver every other read uses — so `$CLAUDE_CONFIG_DIR` is
    /// honoured here exactly as Claude Code honours it.
    fn live_config_text(&self, env: &Env) -> Result<Option<String>, DriverError> {
        let path = paths::config_json(env)?;
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DriverError::Io(e)),
        }
    }

    /// Claude Code supports every verb swapd has.
    /// Claude Code's live login is its OAuth item; a managed `sk-ant-api…` key
    /// is a different axis (`ANTHROPIC_API_KEY` / the approved-key list) that
    /// `write_live` deliberately refuses, so the same gate answers here.
    fn can_activate(&self, login: &Login) -> Result<(), DriverError> {
        live::require_oauth_login(&login.bytes)
    }

    fn is_api_key(&self, login: &Login) -> bool {
        live::looks_like_api_key(&login.bytes)
    }

    fn capabilities(&self) -> Caps {
        Caps {
            ignite: true,
            add_token: true,
            prefer: true,
            refresh: true,
            run: true,
        }
    }
}
