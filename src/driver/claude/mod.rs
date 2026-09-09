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

    /// The `claude` binary, if this machine has one.
    ///
    /// The single process-environment read the driver makes: `installed()` takes
    /// no `Env`, so `PATH` and `HOME` come from the process here (the ruling's
    /// explicit exception). Everything else goes through `Env`.
    fn installed(&self) -> Option<PathBuf> {
        let home = std::env::var("HOME").unwrap_or_default();
        run::find_claude(
            std::env::var("PATH").ok().as_deref(),
            std::path::Path::new(&home),
        )
    }

    fn read_live(&self, env: &Env) -> Result<Login, DriverError> {
        ClaudeDriver::read_live(self, env)
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
        let from_envelope = serde_json::from_str::<serde_json::Value>(&login.bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("oauthAccount")
                    .and_then(live::identity_from_oauth_account)
            });
        if let Some(identity) = from_envelope {
            return Ok(identity);
        }
        oauth::access_token(login)
            .and_then(|token| oauth::profile(&self.endpoints, &token))
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
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

    /// Claude Code supports every verb swapd has.
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
