//! Cooperate with Claude Code's own advisory locks while mutating its files.
//!
//! Whole-file port of cswap `claude_locks.py`. Claude Code guards its OAuth
//! token refresh with the npm `proper-lockfile` package, and its
//! `~/.claude.json` writes with the same mechanism on the config file. The
//! mechanism itself is `driver::lockdir`; what Claude Code specifically takes,
//! in what order and with which staleness bounds, is here:
//!
//! - The refresh path takes **two** locks, in order: the primary
//!   `<config-home>/.oauth_refresh.lock`, then the legacy `<config-home>.lock`
//!   (`~/.claude.lock`) kept for compatibility with external tools. Both run
//!   `stale: 60000, update: 5000`.
//! - The config lock (`~/.claude.json.lock`) keeps the older defaults: stale
//!   after 10s, touched every 5s.
//! - Claude Code retries a held credentials lock with jittered sleeps before
//!   giving up, so briefly holding it is fully cooperative.
//!
//! Holding these while swapping credentials closes the one real race with a
//! running Claude Code: its refresh reads credentials, refreshes over the
//! network and saves — all under both credential locks — so a swap landing
//! inside that window would be overwritten by the refreshed old-account token.

use std::time::Duration;

use crate::driver::claude::paths;
use crate::driver::lockdir::{proper_lockfile, LockGuard};
use crate::driver::{DriverError, Env};

/// Who a `Locked` error from one of these blames: the artifacts are Claude
/// Code's, and it is the holder a waiting swapd is waiting on.
const HOLDER: &str = "claude code";

/// Claude Code's credential-refresh locks run `stale: 60000, update: 5000`
/// (2.1.218 `uKi`): a lock younger than 60s belongs to a live holder and must
/// never be stolen — the holder's toucher may stall well past 10s (suspend,
/// blocked event loop) while it still legitimately owns the lock.
pub const CREDENTIALS_STALENESS: Duration = Duration::from_secs(60);
/// The config lock keeps the older proper-lockfile defaults: stale after 10s.
pub const CONFIG_STALENESS: Duration = Duration::from_secs(10);

/// Hold Claude Code's credential-refresh locks, in Claude Code's own order.
///
/// 2.1.218 takes `<config-home>/.oauth_refresh.lock` first, then the legacy
/// `~/.claude.lock`. Mirroring both the pair and the order means a waiting
/// swapd and a waiting Claude Code can never deadlock against each other.
///
/// The returned vector is **reversed** before it is handed back, so dropping it
/// (front to back) releases the legacy lock first and the primary last — the
/// reverse of acquisition, as the Python `with` stack does.
pub fn credentials_lock(env: &Env, timeout: Duration) -> Result<Vec<LockGuard>, DriverError> {
    let config_home = paths::config_home(env)?;
    let primary = proper_lockfile(
        &config_home.join(".oauth_refresh.lock"),
        HOLDER,
        CREDENTIALS_STALENESS,
        timeout,
    )?;
    let legacy = proper_lockfile(
        &paths::lock_dir_for(&config_home),
        HOLDER,
        CREDENTIALS_STALENESS,
        timeout,
    )?;
    Ok(vec![legacy, primary])
}

/// Hold Claude Code's global-config write lock (`~/.claude.json.lock`).
pub fn config_lock(env: &Env, timeout: Duration) -> Result<LockGuard, DriverError> {
    let path = paths::lock_dir_for(&paths::config_json(env)?);
    proper_lockfile(&path, HOLDER, CONFIG_STALENESS, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::claude::tests::{env_with, temp_home};
    use crate::driver::lockdir::open_dir;
    use std::fs;
    use std::path::Path;
    use std::time::SystemTime;

    fn set_mtime(dir: &Path, ago: Duration) {
        open_dir(dir)
            .unwrap()
            .set_modified(SystemTime::now() - ago)
            .unwrap();
    }

    #[test]
    fn stale_credentials_lock_needs_a_full_minute() {
        let home = temp_home();
        let lock = home.path().join("creds.lock");
        fs::create_dir(&lock).unwrap();
        // 30s old: past the config staleness, but a live Claude Code holder
        // under the 60s credential staleness — must NOT be stolen.
        set_mtime(&lock, Duration::from_secs(30));
        assert!(matches!(
            proper_lockfile(
                &lock,
                HOLDER,
                CREDENTIALS_STALENESS,
                Duration::from_millis(200)
            ),
            Err(DriverError::Locked(_))
        ));

        set_mtime(&lock, Duration::from_secs(90));
        assert!(proper_lockfile(
            &lock,
            HOLDER,
            CREDENTIALS_STALENESS,
            Duration::from_millis(200)
        )
        .is_ok());
    }

    #[test]
    fn credentials_lock_takes_both_in_claude_codes_order() {
        let home = temp_home();
        let env = env_with(&home, []);
        let config_home = home.path().join(".claude");

        let guards = credentials_lock(&env, Duration::from_millis(300)).unwrap();
        assert!(config_home.join(".oauth_refresh.lock").is_dir());
        assert!(home.path().join(".claude.lock").is_dir());
        drop(guards);
        assert!(!config_home.join(".oauth_refresh.lock").exists());
        assert!(!home.path().join(".claude.lock").exists());
    }

    #[test]
    fn config_lock_guards_the_global_config_file() {
        let home = temp_home();
        let env = env_with(&home, []);
        let guard = config_lock(&env, Duration::from_millis(300)).unwrap();
        assert!(home.path().join(".claude.json.lock").is_dir());
        drop(guard);
        assert!(!home.path().join(".claude.json.lock").exists());
    }
}
