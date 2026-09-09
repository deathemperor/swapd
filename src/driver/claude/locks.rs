//! Cooperate with Claude Code's own advisory locks while mutating its files.
//!
//! Whole-file port of cswap `claude_locks.py`. Claude Code guards its OAuth
//! token refresh with the npm `proper-lockfile` package, and its
//! `~/.claude.json` writes with the same mechanism on the config file. The
//! protocol (verified against the 2.1.218 bundle):
//!
//! - The lock artifact is a **directory**; `mkdir` atomicity is the mutex.
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

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::driver::claude::paths;
use crate::driver::{DriverError, Env};

/// Claude Code's credential-refresh locks run `stale: 60000, update: 5000`
/// (2.1.218 `uKi`): a lock younger than 60s belongs to a live holder and must
/// never be stolen — the holder's toucher may stall well past 10s (suspend,
/// blocked event loop) while it still legitimately owns the lock.
pub const CREDENTIALS_STALENESS: Duration = Duration::from_secs(60);
/// The config lock keeps the older proper-lockfile defaults: stale after 10s.
pub const CONFIG_STALENESS: Duration = Duration::from_secs(10);
/// We touch a little faster than Claude Code's 5s, for margin.
const TOUCH_INTERVAL: Duration = Duration::from_secs(3);
/// Claude Code holds the credentials lock for one token-endpoint round trip
/// (sub-second to a few seconds); its config lock for a local read-modify-write.
/// 9s of bounded waiting comfortably outlasts both without stalling forever.
/// This is a PER-LOCK budget: `credentials_lock` acquires two sequentially, so
/// its worst case is ~2x this value.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(9);

/// A held proper-lockfile directory lock. `Drop` stops the toucher thread and
/// removes the directory.
#[derive(Debug)]
pub struct LockGuard {
    dir: PathBuf,
    // Dropping the sender wakes the toucher out of `recv_timeout` at once.
    stop: Option<Sender<()>>,
    toucher: Option<JoinHandle<()>>,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Signalled, then DETACHED rather than joined: the toucher exits at its
        // next wake on its own, and joining it would block the release (and the
        // whole swap) behind a stuck filesystem for as long as the `utime`
        // hangs. Python joined with a 1s timeout; Rust's `join` has none.
        drop(self.stop.take());
        drop(self.toucher.take());
        // A vanished lock means someone took it over as stale; nothing to undo.
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Acquire a proper-lockfile-compatible directory lock on `dir` (the lock
/// artifact itself, e.g. `~/.claude.json.lock`).
///
/// Blocks up to `timeout`, taking over locks whose mtime is older than
/// `staleness`, and touches the directory's mtime while held so other holders
/// don't deem us stale.
///
/// The retry sleep is cswap's `0.25 + random() * 0.25` s. (The brief's "1–2s
/// jittered sleeps" is Claude Code's *own* retry cadence, quoted in
/// `claude_locks.py`'s docstring — not the cadence cswap waits at.)
pub fn proper_lockfile(
    dir: &Path,
    staleness: Duration,
    timeout: Duration,
) -> Result<LockGuard, DriverError> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let start = Instant::now();
    loop {
        match fs::create_dir(dir) {
            Ok(()) => break,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        if start.elapsed() > timeout {
            // The path only — never the holder's contents.
            return Err(DriverError::Locked(format!(
                "claude code holds {}",
                dir.display()
            )));
        }
        let held = match fs::metadata(dir).and_then(|m| m.modified()) {
            Ok(mtime) => mtime,
            // Holder released between mkdir and stat; retry now.
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let age = SystemTime::now()
            .duration_since(held)
            .unwrap_or(Duration::ZERO);
        if age > staleness {
            // Dead holder per the protocol: remove and retake. Losing the
            // rmdir/mkdir race to another waiter just means looping again.
            if fs::remove_dir(dir).is_err() {
                // Can't remove it either; don't spin hot.
                std::thread::sleep(Duration::from_millis(50));
            }
            continue;
        }
        std::thread::sleep(
            Duration::from_millis(250) + Duration::from_secs_f64(rand::random::<f64>() * 0.25),
        );
    }

    let (stop, rx) = mpsc::channel::<()>();
    let touch_dir = dir.to_path_buf();
    let toucher = std::thread::spawn(move || loop {
        match rx.recv_timeout(TOUCH_INTERVAL) {
            Err(RecvTimeoutError::Timeout) => {
                if touch(&touch_dir).is_err() {
                    return; // lock stolen/removed; nothing left to keep alive
                }
            }
            // Guard dropped (or sender gone): stop touching.
            _ => return,
        }
    });

    Ok(LockGuard {
        dir: dir.to_path_buf(),
        stop: Some(stop),
        toucher: Some(toucher),
    })
}

/// Bump `dir`'s mtime (cswap's `os.utime(lock_dir)`).
fn touch(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.set_modified(SystemTime::now())
}

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
        CREDENTIALS_STALENESS,
        timeout,
    )?;
    let legacy = proper_lockfile(
        &paths::lock_dir_for(&config_home),
        CREDENTIALS_STALENESS,
        timeout,
    )?;
    Ok(vec![legacy, primary])
}

/// Hold Claude Code's global-config write lock (`~/.claude.json.lock`).
pub fn config_lock(env: &Env, timeout: Duration) -> Result<LockGuard, DriverError> {
    let path = paths::lock_dir_for(&paths::config_json(env)?);
    proper_lockfile(&path, CONFIG_STALENESS, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::claude::tests::{env_with, temp_home};

    fn set_mtime(dir: &Path, ago: Duration) {
        fs::File::open(dir)
            .unwrap()
            .set_modified(SystemTime::now() - ago)
            .unwrap();
    }

    #[test]
    fn acquire_creates_dir_and_drop_removes_it() {
        let home = temp_home();
        let lock = home.path().join("nested/target.lock");
        {
            let _guard =
                proper_lockfile(&lock, CONFIG_STALENESS, Duration::from_millis(300)).unwrap();
            assert!(lock.is_dir(), "lock directory should exist while held");
        }
        assert!(!lock.exists(), "lock directory should be gone after drop");
    }

    #[test]
    fn fresh_lock_is_not_stolen() {
        let home = temp_home();
        let lock = home.path().join("fresh.lock");
        fs::create_dir(&lock).unwrap();

        let err = proper_lockfile(&lock, CONFIG_STALENESS, Duration::from_millis(300)).unwrap_err();
        match err {
            DriverError::Locked(msg) => {
                assert!(msg.contains(lock.to_str().unwrap()), "message: {msg}");
                assert!(msg.starts_with("claude code holds "), "message: {msg}");
            }
            other => panic!("expected Locked, got {other:?}"),
        }
        assert!(lock.is_dir(), "the holder's lock must survive our timeout");
    }

    #[test]
    fn stale_lock_is_stolen() {
        let home = temp_home();
        let lock = home.path().join("stale.lock");
        fs::create_dir(&lock).unwrap();
        set_mtime(&lock, Duration::from_secs(120));

        let guard = proper_lockfile(&lock, CONFIG_STALENESS, Duration::from_millis(300)).unwrap();
        assert!(lock.is_dir());
        drop(guard);
        assert!(!lock.exists());
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
            proper_lockfile(&lock, CREDENTIALS_STALENESS, Duration::from_millis(200)),
            Err(DriverError::Locked(_))
        ));

        set_mtime(&lock, Duration::from_secs(90));
        assert!(proper_lockfile(&lock, CREDENTIALS_STALENESS, Duration::from_millis(200)).is_ok());
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

    #[test]
    fn holding_a_lock_keeps_its_mtime_fresh() {
        let home = temp_home();
        let lock = home.path().join("touched.lock");
        let _guard = proper_lockfile(&lock, CONFIG_STALENESS, Duration::from_millis(300)).unwrap();
        // Backdate it as a stalled holder would, then let the toucher run.
        // Polled rather than slept once: a loaded runner can overshoot a fixed
        // margin on the 3s timer.
        set_mtime(&lock, Duration::from_secs(600));
        let backdated = fs::metadata(&lock).unwrap().modified().unwrap();
        let deadline = Instant::now() + TOUCH_INTERVAL * 3;
        let touched = loop {
            if fs::metadata(&lock).unwrap().modified().unwrap() > backdated {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(touched, "the toucher should have bumped the mtime");
    }
}
