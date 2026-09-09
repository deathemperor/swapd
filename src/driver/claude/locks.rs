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
/// The budget for a READ that only wants a consistent pair (credential +
/// config). A status verb degrades instead of waiting, so this is short enough
/// that a `list` racing a busy CLI answers rather than stalls.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// A held proper-lockfile directory lock. `Drop` stops the toucher thread and
/// removes the directory.
#[derive(Debug)]
pub struct LockGuard {
    dir: PathBuf,
    /// The directory this guard created, by identity rather than by path. A
    /// holder that stalled past the staleness bound has its lock removed and
    /// remade by whoever takes over, and removing THAT directory on our way
    /// out would release a lock somebody else is holding.
    id: Option<DirId>,
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
        // Identity, never mtime: our own toucher moves the mtime every few
        // seconds, so a timestamp could not tell "still ours" from "taken
        // over".
        if self.id.is_some() && dir_id(&self.dir) != self.id {
            return;
        }
        // A vanished lock means someone took it over as stale; nothing to undo.
        let _ = fs::remove_dir(&self.dir);
    }
}

/// What identifies a lock directory across a take-over.
///
/// `(dev, ino)` alone is not enough: APFS never reuses an inode, but ext4 hands
/// the freed one straight back to the next `mkdir` in the same block group, so
/// a remade lock there can wear the number we recorded. The birth time settles
/// it — a real take-over is at least a staleness bound (10s) after ours, and
/// `btime` is the one timestamp our own toucher does not move. `None` where the
/// filesystem has no `btime`, which just restores the `(dev, ino)` behaviour.
///
/// Windows instead pairs the volume serial number with the file index
/// (`(nFileIndexHigh << 32) | nFileIndexLow`, from `GetFileInformationByHandle`)
/// and deliberately carries no creation time: NTFS name tunneling can hand a
/// re-created name the old creation time back, but the file index already
/// encodes the MFT record's sequence number, so a re-created directory never
/// repeats it.
#[cfg(unix)]
type DirId = (u64, u64, Option<std::time::SystemTime>);
#[cfg(windows)]
type DirId = (u32, u64);

#[cfg(unix)]
fn dir_id(dir: &Path) -> Option<DirId> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(dir).ok()?;
    Some((meta.dev(), meta.ino(), meta.created().ok()))
}

#[cfg(windows)]
fn dir_id(dir: &Path) -> Option<DirId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = open_dir(dir).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Some((info.dwVolumeSerialNumber, file_index))
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
        id: dir_id(dir),
        stop: Some(stop),
        toucher: Some(toucher),
    })
}

/// Bump `dir`'s mtime (cswap's `os.utime(lock_dir)`).
fn touch(dir: &Path) -> std::io::Result<()> {
    open_dir(dir)?.set_modified(SystemTime::now())
}

/// A handle on a DIRECTORY that `set_modified` accepts.
///
/// A plain `File::open` on a directory is refused by Windows, so the toucher
/// could never refresh the mtime there and every held lock would read as
/// stale after `staleness` — and be stolen while its holder is still writing.
/// `FILE_FLAG_BACKUP_SEMANTICS` is how a directory handle is opened on Windows,
/// and `FILE_WRITE_ATTRIBUTES` is exactly the access `SetFileTime` needs — no
/// wider, so an ACL that forbids writing the entries does not block the touch.
fn open_dir(dir: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        opts.access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    #[cfg(not(windows))]
    {
        opts.read(true);
    }
    opts.open(dir)
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
        open_dir(dir)
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

    /// A holder we deemed stale had its directory removed and remade by the
    /// taker; dropping our guard must not remove the taker's lock.
    #[test]
    fn a_stolen_lock_is_left_for_its_new_holder() {
        let home = temp_home();
        let lock = home.path().join("stolen.lock");
        let guard = proper_lockfile(&lock, CONFIG_STALENESS, Duration::from_millis(300)).unwrap();

        // What a taker does: remove the dir it judged stale, then remake it.
        // The pause is the birth-time clock's granularity, not a race: a real
        // take-over waits out a staleness bound first, and on a filesystem that
        // reuses inodes (ext4) two back-to-back `mkdir`s can otherwise share
        // both the inode number and the coarse `btime`.
        fs::remove_dir(&lock).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        fs::create_dir(&lock).unwrap();

        drop(guard);
        assert!(lock.is_dir(), "the new holder's lock must survive our drop");
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
