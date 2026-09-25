//! The daemon's cross-process wake: how a verb that changed what `auto`
//! decides on tells a running daemon to look now, not on its next tick.
//!
//! `auto` sleeps between ticks — a minute ordinarily, ten once every account
//! reads spent — and nothing it decides on changes by itself. An account is
//! added, a refusal is reported (`limit-hit`), the live login is switched by
//! hand, a knob is set: each is a swapd verb, and it is run by whoever runs
//! it — a terminal, the Infinitus app, the menu-bar helper — processes that
//! do not know about each other, at most one of which holds the daemon's
//! stdin (and today none does: the helper installs `auto` under launchd,
//! unsupervised). A wake only a supervisor can send is a wake that never
//! comes, so this one is a file: the verb writes a fresh nonce to
//! `<home>/auto.wake` on its way out, and a sleeping daemon reads that file
//! once a second and ticks when the nonce has changed.
//!
//! Content, not mtime: an mtime is only as fine as the filesystem's clock,
//! and a nudge landing in the same second as the daemon's last look would be
//! lost to a reader comparing stamps. The write is temp-and-rename, so a
//! reader never sees half a nonce and fires twice for one nudge.
//!
//! The wake carries nothing — like the supervised stdin line it stands beside
//! (`cmd::auto`), it means "look now": whatever the verb knew it has already
//! written to the store, and the tick reads the store. Queued wakes collapse
//! into one tick there too.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use crate::paths::Home;

/// How often a sleeping daemon reads the wake file. One small read a second
/// is the mechanism's whole idle cost.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Tell a running daemon to re-evaluate now.
///
/// Best-effort and silent: a data dir with no daemon in it is the ordinary
/// case at a terminal, and a verb that has already succeeded must not fail
/// over its nudge — the daemon's next tick reads the same store either way.
pub fn nudge(home: &Home) {
    let _ = write_nonce(&home.auto_wake_file());
}

fn write_nonce(path: &Path) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let nonce = format!("{:016x}\n", rand::random::<u64>());

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(path.file_name().unwrap_or_default());
    tmp_name.push(format!(".tmp.{}", rand::random::<u64>()));
    let tmp_path = dir.join(tmp_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp_path)?;
    file.write_all(nonce.as_bytes())?;
    drop(file);
    std::fs::rename(&tmp_path, path)
}

/// The wake file's nonce as it stands; a file that is not there reads as
/// empty.
fn read_nonce(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// Watch the wake file from a thread of its own: every `interval`, read it,
/// and send `()` on `wake` when the nonce differs from the last read. The
/// thread ends once nothing is listening any more.
///
/// The first read is the baseline, not a wake: a nudge from before the daemon
/// started has nothing to add to its first tick, which reads everything.
pub fn watch(path: PathBuf, interval: Duration, wake: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let mut last = read_nonce(&path);
        loop {
            std::thread::sleep(interval);
            let current = read_nonce(&path);
            if current != last {
                last = current;
                if wake.send(()).is_err() {
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn home() -> (TempDir, Home) {
        let dir = TempDir::new().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        (dir, home)
    }

    /// Long enough that a loaded runner cannot fail it; the watcher's own
    /// interval below is 10 ms.
    const ARRIVAL: Duration = Duration::from_secs(5);
    /// Long enough for the watcher to have looked several times.
    const SILENCE: Duration = Duration::from_millis(100);

    #[test]
    fn a_nudge_wakes_the_watcher_once_and_a_quiet_file_never_does() {
        let (_dir, home) = home();
        let (tx, rx) = mpsc::channel();
        watch(home.auto_wake_file(), Duration::from_millis(10), tx);

        // Nothing has been nudged: nothing arrives, however long we look.
        assert!(rx.recv_timeout(SILENCE).is_err(), "a quiet file woke it");

        nudge(&home);
        assert!(rx.recv_timeout(ARRIVAL).is_ok(), "a nudge did not wake it");
        // One nudge is one wake, not one per read of the same nonce.
        assert!(rx.recv_timeout(SILENCE).is_err(), "one nudge woke it twice");

        // And the next nudge is the next wake: the nonce is never reused.
        nudge(&home);
        assert!(
            rx.recv_timeout(ARRIVAL).is_ok(),
            "a second nudge did not wake it"
        );
    }

    #[test]
    fn every_nudge_writes_a_new_nonce() {
        let (_dir, home) = home();
        nudge(&home);
        let first = read_nonce(&home.auto_wake_file());
        nudge(&home);
        let second = read_nonce(&home.auto_wake_file());
        assert!(!first.is_empty());
        assert_ne!(first, second);
        // No temp file is left beside it.
        let leftovers: Vec<_> = std::fs::read_dir(&home.root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| name != "auto.wake")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_nudge_with_no_data_dir_is_silent() {
        let (dir, _) = home();
        let missing = Home {
            root: dir.path().join("missing"),
        };
        nudge(&missing); // must not panic, must not create the dir
        assert!(!missing.root.exists());
    }
}
