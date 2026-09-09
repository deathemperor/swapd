use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{ErrorCode, Result, SwapdError};

/// Read `path` as JSON, returning `T::default()` if the file doesn't exist.
pub fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e.into()),
    }
}

/// Serialize `value` to `path` atomically: write to a tmp file in the same
/// directory, then rename over the target. `0600` on unix. The parent
/// directory must already exist (callers run `Home::ensure()` first); a
/// missing directory surfaces as an `ErrorCode::Io` error.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let bytes = serde_json::to_vec_pretty(value)?;

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(path.file_name().unwrap_or_default());
    tmp_name.push(format!(".tmp.{}", rand::random::<u64>()));
    let tmp_path = dir.join(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp_path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);

    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// An advisory lock on `<path>.lock`, held for the lifetime of this value.
pub struct FileLock {
    _file: fs::File,
}

/// What `FileLock::probe` found about a `<path>.lock` sibling, without taking
/// or creating it.
pub struct LockProbe {
    pub held: bool,
    pub note: Option<String>,
}

impl FileLock {
    /// Acquire an exclusive lock on `<path>.lock`, waiting up to `timeout`.
    /// Returns `ErrorCode::Locked` if the timeout elapses first.
    pub fn acquire(path: &Path, timeout: Duration) -> Result<Self> {
        let mut lock_name = path.file_name().unwrap_or_default().to_os_string();
        lock_name.push(".lock");
        let lock_path: PathBuf = path.with_file_name(lock_name);

        let mut opts = fs::OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&lock_path)?;
        let mut rw = fd_lock::RwLock::new(file);

        let start = Instant::now();
        loop {
            let attempt = rw.try_write();
            match attempt {
                Ok(guard) => {
                    // The lock is tied to the underlying fd/handle, which
                    // stays open in `_file` below; forgetting the guard just
                    // skips its (redundant) explicit unlock on drop.
                    std::mem::forget(guard);
                    break;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if start.elapsed() >= timeout {
                        return Err(SwapdError::new(
                            ErrorCode::Locked,
                            format!("timed out waiting for lock on {}", path.display()),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(FileLock {
            _file: rw.into_inner(),
        })
    }

    /// Leave a breadcrumb in the lock file itself (the auto daemon writes its
    /// pid there, cswap `autoswitch.py:2874`).
    ///
    /// Best-effort and deliberately silent: the flock is the authority, the
    /// content is only for a human running `cat auto.lock`, and a failed write
    /// must never keep a daemon that holds the lock from running. Written
    /// through the handle that HOLDS the lock — a second handle would take a
    /// second (Windows: conflicting) range lock on the same file.
    pub fn note(&self, text: &str) {
        use std::io::{Seek as _, SeekFrom};
        let mut file = &self._file;
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.write_all(text.as_bytes());
        let _ = file.flush();
    }

    /// Read `<path>.lock`'s held/free state and any breadcrumb it holds,
    /// without creating the file and without blocking on the lock itself.
    ///
    /// `doctor` is a read verb: it must never create a lock file, so this
    /// opens without `create` — a missing file answers `held: false, note:
    /// None` outright. Otherwise it tries the same `try_write` `acquire`
    /// does; success means nobody holds it, and the guard is dropped
    /// immediately rather than kept. `note` is read independently of that
    /// result (the flock, not the file's content, is the authority), so a
    /// stale breadcrumb from a since-released lock is still reported.
    pub fn probe(path: &Path) -> Result<LockProbe> {
        let mut lock_name = path.file_name().unwrap_or_default().to_os_string();
        lock_name.push(".lock");
        let lock_path: PathBuf = path.with_file_name(lock_name);

        let mut opts = fs::OpenOptions::new();
        opts.write(true);
        let file = match opts.open(&lock_path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(LockProbe {
                    held: false,
                    note: None,
                });
            }
            Err(e) => return Err(e.into()),
        };

        let note = fs::read(&lock_path)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut rw = fd_lock::RwLock::new(file);
        let held = match rw.try_write() {
            Ok(guard) => {
                drop(guard);
                false
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => true,
            Err(e) => return Err(e.into()),
        };

        Ok(LockProbe { held, note })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::slots::SlotsFile;

    #[test]
    fn write_then_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");

        let mut original = SlotsFile {
            schema_version: 1,
            ..Default::default()
        };
        original
            .providers
            .insert("claude".to_string(), Default::default());

        write_json_atomic(&path, &original).unwrap();
        let read: SlotsFile = read_json(&path).unwrap();
        assert_eq!(read, original);
    }

    #[test]
    fn read_json_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let read: SlotsFile = read_json(&path).unwrap();
        assert_eq!(read, SlotsFile::default());
    }

    #[test]
    fn write_is_atomic_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");

        write_json_atomic(&path, &SlotsFile::default()).unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "slots.json")
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn file_lock_times_out_with_locked_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");

        let (tx, rx) = std::sync::mpsc::channel();
        let held_path = path.clone();
        let handle = std::thread::spawn(move || {
            let _lock = FileLock::acquire(&held_path, Duration::from_secs(5)).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        rx.recv().unwrap();
        let result = FileLock::acquire(&path, Duration::from_millis(100));
        match result {
            Err(e) => assert_eq!(e.code, ErrorCode::Locked),
            Ok(_) => panic!("expected timeout"),
        }
        handle.join().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock_path = dir.path().join("slots.json.lock");
            let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn probe_missing_file_is_not_held_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine");

        let probe = FileLock::probe(&path).unwrap();
        assert!(!probe.held);
        assert_eq!(probe.note, None);
        assert!(!dir.path().join("engine.lock").exists());
    }

    #[test]
    fn probe_reports_a_held_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto");

        let lock = FileLock::acquire(&path, Duration::from_secs(1)).unwrap();
        lock.note("held-by-test");

        let probe = FileLock::probe(&path).unwrap();
        assert!(probe.held);
        // Windows locks are mandatory: the note cannot be read from a second
        // handle while the lock is held, so `probe` reports it only once the
        // lock is released (`doctor` shows `held` without a pid there).
        #[cfg(unix)]
        assert_eq!(probe.note.as_deref(), Some("held-by-test"));

        drop(lock);
        let probe = FileLock::probe(&path).unwrap();
        assert!(!probe.held);
        assert_eq!(probe.note.as_deref(), Some("held-by-test"));
    }
}
