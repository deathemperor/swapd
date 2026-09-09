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
}
