use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::errors::{ErrorCode, Result, SwapdError};
use crate::paths::Home;
#[cfg(target_os = "macos")]
use crate::security_cli::RealSecurity;
use crate::security_cli::SecurityCli;

const SERVICE: &str = "swapd";

pub trait Secrets: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

pub struct SecuritySecrets {
    cli: Arc<dyn SecurityCli>,
}

impl SecuritySecrets {
    pub fn new(cli: Arc<dyn SecurityCli>) -> Self {
        Self { cli }
    }
}

impl Secrets for SecuritySecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.cli.find(SERVICE, Some(key))
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        // `security -i add-generic-password ... -X` with an empty hex string is
        // rejected by `security` itself (exit 2), which would otherwise read as a
        // backend error and permanently degrade `StickySecrets` to the file backend.
        if value.is_empty() {
            return Err(SwapdError::new(ErrorCode::InvalidInput, "empty secret"));
        }
        self.cli.add(SERVICE, key, value)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.cli.delete(SERVICE, key)
    }
}

pub struct FileSecrets {
    dir: PathBuf,
}

impl FileSecrets {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn key_path(&self, key: &str) -> Result<PathBuf> {
        if key.contains('/') || key.contains('\\') || key.contains("..") {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                "invalid secret key",
            ));
        }
        Ok(self.dir.join(key.replace(':', "_")))
    }
}

impl Secrets for FileSecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let path = self.key_path(key)?;
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let path = self.key_path(key)?;
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }

        // Single opaque value: written straight to `path`, not through an atomic
        // tmp+rename like `write_json_atomic` — a crash mid-write loses the value
        // rather than leaving the old one intact. `mode(0o600)` only applies at
        // creation, so an existing looser-mode file gets `set_permissions` on the open
        // handle BEFORE any content is written, closing the window where a stale mode
        // would make the secret briefly world/group readable.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_path(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct MemorySecrets(Mutex<HashMap<String, String>>);

impl MemorySecrets {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl Default for MemorySecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl Secrets for MemorySecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Ported sticky per-process fallback: once `primary` errors with
/// `ErrorCode::KeychainUnavailable` — a backend failure, not a caller mistake — every
/// later call in this process goes straight to `fallback`. Any other error
/// (`InvalidInput`, `Io`, …) propagates as-is without degrading: it means the call was
/// wrong, not that the backend is unreachable. A `None` result from `primary` is not a
/// failure either. `delete` fans out to both backends best-effort (so a plaintext copy
/// the file backend may hold can't outlive the keychain item, and vice versa) but
/// reports `primary`'s result while not degraded, `fallback`'s once degraded. A
/// successful `set` on `primary` also clears any stale copy in `fallback` left by an
/// earlier degraded run, ignoring that delete's result.
pub struct StickySecrets {
    primary: Box<dyn Secrets>,
    fallback: Box<dyn Secrets>,
    degraded: AtomicBool,
}

impl StickySecrets {
    pub fn new(primary: Box<dyn Secrets>, fallback: Box<dyn Secrets>) -> Self {
        Self {
            primary,
            fallback,
            degraded: AtomicBool::new(false),
        }
    }
}

impl Secrets for StickySecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        if self.degraded.load(Ordering::SeqCst) {
            return self.fallback.get(key);
        }
        match self.primary.get(key) {
            Ok(v) => Ok(v),
            Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                self.degraded.store(true, Ordering::SeqCst);
                self.fallback.get(key)
            }
            Err(e) => Err(e),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        if self.degraded.load(Ordering::SeqCst) {
            return self.fallback.set(key, value);
        }
        match self.primary.set(key, value) {
            Ok(()) => {
                // Clear any plaintext copy an earlier degraded run may have left in
                // the fallback, so it can't outlive the keychain item. Ignore the
                // result: a missing copy isn't an error, and the write already
                // succeeded via `primary`.
                let _ = self.fallback.delete(key);
                Ok(())
            }
            Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                self.degraded.store(true, Ordering::SeqCst);
                self.fallback.set(key, value)
            }
            Err(e) => Err(e),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        if self.degraded.load(Ordering::SeqCst) {
            return self.fallback.delete(key);
        }
        match self.primary.delete(key) {
            Ok(()) => {
                // Best-effort fan-out: a copy in the fallback shouldn't outlive a
                // keychain item `primary` just deleted, but its result never
                // overrides `primary`'s — that's the one the caller asked about.
                let _ = self.fallback.delete(key);
                Ok(())
            }
            Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                // Same shape as get/set: degrade, then answer from the fallback.
                self.degraded.store(true, Ordering::SeqCst);
                self.fallback.delete(key)
            }
            Err(e) => Err(e),
        }
    }
}

/// `SWAPD_SECRETS` = `file` | `memory` overrides (tests, CI); unset -> macOS
/// `Sticky(Security, File)`, elsewhere `File`. An unrecognized (non-empty, non-`file`,
/// non-`memory`) value also falls back to `File` — never silently to the keychain.
// Not wired into a verb yet; later tasks (login, use) call this to build their store.
pub fn default_secrets(home: &Home) -> Box<dyn Secrets> {
    secrets_for(home, std::env::var("SWAPD_SECRETS").ok().as_deref())
}

/// `default_secrets` reads `SWAPD_SECRETS` from the process environment and calls this;
/// tests call it directly with an explicit `mode` instead of mutating `SWAPD_SECRETS`
/// (a process-global that isn't safe to set/unset from a parallel test binary — a race
/// could let `platform_default` run and, on macOS, write a test value into the real
/// login keychain).
// Not wired into a verb yet; `default_secrets` (above) and tests call this directly.
pub fn secrets_for(home: &Home, mode: Option<&str>) -> Box<dyn Secrets> {
    match mode {
        Some("file") => Box::new(FileSecrets::new(home.credentials_dir())),
        Some("memory") => Box::new(MemorySecrets::new()),
        Some(_) => Box::new(FileSecrets::new(home.credentials_dir())),
        None => platform_default(home),
    }
}

#[cfg(target_os = "macos")]
fn platform_default(home: &Home) -> Box<dyn Secrets> {
    Box::new(StickySecrets::new(
        Box::new(SecuritySecrets::new(Arc::new(RealSecurity))),
        Box::new(FileSecrets::new(home.credentials_dir())),
    ))
}

#[cfg(not(target_os = "macos"))]
fn platform_default(home: &Home) -> Box<dyn Secrets> {
    Box::new(FileSecrets::new(home.credentials_dir()))
}

pub fn slot_key(provider: &str, slot: u32) -> String {
    format!("{provider}:{slot}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_cli::FakeSecurity;

    #[test]
    fn memory_roundtrip() {
        let mem = MemorySecrets::new();
        assert_eq!(mem.get("k").unwrap(), None);
        mem.set("k", "tok-1").unwrap();
        assert_eq!(mem.get("k").unwrap(), Some("tok-1".to_string()));
        mem.delete("k").unwrap();
        assert_eq!(mem.get("k").unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn file_backend_writes_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secrets = FileSecrets::new(dir.path().to_path_buf());
        secrets.set("claude:1", "tok-1").unwrap();

        let path = dir.path().join("claude_1");
        assert_eq!(fs::read_to_string(&path).unwrap(), "tok-1");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        assert_eq!(secrets.get("claude:1").unwrap(), Some("tok-1".to_string()));
        secrets.delete("claude:1").unwrap();
        assert_eq!(secrets.get("claude:1").unwrap(), None);
    }

    #[test]
    fn file_backend_rejects_traversal_keys() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = FileSecrets::new(dir.path().to_path_buf());
        let err = secrets.set("../escape", "tok-1").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn security_secrets_roundtrip_through_fake_cli() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        assert_eq!(secrets.get("claude:1").unwrap(), None);
        secrets.set("claude:1", "tok-1").unwrap();
        assert_eq!(secrets.get("claude:1").unwrap(), Some("tok-1".to_string()));
        secrets.delete("claude:1").unwrap();
        assert_eq!(secrets.get("claude:1").unwrap(), None);
    }

    #[test]
    fn security_not_found_is_none() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        assert_eq!(secrets.get("no-such-key").unwrap(), None);
    }

    struct FailingSecrets;
    impl Secrets for FailingSecrets {
        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
        fn set(&self, _key: &str, _value: &str) -> Result<()> {
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
        fn delete(&self, _key: &str) -> Result<()> {
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
    }

    #[test]
    fn sticky_falls_back_after_primary_error() {
        let sticky = StickySecrets::new(Box::new(FailingSecrets), Box::new(MemorySecrets::new()));
        sticky.set("k", "tok-1").unwrap();
        assert_eq!(sticky.get("k").unwrap(), Some("tok-1".to_string()));
    }

    struct InvalidInputSecrets;
    impl Secrets for InvalidInputSecrets {
        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(SwapdError::new(ErrorCode::InvalidInput, "bad"))
        }
        fn set(&self, _key: &str, _value: &str) -> Result<()> {
            Err(SwapdError::new(ErrorCode::InvalidInput, "bad"))
        }
        fn delete(&self, _key: &str) -> Result<()> {
            Err(SwapdError::new(ErrorCode::InvalidInput, "bad"))
        }
    }

    #[test]
    fn sticky_does_not_degrade_on_invalid_input() {
        let fallback_mem = Arc::new(MemorySecrets::new());
        let sticky = StickySecrets::new(
            Box::new(InvalidInputSecrets),
            Box::new(SharedSecrets(fallback_mem.clone())),
        );

        let err = sticky.set("k", "v").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(
            fallback_mem.get("k").unwrap(),
            None,
            "a caller error must not reach the fallback"
        );

        // Not degraded: a later call still hits the primary, so it fails the same way
        // rather than silently succeeding against the (empty) fallback.
        let err = sticky.get("k").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    struct CountingFailingSecrets(Arc<Mutex<u32>>);
    impl Secrets for CountingFailingSecrets {
        fn get(&self, _key: &str) -> Result<Option<String>> {
            *self.0.lock().unwrap() += 1;
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
        fn set(&self, _key: &str, _value: &str) -> Result<()> {
            *self.0.lock().unwrap() += 1;
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
        fn delete(&self, _key: &str) -> Result<()> {
            *self.0.lock().unwrap() += 1;
            Err(SwapdError::new(ErrorCode::KeychainUnavailable, "fail"))
        }
    }

    #[test]
    fn sticky_stays_on_fallback_for_process_lifetime() {
        let calls = Arc::new(Mutex::new(0u32));
        let sticky = StickySecrets::new(
            Box::new(CountingFailingSecrets(calls.clone())),
            Box::new(MemorySecrets::new()),
        );
        let _ = sticky.get("a");
        let _ = sticky.get("b");
        let _ = sticky.set("c", "tok-1");
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "primary should only be tried once"
        );
    }

    #[test]
    fn env_override_selects_file_backend() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        // Calls `secrets_for` directly rather than mutating the process-global
        // `SWAPD_SECRETS` env var, which a parallel test binary can't safely do (a
        // race would let `platform_default` run and, on macOS, hit the real keychain).
        let secrets = secrets_for(&home, Some("file"));
        secrets.set("claude:1", "tok-1").unwrap();

        let path = home.credentials_dir().join("claude_1");
        assert_eq!(fs::read_to_string(path).unwrap(), "tok-1");
    }

    #[test]
    fn env_override_unrecognized_falls_back_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        let secrets = secrets_for(&home, Some("bogus"));
        secrets.set("claude:1", "tok-1").unwrap();

        // Never the keychain: the value must land in the file backend.
        let path = home.credentials_dir().join("claude_1");
        assert_eq!(fs::read_to_string(path).unwrap(), "tok-1");
    }

    #[test]
    fn security_secrets_rejects_empty_value() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        let err = secrets.set("claude:1", "").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    struct SharedSecrets(Arc<MemorySecrets>);
    impl Secrets for SharedSecrets {
        fn get(&self, key: &str) -> Result<Option<String>> {
            self.0.get(key)
        }
        fn set(&self, key: &str, value: &str) -> Result<()> {
            self.0.set(key, value)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.delete(key)
        }
    }

    #[test]
    fn sticky_delete_reaches_both_backends() {
        let primary_mem = Arc::new(MemorySecrets::new());
        let fallback_mem = Arc::new(MemorySecrets::new());
        primary_mem.set("k", "p").unwrap();
        fallback_mem.set("k", "f").unwrap();

        let sticky = StickySecrets::new(
            Box::new(SharedSecrets(primary_mem.clone())),
            Box::new(SharedSecrets(fallback_mem.clone())),
        );
        // `MemorySecrets::delete` never errors, so this is `Ok(())` regardless of
        // whether `StickySecrets::delete` reports `primary`'s or `fallback`'s result —
        // this test only checks that both backends are actually cleared.
        sticky.delete("k").unwrap();

        assert_eq!(primary_mem.get("k").unwrap(), None);
        assert_eq!(fallback_mem.get("k").unwrap(), None);
    }

    #[test]
    fn sticky_set_on_primary_clears_fallback_copy() {
        let primary_mem = Arc::new(MemorySecrets::new());
        let fallback_mem = Arc::new(MemorySecrets::new());
        // Simulates a stale plaintext copy left by an earlier degraded run.
        fallback_mem.set("k", "stale-plaintext").unwrap();

        let sticky = StickySecrets::new(
            Box::new(SharedSecrets(primary_mem.clone())),
            Box::new(SharedSecrets(fallback_mem.clone())),
        );
        sticky.set("k", "fresh").unwrap();

        assert_eq!(primary_mem.get("k").unwrap(), Some("fresh".to_string()));
        assert_eq!(fallback_mem.get("k").unwrap(), None);
    }
}
