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

// Not wired into a verb yet; `SecuritySecrets` (below) uses this once login/use exist.
#[allow(dead_code)]
const SERVICE: &str = "swapd";

// Not wired into a verb yet; later tasks (login, use) call through this trait.
#[allow(dead_code)]
pub trait Secrets: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

// Not wired into a verb yet; later tasks (login, use) read/write credentials through this.
#[allow(dead_code)]
pub struct SecuritySecrets {
    cli: Arc<dyn SecurityCli>,
}

#[allow(dead_code)]
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
        self.cli.add(SERVICE, key, value)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.cli.delete(SERVICE, key)
    }
}

// Not wired into a verb yet; later tasks (login, use) read/write credentials through this.
#[allow(dead_code)]
pub struct FileSecrets {
    dir: PathBuf,
}

#[allow(dead_code)]
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

        // Single opaque value, no partial-write concern worth an atomic tmp+rename here
        // (unlike the JSON stores in core/store.rs): create straight at 0600, then
        // re-assert the mode in case the file already existed under a looser one.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(&path)?;
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
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

// Not wired into a verb yet; `SWAPD_SECRETS=memory` (tests, CI) selects this.
#[allow(dead_code)]
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

/// Ported sticky per-process fallback: once `primary` errors, every later call in this
/// process goes straight to `fallback`. A `None` result from `primary` is not a failure.
// Not wired into a verb yet; `default_secrets` builds one for the macOS default.
#[allow(dead_code)]
pub struct StickySecrets {
    primary: Box<dyn Secrets>,
    fallback: Box<dyn Secrets>,
    degraded: AtomicBool,
}

#[allow(dead_code)]
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
        self.primary.get(key).or_else(|_| {
            self.degraded.store(true, Ordering::SeqCst);
            self.fallback.get(key)
        })
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        if self.degraded.load(Ordering::SeqCst) {
            return self.fallback.set(key, value);
        }
        self.primary.set(key, value).or_else(|_| {
            self.degraded.store(true, Ordering::SeqCst);
            self.fallback.set(key, value)
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        if self.degraded.load(Ordering::SeqCst) {
            return self.fallback.delete(key);
        }
        self.primary.delete(key).or_else(|_| {
            self.degraded.store(true, Ordering::SeqCst);
            self.fallback.delete(key)
        })
    }
}

/// `SWAPD_SECRETS` = `file` | `memory` overrides (tests, CI); else macOS:
/// `Sticky(Security, File)`; Linux/Windows: `File`.
// Not wired into a verb yet; later tasks (login, use) call this to build their store.
#[allow(dead_code)]
pub fn default_secrets(home: &Home) -> Box<dyn Secrets> {
    match std::env::var("SWAPD_SECRETS").as_deref() {
        Ok("file") => Box::new(FileSecrets::new(home.credentials_dir())),
        Ok("memory") => Box::new(MemorySecrets::new()),
        _ => platform_default(home),
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

// Not wired into a verb yet; later tasks (login, use) build keychain/file keys with this.
#[allow(dead_code)]
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
        std::env::set_var("SWAPD_SECRETS", "file");
        let secrets = default_secrets(&home);
        secrets.set("claude:1", "tok-1").unwrap();
        std::env::remove_var("SWAPD_SECRETS");

        let path = home.credentials_dir().join("claude_1");
        assert_eq!(fs::read_to_string(path).unwrap(), "tok-1");
    }
}
