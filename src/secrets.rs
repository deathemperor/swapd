use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use crate::errors::{ErrorCode, Result, SwapdError};
use crate::paths::Home;
#[cfg(target_os = "macos")]
use crate::security_cli::RealSecurity;
#[cfg(target_os = "macos")]
use crate::security_cli::SecurityCli;

// Only `SecuritySecrets` reads this, and it's macOS-only: the `security` CLI
// backend is never built on another platform.
#[cfg(target_os = "macos")]
const SERVICE: &str = "swapd";

pub trait Secrets: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    /// `"keychain"`, `"file"` or `"memory"` — what `doctor` reports. A
    /// chained/fallback store reports its primary's name, not its own.
    fn name(&self) -> &'static str;
}

#[cfg(target_os = "macos")]
pub struct SecuritySecrets {
    cli: Arc<dyn SecurityCli>,
}

#[cfg(target_os = "macos")]
impl SecuritySecrets {
    pub fn new(cli: Arc<dyn SecurityCli>) -> Self {
        Self { cli }
    }
}

#[cfg(target_os = "macos")]
impl Secrets for SecuritySecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.cli.find(SERVICE, Some(key))
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        // `security -i add-generic-password ... -X` with an empty hex string is
        // rejected by `security` itself (exit 2), which would otherwise read as a
        // backend error and temporarily degrade `StickySecrets` to the file backend.
        if value.is_empty() {
            return Err(SwapdError::new(ErrorCode::InvalidInput, "empty secret"));
        }
        self.cli.add(SERVICE, key, value)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.cli.delete(SERVICE, key)
    }
    fn name(&self) -> &'static str {
        "keychain"
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
        // Atomic, like `store::write_json_atomic`: a new 0600 file, flushed to
        // the disk, then renamed over the target. Truncating the target in
        // place would mean a crash between the truncate and the write leaves an
        // empty file — and on Linux this store is the ONLY one, written right
        // after a refresh has spent the previous token, so that window costs
        // the account. The temp name carries a random suffix because two
        // writers of one key must not share it.
        // Created 0700 in one step (never created loose and tightened after),
        // and re-tightened after a successful write so a directory somebody
        // loosened does not stay that way. AFTER, not before: a directory this
        // process cannot write to must fail the write rather than be repaired
        // into one it can.
        if !self.dir.is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&self.dir)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(&self.dir)?;
        }

        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(path.file_name().unwrap_or_default());
        tmp_name.push(format!(".tmp.{}", rand::random::<u64>()));
        let tmp_path = self.dir.join(tmp_name);

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(&tmp_path)?;
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
        drop(f);

        fs::rename(&tmp_path, &path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
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

    fn name(&self) -> &'static str {
        "file"
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
    fn name(&self) -> &'static str {
        "memory"
    }
}

/// Use the file store while Keychain is unavailable, then retry after a minute.
/// Keep writes made during an outage authoritative until a caller next writes
/// that key to Keychain: a fallback refresh token may have spent the primary's.
/// Recovery reads must not copy tokens back outside the caller's refresh lock.
/// The mutex serializes recovery with reads and writes from collector workers.
#[cfg(target_os = "macos")]
pub struct StickySecrets {
    primary: Box<dyn Secrets>,
    fallback: Box<dyn Secrets>,
    state: Mutex<FallbackState>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct FallbackState {
    retry_at: Option<Instant>,
    // None keeps a fallback deletion authoritative for this process too.
    pending: HashMap<String, Option<String>>,
}

#[cfg(target_os = "macos")]
impl FallbackState {
    fn can_retry(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|at| now >= at)
    }

    fn unavailable(&mut self, now: Instant) {
        self.retry_at = Some(now + Duration::from_secs(60));
    }
}

#[cfg(target_os = "macos")]
impl StickySecrets {
    pub fn new(primary: Box<dyn Secrets>, fallback: Box<dyn Secrets>) -> Self {
        Self {
            primary,
            fallback,
            state: Mutex::new(FallbackState::default()),
            clock: Box::new(Instant::now),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(
        primary: Box<dyn Secrets>,
        fallback: Box<dyn Secrets>,
        clock: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self {
            clock,
            ..Self::new(primary, fallback)
        }
    }
}

#[cfg(target_os = "macos")]
impl Secrets for StickySecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let mut state = self.state.lock().unwrap();
        if state.can_retry((self.clock)()) {
            match self.primary.get(key) {
                Ok(value) => {
                    state.retry_at = None;
                    return Ok(state.pending.get(key).cloned().unwrap_or(value));
                }
                Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                    state.unavailable((self.clock)())
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.get(key)
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.can_retry((self.clock)()) {
            match self.primary.set(key, value) {
                Ok(()) => {
                    state.retry_at = None;
                    state.pending.remove(key);
                    let _ = self.fallback.delete(key);
                    return Ok(());
                }
                Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                    state.unavailable((self.clock)())
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.set(key, value)?;
        state.pending.insert(key.to_owned(), Some(value.to_owned()));
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.can_retry((self.clock)()) {
            match self.primary.delete(key) {
                Ok(()) => {
                    state.retry_at = None;
                    state.pending.remove(key);
                    let _ = self.fallback.delete(key);
                    return Ok(());
                }
                Err(e) if e.code == ErrorCode::KeychainUnavailable => {
                    state.unavailable((self.clock)())
                }
                Err(e) => return Err(e),
            }
        }
        self.fallback.delete(key)?;
        state.pending.insert(key.to_owned(), None);
        Ok(())
    }

    fn name(&self) -> &'static str {
        self.primary.name()
    }
}

/// `SWAPD_SECRETS` = `file` | `memory` overrides (tests, CI); unset (or empty)
/// -> macOS `Sticky(Security, File)`, elsewhere `File`.
pub fn default_secrets(home: &Home) -> Result<Box<dyn Secrets>> {
    secrets_for(home, std::env::var("SWAPD_SECRETS").ok().as_deref())
}

/// `default_secrets` reads `SWAPD_SECRETS` from the process environment and calls this;
/// tests call it directly with an explicit `mode` instead of mutating `SWAPD_SECRETS`
/// (a process-global that isn't safe to set/unset from a parallel test binary — a race
/// could let `platform_default` run and, on macOS, write a test value into the real
/// login keychain).
pub fn secrets_for(home: &Home, mode: Option<&str>) -> Result<Box<dyn Secrets>> {
    match mode {
        Some("file") => Ok(Box::new(FileSecrets::new(home.credentials_dir()))),
        Some("memory") => Ok(Box::new(MemorySecrets::new())),
        // A typo must not silently pick a store: `SWAPD_SECRETS=keychan` used
        // to write the login to disk on a machine whose keychain was the whole
        // point of the setting.
        Some(other) if !other.is_empty() => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown SWAPD_SECRETS value: {other} (file, memory, or unset)"),
        )),
        // An exported-but-empty variable reads as unset, as it does everywhere
        // else in the CLI.
        Some(_) | None => Ok(platform_default(home)),
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
    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
    #[test]
    fn security_secrets_roundtrip_through_fake_cli() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        assert_eq!(secrets.get("claude:1").unwrap(), None);
        secrets.set("claude:1", "tok-1").unwrap();
        assert_eq!(secrets.get("claude:1").unwrap(), Some("tok-1".to_string()));
        secrets.delete("claude:1").unwrap();
        assert_eq!(secrets.get("claude:1").unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_not_found_is_none() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        assert_eq!(secrets.get("no-such-key").unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    struct FailingSecrets;
    #[cfg(target_os = "macos")]
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
        fn name(&self) -> &'static str {
            "failing"
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sticky_falls_back_after_primary_error() {
        let sticky = StickySecrets::new(Box::new(FailingSecrets), Box::new(MemorySecrets::new()));
        sticky.set("k", "tok-1").unwrap();
        assert_eq!(sticky.get("k").unwrap(), Some("tok-1".to_string()));
    }

    #[cfg(target_os = "macos")]
    struct InvalidInputSecrets;
    #[cfg(target_os = "macos")]
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
        fn name(&self) -> &'static str {
            "invalid"
        }
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
    struct CountingFailingSecrets(Arc<Mutex<u32>>);
    #[cfg(target_os = "macos")]
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
        fn name(&self) -> &'static str {
            "counting-failing"
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sticky_waits_before_retrying_unavailable_primary() {
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
            "do not hammer Keychain while the retry interval is pending"
        );
    }

    #[cfg(target_os = "macos")]
    struct RecoveringSecrets {
        available: Arc<std::sync::atomic::AtomicBool>,
        values: Arc<MemorySecrets>,
    }

    #[cfg(target_os = "macos")]
    impl RecoveringSecrets {
        fn check(&self) -> Result<()> {
            if self.available.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(SwapdError::new(ErrorCode::KeychainUnavailable, "offline"))
            }
        }
    }

    #[cfg(target_os = "macos")]
    impl Secrets for RecoveringSecrets {
        fn get(&self, key: &str) -> Result<Option<String>> {
            self.check()?;
            self.values.get(key)
        }
        fn set(&self, key: &str, value: &str) -> Result<()> {
            self.check()?;
            self.values.set(key, value)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.check()?;
            self.values.delete(key)
        }
        fn name(&self) -> &'static str {
            "recovering"
        }
    }

    #[cfg(target_os = "macos")]
    fn retry_now(store: &StickySecrets) {
        store.state.lock().unwrap().retry_at = Some(Instant::now());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sticky_recovers_alternate_accounts_without_losing_refreshed_tokens() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let available = Arc::new(AtomicBool::new(false));
        let primary = Arc::new(MemorySecrets::new());
        let fallback = Arc::new(MemorySecrets::new());
        primary.set("claude:7", "spent-refresh-token").unwrap();
        primary.set("claude:8", "available-account").unwrap();
        let store = StickySecrets::new(
            Box::new(RecoveringSecrets {
                available: available.clone(),
                values: primary.clone(),
            }),
            Box::new(SharedSecrets(fallback.clone())),
        );

        // The daemon adopts the active login while Keychain is unavailable.
        store.set("claude:7", "refreshed-token").unwrap();
        assert_eq!(store.get("claude:8").unwrap(), None);
        available.store(true, Ordering::SeqCst);
        // Recovery is bounded, not one Keychain probe per account per tick.
        assert_eq!(store.get("claude:8").unwrap(), None);
        retry_now(&store);
        assert_eq!(
            store.get("claude:8").unwrap().as_deref(),
            Some("available-account")
        );
        assert_eq!(
            store.get("claude:7").unwrap().as_deref(),
            Some("refreshed-token")
        );
        // Reads do not replay an old write over another process's newer token.
        primary.set("claude:7", "another-process-token").unwrap();
        assert_eq!(
            store.get("claude:7").unwrap().as_deref(),
            Some("refreshed-token")
        );
        assert_eq!(
            primary.get("claude:7").unwrap().as_deref(),
            Some("another-process-token")
        );
        // The next explicit write returns this key to the recovered primary.
        store.set("claude:7", "next-refresh").unwrap();
        assert_eq!(
            store.get("claude:7").unwrap().as_deref(),
            Some("next-refresh")
        );
        assert_eq!(
            primary.get("claude:7").unwrap().as_deref(),
            Some("next-refresh")
        );
        assert_eq!(fallback.get("claude:7").unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sticky_failed_retries_back_off_and_keep_pending_credentials() {
        let calls = Arc::new(Mutex::new(0));
        let store = StickySecrets::new(
            Box::new(CountingFailingSecrets(calls.clone())),
            Box::new(MemorySecrets::new()),
        );
        store.set("claude:7", "refreshed-token").unwrap();
        retry_now(&store);
        assert_eq!(
            store.get("claude:7").unwrap().as_deref(),
            Some("refreshed-token")
        );
        assert_eq!(store.get("claude:8").unwrap(), None);
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sticky_recovery_does_not_resurrect_deleted_credentials() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let available = Arc::new(AtomicBool::new(false));
        let primary = Arc::new(MemorySecrets::new());
        primary.set("claude:7", "removed-account").unwrap();
        let store = StickySecrets::new(
            Box::new(RecoveringSecrets {
                available: available.clone(),
                values: primary.clone(),
            }),
            Box::new(MemorySecrets::new()),
        );
        store.delete("claude:7").unwrap();
        available.store(true, Ordering::SeqCst);
        retry_now(&store);
        assert_eq!(store.get("claude:7").unwrap(), None);
        store.delete("claude:7").unwrap();
        assert_eq!(primary.get("claude:7").unwrap(), None);
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
        let secrets = secrets_for(&home, Some("file")).unwrap();
        secrets.set("claude:1", "tok-1").unwrap();

        let path = home.credentials_dir().join("claude_1");
        assert_eq!(fs::read_to_string(path).unwrap(), "tok-1");
    }

    #[test]
    fn env_override_unrecognized_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        // A typo used to select the file store silently, writing to disk the
        // secrets a macOS user had asked the keychain to hold.
        // Matched rather than `unwrap_err`: a `Box<dyn Secrets>` has no `Debug`,
        // so nothing a secret store holds can reach a panic message.
        match secrets_for(&home, Some("keychan")) {
            Err(e) => {
                assert_eq!(e.code, ErrorCode::InvalidInput);
                assert!(e.message.contains("keychan"), "message: {}", e.message);
            }
            Ok(_) => panic!("an unknown SWAPD_SECRETS value must be refused"),
        }

        // An exported-but-empty value still reads as unset.
        assert!(secrets_for(&home, Some("")).is_ok());
    }

    #[test]
    fn file_secrets_leave_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        let secrets = secrets_for(&home, Some("file")).unwrap();
        secrets.set("claude:1", "tok-1").unwrap();
        secrets.set("claude:1", "tok-2").unwrap();

        assert_eq!(secrets.get("claude:1").unwrap().as_deref(), Some("tok-2"));
        let leftovers: Vec<_> = fs::read_dir(home.credentials_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "claude_1")
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = home.credentials_dir().join("claude_1");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_secrets_rejects_empty_value() {
        let secrets = SecuritySecrets::new(Arc::new(FakeSecurity::new()));
        let err = secrets.set("claude:1", "").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[cfg(target_os = "macos")]
    struct SharedSecrets(Arc<MemorySecrets>);
    #[cfg(target_os = "macos")]
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
        fn name(&self) -> &'static str {
            self.0.name()
        }
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
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
