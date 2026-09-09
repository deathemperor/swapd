use std::path::PathBuf;

use crate::errors::{ErrorCode, Result, SwapdError};

/// Resolves and owns the swapd data directory ("home").
pub struct Home {
    pub root: PathBuf,
}

// Most path helpers aren't consumed yet; later tasks (slots, credentials, history) add the
// code that reads/writes each file.
#[allow(dead_code)]
impl Home {
    /// Resolve the data dir: `$SWAPD_HOME` if set; else the platform default
    /// (macOS `~/.swapd`, Linux `${XDG_DATA_HOME:-~/.local/share}/swapd`,
    /// Windows `%APPDATA%\swapd`).
    pub fn resolve() -> Result<Self> {
        if let Ok(dir) = std::env::var("SWAPD_HOME") {
            return Ok(Self {
                root: PathBuf::from(dir),
            });
        }
        Ok(Self {
            root: Self::default_root()?,
        })
    }

    #[cfg(target_os = "windows")]
    fn default_root() -> Result<PathBuf> {
        let appdata = std::env::var("APPDATA")
            .map_err(|_| SwapdError::new(ErrorCode::Io, "%APPDATA% is not set"))?;
        Ok(PathBuf::from(appdata).join("swapd"))
    }

    #[cfg(target_os = "linux")]
    fn default_root() -> Result<PathBuf> {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg).join("swapd"));
        }
        let home = std::env::var("HOME")
            .map_err(|_| SwapdError::new(ErrorCode::Io, "$HOME is not set"))?;
        Ok(PathBuf::from(home).join(".local/share/swapd"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn default_root() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| SwapdError::new(ErrorCode::Io, "$HOME is not set"))?;
        Ok(PathBuf::from(home).join(".swapd"))
    }

    pub fn slots_file(&self) -> PathBuf {
        self.root.join("slots.json")
    }

    pub fn usage_file(&self) -> PathBuf {
        self.root.join("usage.json")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    /// The switch log. JSONL: it is only ever appended to (see `core::history`).
    pub fn history_file(&self) -> PathBuf {
        self.root.join("history.jsonl")
    }

    /// The base path whose `.lock` sibling — `engine.lock` — fences a whole
    /// switch: the live read, the back-up of the outgoing login, `write_live`,
    /// and the `slots.json` update that records the landing. `FileLock` locks
    /// `<path>.lock`, so this is the file the lock is *named* after rather than
    /// one anything writes.
    pub fn engine_lock_base(&self) -> PathBuf {
        self.root.join("engine")
    }

    pub fn auto_state_file(&self) -> PathBuf {
        self.root.join("auto-state.json")
    }

    /// The base path whose `.lock` sibling — `auto.lock` — is the auto
    /// engine's MUTEX: one daemon per data dir, held for the daemon's whole
    /// lifetime (cswap's `autoswitch_engine.lock`). Deliberately not
    /// `engine.lock`, which fences one switch and must stay free between
    /// ticks so a manual `swapd switch` still works while `auto` runs.
    pub fn auto_lock_base(&self) -> PathBuf {
        self.root.join("auto")
    }

    pub fn credentials_dir(&self) -> PathBuf {
        self.root.join("credentials")
    }

    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    pub fn log_file(&self) -> PathBuf {
        self.root.join("swapd.log")
    }

    /// Create the data dir (and parents) if missing, `0700` on unix.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}
