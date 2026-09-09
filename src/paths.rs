use std::path::PathBuf;

use crate::errors::Result;

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
    pub fn resolve() -> Self {
        if let Ok(dir) = std::env::var("SWAPD_HOME") {
            return Self {
                root: PathBuf::from(dir),
            };
        }
        Self {
            root: Self::default_root(),
        }
    }

    #[cfg(target_os = "windows")]
    fn default_root() -> PathBuf {
        let appdata = std::env::var("APPDATA").expect("%APPDATA% must be set on Windows");
        PathBuf::from(appdata).join("swapd")
    }

    #[cfg(target_os = "linux")]
    fn default_root() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("swapd");
        }
        let home = std::env::var("HOME").expect("$HOME must be set on Linux");
        PathBuf::from(home).join(".local/share/swapd")
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn default_root() -> PathBuf {
        let home = std::env::var("HOME").expect("$HOME must be set on macOS");
        PathBuf::from(home).join(".swapd")
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

    pub fn history_file(&self) -> PathBuf {
        self.root.join("history.json")
    }

    pub fn auto_state_file(&self) -> PathBuf {
        self.root.join("auto-state.json")
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
