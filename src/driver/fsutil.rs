//! Filesystem helpers every driver needs: private files, private directory
//! trees, and "could we actually exec this".
//!
//! These lived under `driver/claude/` while Claude Code was the only driver;
//! the Gemini driver imported them across the provider boundary, and a second
//! copy of `is_executable` and `create_private_dir_all` drifted beside them
//! (issue #17). Nothing here knows which provider it serves.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::driver::DriverError;

/// An existing file we could actually exec. A non-executable CLI on `PATH`
/// (a stray text file, a half-finished install, a *directory* wearing the
/// name) must not shadow a real one further along it — reporting "installed"
/// for something that cannot run turns every later failure into a mystery.
pub fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `mkdir -p` with 0700 on every component swapd creates.
pub fn create_private_dir_all(dir: &Path) -> Result<(), DriverError> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_private_dir_all(parent)?;
    }
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Create `path` with 0600 and write `value` to it.
pub fn write_private_file(path: &Path, value: &str) -> Result<(), DriverError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(value.as_bytes())?;
    // Durable before the rename, as `core::store::write_json_atomic` does.
    file.sync_all()?;
    Ok(())
}
