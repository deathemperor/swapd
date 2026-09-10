//! The `.swapd-seeded` marker a run profile carries: the fingerprint of the
//! credential swapd last seeded into it, so a later launch can tell "never
//! seeded" and "seeded something else" from "seeded this". Shared by every
//! driver with per-slot profiles.

use std::fs;
use std::path::{Path, PathBuf};

use crate::driver::claude::live::write_private_file;
use crate::driver::DriverError;

pub const MARKER: &str = ".swapd-seeded";

fn path(dir: &Path) -> PathBuf {
    dir.join(MARKER)
}

pub fn read(dir: &Path) -> Option<String> {
    fs::read_to_string(path(dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn write(dir: &Path, fingerprint: &str) -> Result<(), DriverError> {
    write_private_file(&path(dir), fingerprint)
}
