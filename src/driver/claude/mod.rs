//! The Claude Code driver.
//!
//! Task 6 ships the environment-facing half: where Claude Code keeps its
//! config and credential (`paths`), the port of its `proper-lockfile`
//! handshake (`locks`), and reading/replacing the live login (`live`).
//! Task 7 adds oauth/usage/run and the `Driver` impl.

pub mod live;
pub mod locks;
pub mod paths;

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use tempfile::TempDir;

    use crate::driver::Env;

    /// A throwaway `$HOME` for one test.
    pub fn temp_home() -> TempDir {
        TempDir::new().expect("temp home")
    }

    /// An `Env` over `home` with `vars` on top of `HOME`. No test ever touches
    /// the process environment: every path and variable this module reads
    /// comes from here.
    pub fn env_with<'a>(home: &TempDir, vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> Env {
        let mut map = HashMap::new();
        map.insert(
            "HOME".to_string(),
            home.path().to_str().expect("utf-8 temp path").to_string(),
        );
        for (key, value) in vars {
            map.insert(key.to_string(), value.to_string());
        }
        Env {
            // swapd's own home, deliberately NOT $HOME — nothing in this
            // module may read Claude Code's paths out of it.
            home: home.path().join("swapd"),
            vars: map,
        }
    }
}
