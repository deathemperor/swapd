//! `list --json` degrades quickly, rather than stalling, behind an in-flight
//! switch: the real binary against a temp swapd home whose `engine.lock` this
//! test holds for the whole call, the same fence a switch holds while it is
//! writing. No network, no keychain — `SWAPD_SECRETS=file` and
//! `SWAPD_LIVE_STORE=file` keep the child off the developer's login keychain.

use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::json;

fn write(path: &std::path::Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

#[test]
fn list_degrades_within_a_second_behind_a_held_engine_lock() {
    let home = tempfile::tempdir().unwrap();
    let claude_home = tempfile::tempdir().unwrap();

    let slots = json!({
        "schemaVersion": 1,
        "providers": {
            "claude": {
                "activeSlot": 1,
                "order": [1],
                "slots": {
                    "1": {
                        "email": "one@example.com",
                        "organizationUuid": "org-1",
                        "organizationName": "Org One",
                    },
                },
            }
        }
    });
    write(&home.path().join("slots.json"), &slots.to_string());

    // Hold `engine.lock` for the whole call, the way a switch in flight does
    // (`Home::engine_lock_base` — `FileLock` locks `<path>.lock`).
    let lock_path = home.path().join("engine.lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true);
    let lock_file = opts.open(&lock_path).unwrap();
    let mut rw = fd_lock::RwLock::new(lock_file);
    let _held = rw.write().unwrap();

    let start = Instant::now();
    let out = Command::cargo_bin("swapd")
        .unwrap()
        .env("SWAPD_HOME", home.path())
        .env("SWAPD_SECRETS", "file")
        .env("SWAPD_LIVE_STORE", "file")
        .env("HOME", claude_home.path())
        .env_remove("CLAUDE_CONFIG_DIR")
        .args(["list", "--json"])
        .output()
        .unwrap();
    let elapsed = start.elapsed();

    assert!(
        out.status.success(),
        "list --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "list took {elapsed:?} behind a held engine lock; it must wait ~1s, not the default 5s"
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["providers"][0]["activeUnreadable"], "switch-in-progress",
        "payload: {v}"
    );
}
