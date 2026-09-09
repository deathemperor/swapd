//! `config` and the other small verbs end to end: the real binary, a temp
//! swapd home and a temp Claude home.
//!
//! Same hermetic contract as `switch.rs` — `SWAPD_SECRETS=file` and
//! `SWAPD_LIVE_STORE=file` keep the suite off the developer's login keychain
//! and off any real credential, and `SWAPD_URL_*` point every upstream at a
//! mock server that these verbs must never call. Nothing here sets a
//! process-wide env var: every child is configured through `Command::env`.

use std::path::Path;

use assert_cmd::Command;
use httpmock::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

struct Fixture {
    home: TempDir,
    claude_home: TempDir,
    server: MockServer,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            home: TempDir::new().unwrap(),
            claude_home: TempDir::new().unwrap(),
            server: MockServer::start(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("swapd").unwrap();
        cmd.env("SWAPD_HOME", self.home.path())
            .env("SWAPD_SECRETS", "file")
            .env("SWAPD_LIVE_STORE", "file")
            .env("SWAPD_URL_ANTHROPIC_API", self.server.base_url())
            .env("SWAPD_URL_PLATFORM", self.server.base_url())
            .env("HOME", self.claude_home.path())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR");
        cmd
    }

    fn run(&self, args: &[&str]) -> Value {
        let out = self.cmd().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Run expecting failure; returns the parsed error envelope.
    fn run_err(&self, args: &[&str]) -> Value {
        let out = self.cmd().args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn settings(&self) -> Value {
        read_json(&self.home.path().join("settings.json"))
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// One key out of a `config` payload.
fn setting<'a>(out: &'a Value, key: &str) -> &'a Value {
    out["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == key)
        .unwrap_or_else(|| panic!("no setting {key}"))
}

#[test]
fn config_list_reports_every_key_with_its_default() {
    let fx = Fixture::new();
    let out = fx.run(&["config", "list", "--json"]);
    assert_eq!(out["schemaVersion"], 1);

    let threshold = setting(&out, "claude.threshold");
    assert_eq!(threshold["value"], 90.0, "cswap's autoswitch default");
    assert_eq!(threshold["default"], 90.0);
    assert_eq!(threshold["isSet"], false, "nothing is stored yet");
    assert_eq!(setting(&out, "claude.strategy")["value"], "best");
    assert_eq!(setting(&out, "claude.unhealthyTicks")["value"], 3);
    assert_eq!(setting(&out, "claude.preferred")["value"], json!([]));

    // No file was created just by reading.
    assert!(!fx.home.path().join("settings.json").exists());
}

#[test]
fn config_set_get_unset_round_trips_through_the_file() {
    let fx = Fixture::new();
    let out = fx.run(&["config", "set", "claude.threshold", "95", "--json"]);
    assert_eq!(setting(&out, "claude.threshold")["value"], 95.0);
    assert_eq!(setting(&out, "claude.threshold")["isSet"], true);
    assert_eq!(
        fx.settings(),
        json!({"schemaVersion": 1, "providers": {"claude": {"threshold": 95.0}}}),
        "the file carries the provider section and nothing else"
    );

    let out = fx.run(&["config", "get", "claude.threshold", "--json"]);
    assert_eq!(setting(&out, "claude.threshold")["value"], 95.0);

    let out = fx.run(&["config", "unset", "claude.threshold", "--json"]);
    assert_eq!(setting(&out, "claude.threshold")["value"], 90.0);
    assert_eq!(setting(&out, "claude.threshold")["isSet"], false);
    assert_eq!(fx.settings()["providers"]["claude"], json!({}));
}

#[test]
fn config_set_is_strict_and_keeps_unknown_keys() {
    let fx = Fixture::new();
    // A hand-written file with a key swapd does not know, plus a stored value.
    write(
        &fx.home.path().join("settings.json"),
        &json!({
            "schemaVersion": 1,
            "experiment": {"whatever": true},
            "providers": {"claude": {"strategy": "consume-first", "futureKnob": 7}},
        })
        .to_string(),
    );

    let err = fx.run_err(&["config", "set", "claude.threshold", "120", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("between 50 and 99.9"),
        "{}",
        err["error"]["message"]
    );

    let err = fx.run_err(&["config", "set", "claude.nope", "1", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("claude.threshold"));

    fx.run(&["config", "set", "claude.enabled", "no", "--json"]);
    let file = fx.settings();
    assert_eq!(file["experiment"]["whatever"], true, "unknown section kept");
    assert_eq!(
        file["providers"]["claude"]["futureKnob"], 7,
        "unknown key kept"
    );
    assert_eq!(file["providers"]["claude"]["enabled"], false);
    assert_eq!(file["providers"]["claude"]["strategy"], "consume-first");
}

#[test]
fn config_list_clamps_an_out_of_range_stored_value() {
    let fx = Fixture::new();
    write(
        &fx.home.path().join("settings.json"),
        &json!({"providers": {"claude": {"threshold": 120.0, "model": "Fable, fable"}}})
            .to_string(),
    );

    let out = fx.run(&["config", "list", "--json"]);
    let threshold = setting(&out, "claude.threshold");
    assert_eq!(threshold["value"], 99.9, "clamped for use");
    assert_eq!(threshold["isSet"], true, "still the user's own value");
    assert_eq!(
        setting(&out, "claude.model")["value"],
        json!(["Fable"]),
        "cswap's comma string, deduped case-insensitively"
    );
}
