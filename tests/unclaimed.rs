//! `swapd unclaimed [--purge id]` and `export`'s `unclaimed` surface, end to
//! end: the real binary, a temp swapd home, hermetic env (no real
//! `~/.claude*`, no keychain — `SWAPD_SECRETS=file`, `SWAPD_LIVE_STORE=file`,
//! a temp `HOME`, `CLAUDE_CONFIG_DIR` removed, as `tests/cli_basics.rs`
//! establishes).
//!
//! The manifest and its secrets are seeded straight onto disk, in the exact
//! shape `core::unclaimed::record` and `FileSecrets` write them, rather than
//! through a live `switch` — that path is covered in `core::switch`'s own
//! tests; this suite only needs the manifest to already exist.

use std::path::Path;

use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::TempDir;

struct Fixture {
    home: TempDir,
    claude_home: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            home: TempDir::new().unwrap(),
            claude_home: TempDir::new().unwrap(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("swapd").unwrap();
        cmd.env("SWAPD_HOME", self.home.path())
            .env("SWAPD_SECRETS", "file")
            .env("SWAPD_LIVE_STORE", "file")
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

    /// Run expecting failure; returns the parsed error envelope and the exit
    /// code.
    fn run_err(&self, args: &[&str]) -> (Value, i32) {
        let out = self.cmd().args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        (
            serde_json::from_slice(&out.stdout).unwrap(),
            out.status.code().unwrap(),
        )
    }

    /// stdout as text, so a test can assert credential bytes never appear in
    /// it — a JSON parse would already have thrown them away.
    fn stdout_raw(&self, args: &[&str]) -> String {
        let out = self.cmd().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// A secret exactly as `FileSecrets` lays it out: `credentials/<key with
    /// ':' folded to '_'>` (see `src/secrets.rs`'s `key_path`).
    fn write_secret(&self, key: &str, value: &str) {
        write(
            &self
                .home
                .path()
                .join("credentials")
                .join(key.replace(':', "_")),
            value,
        );
    }

    fn secret_path(&self, key: &str) -> std::path::PathBuf {
        self.home
            .path()
            .join("credentials")
            .join(key.replace(':', "_"))
    }

    /// The unclaimed manifest, in the shape `core::unclaimed::record` writes.
    fn write_unclaimed(&self, entries: Value) {
        write(
            &self.home.path().join("unclaimed.json"),
            &json!({ "entries": entries }).to_string(),
        );
    }

    /// One managed slot with a stored credential — `export` refuses to run
    /// with none, and this suite is not about slot accounts.
    fn write_slot(&self, slot: u32, email: &str, credential: &str) {
        let mut slots = serde_json::Map::new();
        slots.insert(
            slot.to_string(),
            json!({
                "email": email,
                "organizationUuid": "",
                "organizationName": "",
            }),
        );
        write(
            &self.home.path().join("slots.json"),
            &json!({
                "schemaVersion": 1,
                "providers": {"claude": {
                    "activeSlot": Value::Null,
                    "order": [slot],
                    "slots": slots,
                }},
            })
            .to_string(),
        );
        self.write_secret(&format!("claude:{slot}"), credential);
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// One manifest row, in `core::unclaimed::Entry`'s camelCase shape.
fn entry(secret_key: &str, email: &str, stashed_at: u64) -> Value {
    json!({
        "provider": "claude",
        "stashedAt": stashed_at,
        "email": email,
        "fingerprint": "sha256:deadbeef",
        "reason": "switch: live login matched no slot",
        "secretKey": secret_key,
    })
}

#[test]
fn unclaimed_list_purge_and_export_round_trip() {
    let fx = Fixture::new();

    // A managed slot, so `export` has an account to carry besides the
    // unclaimed rows.
    fx.write_slot(1, "kept@example.com", "sk-ant-api03-kept-key");

    // Two stashed logins, exactly as `preserve_outgoing` would have left
    // them: a manifest row, and the secret its `secretKey` names.
    let mut entries = serde_json::Map::new();
    entries.insert(
        "1757000000-aaa11111".to_string(),
        entry(
            "claude:unclaimed-1757000000-aaa11111",
            "stray1@example.com",
            1_757_000_000,
        ),
    );
    entries.insert(
        "1757000100-bbb22222".to_string(),
        entry(
            "claude:unclaimed-1757000100-bbb22222",
            "stray2@example.com",
            1_757_000_100,
        ),
    );
    fx.write_unclaimed(Value::Object(entries));
    fx.write_secret(
        "claude:unclaimed-1757000000-aaa11111",
        r#"{"claudeAiOauth":{"refreshToken":"rt-stray1"}}"#,
    );
    fx.write_secret(
        "claude:unclaimed-1757000100-bbb22222",
        r#"{"claudeAiOauth":{"refreshToken":"rt-stray2"}}"#,
    );

    // Listed, sorted by id, and neither credential's bytes (nor the secret
    // key that names them) anywhere in stdout.
    let raw = fx.stdout_raw(&["unclaimed", "--json"]);
    assert!(!raw.contains("rt-stray1"), "{raw}");
    assert!(!raw.contains("rt-stray2"), "{raw}");
    assert!(!raw.contains("secretKey"), "{raw}");
    assert!(!raw.contains("unclaimed-1757000000-aaa11111"), "{raw}");
    let out: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(out["schemaVersion"], 1);
    let ids: Vec<&str> = out["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["1757000000-aaa11111", "1757000100-bbb22222"]);
    assert_eq!(out["entries"][0]["stashedAt"], "2025-09-04T15:33:20Z");

    // Text form: one line per entry, no credential bytes there either.
    let text = fx.stdout_raw(&["unclaimed"]);
    assert!(text.contains("1757000000-aaa11111"));
    assert!(text.contains("stray1@example.com"));
    assert!(!text.contains("rt-stray1"));

    // Purge one: its secret file and its row both go; the other survives.
    let purged = fx.run(&["unclaimed", "--purge", "1757000000-aaa11111", "--json"]);
    assert_eq!(purged["purged"], "1757000000-aaa11111");
    assert!(!fx
        .secret_path("claude:unclaimed-1757000000-aaa11111")
        .exists());
    assert!(fx
        .secret_path("claude:unclaimed-1757000100-bbb22222")
        .exists());

    let after = fx.run(&["unclaimed", "--json"]);
    let ids: Vec<&str> = after["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["1757000100-bbb22222"]);

    // An unknown id is `invalid-input`, exit 1.
    let (err, code) = fx.run_err(&["unclaimed", "--purge", "nope", "--json"]);
    assert_eq!(code, 1);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert_eq!(err["schemaVersion"], 1);

    // The surviving entry rides along in `export`, credential and all.
    let envelope = fx.run(&["export", "-", "--json"]);
    let unclaimed = envelope["unclaimed"].as_array().unwrap();
    assert_eq!(unclaimed.len(), 1);
    assert_eq!(unclaimed[0]["id"], "1757000100-bbb22222");
    assert_eq!(unclaimed[0]["provider"], "claude");
    assert_eq!(unclaimed[0]["email"], "stray2@example.com");
    assert_eq!(unclaimed[0]["stashedAt"], "2025-09-04T15:35:00Z");
    assert_eq!(
        unclaimed[0]["credential"],
        r#"{"claudeAiOauth":{"refreshToken":"rt-stray2"}}"#
    );
    // Slot accounts still export as they always have.
    let accounts = envelope["providers"][0]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["email"], "kept@example.com");
}

#[test]
fn export_reports_an_unreadable_unclaimed_secret_without_a_credential() {
    let fx = Fixture::new();
    fx.write_slot(1, "kept@example.com", "sk-ant-api03-kept-key");

    let mut entries = serde_json::Map::new();
    entries.insert(
        "1757000000-ccc33333".to_string(),
        entry(
            "claude:unclaimed-1757000000-ccc33333",
            "ghost@example.com",
            1_757_000_000,
        ),
    );
    // No secret file written for this entry: the row exists, the bytes do
    // not.
    fx.write_unclaimed(Value::Object(entries));

    let out = fx.cmd().args(["export", "-", "--json"]).output().unwrap();
    assert!(out.status.success());
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    let unclaimed = envelope["unclaimed"].as_array().unwrap();
    assert_eq!(unclaimed.len(), 1);
    assert_eq!(unclaimed[0]["id"], "1757000000-ccc33333");
    assert!(unclaimed[0].get("credential").is_none());

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("1757000000-ccc33333"),
        "warning must name the id: {stderr}"
    );
}
