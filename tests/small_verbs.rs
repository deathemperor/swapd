//! `config`, the slots.json editors (`alias`, `icon`, `prefer`, `hold`,
//! `unhold`, `reorder`, `remove`), `notify` and `export` end to end: the real
//! binary, a temp swapd home and a temp Claude home.
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

/// Far enough out that a seeded login is never treated as expired.
const NOT_EXPIRED_MS: i64 = 4_102_444_800_000; // 2100-01-01

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

    fn slots(&self) -> Value {
        read_json(&self.home.path().join("slots.json"))
    }

    /// A slots file with `n` accounts and `active` as the live one.
    fn write_slots(&self, accounts: &[(u32, &str, &str)], active: Option<u32>) {
        let mut slots = serde_json::Map::new();
        let mut order = Vec::new();
        for (slot, email, org) in accounts {
            order.push(*slot);
            slots.insert(
                slot.to_string(),
                json!({
                    "email": email,
                    "organizationUuid": org,
                    "organizationName": "Org",
                    "alias": format!("a{slot}"),
                }),
            );
        }
        write(
            &self.home.path().join("slots.json"),
            &json!({
                "schemaVersion": 1,
                "providers": {"claude": {
                    "activeSlot": active,
                    "order": order,
                    "slots": slots,
                }},
            })
            .to_string(),
        );
    }

    /// An OAuth login for a slot, with the `oauthAccount` envelope that gives
    /// it an offline identity.
    fn login(&self, email: &str, org: &str, refresh: &str) -> Value {
        json!({
            "claudeAiOauth": {
                "accessToken": format!("tok-{refresh}"),
                "refreshToken": refresh,
                "expiresAt": NOT_EXPIRED_MS,
                "scopes": ["user:inference"],
            },
            "oauthAccount": {
                "emailAddress": email,
                "organizationUuid": org,
                "organizationName": "Org",
            },
        })
    }

    /// A slot's stored login, as `FileSecrets` lays it out.
    fn stored(&self, slot: u32) -> String {
        std::fs::read_to_string(self.credential(slot)).unwrap()
    }

    fn write_stored(&self, slot: u32, login: &Value) {
        write(&self.credential(slot), &login.to_string());
    }

    fn credential(&self, slot: u32) -> std::path::PathBuf {
        self.home
            .path()
            .join("credentials")
            .join(format!("claude_{slot}"))
    }

    /// Claude Code's live login, plus the `~/.claude.json` identity it
    /// advertises for it.
    fn write_live(&self, email: &str, org: &str, refresh: &str) {
        write(
            &self.claude_home.path().join(".claude/.credentials.json"),
            &json!({
                "claudeAiOauth": {
                    "accessToken": format!("live-{refresh}"),
                    "refreshToken": refresh,
                    "expiresAt": NOT_EXPIRED_MS,
                    "scopes": ["user:inference"],
                }
            })
            .to_string(),
        );
        write(
            &self.claude_home.path().join(".claude.json"),
            &json!({
                "oauthAccount": {
                    "emailAddress": email,
                    "organizationUuid": org,
                    "organizationName": "Org",
                },
                "numStartups": 7,
            })
            .to_string(),
        );
    }

    /// Fresh usage rows, so a verb that reports the list payload fetches
    /// nothing: the mock server here answers no route at all.
    fn write_usage(&self, accounts: &[(u32, &str, &str)]) {
        let now = now_s();
        let mut rows = serde_json::Map::new();
        for (slot, email, org) in accounts {
            rows.insert(
                format!("claude:{slot}"),
                json!({
                    "email": email, "org": org, "fetchedAt": now - 5.0,
                    "lastGood": [{"kind": "7d", "pct": 10.0, "resetsAt": "2026-09-20T00:00:00Z"}],
                }),
            );
        }
        write(
            &self.home.path().join("usage.json"),
            &json!({"schemaVersion": 2, "rows": rows}).to_string(),
        );
    }

    /// Three accounts, all logged in, slot 1 live, nothing due for a fetch.
    fn board(&self) -> &Self {
        let accounts = [
            (1u32, "one@example.com", "org-1"),
            (2, "two@example.com", "org-2"),
            (3, "three@example.com", "org-3"),
        ];
        self.write_slots(&accounts, Some(1));
        for (slot, email, org) in accounts {
            self.write_stored(slot, &self.login(email, org, &format!("rt-{slot}")));
        }
        self.write_live("one@example.com", "org-1", "rt-1");
        self.write_usage(&accounts);
        self
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn now_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn slot_of(slots: &Value, n: u32) -> Value {
    slots["providers"]["claude"]["slots"][n.to_string()].clone()
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

/// One account out of a `list` payload.
fn account(out: &Value, slot: u32) -> Value {
    out["providers"][0]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["slot"] == slot)
        .unwrap_or_else(|| panic!("no account in slot {slot}"))
        .clone()
}

#[test]
fn alias_sets_clears_and_refuses_a_name_that_cannot_be_resolved() {
    let fx = Fixture::new();
    fx.board();

    let out = fx.run(&["alias", "2", "death2", "--json"]);
    assert_eq!(account(&out, 2)["alias"], "death2", "the list reports it");
    assert_eq!(slot_of(&fx.slots(), 2)["alias"], "death2");

    // The new name resolves: every `<ident>` verb shares one resolver.
    fx.run(&["hold", "death2", "--json"]);
    assert_eq!(slot_of(&fx.slots(), 2)["disabled"], true);

    // A number would be read as a slot, and a name another slot answers to
    // would make `<ident>` ambiguous.
    let err = fx.run_err(&["alias", "2", "7", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    let err = fx.run_err(&["alias", "2", "a3", "--json"]);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("already used by slot 3"));
    // `resolve` tries aliases before emails, so an alias spelled like another
    // slot's address would send every `<ident>` verb — `remove` included — to
    // the wrong account.
    let err = fx.run_err(&["alias", "2", "THREE@example.com", "--json"]);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("slot 3's email"),
        "{}",
        err["error"]["message"]
    );

    let out = fx.run(&["alias", "2", "--unset", "--json"]);
    assert!(account(&out, 2)["alias"].is_null());
    assert!(slot_of(&fx.slots(), 2)["alias"].is_null());

    // Naming both, or neither, is refused rather than guessed at.
    assert_eq!(
        fx.run_err(&["alias", "2", "x", "--unset", "--json"])["error"]["code"],
        "invalid-input"
    );
    assert_eq!(
        fx.run_err(&["alias", "2", "--json"])["error"]["code"],
        "invalid-input"
    );
}

#[test]
fn icon_prefer_hold_and_unhold_edit_the_row_and_report_the_board() {
    let fx = Fixture::new();
    fx.board();

    let out = fx.run(&["icon", "two@example.com", "🩸", "--json"]);
    assert_eq!(account(&out, 2)["icon"], "🩸");

    let out = fx.run(&["prefer", "2", "on", "--json"]);
    assert_eq!(account(&out, 2)["preferred"], true);
    assert_eq!(slot_of(&fx.slots(), 2)["preferred"], true);

    let out = fx.run(&["hold", "a3", "--json"]);
    assert_eq!(account(&out, 3)["disabled"], true);
    // A held account is out of the rotation but still on the board.
    assert_eq!(out["providers"][0]["nextCandidate"], 2);

    let out = fx.run(&["unhold", "a3", "--json"]);
    assert_eq!(account(&out, 3)["disabled"], false);

    let out = fx.run(&["prefer", "2", "off", "--json"]);
    assert_eq!(account(&out, 2)["preferred"], false);
    let out = fx.run(&["icon", "2", "--unset", "--json"]);
    assert!(account(&out, 2)["icon"].is_null());

    assert_eq!(
        fx.run_err(&["prefer", "2", "maybe", "--json"])["error"]["code"],
        "invalid-input"
    );
    assert_eq!(
        fx.run_err(&["hold", "nobody@example.com", "--json"])["error"]["code"],
        "no-such-slot"
    );
}

#[test]
fn reorder_takes_the_whole_order_and_nothing_less() {
    let fx = Fixture::new();
    fx.board();

    let out = fx.run(&["reorder", "3", "a1", "two@example.com", "--json"]);
    assert_eq!(
        fx.slots()["providers"]["claude"]["order"],
        json!([3, 1, 2]),
        "named by number, alias and email alike"
    );
    // The board is rebuilt in the new order, which is the order
    // `next-available` resumes from.
    let slots: Vec<Value> = out["providers"][0]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["slot"].clone())
        .collect();
    assert_eq!(slots, vec![json!(3), json!(1), json!(2)]);

    let err = fx.run_err(&["reorder", "3", "1", "--json"]);
    assert!(
        err["error"]["message"].as_str().unwrap().contains("slot 2"),
        "{}",
        err["error"]["message"]
    );
    let err = fx.run_err(&["reorder", "3", "3", "1", "2", "--json"]);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("named twice"));
    // A rejected order leaves the last good one alone.
    assert_eq!(fx.slots()["providers"]["claude"]["order"], json!([3, 1, 2]));
}

#[test]
fn remove_deletes_the_login_and_refuses_the_live_one() {
    let fx = Fixture::new();
    fx.board();
    // The slot's run profile holds a copy of the credential.
    let profile = fx.home.path().join("profiles/claude/2");
    write(&profile.join(".credentials.json"), "{}");

    // The active slot cannot be removed, so `remove` can never clear
    // `activeSlot` out from under the live login.
    let err = fx.run_err(&["remove", "1", "--yes", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("switch away first"));
    assert_eq!(fx.slots()["providers"]["claude"]["activeSlot"], 1);

    // And nothing is deleted without the confirmation.
    let err = fx.run_err(&["remove", "2", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(fx.credential(2).exists());

    let out = fx.run(&["remove", "two@example.com", "--yes", "--json"]);
    assert_eq!(out["ok"], true);
    assert_eq!(out["slot"], 2);
    assert!(!fx.credential(2).exists(), "the stored login is gone");
    assert!(!profile.exists(), "so is the run profile");
    let slots = fx.slots();
    assert!(slot_of(&slots, 2).is_null());
    assert_eq!(
        slots["providers"]["claude"]["order"],
        json!([1, 3]),
        "and the rotation order forgets it"
    );
}

#[test]
fn notify_reports_masked_channels_and_nulls_when_unset() {
    let fx = Fixture::new();
    let out = fx.run(&["notify", "--json"]);
    assert!(out["slackWebhookUrl"].is_null());
    assert!(out["telegramBotToken"].is_null());
    assert!(out["telegramChatId"].is_null());

    write(
        &fx.home.path().join("notify.json"),
        &json!({
            "slackWebhookUrl": "https://hooks.slack.com/services/T00/B00/secret1234",
            "telegramBotToken": "1234567:AAsecrettoken9876",
        })
        .to_string(),
    );
    let out = fx.run(&["notify", "--json"]);
    assert_eq!(out["slackWebhookUrl"], "hooks.slack.com…1234");
    assert_eq!(out["telegramBotToken"], "…9876");
    assert!(out["telegramChatId"].is_null());
    // Nothing prints a secret, ever.
    let text = out.to_string();
    assert!(!text.contains("secret1234"), "{text}");
    assert!(!text.contains("AAsecrettoken"), "{text}");
}

#[test]
fn export_then_import_roundtrip() {
    let source = Fixture::new();
    source.board();
    source.run(&["alias", "2", "death2", "--json"]);
    source.run(&["prefer", "2", "on", "--json"]);
    let file = source.home.path().join("backup.json");

    let out = source.run(&["export", file.to_str().unwrap(), "--json"]);
    assert_eq!(out["accounts"], 3);
    let envelope = read_json(&file);
    assert_eq!(envelope["format"], "swapd/1");
    assert_eq!(envelope["providers"][0]["provider"], "claude");
    assert_eq!(envelope["providers"][0]["activeSlot"], 1);
    let exported = envelope["providers"][0]["accounts"].clone();
    let one = exported
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["slot"] == 1)
        .unwrap();
    assert_eq!(
        one["credentials"]["claudeAiOauth"]["accessToken"], "live-rt-1",
        "the active slot's credential comes from the live login, not the store"
    );
    assert_eq!(
        one["credentials"]["oauthAccount"]["emailAddress"], "one@example.com",
        "with the identity envelope that survives the trip"
    );
    let two = exported
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["slot"] == 2)
        .unwrap();
    assert_eq!(two["alias"], "death2");
    assert_eq!(two["preferred"], true);
    assert!(two["config"].is_null(), "no config without --full");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "an export holds logins");
    }

    // A second machine reads it back through the real `import` verb.
    let target = Fixture::new();
    let out = target.run(&["import", file.to_str().unwrap(), "--json"]);
    assert_eq!(out["imported"], json!([1, 2, 3]));
    assert_eq!(out["activeSlot"], 1, "recorded, never activated");
    let slots = target.slots();
    assert!(
        slots["providers"]["claude"]["activeSlot"].is_null(),
        "an import is not a switch"
    );
    assert_eq!(slot_of(&slots, 2)["email"], "two@example.com");
    assert_eq!(slot_of(&slots, 2)["alias"], "death2");
    assert_eq!(
        slot_of(&slots, 2)["preferred"],
        true,
        "the user's own choices travel, not just the credential"
    );
    let imported: Value = serde_json::from_str(&target.stored(3)).unwrap();
    assert_eq!(imported["claudeAiOauth"]["refreshToken"], "rt-3");
    assert_eq!(
        imported["oauthAccount"]["emailAddress"],
        "three@example.com"
    );
}

#[test]
fn export_falls_back_to_the_stored_copy_when_the_live_login_moved() {
    let fx = Fixture::new();
    fx.board();
    // Claude Code's own `/login` landed on an account swapd does not manage:
    // exporting those bytes under slot 1's address would file one account's
    // credential under another's name.
    fx.write_live("stranger@example.com", "org-x", "rt-stranger");

    let out = fx
        .cmd()
        .args(["export", "-", "--full", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    let one = envelope["providers"][0]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["slot"] == 1)
        .unwrap()
        .clone();
    assert_eq!(
        one["credentials"]["claudeAiOauth"]["accessToken"],
        "tok-rt-1"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not slot 1"),
        "the mismatch is reported: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn export_to_stdout_full_carries_the_active_config() {
    let fx = Fixture::new();
    fx.board();

    let envelope = fx.run(&["export", "-", "--full", "--json"]);
    let accounts = envelope["providers"][0]["accounts"].as_array().unwrap();
    let active = accounts.iter().find(|a| a["slot"] == 1).unwrap();
    assert_eq!(
        active["config"]["oauthAccount"]["emailAddress"],
        "one@example.com"
    );
    assert_eq!(
        active["config"]["numStartups"], 7,
        "--full is a same-machine backup: the whole snapshot"
    );
    for account in accounts.iter().filter(|a| a["slot"] != 1) {
        assert!(
            account["config"].is_null(),
            "only the active slot has a config on this machine"
        );
    }
}

#[test]
fn export_slot_names_one_account_and_a_missing_login_is_its_error() {
    let fx = Fixture::new();
    fx.board();
    std::fs::remove_file(fx.credential(3)).unwrap();

    let file = fx.home.path().join("one.json");
    fx.run(&["export", file.to_str().unwrap(), "--slot", "2", "--json"]);
    let envelope = read_json(&file);
    let accounts = envelope["providers"][0]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["slot"], 2);
    assert!(
        envelope["providers"][0]["activeSlot"].is_null(),
        "the active slot is not in this payload"
    );

    // Named explicitly, a slot with nothing to export is an error — and one
    // that exists says so, rather than borrowing `no-such-slot` from the slot
    // number that is genuinely not in the table.
    let err = fx.run_err(&["export", "-", "--slot", "3", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("has no stored login"),
        "{}",
        err["error"]["message"]
    );
    let err = fx.run_err(&["export", "-", "--slot", "9", "--json"]);
    assert_eq!(err["error"]["code"], "no-such-slot");

    // …but a whole-backup export skips it, so one damaged slot does not
    // poison the rest.
    let out = fx.run(&["export", file.to_str().unwrap(), "--json"]);
    assert_eq!(out["accounts"], 2);
    assert_eq!(out["warnings"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn remove_keeps_the_row_when_the_credential_cannot_be_deleted() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new();
    fx.board();
    // Unlinking needs write permission on the directory, so this is a delete
    // that fails after the row has been removed in memory.
    let dir = fx.home.path().join("credentials");
    let saved = std::fs::metadata(&dir).unwrap().permissions();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let err = fx.run_err(&["remove", "2", "--yes", "--json"]);
    std::fs::set_permissions(&dir, saved).unwrap();

    assert_eq!(err["error"]["code"], "io");
    // The whole removal is one lock cycle: a delete that fails writes nothing,
    // so the row still points at the credential that is still there.
    assert_eq!(slot_of(&fx.slots(), 2)["email"], "two@example.com");
    assert_eq!(fx.slots()["providers"]["claude"]["order"], json!([1, 2, 3]));
    assert!(fx.credential(2).exists());
}

#[test]
fn config_refuses_to_write_a_settings_file_from_another_schema() {
    let fx = Fixture::new();
    write(
        &fx.home.path().join("settings.json"),
        &json!({"schemaVersion": 2, "providers": {"claude": {"threshold": 95.0}}}).to_string(),
    );

    // Reading still works — a policy verb with no policy would be worse than
    // one reading a file it half understands.
    let out = fx.run(&["config", "list", "--json"]);
    assert_eq!(setting(&out, "claude.threshold")["value"], 95.0);

    // Writing does not: this build would put v1 semantics under a v2 stamp.
    for args in [
        vec!["config", "set", "claude.threshold", "60", "--json"],
        vec!["config", "unset", "claude.threshold", "--json"],
    ] {
        let err = fx.run_err(&args);
        assert_eq!(err["error"]["code"], "unsupported", "{args:?}");
    }
    assert_eq!(
        fx.settings()["schemaVersion"],
        2,
        "and the file is untouched"
    );

    // A file this build wrote is always stamped with the version it means.
    std::fs::remove_file(fx.home.path().join("settings.json")).unwrap();
    fx.run(&["config", "set", "claude.threshold", "60", "--json"]);
    assert_eq!(fx.settings()["schemaVersion"], 1);
}
