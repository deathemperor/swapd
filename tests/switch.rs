//! `add`, `add-token`, `switch`, `rotate` and `history` end to end: the real
//! binary, a temp swapd home, a temp Claude home and an httpmock upstream.
//!
//! Same hermetic contract as `list_refresh.rs` — `SWAPD_SECRETS=file` and
//! `SWAPD_LIVE_STORE=file` keep the suite off the developer's login keychain
//! and off any real credential, and `SWAPD_URL_*` point every upstream at the
//! mock server. Nothing here sets a process-wide env var: every child is
//! configured through `Command::env`.

use std::path::Path;

use assert_cmd::Command;
use httpmock::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

/// Far enough out that a seeded login is never treated as expired.
const NOT_EXPIRED_MS: i64 = 4_102_444_800_000; // 2100-01-01
/// Long expired: a switch must refresh it before it can land.
const EXPIRED_MS: i64 = 1_000_000_000_000; // 2001-09-09

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

    /// Claude Code's live login, plus the `~/.claude.json` identity it
    /// advertises for it. `extra` is spliced into the credential object, which
    /// is how the machine-shared `mcpOAuth` state is seeded.
    fn write_live(&self, email: &str, org: &str, refresh: &str, expires_at: i64, extra: Value) {
        let mut credential = json!({
            "claudeAiOauth": {
                "accessToken": format!("live-{refresh}"),
                "refreshToken": refresh,
                "expiresAt": expires_at,
                "scopes": ["user:inference"],
            }
        });
        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                credential[key] = value.clone();
            }
        }
        write(&self.live_credentials(), &credential.to_string());
        write(
            &self.claude_json(),
            &json!({
                "oauthAccount": {
                    "emailAddress": email,
                    "organizationUuid": org,
                    "organizationName": "Org One",
                }
            })
            .to_string(),
        );
    }

    fn live_credentials(&self) -> std::path::PathBuf {
        self.claude_home.path().join(".claude/.credentials.json")
    }

    fn claude_json(&self) -> std::path::PathBuf {
        self.claude_home.path().join(".claude.json")
    }

    fn slots(&self) -> Value {
        read_json(&self.home.path().join("slots.json"))
    }

    /// A slot's stored login, as `FileSecrets` lays it out.
    fn stored(&self, slot: u32) -> String {
        std::fs::read_to_string(
            self.home
                .path()
                .join("credentials")
                .join(format!("claude_{slot}")),
        )
        .unwrap()
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

    fn usage_rows(&self) -> Value {
        read_json(&self.home.path().join("usage.json"))["rows"].clone()
    }

    /// Every stashed credential the run left behind, by secret name.
    fn stash(&self) -> Vec<(String, String)> {
        let dir = self.home.path().join("credentials");
        let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.contains("unclaimed"))
                    .map(|name| {
                        let bytes = std::fs::read_to_string(dir.join(&name)).unwrap();
                        (name, bytes)
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// A slots file with `n` accounts, none of them logged in yet.
    fn write_slots(&self, accounts: &[(u32, &str, &str)]) {
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
                    "activeSlot": null,
                    "order": order,
                    "slots": slots,
                }},
            })
            .to_string(),
        );
    }

    /// An OAuth login for a slot, with the `oauthAccount` envelope that gives
    /// it an offline identity.
    fn login(&self, email: &str, org: &str, refresh: &str, expires_at: i64) -> Value {
        json!({
            "claudeAiOauth": {
                "accessToken": format!("tok-{refresh}"),
                "refreshToken": refresh,
                "expiresAt": expires_at,
                "scopes": ["user:inference"],
            },
            "oauthAccount": {
                "emailAddress": email,
                "organizationUuid": org,
                "organizationName": "Org",
            },
        })
    }

    /// Seed a stored usage row so the ranking has something to rank on.
    fn write_usage(&self, rows: Value) {
        write(
            &self.home.path().join("usage.json"),
            &json!({"schemaVersion": 2, "rows": rows}).to_string(),
        );
    }

    fn history(&self) -> Vec<Value> {
        let path = self.home.path().join("history.jsonl");
        match std::fs::read_to_string(path) {
            Ok(text) => text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
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

fn slot_of(slots: &Value, n: u32) -> &Value {
    &slots["providers"]["claude"]["slots"][n.to_string()]
}

#[test]
fn add_captures_live_login_into_next_free_slot() {
    let fx = Fixture::new();
    fx.write_slots(&[(1, "one@example.com", "org-1")]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "two@example.com",
        "org-2",
        "rt-live",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--json"]);
    assert_eq!(out["slot"], 2, "the next free slot, not slot 1");
    assert_eq!(out["email"], "two@example.com");
    assert_eq!(out["created"], true);

    // The row carries the identity `~/.claude.json` advertised, and the slot
    // holds the live bytes.
    let slots = fx.slots();
    assert_eq!(slot_of(&slots, 2)["email"], "two@example.com");
    assert_eq!(slot_of(&slots, 2)["organizationUuid"], "org-2");
    assert_eq!(slot_of(&slots, 2)["organizationName"], "Org One");
    assert!(slot_of(&slots, 2)["fingerprint"].is_string());
    assert!(slot_of(&slots, 2)["added"].is_string());
    assert_eq!(slots["providers"]["claude"]["activeSlot"], 2);

    let stored: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-live");
    // Slot 1 is untouched.
    let one: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(one["claudeAiOauth"]["refreshToken"], "rt-1");
}

#[test]
fn add_refreshes_existing_slot_in_place() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-old", NOT_EXPIRED_MS),
    );
    // The same account as slot 1, one refresh-token generation later.
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-new",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--json"]);
    assert_eq!(
        out["slot"], 1,
        "the account's own slot, not the next free one"
    );
    assert_eq!(out["created"], false);

    let stored: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-new");
    // The user's own label survives a credential refresh.
    assert_eq!(slot_of(&fx.slots(), 1)["alias"], "a1");
}

#[test]
fn add_refuses_to_capture_a_login_older_than_the_stored_one() {
    let fx = Fixture::new();
    fx.write_slots(&[(1, "one@example.com", "org-1")]);
    // The collector persisted a rotation whose `write_live` then failed: the
    // slot holds the only unspent generation and the live copy is the spent
    // one. Capturing over it would strand the account.
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-new", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-spent",
        NOT_EXPIRED_MS - 60_000,
        json!({}),
    );

    let err = fx.run_err(&["add", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("slot 1"),
        "the message names the slot: {message}"
    );
    assert!(
        message.contains("swapd list"),
        "the message names the verb that heals it: {message}"
    );

    // And the newer generation is still there.
    let stored: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-new");
}

#[test]
fn add_slot_moves_an_account_that_already_owns_another_slot() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (2, "one@example.com", "org-1"),
        (3, "three@example.com", "org-3"),
    ]);
    fx.write_stored(
        2,
        &fx.login("one@example.com", "org-1", "rt-old", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        3,
        &fx.login("three@example.com", "org-3", "rt-3", NOT_EXPIRED_MS),
    );
    fx.write_usage(json!({
        "claude:2": {
            "email": "one@example.com", "org": "org-1",
            "fetchedAt": now_s() - 5.0,
            "lastGood": [{"kind": "7d", "pct": 42.0, "resetsAt": "2026-09-20T00:00:00Z"}],
        },
    }));
    // The same account as slot 2, one refresh-token generation later.
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-new",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--slot", "5", "--json"]);
    assert_eq!(out["slot"], 5);
    assert_eq!(out["email"], "one@example.com");
    assert_eq!(out["movedFrom"], 2);

    let slots = fx.slots();
    assert!(slot_of(&slots, 2).is_null(), "slot 2 no longer has a row");
    assert_eq!(slot_of(&slots, 5)["email"], "one@example.com");
    assert_eq!(
        slot_of(&slots, 5)["alias"],
        "a2",
        "the alias the account had at slot 2 follows it"
    );
    assert_eq!(
        slots["providers"]["claude"]["activeSlot"], 5,
        "the live login's slot is active, not the one it moved from"
    );
    assert_eq!(
        slots["providers"]["claude"]["order"],
        json!([5, 3]),
        "the moved account keeps slot 2's place in the rotation, not the tail"
    );

    let stored: Value = serde_json::from_str(&fx.stored(5)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-new");
    assert!(!fx.credential(2).exists(), "slot 2's secret is gone");

    let usage = fx.usage_rows();
    assert!(usage.get("claude:2").is_none(), "slot 2's usage row moved");
    assert_eq!(usage["claude:5"]["lastGood"][0]["pct"], 42.0);
}

#[test]
fn add_slot_refuses_an_occupied_slot_without_force() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (2, "one@example.com", "org-1"),
        (3, "three@example.com", "org-3"),
    ]);
    fx.write_stored(
        2,
        &fx.login("one@example.com", "org-1", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        3,
        &fx.login("three@example.com", "org-3", "rt-3", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-new",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let err = fx.run_err(&["add", "--slot", "3", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("three@example.com"));

    // Nothing moved.
    let slots = fx.slots();
    assert_eq!(slot_of(&slots, 2)["email"], "one@example.com");
    assert_eq!(slot_of(&slots, 3)["email"], "three@example.com");
    let stored: Value = serde_json::from_str(&fx.stored(3)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-3");
}

#[test]
fn add_slot_force_overwrites_the_occupant_and_still_moves_the_owner() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (2, "one@example.com", "org-1"),
        (3, "three@example.com", "org-3"),
    ]);
    fx.write_stored(
        2,
        &fx.login("one@example.com", "org-1", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        3,
        &fx.login("three@example.com", "org-3", "rt-3", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-new",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--slot", "3", "--force", "--json"]);
    assert_eq!(out["slot"], 3);
    assert_eq!(out["movedFrom"], 2);

    let slots = fx.slots();
    assert!(slot_of(&slots, 2).is_null());
    assert_eq!(slot_of(&slots, 3)["email"], "one@example.com");

    let stored: Value = serde_json::from_str(&fx.stored(3)).unwrap();
    assert_eq!(
        stored["claudeAiOauth"]["refreshToken"], "rt-new",
        "the occupant's secret is gone; the moved account's is there instead"
    );
}

#[test]
fn add_slot_matching_the_owners_own_slot_refreshes_in_place() {
    let fx = Fixture::new();
    fx.write_slots(&[(2, "one@example.com", "org-1")]);
    fx.write_stored(
        2,
        &fx.login("one@example.com", "org-1", "rt-old", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-new",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--slot", "2", "--json"]);
    assert_eq!(out["slot"], 2);
    assert!(
        out.as_object().unwrap().get("movedFrom").is_none(),
        "no move happened, so the field is skipped rather than null: {out}"
    );

    let stored: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-new");
}

#[test]
fn add_then_add_slot_move_leaves_one_account_in_the_list() {
    let fx = Fixture::new();
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["add", "--json"]);
    assert_eq!(out["slot"], 1);
    assert!(out.as_object().unwrap().get("movedFrom").is_none());

    let out = fx.run(&["add", "--slot", "5", "--json"]);
    assert_eq!(out["slot"], 5);
    assert_eq!(out["movedFrom"], 1);

    let listed = fx.run(&["list", "--json"]);
    let accounts = listed["providers"][0]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1, "the account, not a duplicate: {listed}");
    assert_eq!(accounts[0]["slot"], 5);
    assert_eq!(accounts[0]["email"], "one@example.com");
}

#[test]
fn add_token_api_key_gets_token_local_email() {
    let fx = Fixture::new();

    let out = serde_json::from_slice::<Value>(
        &fx.cmd()
            .args(["add-token", "-", "--json"])
            .write_stdin("sk-ant-api03-secret-key\n")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert_eq!(out["slot"], 1);
    assert_eq!(out["email"], "api-key-1@token.local");
    assert_eq!(out["created"], true);

    // Stored raw, on Claude Code's API-key axis — never wrapped in OAuth JSON.
    assert_eq!(fx.stored(1), "sk-ant-api03-secret-key");
    assert_eq!(slot_of(&fx.slots(), 1)["email"], "api-key-1@token.local");

    // An OAuth setup token takes the other label, and is wrapped.
    let out = serde_json::from_slice::<Value>(
        &fx.cmd()
            .args(["add-token", "-", "--json"])
            .write_stdin("sk-ant-oat01-setup-token\n")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert_eq!(out["email"], "setup-token-2@token.local");
    let stored: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(
        stored["claudeAiOauth"]["accessToken"],
        "sk-ant-oat01-setup-token"
    );
    assert_eq!(
        stored["oauthAccount"]["emailAddress"],
        "setup-token-2@token.local"
    );
}

#[test]
fn add_token_refuses_a_token_on_the_command_line() {
    let fx = Fixture::new();
    // A secret in argv is visible in every process listing on the machine.
    let err = fx.run_err(&["add-token", "sk-ant-api03-secret", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(
        !err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("sk-ant-api03-secret"),
        "the message must not echo the token"
    );
}

/// Spec §10's lock-contention case, end to end: one process holds the engine
/// lock (as a switch in flight does), a second `swapd switch` runs, and the
/// refusal is the `locked` envelope rather than a hang or a half-swap.
#[test]
fn a_switch_is_refused_while_another_process_holds_the_engine_lock() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    // Held the way `core::store::FileLock` holds it: an exclusive advisory lock
    // on `<home>/engine.lock`, from a different process's point of view.
    let lock_path = fx.home.path().join("engine.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .unwrap();
    let mut lock = fd_lock::RwLock::new(file);
    let _held = lock.try_write().expect("the test must own the lock");

    let started = std::time::Instant::now();
    let err = fx.run_err(&["switch", "2", "--json"]);
    assert_eq!(err["error"]["code"], "locked");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the wait is bounded by the lock timeout, not by the holder"
    );

    // And nothing moved: the live login is still slot 1's.
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-1");
}

#[test]
fn switch_writes_target_and_backs_up_live_into_its_slot() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-stale", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    // Slot 1 is live, and Claude Code has rotated its token past the copy the
    // slot holds — the rotation must survive the switch away from it.
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-rotated",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["switch", "2", "--json"]);
    assert_eq!(out["switched"], true);
    assert_eq!(out["from"]["slot"], 1);
    assert_eq!(out["from"]["email"], "one@example.com");
    assert_eq!(out["to"]["slot"], 2);
    assert_eq!(out["warnings"].as_array().unwrap().len(), 0);

    // The live store now holds slot 2, and `~/.claude.json` names it.
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-2");
    assert!(
        live.get("oauthAccount").is_none(),
        "the envelope key never reaches the credential store"
    );
    let config: Value = read_json(&fx.claude_json());
    assert_eq!(config["oauthAccount"]["emailAddress"], "two@example.com");

    // The outgoing rotation landed in ITS OWN slot, not in the target's.
    let one: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(one["claudeAiOauth"]["refreshToken"], "rt-rotated");
    assert!(fx.stash().is_empty(), "a matched login is never stashed");

    assert_eq!(fx.slots()["providers"]["claude"]["activeSlot"], 2);

    let history = fx.history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["from"]["slot"], 1);
    assert_eq!(history[0]["to"]["slot"], 2);
    assert_eq!(history[0]["trigger"], "manual");
    assert!(history[0]["ts"].as_str().unwrap().ends_with('Z'));

    // And the verb reports it.
    let listed = fx.run(&["history", "--json"]);
    assert_eq!(listed["switches"].as_array().unwrap().len(), 1);
    assert_eq!(listed["switches"][0]["to"]["slot"], 2);

    // Switching to where we already are changes nothing.
    let again = fx.run(&["switch", "2", "--json"]);
    assert_eq!(again["switched"], false);
    assert_eq!(again["reason"], "already-active");
    assert_eq!(fx.history().len(), 1, "a no-op switch writes no history");
}

#[test]
fn switch_stashes_an_unmanaged_live_login_and_warns() {
    let fx = Fixture::new();
    fx.write_slots(&[(1, "one@example.com", "org-1")]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    // Nobody manages this account: it belongs to no slot by identity, and its
    // fingerprint matches none either.
    fx.write_live(
        "stranger@example.com",
        "org-9",
        "rt-stranger",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["switch", "1", "--json"]);
    assert_eq!(out["switched"], true);
    assert_eq!(out["from"]["email"], "stranger@example.com");
    assert!(
        out["from"].get("slot").is_none(),
        "an unmanaged login has no slot"
    );
    assert_eq!(out["warnings"].as_array().unwrap().len(), 1);

    // Never discarded: the stash is the only copy of that credential anywhere.
    let stash = fx.stash();
    assert_eq!(stash.len(), 1, "expected one stashed credential: {stash:?}");
    assert!(
        stash[0].0.starts_with("claude_unclaimed-"),
        "unexpected stash name: {}",
        stash[0].0
    );
    let stashed: Value = serde_json::from_str(&stash[0].1).unwrap();
    assert_eq!(stashed["claudeAiOauth"]["refreshToken"], "rt-stranger");
}

#[test]
fn switch_preserves_mcp_oauth_from_live() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    // The target's frozen copy holds a rotated-out MCP token.
    let mut two = fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS);
    two["mcpOAuth"] = json!({"server": "stale-mcp-token"});
    fx.write_stored(2, &two);
    // The machine's live copy is by definition the current generation.
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({"mcpOAuth": {"server": "live-mcp-token"}}),
    );

    fx.run(&["switch", "2", "--json"]);

    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-2");
    assert_eq!(
        live["mcpOAuth"]["server"], "live-mcp-token",
        "machine-shared MCP state is live-owned and must survive the swap"
    );
}

/// The end-to-end half of the restore contract: whatever the driver does
/// internally, a failed switch must leave the machine exactly as it was.
///
/// The mechanism itself — `perform` writing the previous login back after a
/// refused `write_live` — is proved in `core::switch`'s own
/// `switch_restores_live_on_write_failure`, against a driver that can be told
/// to fail. It cannot be reached from here: with the file live store the
/// Claude driver's only post-write failure is the `~/.claude.json` splice, and
/// every portable way to break that write also breaks Claude Code's lock
/// directories, so the driver fails before it has written anything.
#[test]
fn switch_leaves_the_live_login_untouched_when_the_write_fails() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );
    let before = std::fs::read_to_string(fx.live_credentials()).unwrap();

    // A torn `~/.claude.json` fails the write: the driver refuses to clobber
    // the user's config, so the swap cannot complete.
    write(&fx.claude_json(), "{ not json");

    let err = fx.run_err(&["switch", "2", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");

    // What matters is what survives: the live login is exactly what it was,
    // and nothing recorded a switch that did not happen.
    assert_eq!(
        std::fs::read_to_string(fx.live_credentials()).unwrap(),
        before,
        "the live login must be left as it was found"
    );
    assert!(fx.history().is_empty(), "a failed switch writes no history");
    assert!(
        fx.slots()["providers"]["claude"]["activeSlot"].is_null(),
        "a failed switch does not move the active slot"
    );
    // The target's own credential is untouched either way.
    let two: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(two["claudeAiOauth"]["refreshToken"], "rt-2");
}

#[test]
fn switch_refreshes_an_expired_target_before_taking_the_locks() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(2, &fx.login("two@example.com", "org-2", "rt-2", EXPIRED_MS));
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "tok-fresh",
                "refresh_token": "rt-fresh",
                "expires_in": 28800,
            }));
    });

    let out = fx.run(&["switch", "2", "--json"]);
    assert_eq!(out["switched"], true);
    token.assert_hits(1);

    // The rotation is persisted — a refresh token is single-use, so a
    // generation that only reached the live store would be lost to the slot.
    let two: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(two["claudeAiOauth"]["refreshToken"], "rt-fresh");
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-fresh");
    let slots = fx.slots();
    let fingerprint = slot_of(&slots, 2)["fingerprint"].as_str().unwrap();
    assert!(
        fingerprint.starts_with("sha256:"),
        "the rotation must be re-stamped: {fingerprint}"
    );
}

#[test]
fn rotate_consume_first_picks_soonest_weekly_reset() {
    // Fresh rows, so nothing is fetched: slot 3's weekly window resets first,
    // slot 2 has more headroom. consume-first must take 3 anyway.
    let fx = rotate_fixture();

    let out = fx.run(&["rotate", "--strategy", "consume-first", "--json"]);
    assert_eq!(out["switched"], true);
    assert_eq!(out["to"]["slot"], 3, "soonest weekly reset wins");
    assert_eq!(fx.history()[0]["trigger"], "rotate");

    // `best` would have taken the other one.
    let fx2 = rotate_fixture();
    let out = fx2.run(&["rotate", "--strategy", "best", "--json"]);
    assert_eq!(out["to"]["slot"], 2, "most headroom wins");
}

/// The same three-account board as `rotate_consume_first_picks_soonest_weekly_reset`.
fn rotate_fixture() -> Fixture {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
        (3, "three@example.com", "org-3"),
    ]);
    for (slot, email, org) in [
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
        (3, "three@example.com", "org-3"),
    ] {
        fx.write_stored(
            slot,
            &fx.login(email, org, &format!("rt-{slot}"), NOT_EXPIRED_MS),
        );
    }
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 10.0, "resetsAt": "2026-09-30T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 40.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
    }));
    fx
}

/// `next-available` answers with the collector's own health rule, so it skips
/// an account `list` would not have called `nextCandidate` either.
#[test]
fn rotate_next_available_skips_an_account_over_the_threshold() {
    let fx = rotate_fixture();
    // Slot 2 is next in rotation order after the active slot 1, but it is at
    // 95% of its binding window — past the 90% default threshold.
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 95.0, "resetsAt": "2026-09-30T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 40.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
    }));

    // `list` says the same thing about the same board, which is the parity the
    // strategy's name claims.
    let listed = fx.run(&["list", "--json", "--provider", "claude"]);
    assert_eq!(listed["providers"][0]["nextCandidate"], 3);

    let out = fx.run(&["rotate", "--strategy", "next-available", "--json"]);
    assert_eq!(
        out["to"]["slot"], 3,
        "the account over the threshold is not available"
    );
}

#[test]
fn rotate_lands_on_a_preferred_account_first() {
    // Slot 3 resets soonest, so plain consume-first takes it (the test above).
    // `claude.preferred` names slot 2's email: a pinned account wins among the
    // candidates the strategy's own gates already admit.
    let fx = rotate_fixture();
    write(
        &fx.home.path().join("settings.json"),
        &json!({
            "schemaVersion": 1,
            "providers": {"claude": {"preferred": "TWO@example.com"}},
        })
        .to_string(),
    );

    let out = fx.run(&["rotate", "--strategy", "consume-first", "--json"]);
    assert_eq!(
        out["to"]["slot"], 2,
        "the pinned account outranks the reset"
    );
}

/// The gate is the collector's INPUTS as well as its rule: a measurement past
/// the store's trust ceiling is unknown to `list`, so it must be unknown to
/// `rotate` too, or the two name different slots on one board.
#[test]
fn rotate_next_available_agrees_with_list_on_a_stale_board() {
    let fx = rotate_fixture();
    // Two hours old: past the store's trust ceiling, so `lastGood` is no longer
    // authoritative and slot 2's 95% reads as unknown — a candidate again.
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 7200.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 7200.0,
            "lastGood": [{"kind": "7d", "pct": 95.0, "resetsAt": "2026-09-30T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 7200.0,
            "lastGood": [{"kind": "7d", "pct": 40.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
    }));

    let listed = fx.run(&["list", "--json", "--provider", "claude"]);
    let next_candidate = listed["providers"][0]["nextCandidate"].clone();
    assert_eq!(next_candidate, 2, "a reading this old is unknown, not 95%");

    let out = fx.run(&["rotate", "--strategy", "next-available", "--json"]);
    assert_eq!(
        out["to"]["slot"], next_candidate,
        "`next-available` must land where `nextCandidate` said"
    );
}

/// `consume-first` consumes the account closest to its reset AMONG THE HEALTHY
/// ones (brief step 5, cswap `autoswitch.py:2109-2113`): an account already over
/// the threshold is not one to consume further.
#[test]
fn rotate_consume_first_skips_an_account_over_the_threshold() {
    let fx = rotate_fixture();
    // Slot 2 resets soonest — and is at 95%, so it is out. Slot 3 is the
    // soonest healthy one.
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 95.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 40.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
    }));

    let out = fx.run(&["rotate", "--strategy", "consume-first", "--json"]);
    assert_eq!(
        out["to"]["slot"], 3,
        "the 95% account is not one to consume"
    );
}

/// cswap's `all_above` escape (`autoswitch.py:2113-2135`): when EVERY candidate
/// is over the threshold the gate is dropped rather than the answer withheld —
/// while `next-available`, which promises parity with `nextCandidate`, still
/// says there is none.
#[test]
fn rotate_consume_first_escapes_the_gate_when_every_candidate_is_above_it() {
    let fx = rotate_fixture();
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 95.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 97.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
    }));

    // `list` has no candidate to offer on this board.
    let listed = fx.run(&["list", "--json", "--provider", "claude"]);
    assert!(listed["providers"][0]["nextCandidate"].is_null());
    let out = fx.run(&["rotate", "--strategy", "next-available", "--json"]);
    assert_eq!(out["switched"], false);
    assert_eq!(out["reason"], "no-candidate");

    // consume-first still answers, with the soonest reset among them all.
    let out = fx.run(&["rotate", "--strategy", "consume-first", "--json"]);
    assert_eq!(out["to"]["slot"], 2, "soonest reset, gate dropped");

    // And `best`, ungated by design, names the one with the most headroom.
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
        (3, "three@example.com", "org-3"),
    ]);
    for (slot, email, org) in [
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
        (3, "three@example.com", "org-3"),
    ] {
        fx.write_stored(
            slot,
            &fx.login(email, org, &format!("rt-{slot}"), NOT_EXPIRED_MS),
        );
    }
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 95.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 97.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
    }));
    let out = fx.run(&["rotate", "--strategy", "best", "--json"]);
    assert_eq!(out["to"]["slot"], 2, "most headroom, gate never applied");
}

/// `settings.json`'s `<provider>.strategy` IS the strategy a plain `rotate`
/// uses: a knob the user can set and the verb ignores is a silent no-op.
#[test]
fn rotate_takes_its_default_strategy_from_settings() {
    let fx = rotate_fixture();
    // Slot 2 is next in the rotation order after the active slot 1; slot 3 has
    // less headroom than slot 2, so `best` and `next-available` disagree.
    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 60.0, "resetsAt": "2026-09-30T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 20.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
    }));
    // The default is cswap's `best`: the most headroom.
    let out = fx.run(&["rotate", "--json"]);
    assert_eq!(out["to"]["slot"], 3, "settings default is `best`");

    let fx = rotate_fixture();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 50.0, "resetsAt": "2026-09-20T00:00:00Z"}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 60.0, "resetsAt": "2026-09-30T00:00:00Z"}]},
        "claude:3": {"email": "three@example.com", "org": "org-3", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 20.0, "resetsAt": "2026-09-11T00:00:00Z"}]},
    }));
    fx.run(&[
        "config",
        "set",
        "claude.strategy",
        "next-available",
        "--json",
    ]);
    let listed = fx.run(&["list", "--json", "--provider", "claude"]);
    assert_eq!(listed["providers"][0]["nextCandidate"], 2);

    let out = fx.run(&["rotate", "--json"]);
    assert_eq!(
        out["to"]["slot"], listed["providers"][0]["nextCandidate"],
        "the stored strategy decides, and it lands where `list` said"
    );

    // An explicit `--strategy` still overrides the file.
    let fx = rotate_fixture();
    fx.run(&[
        "config",
        "set",
        "claude.strategy",
        "next-available",
        "--json",
    ]);
    let out = fx.run(&["rotate", "--strategy", "consume-first", "--json"]);
    assert_eq!(out["to"]["slot"], 3, "soonest weekly reset, as asked");
}

/// A candidate whose credential turns out to be dead is what rotation is FOR:
/// the next one in the ranking is tried rather than the rotate failing.
#[test]
fn rotate_skips_a_candidate_whose_refresh_token_is_dead() {
    let fx = rotate_fixture();
    // Slot 2 ranks first (rotation order after the active slot 1) but its
    // stored login is expired, and the endpoint refuses the grant.
    fx.write_stored(2, &fx.login("two@example.com", "org-2", "rt-2", EXPIRED_MS));
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "error": "invalid_grant" }));
    });

    let out = fx.run(&["rotate", "--strategy", "next-available", "--json"]);
    token.assert_hits(1);
    assert_eq!(out["switched"], true);
    assert_eq!(out["to"]["slot"], 3, "the next candidate takes it");
    let warnings = out["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("slot 2")),
        "the skipped candidate must be reported: {warnings:?}"
    );
    // One switch, and it is the one that landed.
    let history = fx.history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["to"]["slot"], 3);
}

/// Once `write_live` has returned, the swap has landed: a bookkeeping failure
/// after it is a warning on a successful switch, not a failed one.
#[test]
fn a_landed_switch_reports_a_logging_failure_as_a_warning() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );
    // A directory where the log belongs: appending to it cannot succeed.
    std::fs::create_dir_all(fx.home.path().join("history.jsonl")).unwrap();

    let out = fx.run(&["switch", "2", "--json"]);
    assert_eq!(out["switched"], true, "the live store holds the target");
    let warnings = out["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("not logged")),
        "the unlogged switch must be reported: {warnings:?}"
    );
    // And the switch really did land, record and all.
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-2");
    assert_eq!(fx.slots()["providers"]["claude"]["activeSlot"], 2);
}

/// `add` with nothing to capture is not a slot problem.
#[test]
fn add_without_a_live_login_is_invalid_input() {
    let fx = Fixture::new();
    let err = fx.run_err(&["add", "--json"]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("log in first"));
}

#[test]
fn rotate_reports_no_candidate_when_every_peer_is_spent() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let now = now_s();
    fx.write_usage(json!({
        "claude:1": {"email": "one@example.com", "org": "org-1", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 10.0}]},
        "claude:2": {"email": "two@example.com", "org": "org-2", "fetchedAt": now - 5.0,
            "lastGood": [{"kind": "7d", "pct": 100.0}]},
    }));

    let out = fx.run(&["rotate", "--json"]);
    assert_eq!(out["switched"], false);
    assert_eq!(out["reason"], "no-candidate");
    assert!(fx.history().is_empty());
}

#[test]
fn switch_names_an_account_by_alias_and_email() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let out = fx.run(&["switch", "A2", "--json"]);
    assert_eq!(out["to"]["slot"], 2, "aliases are case-insensitive");

    let out = fx.run(&["switch", "ONE@EXAMPLE.COM", "--json"]);
    assert_eq!(out["to"]["slot"], 1, "emails are case-insensitive");

    let err = fx.run_err(&["switch", "nobody", "--json"]);
    assert_eq!(err["error"]["code"], "no-such-slot");
}

#[test]
fn switch_refuses_a_slot_with_no_stored_login() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let err = fx.run_err(&["switch", "2", "--json"]);
    assert_eq!(err["error"]["code"], "no-such-slot");
    // The live login is untouched by a refused switch.
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-1");
}

#[test]
fn history_limit_keeps_the_newest() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(
        2,
        &fx.login("two@example.com", "org-2", "rt-2", NOT_EXPIRED_MS),
    );
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    fx.run(&["switch", "2", "--json"]);
    fx.run(&["switch", "1", "--json"]);

    let all = fx.run(&["history", "--json"]);
    assert_eq!(all["switches"].as_array().unwrap().len(), 2);
    assert_eq!(all["switches"][1]["to"]["slot"], 1, "newest last");

    let last = fx.run(&["history", "--limit", "1", "--json"]);
    assert_eq!(last["switches"].as_array().unwrap().len(), 1);
    assert_eq!(last["switches"][0]["to"]["slot"], 1);
}

/// A per-slot refresh lock is a fact about ONE candidate's credential, so the
/// refusal is `refresh-denied` (which `rotate` skips past) and not `locked`
/// (which is about the machine, and stops it).
#[test]
fn an_expired_target_whose_refresh_lock_is_held_is_refresh_denied() {
    let fx = Fixture::new();
    fx.write_slots(&[
        (1, "one@example.com", "org-1"),
        (2, "two@example.com", "org-2"),
    ]);
    fx.write_stored(
        1,
        &fx.login("one@example.com", "org-1", "rt-1", NOT_EXPIRED_MS),
    );
    fx.write_stored(2, &fx.login("two@example.com", "org-2", "rt-2", EXPIRED_MS));
    fx.write_live(
        "one@example.com",
        "org-1",
        "rt-1",
        NOT_EXPIRED_MS,
        json!({}),
    );

    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "tok-fresh",
                "refresh_token": "rt-fresh",
                "expires_in": 28800,
            }));
    });

    // Another process is mid-rotation of slot 2's single-use token.
    let lock_path = fx.home.path().join("refresh-claude-2.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .unwrap();
    let mut lock = fd_lock::RwLock::new(file);
    let _held = lock.try_write().expect("the test must own the lock");

    let err = fx.run_err(&["switch", "2", "--json"]);
    assert_eq!(err["error"]["code"], "refresh-denied");
    // Not a token was spent, and the live login is still slot 1's.
    token.assert_hits(0);
    let live: Value = read_json(&fx.live_credentials());
    assert_eq!(live["claudeAiOauth"]["refreshToken"], "rt-1");
}
