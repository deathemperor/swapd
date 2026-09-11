//! `import` end to end, against both envelopes it accepts: cswap's
//! (`{"version":1,…}`) and swapd's own (`{"format":"swapd/1",…}`).
//!
//! Hermetic on the same terms as the other suites: a temp swapd home, a temp
//! `HOME`, the file secret backend, and no network at all — import never talks
//! to an upstream.

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
            // Unroutable on purpose: nothing in `import` may reach an upstream,
            // and a request that tried would fail rather than escape the suite.
            .env("SWAPD_URL_ANTHROPIC_API", "http://127.0.0.1:1")
            .env("SWAPD_URL_PLATFORM", "http://127.0.0.1:1")
            .env("HOME", self.claude_home.path())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR");
        cmd
    }

    /// Import from stdin, so no export file ever lands on disk.
    fn import(&self, envelope: &Value, args: &[&str]) -> Value {
        let out = self
            .cmd()
            .args(["import", "-", "--json"])
            .args(args)
            .write_stdin(envelope.to_string())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "import failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn import_err(&self, envelope: &Value, args: &[&str]) -> Value {
        let out = self
            .cmd()
            .args(["import", "-", "--json"])
            .args(args)
            .write_stdin(envelope.to_string())
            .output()
            .unwrap();
        assert!(!out.status.success(), "import unexpectedly succeeded");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn slots(&self) -> Value {
        let path = self.home.path().join("slots.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn stored(&self, slot: u32) -> String {
        std::fs::read_to_string(
            self.home
                .path()
                .join("credentials")
                .join(format!("claude_{slot}")),
        )
        .unwrap()
    }

    fn write_slots(&self, accounts: &[(u32, &str, &str)]) {
        let mut slots = serde_json::Map::new();
        let mut order = Vec::new();
        for (slot, email, org) in accounts {
            order.push(*slot);
            slots.insert(
                slot.to_string(),
                json!({"email": email, "organizationUuid": org, "organizationName": "Org"}),
            );
        }
        write(
            &self.home.path().join("slots.json"),
            &json!({
                "schemaVersion": 1,
                "providers": {"claude": {"activeSlot": null, "order": order, "slots": slots}},
            })
            .to_string(),
        );
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// One account in cswap's export shape: the credential and the config that
/// names it travel as two members.
fn account(number: u32, email: &str, org: &str) -> Value {
    json!({
        "number": number,
        "email": email,
        "uuid": format!("acct-{number}"),
        "organizationUuid": org,
        "organizationName": "Org",
        "added": "2026-01-01T00:00:00Z",
        "alias": format!("a{number}"),
        "credentials": {
            "claudeAiOauth": {
                "accessToken": format!("tok-{number}"),
                "refreshToken": format!("rt-{number}"),
                "expiresAt": 4_102_444_800_000i64,
                "scopes": ["user:inference"],
            }
        },
        "config": {
            "oauthAccount": {
                "emailAddress": email,
                "organizationUuid": org,
                "organizationName": "Org",
            }
        },
    })
}

fn cswap_envelope(accounts: Vec<Value>) -> Value {
    json!({
        "version": 1,
        "exportedAt": "2026-09-09T00:00:00Z",
        "encrypted": false,
        "activeAccountNumber": 2,
        "accounts": accounts,
    })
}

fn slot_of(slots: &Value, n: u32) -> Value {
    slots["providers"]["claude"]["slots"][n.to_string()].clone()
}

#[test]
fn import_cswap_envelope_two_accounts() {
    let fx = Fixture::new();
    let envelope = cswap_envelope(vec![
        account(1, "one@example.com", "org-1"),
        account(2, "two@example.com", "org-2"),
    ]);

    let out = fx.import(&envelope, &[]);
    assert_eq!(out["imported"], json!([1, 2]));
    assert_eq!(out["skipped"], json!([]));
    // Recorded, never activated: an import is not a switch.
    assert_eq!(out["activeSlot"], 2);
    assert!(
        fx.slots()["providers"]["claude"]["activeSlot"].is_null(),
        "import must not move the live login"
    );

    let slots = fx.slots();
    assert_eq!(slot_of(&slots, 1)["email"], "one@example.com");
    assert_eq!(slot_of(&slots, 1)["organizationUuid"], "org-1");
    assert_eq!(slot_of(&slots, 1)["organizationName"], "Org");
    assert_eq!(slot_of(&slots, 1)["alias"], "a1");
    assert_eq!(slot_of(&slots, 1)["added"], "2026-01-01T00:00:00Z");
    assert!(slot_of(&slots, 1)["fingerprint"].is_string());
    assert_eq!(slot_of(&slots, 2)["email"], "two@example.com");

    // The credential landed, with the export's `config.oauthAccount` folded in:
    // that is what gives the slot an offline identity, and what `switch` splices
    // back into `~/.claude.json`.
    let stored: Value = serde_json::from_str(&fx.stored(2)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-2");
    assert_eq!(stored["oauthAccount"]["emailAddress"], "two@example.com");

    // The imported accounts are visible as accounts.
    let listed: Value = serde_json::from_slice(
        &fx.cmd()
            .args(["list", "--json", "--provider", "claude"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let accounts = listed["providers"][0]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2);
}

#[test]
fn import_reads_swapds_own_envelope() {
    let fx = Fixture::new();
    let envelope = json!({
        "format": "swapd/1",
        "activeSlot": 1,
        "accounts": [account(1, "one@example.com", "org-1")],
    });
    let out = fx.import(&envelope, &[]);
    assert_eq!(out["imported"], json!([1]));
    assert_eq!(out["activeSlot"], 1);
}

#[test]
fn import_refuses_occupied_slot_without_force() {
    let fx = Fixture::new();
    fx.write_slots(&[(1, "resident@example.com", "org-9")]);

    let envelope = cswap_envelope(vec![account(1, "one@example.com", "org-1")]);
    let err = fx.import_err(&envelope, &[]);
    assert_eq!(err["error"]["code"], "invalid-input");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains("slot 1"), "{message}");
    assert!(message.contains("resident@example.com"), "{message}");
    assert!(message.contains("--force"), "{message}");

    // Refused before any write: the occupant is untouched and no credential
    // for the incoming account exists.
    assert_eq!(slot_of(&fx.slots(), 1)["email"], "resident@example.com");
    assert!(
        !fx.home.path().join("credentials/claude_1").exists(),
        "a refused import must write nothing"
    );

    // With --force it lands, replacing the occupant.
    let out = fx.import(&envelope, &["--force"]);
    assert_eq!(out["imported"], json!([1]));
    assert_eq!(slot_of(&fx.slots(), 1)["email"], "one@example.com");
    let stored: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-1");
}

#[test]
fn import_skips_an_account_the_slot_already_holds() {
    let fx = Fixture::new();
    let envelope = cswap_envelope(vec![account(1, "one@example.com", "org-1")]);
    assert_eq!(fx.import(&envelope, &[])["imported"], json!([1]));
    let stored = fx.stored(1);

    // The same generation again: nothing newer, so nothing written.
    let out = fx.import(&envelope, &[]);
    assert_eq!(out["imported"], json!([]));
    assert_eq!(out["refreshed"], json!([]));
    assert_eq!(out["skipped"][0]["slot"], 1);
    assert_eq!(out["skipped"][0]["reason"], "already-present");
    assert_eq!(out["updated"], json!([]));
    assert_eq!(fx.stored(1), stored, "a skipped account writes nothing");

    // The same generation with a new alias: the credential stays, the row
    // takes the file's labels, and the run is reported as `updated`.
    let mut renamed = account(1, "one@example.com", "org-1");
    renamed["alias"] = json!("renamed");
    let out = fx.import(&cswap_envelope(vec![renamed]), &[]);
    assert_eq!(out["refreshed"], json!([]));
    assert_eq!(out["updated"], json!([1]));
    assert_eq!(out["skipped"], json!([]));
    assert_eq!(fx.stored(1), stored);
    assert_eq!(
        fx.slots()["providers"]["claude"]["slots"]["1"]["alias"],
        "renamed"
    );

    // A row that lost its credential takes the file's copy, whatever its age.
    std::fs::remove_file(fx.home.path().join("credentials/claude_1")).unwrap();
    let out = fx.import(&envelope, &[]);
    assert_eq!(out["refreshed"], json!([1]));
    assert_eq!(fx.stored(1), stored);

    // The exporter's rotation — a provably newer generation of the same
    // lineage — replaces the stored copy without `--force`.
    let mut rotated = account(1, "one@example.com", "org-1");
    rotated["credentials"]["claudeAiOauth"]["accessToken"] = json!("tok-1-rotated");
    rotated["credentials"]["claudeAiOauth"]["expiresAt"] = json!(4_102_444_900_000i64);
    let out = fx.import(&cswap_envelope(vec![rotated]), &[]);
    assert_eq!(out["imported"], json!([]));
    assert_eq!(out["refreshed"], json!([1]));
    assert!(fx.stored(1).contains("tok-1-rotated"));

    // An older generation is never written over its successor…
    let out = fx.import(&envelope, &[]);
    assert_eq!(out["skipped"][0]["reason"], "already-present");
    assert!(fx.stored(1).contains("tok-1-rotated"));

    // …except by `--force`, which rewrites regardless.
    let out = fx.import(&envelope, &["--force"]);
    assert_eq!(out["imported"], json!([1]));
    assert!(fx.stored(1).contains("\"tok-1\""));
}

#[test]
fn import_carries_an_api_key_account_verbatim() {
    let fx = Fixture::new();
    let mut api = account(1, "api-key-1@token.local", "");
    api["credentials"] = json!("sk-ant-api03-imported");
    api["kind"] = json!("api_key");

    let out = fx.import(&cswap_envelope(vec![api]), &[]);
    assert_eq!(out["imported"], json!([1]));
    assert_eq!(fx.stored(1), "sk-ant-api03-imported");
}

#[test]
fn a_malformed_account_imports_nothing_at_all() {
    let fx = Fixture::new();
    // The second account is unusable; the first must not land regardless.
    let mut broken = account(2, "two@example.com", "org-2");
    broken["credentials"] = json!("not-an-api-key");
    let envelope = cswap_envelope(vec![account(1, "one@example.com", "org-1"), broken]);

    let err = fx.import_err(&envelope, &[]);
    assert_eq!(err["error"]["code"], "invalid-input");
    assert!(
        !fx.home.path().join("credentials/claude_1").exists(),
        "validation runs before any write"
    );
    assert!(!fx.home.path().join("slots.json").exists());
}

/// A refusal is decided before anything is written: an occupied slot late in
/// the file must not leave the accounts before it with credentials on disk that
/// no row refers to.
#[test]
fn a_refused_import_writes_no_credential_for_the_accounts_before_it() {
    let fx = Fixture::new();
    fx.write_slots(&[(2, "resident@example.com", "org-9")]);

    let envelope = cswap_envelope(vec![
        account(1, "one@example.com", "org-1"),
        account(2, "two@example.com", "org-2"),
    ]);
    let err = fx.import_err(&envelope, &[]);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--force"));

    assert!(
        !fx.home.path().join("credentials/claude_1").exists(),
        "slot 1's credential must not be written for an import that is refused"
    );
    assert!(slot_of(&fx.slots(), 1).is_null(), "and it has no row");
    assert_eq!(slot_of(&fx.slots(), 2)["email"], "resident@example.com");
}

/// A credential that cannot be stored stops the import, and the error says
/// which accounts did land — the rows for those are written, so the import is
/// resumable rather than a table half of whose slots have no credential.
#[test]
fn a_credential_that_cannot_be_stored_names_what_was_imported() {
    let fx = Fixture::new();
    // A directory where slot 2's credential belongs: `set` cannot write it.
    std::fs::create_dir_all(fx.home.path().join("credentials").join("claude_2")).unwrap();

    let envelope = cswap_envelope(vec![
        account(1, "one@example.com", "org-1"),
        account(2, "two@example.com", "org-2"),
    ]);
    let err = fx.import_err(&envelope, &[]);
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains("slot 2"), "{message}");
    assert!(
        message.contains("already imported: 1"),
        "the error must name what landed: {message}"
    );

    // Slot 1 landed whole — credential and row — so a rerun has less to do,
    // and no row points at bytes that were never written.
    let slots = fx.slots();
    assert_eq!(slot_of(&slots, 1)["email"], "one@example.com");
    assert!(slot_of(&slots, 1)["fingerprint"].is_string());
    assert!(slot_of(&slots, 2).is_null(), "slot 2 has no row");
    let stored: Value = serde_json::from_str(&fx.stored(1)).unwrap();
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-1");
}

/// Two failures at once: the message the user gets must be the one that says
/// what happened to their import, not an unrelated bookkeeping error about a
/// slot that landed fine.
#[test]
fn a_quarantine_that_cannot_be_lifted_does_not_mask_the_store_failure() {
    let fx = Fixture::new();
    // Slot 2's credential cannot be written…
    std::fs::create_dir_all(fx.home.path().join("credentials").join("claude_2")).unwrap();
    // …and slot 1's dead-token quarantine cannot be lifted either.
    std::fs::create_dir_all(fx.home.path().join("usage.json")).unwrap();

    let envelope = cswap_envelope(vec![
        account(1, "one@example.com", "org-1"),
        account(2, "two@example.com", "org-2"),
    ]);
    let err = fx.import_err(&envelope, &[]);
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains("slot 2"), "{message}");
    assert!(message.contains("already imported: 1"), "{message}");
}

#[test]
fn unknown_envelopes_are_refused_by_name() {
    let fx = Fixture::new();

    let err = fx.import_err(&json!({"version": 2, "accounts": []}), &[]);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("version"),
        "{}",
        err["error"]["message"]
    );

    let err = fx.import_err(&json!({"format": "swapd/9", "accounts": []}), &[]);
    assert!(err["error"]["message"].as_str().unwrap().contains("format"));

    // An encrypted export is refused rather than parsed as garbage.
    let err = fx.import_err(
        &json!({"version": 1, "encrypted": true, "accounts": [account(1, "a@b.com", "")]}),
        &[],
    );
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("encrypted"));
}
