//! `list` / `refresh` end to end: the real binary, a temp swapd home, a temp
//! Claude home and an httpmock upstream.
//!
//! Every child gets `SWAPD_SECRETS=file` and `SWAPD_LIVE_STORE=file`, so the
//! suite reaches neither the developer's login keychain nor any real
//! credential, and `SWAPD_URL_*` point both upstreams at the mock server.

use std::path::Path;

use assert_cmd::Command;
use httpmock::prelude::*;
use httpmock::Mock;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Far enough out that the seeded logins are never treated as expired.
const NOT_EXPIRED_MS: i64 = 4_102_444_800_000; // 2100-01-01
/// Long expired: the collector must refresh before it can fetch usage.
const EXPIRED_MS: i64 = 1_000_000_000_000; // 2001-09-09

struct Fixture {
    home: TempDir,
    claude_home: TempDir,
    server: MockServer,
}

impl Fixture {
    /// Two slots, both logged in with a non-expired OAuth login.
    fn new() -> Self {
        let fx = Fixture {
            home: TempDir::new().unwrap(),
            claude_home: TempDir::new().unwrap(),
            server: MockServer::start(),
        };
        fx.write_slots();
        fx.write_login(1, NOT_EXPIRED_MS);
        fx.write_login(2, NOT_EXPIRED_MS);
        fx
    }

    fn write_slots(&self) {
        let slots = json!({
            "schemaVersion": 1,
            "providers": {
                "claude": {
                    "activeSlot": null,
                    "order": [1, 2],
                    "slots": {
                        "1": {
                            "email": "one@example.com",
                            "organizationUuid": "org-1",
                            "organizationName": "Org One",
                            "alias": "one",
                        },
                        "2": {
                            "email": "two@example.com",
                            "organizationUuid": "org-2",
                            "organizationName": "Org Two",
                            "alias": "two",
                        },
                    },
                }
            }
        });
        write(&self.home.path().join("slots.json"), &slots.to_string());
    }

    /// A slot's stored login, laid out the way `FileSecrets` does (`:` folded
    /// to `_` under `<home>/credentials`).
    fn write_login(&self, slot: u32, expires_at: i64) {
        self.write_slot_login(
            slot,
            &format!("tok-{slot}"),
            &format!("rt-{slot}"),
            expires_at,
        );
    }

    fn write_slot_login(&self, slot: u32, access: &str, refresh: &str, expires_at: i64) {
        let login = json!({
            "claudeAiOauth": {
                "accessToken": access,
                "refreshToken": refresh,
                "expiresAt": expires_at,
                "scopes": ["user:inference"],
            }
        });
        write(
            &self
                .home
                .path()
                .join("credentials")
                .join(format!("claude_{slot}")),
            &login.to_string(),
        );
    }

    /// Claude Code's own live login, as the file store keeps it, plus the
    /// `~/.claude.json` identity it advertises for it.
    fn write_live_login(
        &self,
        email: &str,
        org: &str,
        access: &str,
        refresh: &str,
        expires_at: i64,
    ) {
        let login = json!({
            "claudeAiOauth": {
                "accessToken": access,
                "refreshToken": refresh,
                "expiresAt": expires_at,
                "scopes": ["user:inference"],
            }
        });
        write(
            &self.claude_home.path().join(".claude/.credentials.json"),
            &login.to_string(),
        );
        let config = json!({
            "oauthAccount": {
                "emailAddress": email,
                "organizationUuid": org,
                "organizationName": "Org Two",
            }
        });
        write(
            &self.claude_home.path().join(".claude.json"),
            &config.to_string(),
        );
    }

    /// Seed a stored measurement, the shape a successful pass leaves behind.
    /// `poll_ago_s` stamps a poll plan that has already come due; `strikes`
    /// quarantines the row against the credential `dead_fp` was taken from.
    fn write_usage_row(&self, row: UsageRow) {
        let now = now_s();
        let mut stored = json!({
            "email": row.email,
            "org": row.org,
            "lastGood": [{
                "kind": "5h",
                "pct": row.pct,
                "resetsAt": "2026-09-09T05:59:59Z",
            }],
            "fetchedAt": now - row.age_s,
            "consecutiveFailures": 0,
            "authDeadStrikes": row.strikes,
        });
        if let Some(ago) = row.poll_ago_s {
            stored["nextPollAt"] = json!(now - ago);
            stored["intervalS"] = json!(180.0);
        }
        if let Some(ahead) = row.backoff_ahead_s {
            stored["backoffUntil"] = json!(now + ahead);
            stored["consecutiveFailures"] = json!(2);
            stored["lastError"] = json!("timeout");
        }
        if let Some(fp) = row.dead_fp {
            stored["deadFingerprint"] = json!(fp);
        }
        let rows = json!({
            "schemaVersion": 2,
            "rows": { format!("claude:{}", row.slot): stored },
        });
        write(&self.home.path().join("usage.json"), &rows.to_string());
    }

    /// The usage endpoint, answering only for this slot's access token.
    fn usage_mock(&self, slot: u32, status: u16, body: serde_json::Value) -> Mock<'_> {
        self.server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/usage")
                .header("Authorization", format!("Bearer tok-{slot}"));
            then.status(status)
                .header("content-type", "application/json")
                .json_body(body);
        })
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

    fn list(&self) -> serde_json::Value {
        self.run(&["list", "--json"])
    }

    fn run(&self, args: &[&str]) -> serde_json::Value {
        let out = self.cmd().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

/// One seeded `usage.json` row.
struct UsageRow<'a> {
    slot: u32,
    email: &'a str,
    org: &'a str,
    /// How long ago the measurement was taken.
    age_s: f64,
    pct: f64,
    /// How long ago the stored poll plan came due, if it has one.
    poll_ago_s: Option<f64>,
    /// How far ahead the failure backoff still runs, if it does.
    backoff_ahead_s: Option<f64>,
    strikes: u32,
    dead_fp: Option<String>,
}

impl<'a> UsageRow<'a> {
    fn new(slot: u32, email: &'a str, org: &'a str, age_s: f64, pct: f64) -> Self {
        UsageRow {
            slot,
            email,
            org,
            age_s,
            pct,
            poll_ago_s: None,
            backoff_ahead_s: None,
            strikes: 0,
            dead_fp: None,
        }
    }
}

fn now_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// The fingerprint the collector computes for a login with this refresh token
/// (`Login::fingerprint`).
fn fingerprint_of(refresh_token: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(refresh_token.as_bytes()))
    )
}

/// Restores a directory's mode however the test ends.
struct Mode(std::path::PathBuf, u32);

impl Drop for Mode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn usage_body(five_hour: f64, seven_day: f64) -> serde_json::Value {
    json!({
        "five_hour": { "utilization": five_hour, "resets_at": "2026-09-09T05:59:59Z" },
        "seven_day": { "utilization": seven_day },
    })
}

fn account(payload: &serde_json::Value, slot: u32) -> &serde_json::Value {
    payload["providers"][0]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["slot"] == slot)
        .unwrap()
}

#[test]
fn list_serves_from_store_within_serve_ttl() {
    let fx = Fixture::new();
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));

    let first = fx.list();
    assert_eq!(account(&first, 1)["usageStatus"], "ok");
    assert_eq!(account(&first, 1)["windows"][0]["pct"], 12.0);
    one.assert_hits(1);
    two.assert_hits(1);

    // Inside the serve TTL the second pass is answered from the table.
    let second = fx.list();
    assert_eq!(account(&second, 1)["usageStatus"], "ok");
    assert_eq!(account(&second, 1)["windows"][0]["pct"], 12.0);
    one.assert_hits(1);
    two.assert_hits(1);
}

#[test]
fn refresh_slot_bypasses_serve_ttl() {
    let fx = Fixture::new();
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));

    fx.list();
    one.assert_hits(1);
    two.assert_hits(1);

    // `refresh --slot 1` forces slot 1 past the TTL and leaves slot 2 alone.
    let refreshed = fx.run(&["refresh", "--slot", "1", "--json"]);
    assert_eq!(account(&refreshed, 1)["usageStatus"], "ok");
    one.assert_hits(2);
    two.assert_hits(1);
}

#[test]
fn dead_token_is_relogin_required_and_not_fetched() {
    let fx = Fixture::new();
    fx.write_login(2, EXPIRED_MS);
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "error": "invalid_grant" }));
    });

    // Pass 1: the expired login is refreshed, the grant is rejected, and the
    // strike surfaces in this pass rather than the next.
    let first = fx.list();
    assert_eq!(account(&first, 2)["usageStatus"], "relogin-required");
    token.assert_hits(1);
    two.assert_hits(0);

    // Pass 2: quarantined — neither endpoint is asked again.
    let second = fx.list();
    assert_eq!(account(&second, 2)["usageStatus"], "relogin-required");
    token.assert_hits(1);
    two.assert_hits(0);

    // The healthy sibling is unaffected.
    assert_eq!(account(&second, 1)["usageStatus"], "ok");
    one.assert_hits(1);
}

#[test]
fn stale_on_error_keeps_last_good() {
    let fx = Fixture::new();
    // A measurement from before the stale-OK bound, as a prior successful pass
    // would have left it.
    fx.write_usage_row(UsageRow::new(1, "one@example.com", "org-1", 400.0, 42.0));
    let one = fx.usage_mock(1, 500, json!({ "error": "boom" }));

    let payload = fx.list();
    one.assert_hits(1);
    let slot = account(&payload, 1);
    assert_eq!(slot["usageStatus"], "stale");
    assert_eq!(slot["windows"].as_array().unwrap().len(), 0);
    assert_eq!(slot["lastGood"]["windows"][0]["pct"], 42.0);
    assert!(slot["lastGood"]["fetchedAt"].is_string());
}

#[test]
fn windows_in_payload_match_snapshot() {
    let fx = Fixture::new();
    fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    fx.usage_mock(2, 200, usage_body(56.0, 7.0));

    let payload = fx.list();
    insta::assert_json_snapshot!("list_payload", payload, {
        // Wall-clock and machine facts, not contract shape.
        ".**.fetchedAt" => "[fetched-at]",
        ".**.ageSeconds" => "[age]",
        ".**.pace" => "[pace]",
        ".providers[].installed" => "[installed]",
    });
}

#[test]
fn active_slot_matches_the_live_login_by_identity() {
    let fx = Fixture::new();
    // Claude Code holds slot 2's account, on a lineage it rotated itself since
    // the slot's copy was stored.
    fx.write_live_login(
        "two@example.com",
        "org-2",
        "tok-2",
        "rt-2-rotated",
        NOT_EXPIRED_MS,
    );
    fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    fx.usage_mock(2, 200, usage_body(56.0, 7.0));

    let payload = fx.list();
    assert_eq!(payload["providers"][0]["activeSlot"], 2);
    assert_eq!(account(&payload, 2)["active"], true);
    assert_eq!(account(&payload, 1)["active"], false);

    // The rotation is adopted: the slot's stored copy is no longer the spent
    // generation, and `slots.json` records the credential it now holds.
    let stored =
        std::fs::read_to_string(fx.home.path().join("credentials").join("claude_2")).unwrap();
    assert!(stored.contains("rt-2-rotated"), "{stored}");
    let slots: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fx.home.path().join("slots.json")).unwrap())
            .unwrap();
    assert!(slots["providers"]["claude"]["slots"]["2"]["fingerprint"]
        .as_str()
        .is_some_and(|fp| fp.starts_with("sha256:")));
}

#[test]
fn refreshed_rotation_is_persisted_before_the_retry() {
    let fx = Fixture::new();
    // The active account's live credential is expired, and the slot's stored
    // copy is the same generation: the pass has to refresh it, persist the
    // successor everywhere, and only then fetch usage.
    fx.write_login(2, EXPIRED_MS);
    fx.write_live_login("two@example.com", "org-2", "tok-2", "rt-2", EXPIRED_MS);
    fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let spent = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    let rotated = fx.server.mock(|when, then| {
        when.method(GET)
            .path("/api/oauth/usage")
            .header("Authorization", "Bearer tok-2b");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(usage_body(56.0, 7.0));
    });
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "tok-2b",
                "refresh_token": "rt-2b",
                "expires_in": 3600,
            }));
    });

    let payload = fx.list();
    assert_eq!(account(&payload, 2)["usageStatus"], "ok");
    assert_eq!(account(&payload, 2)["active"], true);
    // Exactly one refresh, and usage is only ever asked with the successor.
    token.assert_hits(1);
    spent.assert_hits(0);
    rotated.assert_hits(1);

    // The rotation reached both stores before the retry could fail, and the
    // slot records the generation it now holds.
    let stored =
        std::fs::read_to_string(fx.home.path().join("credentials").join("claude_2")).unwrap();
    assert!(stored.contains("rt-2b"), "{stored}");
    let live =
        std::fs::read_to_string(fx.claude_home.path().join(".claude/.credentials.json")).unwrap();
    assert!(live.contains("rt-2b"), "{live}");
    let slots: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fx.home.path().join("slots.json")).unwrap())
            .unwrap();
    assert!(slots["providers"]["claude"]["slots"]["2"]["fingerprint"]
        .as_str()
        .is_some_and(|fp| fp.starts_with("sha256:")));
}

#[test]
fn refresh_without_a_slot_fetches_a_due_row_inside_the_serve_ttl() {
    let fx = Fixture::new();
    // Fresh (10s) but past its poll plan: `list` respects the plan and the
    // serve floor, so it leaves this row alone; `refresh` sweeps it.
    let mut row = UsageRow::new(1, "one@example.com", "org-1", 10.0, 42.0);
    row.poll_ago_s = Some(5.0);
    fx.write_usage_row(row);
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));

    fx.list();
    one.assert_hits(0);
    two.assert_hits(1);

    let refreshed = fx.run(&["refresh", "--json"]);
    assert_eq!(account(&refreshed, 1)["usageStatus"], "ok");
    one.assert_hits(1);
    // Slot 2's fetch a moment ago left it fresh with a plan of its own.
    two.assert_hits(1);
}

#[test]
fn transient_refresh_error_is_token_expired_on_the_active_slot() {
    let fx = Fixture::new();
    fx.write_login(2, EXPIRED_MS);
    fx.write_live_login("two@example.com", "org-2", "tok-2", "rt-2", EXPIRED_MS);
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    // Not a rejected grant — a server fault, which says nothing about the token.
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(500).body("upstream is unwell");
    });

    let payload = fx.list();
    assert_eq!(account(&payload, 2)["usageStatus"], "token-expired");
    token.assert_hits(1);
    // The expired token is never presented to the usage endpoint.
    two.assert_hits(0);
}

#[cfg(unix)]
#[test]
fn write_live_failure_degrades_to_token_expired() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new();
    fx.write_login(2, EXPIRED_MS);
    fx.write_live_login("two@example.com", "org-2", "tok-2", "rt-2", EXPIRED_MS);
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let rotated = fx.server.mock(|when, then| {
        when.method(GET)
            .path("/api/oauth/usage")
            .header("Authorization", "Bearer tok-2b");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(usage_body(56.0, 7.0));
    });
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "tok-2b",
                "refresh_token": "rt-2b",
                "expires_in": 3600,
            }));
    });

    // Claude Code's config dir is read-only for this run, so the live write
    // cannot land.
    let claude_dir = fx.claude_home.path().join(".claude");
    let _restore = Mode(claude_dir.clone(), 0o700);
    std::fs::set_permissions(&claude_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::File::create(claude_dir.join(".probe")).is_ok() {
        // Running as root (some CI containers): the mode proves nothing.
        std::fs::remove_file(claude_dir.join(".probe")).unwrap();
        return;
    }

    let payload = fx.list();
    // One account degrades; the rest of the payload still stands.
    assert_eq!(account(&payload, 2)["usageStatus"], "token-expired");
    assert_eq!(account(&payload, 1)["usageStatus"], "ok");
    one.assert_hits(1);
    token.assert_hits(1);
    // The retry is skipped: the live store and the secret disagree.
    rotated.assert_hits(0);

    // The rotation the token endpoint already spent survives where it matters.
    let stored =
        std::fs::read_to_string(fx.home.path().join("credentials").join("claude_2")).unwrap();
    assert!(stored.contains("rt-2b"), "{stored}");
}

#[test]
fn an_older_live_generation_is_not_adopted_and_the_live_store_is_healed() {
    let fx = Fixture::new();
    // The slot holds the newer generation (an earlier pass rotated it and could
    // not write it back); the live store still has its predecessor.
    fx.write_slot_login(2, "tok-2b", "rt-2b", NOT_EXPIRED_MS);
    fx.write_live_login(
        "two@example.com",
        "org-2",
        "tok-2",
        "rt-2",
        NOT_EXPIRED_MS - 100_000,
    );
    let spent = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    let newer = fx.server.mock(|when, then| {
        when.method(GET)
            .path("/api/oauth/usage")
            .header("Authorization", "Bearer tok-2b");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(usage_body(56.0, 7.0));
    });

    let payload = fx.list();
    assert_eq!(payload["providers"][0]["activeSlot"], 2);
    assert_eq!(account(&payload, 2)["usageStatus"], "ok");
    // The older live credential is neither adopted nor presented.
    spent.assert_hits(0);
    newer.assert_hits(1);
    let stored =
        std::fs::read_to_string(fx.home.path().join("credentials").join("claude_2")).unwrap();
    assert!(stored.contains("rt-2b"), "{stored}");
    // ... and the divergence is healed rather than left for the next pass.
    let live =
        std::fs::read_to_string(fx.claude_home.path().join(".claude/.credentials.json")).unwrap();
    assert!(live.contains("rt-2b"), "{live}");
}

#[test]
fn a_struck_slot_is_fetched_again_after_a_new_credential() {
    let fx = Fixture::new();
    // Slot 2's stored refresh lineage was condemned by an earlier pass.
    let mut row = UsageRow::new(2, "two@example.com", "org-2", 400.0, 42.0);
    row.strikes = 1;
    row.dead_fp = Some(fingerprint_of("rt-2"));
    fx.write_usage_row(row);
    let one = fx.usage_mock(1, 200, usage_body(12.0, 34.0));
    let struck = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    let relogged = fx.server.mock(|when, then| {
        when.method(GET)
            .path("/api/oauth/usage")
            .header("Authorization", "Bearer tok-2new");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(usage_body(56.0, 7.0));
    });

    // Quarantined: reported, never fetched.
    let before = fx.list();
    assert_eq!(account(&before, 2)["usageStatus"], "relogin-required");
    assert_eq!(account(&before, 2)["lastGood"]["windows"][0]["pct"], 42.0);
    struck.assert_hits(0);
    one.assert_hits(1);

    // The user logs in again; Claude Code writes a credential of its own.
    fx.write_live_login(
        "two@example.com",
        "org-2",
        "tok-2new",
        "rt-2new",
        NOT_EXPIRED_MS,
    );
    let after = fx.list();
    assert_eq!(account(&after, 2)["usageStatus"], "ok");
    relogged.assert_hits(1);
    struck.assert_hits(0);

    // The quarantine is lifted in the table too, not just in the display.
    let usage: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fx.home.path().join("usage.json")).unwrap())
            .unwrap();
    assert_eq!(usage["rows"]["claude:2"]["authDeadStrikes"], 0);
}

#[test]
fn a_gated_active_slot_with_an_expired_login_reports_token_expired() {
    let fx = Fixture::new();
    // Slot 2 is the active account, its credential is expired, and its failure
    // backoff keeps it out of this pass entirely.
    fx.write_login(2, EXPIRED_MS);
    fx.write_live_login("two@example.com", "org-2", "tok-2", "rt-2", EXPIRED_MS);
    let mut row = UsageRow::new(2, "two@example.com", "org-2", 60.0, 42.0);
    row.backoff_ahead_s = Some(600.0);
    fx.write_usage_row(row);
    let two = fx.usage_mock(2, 200, usage_body(56.0, 7.0));
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200).json_body(json!({}));
    });

    let payload = fx.list();
    let slot = account(&payload, 2);
    // Not "ok off a 60-second-old row": the credential cannot serve a request.
    assert_eq!(slot["usageStatus"], "token-expired");
    assert_eq!(slot["windows"].as_array().unwrap().len(), 0);
    assert_eq!(slot["lastGood"]["windows"][0]["pct"], 42.0);
    two.assert_hits(0);
    token.assert_hits(0);
}
