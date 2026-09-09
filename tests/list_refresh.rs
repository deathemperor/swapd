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
        let login = json!({
            "claudeAiOauth": {
                "accessToken": format!("tok-{slot}"),
                "refreshToken": format!("rt-{slot}"),
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

    /// Seed a stored measurement older than `STALE_OK_S`, with no poll plan —
    /// the shape a successful pass some minutes ago leaves behind.
    fn write_usage_row(&self, slot: u32, email: &str, org: &str, age_s: f64, pct: f64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let rows = json!({
            "schemaVersion": 2,
            "rows": {
                format!("claude:{slot}"): {
                    "email": email,
                    "org": org,
                    "lastGood": [{
                        "kind": "5h",
                        "pct": pct,
                        "resetsAt": "2026-09-09T05:59:59Z",
                    }],
                    "fetchedAt": now - age_s,
                    "consecutiveFailures": 0,
                    "authDeadStrikes": 0,
                }
            }
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
    fx.write_usage_row(1, "one@example.com", "org-1", 400.0, 42.0);
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
    // The active account's live credential is expired: the pass has to refresh
    // it, persist the successor everywhere, and only then fetch usage.
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
