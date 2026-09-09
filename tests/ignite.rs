//! `ignite` and `run` end to end: the real binary, a temp swapd home, a temp
//! Claude home, an httpmock upstream — and a `claude` that is a shell script.
//!
//! `SWAPD_CLAUDE_CLI` names that script, which is the only way a run stays
//! hermetic: two of the driver's well-known install locations are absolute
//! paths that exist on a developer's machine whatever `HOME` says, so a suite
//! that merely emptied `PATH` would find and run the real CLI as the real
//! account. The stub records its argv and environment to a witness file and can
//! rewrite the profile's credential the way Claude Code does when it refreshes
//! mid-run. Nothing here sets a process-wide env var: every child is configured
//! through `Command::env`.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use httpmock::prelude::*;
use httpmock::Mock;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Far enough out that a seeded login is never treated as expired.
const NOT_EXPIRED_MS: i64 = 4_102_444_800_000; // 2100-01-01
/// Long expired: the verb must refresh before it may run anything.
const EXPIRED_MS: i64 = 1_000_000_000_000; // 2001-09-09

/// The credential the stub writes when it is told to rotate — a whole
/// generation on from the seeded one, as a real mid-run refresh leaves behind.
const ROTATED: &str = concat!(
    r#"{"claudeAiOauth":{"accessToken":"tok-1b","refreshToken":"rt-1b","#,
    r#""expiresAt":4102444800000,"scopes":["user:inference"]}}"#
);

struct Fixture {
    home: TempDir,
    claude_home: TempDir,
    bin: TempDir,
    server: MockServer,
}

/// What the stub `claude` should do when it runs.
struct Stub {
    /// Exit with this code.
    exit: i32,
    /// Rewrite the profile's `.credentials.json` first, as a mid-run refresh
    /// does.
    rotate: bool,
    /// Print this on stdout, so a test can prove the child's output reached the
    /// user's.
    say: &'static str,
}

impl Stub {
    fn new() -> Self {
        Stub {
            exit: 0,
            rotate: false,
            say: "",
        }
    }
}

impl Fixture {
    /// One slot, logged in with a non-expired OAuth login.
    fn new() -> Self {
        let fx = Fixture {
            home: TempDir::new().unwrap(),
            claude_home: TempDir::new().unwrap(),
            bin: TempDir::new().unwrap(),
            server: MockServer::start(),
        };
        write(
            &fx.home.path().join("slots.json"),
            &json!({
                "schemaVersion": 1,
                "providers": {"claude": {
                    "activeSlot": null,
                    "order": [1],
                    "slots": {"1": {
                        "email": "one@example.com",
                        "organizationUuid": "org-1",
                        "organizationName": "Org One",
                        "alias": "one",
                    }},
                }},
            })
            .to_string(),
        );
        fx.write_login(NOT_EXPIRED_MS);
        fx
    }

    /// Slot 1's stored login, laid out the way `FileSecrets` does.
    fn write_login(&self, expires_at: i64) {
        write(
            &self.credential(),
            &json!({
                "claudeAiOauth": {
                    "accessToken": "tok-1",
                    "refreshToken": "rt-1",
                    "expiresAt": expires_at,
                    "scopes": ["user:inference"],
                },
                "oauthAccount": {
                    "emailAddress": "one@example.com",
                    "organizationUuid": "org-1",
                    "organizationName": "Org One",
                },
            })
            .to_string(),
        );
    }

    fn credential(&self) -> PathBuf {
        self.home.path().join("credentials/claude_1")
    }

    fn stored_login(&self) -> String {
        std::fs::read_to_string(self.credential()).unwrap()
    }

    fn profile(&self) -> PathBuf {
        self.home.path().join("profiles/claude/1")
    }

    /// The profile's seed marker: the fingerprint of the generation swapd's
    /// STORE holds for this slot, which is what keeps a later launch from
    /// seeding an older copy over a rotation.
    fn marker(&self) -> String {
        std::fs::read_to_string(self.profile().join(".swapd-seeded")).unwrap()
    }

    fn witness_path(&self) -> PathBuf {
        self.bin.path().join("witness")
    }

    /// What the stub recorded about the run it was given, as `key:value` lines.
    fn witness(&self) -> String {
        std::fs::read_to_string(self.witness_path()).unwrap()
    }

    fn witness_line(&self, key: &str) -> String {
        let witness = self.witness();
        witness
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}:")).map(str::to_string))
            .unwrap_or_else(|| panic!("no {key} in witness:\n{witness}"))
    }

    /// Install the stub `claude`. It records its argv and the environment it was
    /// handed, then optionally rotates the profile's credential and fails.
    fn write_stub(&self, stub: Stub) {
        let mut script = String::from("#!/bin/sh\n{\n");
        script.push_str("  printf 'argv:%s\\n' \"$*\"\n");
        script.push_str("  printf 'config:%s\\n' \"$CLAUDE_CONFIG_DIR\"\n");
        script.push_str("  printf 'secure:%s\\n' \"$CLAUDE_SECURESTORAGE_CONFIG_DIR\"\n");
        script.push_str("  printf 'apikey:[%s]\\n' \"$ANTHROPIC_API_KEY\"\n");
        script.push_str("  printf 'cwd:%s\\n' \"$PWD\"\n");
        script.push_str(
            "  printf 'seeded:%s\\n' \"$(cat \"$CLAUDE_CONFIG_DIR/.credentials.json\" 2>/dev/null)\"\n",
        );
        script.push_str(&format!("}} > '{}'\n", self.witness_path().display()));
        if stub.rotate {
            script.push_str(&format!(
                "printf '%s' '{ROTATED}' > \"$CLAUDE_CONFIG_DIR/.credentials.json\"\n"
            ));
        }
        if !stub.say.is_empty() {
            script.push_str(&format!("printf '%s\\n' '{}'\n", stub.say));
        }
        script.push_str(&format!("exit {}\n", stub.exit));
        let path = self.bin.path().join("claude");
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The usage endpoint, answering only for this access token.
    fn usage_mock(&self, token: &str, body: Value) -> Mock<'_> {
        self.server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/usage")
                .header("Authorization", format!("Bearer {token}"));
            then.status(200)
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
            // The stub, named outright: the real `claude` must never be reached.
            .env("SWAPD_CLAUDE_CLI", self.bin.path().join("claude"))
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
            String::from_utf8_lossy(&out.stdout)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Run expecting failure; returns the parsed error envelope.
    fn run_err(&self, args: &[&str]) -> Value {
        let out = self.cmd().args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn slots(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.home.path().join("slots.json")).unwrap())
            .unwrap()
    }

    /// Give the board a second account, so a forced pass has something it is
    /// visibly not fetching.
    fn write_second_slot(&self) {
        let mut slots = self.slots();
        slots["providers"]["claude"]["order"] = json!([1, 2]);
        slots["providers"]["claude"]["slots"]["2"] = json!({
            "email": "two@example.com",
            "organizationUuid": "org-2",
            "organizationName": "Org Two",
            "alias": "two",
        });
        write(&self.home.path().join("slots.json"), &slots.to_string());
        write(
            &self.home.path().join("credentials/claude_2"),
            &json!({
                "claudeAiOauth": {
                    "accessToken": "tok-2",
                    "refreshToken": "rt-2",
                    "expiresAt": NOT_EXPIRED_MS,
                    "scopes": ["user:inference"],
                },
                "oauthAccount": {
                    "emailAddress": "two@example.com",
                    "organizationUuid": "org-2",
                    "organizationName": "Org Two",
                },
            })
            .to_string(),
        );
    }

    /// A measurement taken `age_s` ago — the shape a successful pass leaves
    /// behind, and inside the serve TTL when it is fresh.
    fn write_usage_row(&self, slot: u32, email: &str, org: &str, age_s: f64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        write(
            &self.home.path().join("usage.json"),
            &json!({
                "schemaVersion": 2,
                "rows": { format!("claude:{slot}"): {
                    "email": email,
                    "org": org,
                    "lastGood": [{"kind": "5h", "pct": 3.0, "resetsAt": "2026-09-09T05:59:59Z"}],
                    "fetchedAt": now - age_s,
                    "consecutiveFailures": 0,
                    "authDeadStrikes": 0,
                }},
            })
            .to_string(),
        );
    }

    /// Claude Code's own live login, and the `~/.claude.json` identity it
    /// advertises for it.
    fn write_live_login(&self, email: &str, org: &str) {
        write(
            &self.claude_home.path().join(".claude/.credentials.json"),
            &json!({
                "claudeAiOauth": {
                    "accessToken": "tok-live",
                    "refreshToken": "rt-live",
                    "expiresAt": NOT_EXPIRED_MS,
                    "scopes": ["user:inference"],
                },
            })
            .to_string(),
        );
        write(
            &self.claude_home.path().join(".claude.json"),
            &json!({
                "oauthAccount": {
                    "emailAddress": email,
                    "organizationUuid": org,
                    "organizationName": "Org One",
                },
            })
            .to_string(),
        );
    }

    fn live_credential(&self) -> String {
        std::fs::read_to_string(self.claude_home.path().join(".claude/.credentials.json")).unwrap()
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn usage_body(five_hour: f64, seven_day: f64) -> Value {
    json!({
        "five_hour": { "utilization": five_hour, "resets_at": "2026-09-09T05:59:59Z" },
        "seven_day": { "utilization": seven_day },
    })
}

/// The fingerprint the board stamps for a login with this refresh token.
fn fingerprint_of(refresh_token: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(refresh_token.as_bytes()))
    )
}

#[test]
fn ignite_runs_igniter_then_forces_refresh() {
    let fx = Fixture::new();
    // A second account, and a measurement for slot 1 taken seconds ago. Without
    // `force_slots` this pass would serve slot 1 from the table and fetch slot
    // 2, which has none — so the hit counts below prove the force, and prove it
    // is a force of exactly one slot.
    fx.write_second_slot();
    fx.write_usage_row(1, "one@example.com", "org-1", 5.0);
    // The real shape of a run: `claude` refreshes its own token first, in the
    // profile, and tells nobody.
    fx.write_stub(Stub {
        rotate: true,
        ..Stub::new()
    });
    // The seeded generation is spent the moment the CLI rotates past it, so the
    // forced fetch must go out as the NEW one. Matching the mock on the token
    // is what proves the rotation was persisted before the collect, and not
    // merely that a collect happened.
    let spent = fx.usage_mock("tok-1", usage_body(1.0, 2.0));
    let rotated = fx.usage_mock("tok-1b", usage_body(12.0, 34.0));
    let other = fx.usage_mock("tok-2", usage_body(56.0, 7.0));

    // The baseline this test turns on: a plain pass serves slot 1 from the
    // table (inside the serve TTL) and fetches only the sibling.
    let listed = fx.run(&["list", "--json"]);
    assert_eq!(
        listed["providers"][0]["accounts"][0]["windows"][0]["pct"],
        3.0
    );
    spent.assert_hits(0);
    other.assert_hits(1);

    let out = fx
        .cmd()
        .args(["ignite", "one", "--json"])
        // An exported API key makes the CLI bypass account OAuth entirely,
        // which would open some other account's window and report it as this
        // slot's.
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-exported")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ignite failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let out: Value = serde_json::from_slice(&out.stdout).unwrap();

    // The igniter ran in the slot's own profile, on both axes, with one minimal
    // turn and the auth override scrubbed.
    assert_eq!(fx.witness_line("argv"), "-p . --max-turns 1");
    assert_eq!(fx.witness_line("config"), fx.profile().to_str().unwrap());
    assert_eq!(fx.witness_line("secure"), fx.profile().to_str().unwrap());
    assert_eq!(fx.witness_line("apikey"), "[]");
    // ...and in swapd's own empty directory, not wherever the user happened to
    // be: `claude` records a run against the project it finds in its cwd.
    assert!(fx.witness_line("cwd").contains("ignite-cwd"));
    assert!(fx.witness_line("seeded").contains("rt-1"));

    // The rotation reached the store, so the account is not left holding a
    // refresh token the server has already spent.
    assert!(fx.stored_login().contains("rt-1b"));
    assert_eq!(
        fx.slots()["providers"]["claude"]["slots"]["1"]["fingerprint"],
        fingerprint_of("rt-1b")
    );
    // ...and only then did the profile's marker follow it.
    assert_eq!(fx.marker(), fingerprint_of("rt-1b"));

    // The window the run just opened is only visible in a fetch made after it,
    // and that fetch went out as the rotated token.
    rotated.assert_hits(1);
    spent.assert_hits(0);
    // Past the serve TTL for the named slot, and only for it: the sibling's
    // endpoint stayed at the hit count the baseline pass left it on.
    other.assert_hits(1);
    assert_eq!(out["ignited"]["slot"], 1);
    assert_eq!(out["ignited"]["rotated"], true);
    assert!(out["ignited"]["at"].as_str().unwrap().ends_with('Z'));
    // The payload is `list`'s, so one call both ignites and reports the board.
    assert_eq!(out["schemaVersion"], 1);
    assert_eq!(out["providers"][0]["accounts"].as_array().unwrap().len(), 2);
    let account = &out["providers"][0]["accounts"][0];
    assert_eq!(account["slot"], 1);
    assert_eq!(account["usageStatus"], "ok");
    assert_eq!(account["windows"][0]["pct"], 12.0);
}

#[test]
fn ignite_without_cli_is_provider_not_installed() {
    let fx = Fixture::new();
    // No stub at all: `SWAPD_CLAUDE_CLI` names a file that is not there, and
    // that is "not installed" rather than a licence to fall back to whatever
    // `claude` the machine has.
    let usage = fx.usage_mock("tok-1", usage_body(12.0, 34.0));

    let err = fx.run_err(&["ignite", "1", "--json"]);
    assert_eq!(err["error"]["code"], "provider-not-installed");

    // Asked before anything happened: no profile was seeded, no token was
    // spent, no fetch went out.
    assert!(!fx.profile().exists());
    assert!(fx.stored_login().contains("rt-1"));
    usage.assert_hits(0);
}

#[test]
fn ignite_persists_a_rotation_before_reporting_a_failed_run() {
    let fx = Fixture::new();
    // `claude` refreshes its token first and only then does the work that
    // fails, so a failed run routinely carries a real rotation.
    fx.write_stub(Stub {
        exit: 3,
        rotate: true,
        ..Stub::new()
    });
    let usage = fx.usage_mock("tok-1b", usage_body(12.0, 34.0));

    let err = fx.run_err(&["ignite", "1", "--json"]);
    assert_eq!(err["error"]["code"], "http");
    assert_eq!(err["error"]["message"], "igniter exited 3");

    // The rotation was persisted anyway: dropping it would leave the slot on a
    // spent refresh token, whose next use answers `invalid_grant` and reads as
    // a dead account.
    assert!(fx.stored_login().contains("rt-1b"));
    assert_eq!(
        fx.slots()["providers"]["claude"]["slots"]["1"]["fingerprint"],
        fingerprint_of("rt-1b")
    );
    // And no forced fetch: the run did not open a window to measure.
    usage.assert_hits(0);
}

#[test]
fn ignite_refuses_a_slot_whose_refresh_token_is_dead() {
    let fx = Fixture::new();
    fx.write_login(EXPIRED_MS);
    fx.write_stub(Stub::new());
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "error": "invalid_grant" }));
    });

    let err = fx.run_err(&["ignite", "1", "--json"]);
    assert_eq!(err["error"]["code"], "token-dead");
    token.assert_hits(1);
    // The CLI was never launched: it would have come up logged out, and the
    // error already says why.
    assert!(!fx.witness_path().exists());
}

#[test]
fn run_passes_argv_through_the_profile_and_propagates_the_exit_code() {
    let fx = Fixture::new();
    fx.write_stub(Stub {
        exit: 7,
        rotate: true,
        say: "hello from the model",
    });
    let usage = fx.usage_mock("tok-1", usage_body(12.0, 34.0));

    let out = fx
        .cmd()
        .args(["run", "one", "--", "--model", "opus", "-p", "hi"])
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-exported")
        .output()
        .unwrap();

    // The child's code is the verb's: a wrapper that flattens exit codes breaks
    // every script around it.
    assert_eq!(out.status.code(), Some(7));
    // Its stdout is the user's — `run` inherits stdio and says nothing itself.
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello from the model"
    );

    // Everything after `--` reached the CLI untouched...
    assert_eq!(fx.witness_line("argv"), "--model opus -p hi");
    // ...in the slot's own profile, with the auth override scrubbed.
    assert_eq!(fx.witness_line("config"), fx.profile().to_str().unwrap());
    assert_eq!(fx.witness_line("secure"), fx.profile().to_str().unwrap());
    assert_eq!(fx.witness_line("apikey"), "[]");

    // The rotation the child made inside the profile was read back and stored,
    // even though the run failed — and the marker followed the store.
    assert!(fx.stored_login().contains("rt-1b"));
    assert_eq!(
        fx.slots()["providers"]["claude"]["slots"]["1"]["fingerprint"],
        fingerprint_of("rt-1b")
    );
    assert_eq!(fx.marker(), fingerprint_of("rt-1b"));
    // `run` measures nothing: it is the user's own session, wearing an account.
    usage.assert_hits(0);
    // And the live login is untouched — that is the whole point of a profile.
    assert!(!fx
        .claude_home
        .path()
        .join(".claude/.credentials.json")
        .exists());
}

#[test]
fn run_refreshes_an_expired_login_before_it_starts_the_cli() {
    let fx = Fixture::new();
    fx.write_login(EXPIRED_MS);
    fx.write_stub(Stub::new());
    let token = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "tok-1b",
                "refresh_token": "rt-1b",
                "expires_in": 3600,
            }));
    });

    let out = fx.cmd().args(["run", "1", "--"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));

    token.assert_hits(1);
    // The profile was seeded with the refreshed generation, so the CLI comes up
    // logged in rather than being handed an expired token to choke on.
    assert!(fx.witness_line("seeded").contains("rt-1b"));
    // And the rotation was persisted before the run, not after it: a refresh
    // token is single-use, so one nobody stores is a generation lost.
    assert!(fx.stored_login().contains("rt-1b"));
}

#[test]
fn run_and_ignite_refuse_an_unknown_account() {
    let fx = Fixture::new();
    fx.write_stub(Stub::new());

    for args in [
        vec!["ignite", "9", "--json"],
        vec!["run", "9", "--json"],
        vec!["ignite", "nobody@example.com", "--json"],
    ] {
        let err = fx.run_err(&args);
        assert_eq!(err["error"]["code"], "no-such-slot", "{args:?}");
    }
    // Nothing was launched for an account that does not exist.
    assert!(!fx.witness_path().exists());
}

#[test]
fn run_on_the_live_account_takes_the_ambient_fast_path() {
    let fx = Fixture::new();
    // The live login IS slot 1's account. cswap's same-account fast path
    // (`session.py:536-551`): making a second copy of this credential is how
    // the two drift — the profile's rotation spends the generation `~/.claude`
    // still holds, and the user's next plain `claude` is logged out.
    fx.write_live_login("one@example.com", "org-1");
    fx.write_stub(Stub {
        exit: 5,
        ..Stub::new()
    });

    let out = fx
        .cmd()
        .args(["run", "one", "--", "--model", "opus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));

    // The CLI ran with the ambient environment: no config dir was imposed on
    // it, so it read the live login exactly as a plain `claude` would.
    assert_eq!(fx.witness_line("argv"), "--model opus");
    assert_eq!(fx.witness_line("config"), "");
    assert_eq!(fx.witness_line("secure"), "");
    // ...and no profile was built for it at all.
    assert!(!fx.profile().exists());
    // Nothing was written on either side: no second copy to drift, and the
    // live credential is the CLI's own to rotate.
    assert!(fx.stored_login().contains("rt-1"));
    assert!(fx.live_credential().contains("rt-live"));

    // Said out loud, on stderr, so the user knows why this run looks different.
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("already the live login"),
        "stderr was: {said}"
    );
    // The child owns stdout; swapd puts nothing on it.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn run_with_an_ambient_config_dir_keeps_the_profile_and_warns() {
    let fx = Fixture::new();
    // Same live login as above, so the fast path would fire — except the user
    // already points the CLI somewhere of their own, and "the live login" is
    // then not what a plain run would use (`session.py:528-536`).
    fx.write_live_login("one@example.com", "org-1");
    fx.write_stub(Stub::new());
    let ambient = fx.claude_home.path().join("their-own-dir");
    std::fs::create_dir_all(&ambient).unwrap();

    let out = fx
        .cmd()
        .args(["run", "1", "--"])
        .env("CLAUDE_CONFIG_DIR", &ambient)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    // The profile route, not the fast path.
    assert_eq!(fx.witness_line("config"), fx.profile().to_str().unwrap());
    assert!(fx.profile().exists());
    // And the override is announced rather than done silently.
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("CLAUDE_CONFIG_DIR is set"),
        "stderr was: {said}"
    );
    assert!(
        !said.contains("already the live login"),
        "stderr was: {said}"
    );
}

#[test]
fn a_rotation_survives_a_failed_persist_and_lands_on_the_next_run() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new();
    fx.write_stub(Stub {
        exit: 7,
        rotate: true,
        ..Stub::new()
    });
    // The stored login can be read (so the profile is seeded and the child
    // runs) but not written: this is the failure that happens AFTER the child
    // has exited, with its code already decided. The DIRECTORY is what loses
    // write permission — the store replaces a secret by renaming a new file
    // over it, so a read-only file alone would not stop it.
    let dir = fx.credential().parent().unwrap().to_path_buf();
    let saved = std::fs::metadata(&dir).unwrap().permissions();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out = fx.cmd().args(["run", "1", "--"]).output().unwrap();
    std::fs::set_permissions(&dir, saved).unwrap();

    // The child is gone and its code is the answer to the command the user
    // gave; a swapd-side failure to store the rotation must not overwrite it.
    assert_eq!(out.status.code(), Some(7));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("could not store it"), "stderr was: {said}");
    assert!(
        said.contains(fx.profile().to_str().unwrap()),
        "stderr was: {said}"
    );

    // The state that makes the advice sound: the store is still on the old
    // generation, the profile holds the new one, and the marker names what the
    // STORE holds — not what the profile does.
    assert!(fx.stored_login().contains("rt-1"));
    assert!(
        std::fs::read_to_string(fx.profile().join(".credentials.json"))
            .unwrap()
            .contains("rt-1b")
    );
    assert_eq!(fx.marker(), fingerprint_of("rt-1"));

    // So the next run does NOT re-seed the older copy over it: the same stored
    // login goes in, the profile keeps the rotation, and the read-back lands it
    // for real this time.
    assert!(
        said.contains("run `swapd run 1` again"),
        "stderr was: {said}"
    );
    let out = fx.cmd().args(["run", "1", "--"]).output().unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert!(fx.stored_login().contains("rt-1b"));
    assert_eq!(
        fx.slots()["providers"]["claude"]["slots"]["1"]["fingerprint"],
        fingerprint_of("rt-1b")
    );
    // And only now, with the store holding it, does the marker move.
    assert_eq!(fx.marker(), fingerprint_of("rt-1b"));
}

#[test]
fn run_takes_the_profile_route_when_a_different_account_is_live() {
    let fx = Fixture::new();
    // Somebody else is logged in. The fast path's question is "would a plain
    // CLI run already be this account", and here the answer is no — running
    // slot 1 ambiently would run the OTHER account's credential under slot 1's
    // name, which is the inversion this test exists to catch.
    fx.write_live_login("two@example.com", "org-2");
    fx.write_stub(Stub::new());

    let out = fx
        .cmd()
        .args(["run", "1", "--", "-p", "hi"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    // The profile route, with slot 1's own login seeded into it.
    assert_eq!(fx.witness_line("config"), fx.profile().to_str().unwrap());
    assert!(fx.witness_line("seeded").contains("rt-1"));
    // And the live login is exactly where it was: a run wearing one account
    // never touches which account the next plain `claude` will be.
    assert!(fx.live_credential().contains("rt-live"));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        !said.contains("already the live login"),
        "stderr was: {said}"
    );
}

#[test]
fn run_refuses_an_api_key_slot_that_shares_the_live_login_s_address() {
    let fx = Fixture::new();
    // A managed key registered under an address of the user's choosing...
    fx.cmd()
        .args([
            "add-token",
            "-",
            "--slot",
            "2",
            "--email",
            "keyed@example.com",
        ])
        .write_stdin("sk-ant-api03-managed")
        .assert()
        .success();
    // ...which happens to be the address the CLI is currently logged in as, on
    // a personal account that carries no org — so the identity match answers
    // "slot 2 is live". Without the kind guard the fast path would fire and run
    // the CLI as that OAuth login, which is not the credential slot 2 names.
    fx.write_live_login("keyed@example.com", "");
    fx.write_stub(Stub::new());

    let err = fx.run_err(&["run", "2", "--json", "--"]);
    assert_eq!(err["error"]["code"], "unsupported");
    // Nothing was launched, on either path.
    assert!(!fx.witness_path().exists());
    assert!(!fx.profile().exists());
}
