//! `swapd add-oauth` end to end: the real binary holds the loopback port, a
//! test plays the browser, and the account lands in a slot.
//!
//! Same hermetic contract as the other suites — `SWAPD_SECRETS=file` and
//! `SWAPD_LIVE_STORE=file` keep the run off the developer's keychain and off
//! any real credential, `SWAPD_URL_*` point the sign-in and the token grant at
//! a mock server, and `SWAPD_OAUTH_PORT` moves the listener off the registered
//! one so a test never fights a real sign-in for it. Nothing sets a
//! process-wide env var: every child is configured through `Command::env`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};

use httpmock::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const GRANT: &str = r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":28800,"scope":"user:profile user:inference","account":{"uuid":"acc-1","email_address":"new@example.com"},"organization":{"uuid":"org-1"}}"#;

struct Fixture {
    home: TempDir,
    claude_home: TempDir,
    server: MockServer,
    port: u16,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            home: TempDir::new().unwrap(),
            claude_home: TempDir::new().unwrap(),
            server: MockServer::start(),
            port: free_port(),
        }
    }

    /// The verb, started and blocked on its listener. Answers the URL line it
    /// printed before it blocked, and the child, whose remaining line is the
    /// `add` envelope.
    fn begin(&self, args: &[&str]) -> (Value, Child, BufReader<ChildStdout>) {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("swapd"));
        cmd.args(["--json", "add-oauth"])
            .args(args)
            .env("SWAPD_HOME", self.home.path())
            .env("SWAPD_SECRETS", "file")
            .env("SWAPD_LIVE_STORE", "file")
            .env("SWAPD_URL_ANTHROPIC_API", self.server.base_url())
            .env("SWAPD_URL_PLATFORM", self.server.base_url())
            .env("SWAPD_URL_CLAUDE_WEB", self.server.base_url())
            .env("SWAPD_OAUTH_PORT", self.port.to_string())
            .env("HOME", self.claude_home.path())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        (read_line(&mut reader), child, reader)
    }

    fn slots(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.home.path().join("slots.json")).unwrap())
            .unwrap()
    }

    fn stored(&self, slot: u32) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(
                self.home
                    .path()
                    .join("credentials")
                    .join(format!("claude_{slot}")),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

/// A port nothing holds. Bound and released, which is the usual small race —
/// and the only alternative is a fixed port, which every parallel test would
/// then fight over.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn read_line(reader: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("not one JSON line: {line:?} ({e})"))
}

/// The `state` the authorize URL carried — the browser hands it back, and a
/// callback without it is not an answer to this attempt.
fn state_of(url: &str) -> String {
    let query = url.split_once('?').unwrap().1;
    let raw = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("state="))
        .expect("the authorize URL names a state");
    // The URL carries it encoded; the callback sends back the decoded value.
    raw.replace("%2F", "/")
        .replace("%2B", "+")
        .replace("%3D", "=")
}

/// Play the browser: one GET at the loopback listener, and the page it answered.
fn callback(port: u16, query: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET /callback?{query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn a_browser_round_trip_registers_the_account() {
    let fx = Fixture::new();
    let grant = fx.server.mock(|when, then| {
        when.method(POST)
            .path("/v1/oauth/token")
            .json_body_partial(r#"{"grant_type":"authorization_code","code":"ac-1"}"#);
        then.status(200)
            .header("content-type", "application/json")
            .body(GRANT);
    });

    let (url_line, mut child, mut reader) = fx.begin(&[]);
    // The first line lands while the verb still holds the socket, which is what
    // lets a caller open the page.
    assert_eq!(url_line["port"], fx.port);
    let url = url_line["url"].as_str().unwrap().to_string();
    assert!(url.starts_with(&format!("{}/cai/oauth/authorize?", fx.server.base_url())));
    assert!(url.contains(&format!(
        "redirect_uri=http%3A%2F%2Flocalhost%3A{}%2Fcallback",
        fx.port
    )));

    // A stray connection is not this sign-in and must not end the wait.
    assert!(callback(fx.port, "code=ac-9&state=not-mine").contains("400 Bad Request"));

    let page = callback(fx.port, &format!("code=ac-1&state={}", state_of(&url)));
    assert!(page.contains("200 OK"));
    assert!(page.contains("You can close this window"));
    let (headers, body) = page.split_once("\r\n\r\n").unwrap();
    assert!(headers.contains(&format!("Content-Length: {}", body.len())));
    assert!(body.contains("<title>Signed in</title>"));
    assert!(!body.contains("ac-1"));
    assert!(!body.contains(&state_of(&url)));

    let out = read_line(&mut reader);
    assert!(child.wait().unwrap().success());
    grant.assert();

    assert_eq!(out["slot"], 1);
    assert_eq!(out["email"], "new@example.com");
    assert_eq!(out["created"], true);
    assert_eq!(out["movedFrom"], Value::Null);

    // The credential is stored, and the account named in the row.
    let stored = fx.stored(1);
    assert_eq!(stored["claudeAiOauth"]["accessToken"], "at-1");
    assert_eq!(stored["claudeAiOauth"]["refreshToken"], "rt-1");
    assert_eq!(stored["oauthAccount"]["emailAddress"], "new@example.com");
    let slots = fx.slots();
    assert_eq!(
        slots["providers"]["claude"]["slots"]["1"]["email"],
        "new@example.com"
    );
    // Not activated: a credential minted here is not the login the CLI holds.
    assert_eq!(slots["providers"]["claude"]["activeSlot"], Value::Null);
    // And nothing was written over Claude Code's own live login.
    assert!(!fx
        .claude_home
        .path()
        .join(".claude/.credentials.json")
        .exists());
}

#[test]
fn an_alias_and_a_chosen_slot_ride_through() {
    let fx = Fixture::new();
    fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200).body(GRANT);
    });

    let (url_line, mut child, mut reader) = fx.begin(&["--slot", "4", "--alias", "work"]);
    let url = url_line["url"].as_str().unwrap().to_string();
    callback(fx.port, &format!("code=ac-1&state={}", state_of(&url)));

    let out = read_line(&mut reader);
    assert!(child.wait().unwrap().success());
    assert_eq!(out["slot"], 4);
    let slots = fx.slots();
    assert_eq!(slots["providers"]["claude"]["slots"]["4"]["alias"], "work");
}

#[test]
fn a_refused_sign_in_is_the_providers_own_word() {
    let fx = Fixture::new();
    let grant = fx.server.mock(|when, then| {
        when.method(POST).path("/v1/oauth/token");
        then.status(200).body(GRANT);
    });

    let (url_line, mut child, mut reader) = fx.begin(&[]);
    let url = url_line["url"].as_str().unwrap().to_string();
    let page = callback(
        fx.port,
        &format!("error=access_denied&state={}", state_of(&url)),
    );
    assert!(page.contains("Sign-in failed"));
    assert!(!page.contains("<script>"));

    let out = read_line(&mut reader);
    assert!(!child.wait().unwrap().success());
    assert_eq!(out["error"]["code"], "invalid-input");
    assert!(out["error"]["message"]
        .as_str()
        .unwrap()
        .contains("access_denied"));
    // Nothing was redeemed, so nothing was stored.
    grant.assert_hits(0);
    assert!(!fx.home.path().join("slots.json").exists());
}

#[test]
fn a_port_already_held_is_refused_before_the_url_is_printed() {
    let fx = Fixture::new();
    let held = TcpListener::bind(("127.0.0.1", fx.port)).unwrap();

    let (line, mut child, _reader) = fx.begin(&[]);
    assert!(!child.wait().unwrap().success());
    // The refusal IS the first line: a browser window whose answer has nowhere
    // to land is worse than no window.
    assert_eq!(line["error"]["code"], "invalid-input");
    assert!(line["error"]["message"]
        .as_str()
        .unwrap()
        .contains(&format!("port {} is not free", fx.port)));
    drop(held);
}

#[test]
fn the_wait_gives_up() {
    let fx = Fixture::new();
    let (_url, mut child, mut reader) = fx.begin(&["--timeout", "1"]);
    let out = read_line(&mut reader);
    assert!(!child.wait().unwrap().success());
    assert!(out["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not completed in time"));
}

#[test]
fn gemini_has_no_browser_sign_in() {
    let fx = Fixture::new();
    let out = Command::new(assert_cmd::cargo::cargo_bin("swapd"))
        .args(["--json", "--provider", "gemini", "add-oauth"])
        .env("SWAPD_HOME", fx.home.path())
        .env("SWAPD_SECRETS", "file")
        .env("SWAPD_LIVE_STORE", "file")
        .env("HOME", fx.claude_home.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["error"]["code"], "unsupported");
}
