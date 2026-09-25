//! `swapd auto` as a process: the daemon mutex, the supervised exit and the
//! wake another process sends.
//!
//! The engine's decisions are unit-tested in `src/core/auto.rs`, where a fake
//! driver and an injected clock can drive a tick directly. What can only be
//! tested out here is what a SECOND process sees (the mutex), what happens
//! when the parent goes away (the supervised stdin watch) and what a verb run
//! elsewhere does to a sleeping daemon (the wake file) — so these three tests
//! are the only ones that pay for spawning a binary.
//!
//! Same hermetic contract as the other suites: a temp swapd home, a temp
//! `$HOME`, file-backed secrets and live store, every upstream URL pointed at
//! nothing reachable, and `CLAUDE_*` removed so no developer's real config dir
//! leaks in. A board with no accounts polls nothing, so no request is ever
//! made. Nothing here sets a process-wide env var.

use std::io::{BufRead, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt as _;
use serde_json::Value;
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
            .env("SWAPD_URL_ANTHROPIC_API", "http://127.0.0.1:1")
            .env("SWAPD_URL_PLATFORM", "http://127.0.0.1:1")
            .env("HOME", self.claude_home.path())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR");
        cmd
    }

    /// Start a daemon and wait for its first event, so the caller knows the
    /// mutex is held and the stream is live.
    fn start(&self, supervised: bool) -> (Child, Value) {
        let mut cmd = self.cmd();
        cmd.args(["auto", "--json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if supervised {
            cmd.env("SWAPD_SUPERVISED", "1");
        }
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let first = lines
            .next()
            .expect("the daemon must emit its first event before it sleeps")
            .unwrap();
        (child, serde_json::from_str(&first).unwrap())
    }

    /// Start an unsupervised daemon and keep reading its stream on a thread:
    /// every event, in order, as it is written. The reader ends with the pipe.
    fn start_streaming(&self) -> (Child, mpsc::Receiver<Value>) {
        let mut child = self
            .cmd()
            .args(["auto", "--json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (events, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(event) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if events.send(event).is_err() {
                    break;
                }
            }
        });
        (child, rx)
    }
}

/// The next event of `kind` on the stream, or `None` once `within` has passed.
fn next_event(events: &mpsc::Receiver<Value>, kind: &str, within: Duration) -> Option<Value> {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match events.recv_timeout(left) {
            Ok(event) if event["event"] == kind => return Some(event),
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

fn wait_for_exit(child: &mut Child, within: Duration) -> Option<(i32, Duration)> {
    let start = Instant::now();
    let deadline = start + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some((status.code().unwrap_or(-1), start.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// How long the EOF exit is given before the test calls it broken.
///
/// Generous on purpose. What is under test is that EOF ends the daemon at all
/// — a watcher that never fires never exits, so any finite deadline catches
/// the bug this guards. "Promptly" is a scheduling property of the runner, not
/// of the code: a 2 s deadline failed once on a loaded macos-14 runner while
/// the sibling test's daemons were starting, and the rerun of the same sha
/// passed everywhere (#19). So the deadline answers the question the test is
/// for, and the time actually taken rides out as a measured note.
const EXIT_DEADLINE: Duration = Duration::from_secs(10);

/// What the exit should take on an unloaded machine; over this the test still
/// passes and says how long it took, so a real regression shows up in the log
/// before it becomes a flake.
const EXIT_PROMPT: Duration = Duration::from_secs(2);

/// A supervisor holds the daemon's stdin open; closing it is how it says it is
/// gone. An orphaned daemon would keep switching accounts under a user who has
/// quit the app, so EOF is an exit — with a zero status, because being told to
/// stop is not a failure.
#[test]
fn supervised_exits_on_stdin_eof() {
    let fixture = Fixture::new();
    let (mut child, first) = fixture.start(true);

    // The stream's shape, from a real process: one JSON object per line,
    // flushed as it goes (this line arrived while the daemon was still
    // running, which a block-buffered stdout would not have delivered).
    assert_eq!(first["schemaVersion"], 1);
    assert_eq!(first["event"], "poll");
    assert_eq!(first["provider"], "claude");
    assert!(first["ts"].as_str().unwrap().ends_with('Z'));

    drop(child.stdin.take());
    let exit = wait_for_exit(&mut child, EXIT_DEADLINE);
    if exit.is_none() {
        let _ = child.kill();
    }
    let (code, took) = exit.unwrap_or_else(|| {
        panic!("EOF on stdin must end the daemon; still running after {EXIT_DEADLINE:?}")
    });
    assert_eq!(
        code, 0,
        "EOF on stdin must end the daemon with a zero status"
    );
    if took > EXIT_PROMPT {
        // Straight to the fd, not `eprintln!`: libtest captures the print
        // macros for a passing test, and a note nobody reads is not a note.
        let _ = writeln!(
            std::io::stderr(),
            "note: the EOF exit took {took:?} (over the {EXIT_PROMPT:?} it takes idle)"
        );
    }
}

/// Two engines polling and switching one credential store is never what the
/// user meant: the second refuses, says so on the stream (not as an error
/// envelope — a supervisor reading events must not have to parse two shapes),
/// and exits 1.
#[test]
fn second_auto_is_refused() {
    let fixture = Fixture::new();
    let (mut first, _) = fixture.start(false);

    let second = fixture.cmd().args(["auto", "--json"]).output().unwrap();
    let refused: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(refused["event"], "engine-refused");
    assert_eq!(refused["schemaVersion"], 1);
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("already running"),
        "{refused}"
    );
    assert_eq!(second.status.code(), Some(1));

    // The first is still running, and still holding the mutex.
    assert_eq!(first.try_wait().unwrap(), None);
    first.kill().unwrap();
    first.wait().unwrap();
}

/// How long a wake is given to reach the daemon. The watcher reads the wake
/// file once a second, so a few seconds is generous — but the idle sleep it
/// cuts short is about a minute, and the assertion below checks that, so a
/// poll inside this deadline can only be the wake.
const WAKE_DEADLINE: Duration = Duration::from_secs(10);

/// How long the first tick's events are given to arrive.
const STREAM_DEADLINE: Duration = Duration::from_secs(10);

/// A verb that changed the daemon's picture wakes it, from any process. The
/// daemon runs unsupervised under the menu-bar helper's launch agent, so the
/// stdin line is not how the app's `add-oauth` or the server's `limit-hit`
/// reach it — the wake file is (`core::wake`). An idle tick sleeps about a
/// minute; the next poll arriving within seconds of the nudge is the proof.
#[test]
fn a_store_change_wakes_a_sleeping_daemon() {
    let fixture = Fixture::new();
    let (mut child, events) = fixture.start_streaming();
    let first_sleep = next_event(&events, "sleep", STREAM_DEADLINE)
        .expect("the first tick must end in a sleep event");
    let idle_s = first_sleep["seconds"].as_f64().unwrap();
    assert!(
        idle_s > 2.0 * WAKE_DEADLINE.as_secs_f64(),
        "the idle sleep ({idle_s}s) must be long enough to tell a wake from a tick"
    );

    // `config set` in another process: a policy knob the next tick reads.
    let set = fixture
        .cmd()
        .args(["config", "set", "claude.threshold", "80"])
        .output()
        .unwrap();
    assert!(
        set.status.success(),
        "config set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );

    let woke = next_event(&events, "poll", WAKE_DEADLINE);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        woke.is_some(),
        "a store change must wake the daemon within {WAKE_DEADLINE:?} (it was asleep for {idle_s}s)"
    );
}
