//! `swapd auto` — run the switching daemon, and stream what it decides.
//!
//! The loop is deliberately thin: `core::auto::AutoEngine` owns every
//! decision, this owns the process. Three things live here because they are
//! about being a daemon rather than about switching accounts — the mutex that
//! admits one engine per data dir, the supervised-child stdin watch, and the
//! sleep between ticks.
//!
//! Idle cost between ticks is a blocked `recv_timeout` and, when supervised, a
//! thread blocked in `read`: no polling loop, no timer thread, nothing that
//! wakes to discover it has nothing to do.

use std::io::{Read as _, Write as _};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use crate::core::auto::AutoEngine;
use crate::core::events::{Emit, Event};
use crate::core::store::FileLock;
use crate::ctx::Ctx;
use crate::driver::claude::usage::format_ts;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result};

/// How long to wait for the engine mutex. Nonzero because a supervisor can
/// restart its daemon without waiting for the old process to exit, so the lock
/// is routinely still held for the first few hundred milliseconds.
const MUTEX_TIMEOUT: Duration = Duration::from_secs(5);

/// Set by a supervisor (the Infinitus app) that wants the daemon to die with
/// it: the parent holds the child's stdin open, so EOF means the parent is
/// gone. Without it an orphaned daemon would keep switching accounts under a
/// user who has quit the app.
const SUPERVISED_ENV: &str = "SWAPD_SUPERVISED";

/// Run until the process is stopped. Answers the exit code: `0` for a daemon
/// that ran, `1` for one that refused to start because another already holds
/// the mutex.
pub fn run(ctx: Ctx, driver: &dyn Driver, json: bool) -> Result<i32> {
    // The mutex, not `engine.lock`: two engines polling and switching one
    // credential store is never what the user meant, but a manual `swapd
    // switch` must keep working while the daemon runs — so the per-switch lock
    // is taken by `switch::perform` for the length of one switch and nothing
    // holds it across ticks.
    let mutex = match FileLock::acquire(&ctx.home.auto_lock_base(), MUTEX_TIMEOUT) {
        Ok(lock) => lock,
        Err(e) if e.code == ErrorCode::Locked => {
            let refused = Emit {
                ts: format_ts(ctx.now()).unwrap_or_default(),
                provider: driver.id().to_string(),
                event: Event::EngineRefused {
                    message: "another swapd auto engine is already running for this \
                              data dir; this one will not start"
                        .to_string(),
                },
            };
            print_event(&refused, json);
            return Ok(1);
        }
        Err(e) => return Err(e),
    };
    // A breadcrumb for whoever wonders which process holds it; the flock, not
    // this content, is the authority.
    mutex.note(&json!({ "pid": std::process::id() }).to_string());

    if std::env::var(SUPERVISED_ENV).as_deref() == Ok("1") {
        exit_on_stdin_eof();
    }

    // The channel is the sleep: `recv_timeout` blocks the thread outright, so
    // an idle daemon costs nothing between ticks. The sender is kept alive for
    // the loop's lifetime on purpose — dropping it would make every
    // `recv_timeout` return `Disconnected` at once and spin the loop.
    let (_wake, rx) = mpsc::channel::<()>();
    let mut engine = AutoEngine::new(ctx, driver, Box::new(move |emit| print_event(emit, json)));
    loop {
        let outcome = engine.tick();
        let delay = engine.schedule(outcome, rand::random::<f64>);
        match rx.recv_timeout(Duration::from_secs_f64(delay.max(0.0))) {
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            // Nothing sends today; either arm means the wake channel is gone,
            // which is not a state a daemon should keep looping in.
            _ => break,
        }
    }
    Ok(0)
}

/// Exit as soon as the supervising parent closes our stdin.
///
/// The thread blocks in `read` — it is not a poll — so a supervised daemon
/// costs exactly one sleeping thread more than an unsupervised one. Reading
/// (rather than waiting for the fd to close) also means a parent that writes
/// to us is simply ignored instead of being mistaken for EOF.
fn exit_on_stdin_eof() {
    std::thread::spawn(|| {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 256];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = std::io::stdout().flush();
        std::process::exit(0);
    });
}

/// One event, one line, flushed.
///
/// The flush is the contract, not a nicety: stdout is block-buffered when it
/// is a pipe, and a supervisor reading the stream one line at a time would
/// otherwise see nothing until the buffer filled — minutes of ticks later.
fn print_event(emit: &Emit, json: bool) {
    let line = if json {
        emit.to_json().to_string()
    } else {
        emit.human()
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}
