//! `swapd auto` — run the switching daemon, and stream what it decides.
//!
//! The loop is deliberately thin: `core::auto::AutoEngine` owns every
//! decision, this owns the process. Four things live here because they are
//! about being a daemon rather than about switching accounts — the mutex that
//! admits one engine per data dir, the supervised-child stdin watch, the
//! wake-file watch, and the sleep between ticks.
//!
//! Idle cost between ticks is a blocked `recv_timeout`, one thread that reads
//! the wake file once a second (`core::wake` — the one poll here, and the
//! price of a wake any process can send without holding this one's stdin)
//! and, when supervised, a thread blocked in `read`.

use std::io::{BufRead as _, Write as _};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use crate::core::auto::AutoEngine;
use crate::core::events::{Emit, Event};
use crate::core::store::FileLock;
use crate::core::wake;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result};
use crate::timefmt::format_ts;

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

    // The channel is the sleep: `recv_timeout` blocks the thread outright, so
    // an idle daemon costs nothing between ticks. The sender is kept alive for
    // the loop's lifetime on purpose — dropping it would make every
    // `recv_timeout` return `Disconnected` at once and spin the loop.
    let (wakes, rx) = mpsc::channel::<()>();
    if ctx.env.vars.get(SUPERVISED_ENV).map(String::as_str) == Some("1") {
        watch_stdin(wakes.clone());
    }
    // Any process that changes the store can wake the daemon, not only one
    // holding its stdin: `add` at a terminal, `add-oauth` from the app,
    // `limit-hit` from the server — and the daemon the menu-bar helper runs
    // under launchd has no supervisor at all. Same channel, so a burst of
    // nudges collapses the way a burst of lines does.
    wake::watch(
        ctx.home.auto_wake_file(),
        wake::POLL_INTERVAL,
        wakes.clone(),
    );

    let mut engine = AutoEngine::new(ctx, driver, Box::new(move |emit| print_event(emit, json)));
    loop {
        let outcome = engine.tick();
        let delay = engine.schedule(outcome, rand::random::<f64>);
        match rx.recv_timeout(Duration::from_secs_f64(delay.max(0.0))) {
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            // Woken early: a supervisor's line, or a verb's nudge through the
            // wake file. Whatever the sender knew is already in the store
            // (`swapd limit-hit`, `swapd add`), so the wake carries nothing
            // but "look now" — and a burst of them is one tick, not one each.
            Ok(()) => {
                drain(&rx);
                continue;
            }
            // The outer sender above outlives the loop, so this cannot be the
            // ordinary end of the stdin watcher; it means the channel itself is
            // gone, which is not a state a daemon should keep looping in.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(0)
}

/// Discard wakes that queued while a tick ran.
///
/// A supervisor reporting a refusal on four accounts at once wants one
/// re-evaluation, not four: the tick reads the whole store either way, and each
/// extra pass costs a live-login read for nothing.
fn drain(rx: &mpsc::Receiver<()>) {
    while rx.try_recv().is_ok() {}
}

/// Read the supervising parent's stdin: each line is "re-evaluate now", and
/// EOF — the parent gone — exits the process.
///
/// The thread blocks in `read` — it is not a poll — so a supervised daemon
/// costs exactly one sleeping thread more than an unsupervised one. A line
/// carries nothing: whatever the parent knows it has already written to the
/// store (`swapd limit-hit`), and the tick reads the store. That keeps this end
/// of the pipe a single byte's worth of protocol, and leaves a parsed command
/// line free to mean something later without breaking a parent that just writes
/// a newline.
fn watch_stdin(wake: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            // A send that fails means the loop is gone, which EOF handles; a
            // read error is the pipe breaking, same as EOF.
            if line.is_err() || wake.send(()).is_err() {
                break;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst of wakes is one re-evaluation, not one each: the tick reads the
    /// whole store, so by the time it runs the second line has nothing left to
    /// tell it.
    #[test]
    fn queued_wakes_collapse_into_one_tick() {
        let (wake, rx) = mpsc::channel::<()>();
        for _ in 0..4 {
            wake.send(()).unwrap();
        }

        // What the loop does: take the wake that ended the sleep, then drop the
        // ones that arrived behind it.
        assert!(rx.recv_timeout(Duration::from_secs(0)).is_ok());
        drain(&rx);

        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
}
