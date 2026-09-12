//! `swapd ignite <ident>` — make an account's usage window start.
//!
//! One minimal run of the provider's CLI in the slot's own profile, then a
//! forced re-fetch of that account: the window opens the moment the account is
//! first used, so the numbers a rotation plans against do not exist until
//! something spends a token as it. The live login is never touched.
//!
//! The usage endpoint lags the request that opened the window — a fetch made
//! right after the run still reads the account as cold — so the re-fetch is
//! repeated on a short backoff until the 5h window shows a reset ahead, and
//! the reply says whether it ever did.

use std::time::Duration;

use serde::Serialize;

use crate::contract::{ListPayload, ProviderView, UsageStatus, WindowKind};
use crate::core::collect::{collect, CollectOpts};
use crate::core::poll_policy::parse_reset_ts;
use crate::core::slots::{self, LOCK_TIMEOUT};
use crate::core::store::FileLock;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::claude::usage::format_ts;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// `list`'s payload plus what this run did, so one call both ignites the
/// account and hands back the board it changed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IgniteOutput {
    #[serde(flatten)]
    pub list: ListPayload,
    pub ignited: Ignited,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ignited {
    pub slot: u32,
    pub at: String,
    /// Whether the CLI rotated the slot's credential while it ran. Reported
    /// because the rotation is invisible otherwise: it happened inside the
    /// profile, and what swapd now stores is a generation the user never saw.
    pub rotated: bool,
    /// Whether the account's 5h window read as open — a reset later than now
    /// — by the last fetch. `false` means the run finished but the endpoint
    /// still showed the account cold after every wait, so a caller planning
    /// against the board must not take the run's time as the window's start.
    /// Absent for a provider that reports no 5h window: nothing to wait for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seen: Option<bool>,
}

/// Seconds between the forced re-fetches after the run. Measured: the window
/// was not visible 2 s after the request and was 6.5 min later; nothing
/// finer is known. Five fetches in about a minute stay well inside the usage
/// endpoint's budget of roughly thirty an hour per account.
const WINDOW_WAITS_S: [u64; 4] = [3, 7, 15, 30];

/// `Some(true)` when the slot's 5h window resets later than `now`, `Some(false)`
/// when it is reported but cold, `None` when there is nothing to wait for: the
/// account carries no 5h window (a provider without one) or the fetch did not
/// succeed, so the windows shown are a stale row's and a wait would not
/// change them.
fn window_seen(view: &ProviderView, slot: u32, now: f64) -> Option<bool> {
    let account = view
        .accounts
        .iter()
        .find(|a| a.slot == slot && a.usage_status == UsageStatus::Ok)?;
    let window = account
        .windows
        .iter()
        .find(|w| matches!(w.kind, WindowKind::FiveHour))?;
    Some(parse_reset_ts(window.resets_at.as_deref()).is_some_and(|reset| reset > now))
}

/// `wait` is how the verb sleeps between re-fetches: the real clock from
/// `main`, a recorder in tests.
pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    ident: &str,
    wait: &dyn Fn(Duration),
) -> Result<IgniteOutput> {
    let id = driver.id();
    // Resolved from the file, before anything is created or fetched: naming an
    // account must not depend on the network being up.
    let slots = slots::load(&ctx.home, id)?;
    let slot = resolve(&slots, id, ident)?;
    if !driver.capabilities().ignite {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{id} cannot ignite an account"),
        ));
    }
    // Asked before the profile is seeded and — more importantly — before the
    // login is refreshed: a refresh token is single-use, so spending one for a
    // run that cannot happen costs the account a generation for nothing.
    if driver.installed(&ctx.env).is_none() {
        return Err(SwapdError::new(
            ErrorCode::ProviderNotInstalled,
            format!("{id} is not installed"),
        ));
    }

    // The slot is in use from before its login is refreshed until the
    // rotation is persisted and committed (see `cmd::run`); a renumber skips
    // a slot whose lock is held.
    let session = FileLock::acquire_shared(&ctx.home.run_lock_base(id, slot), LOCK_TIMEOUT)?;
    let login = super::login_to_run(ctx, driver, slot)?;
    let outcome = driver.ignite(&ctx.env, slot, &login)?;

    // Persisted FIRST, whatever the exit code. The CLI refreshes its token
    // early in a run and can still fail afterwards, so a failed run routinely
    // carries a rotation — and the token it replaced is already spent, so
    // dropping it would leave the slot holding a credential whose next refresh
    // answers `invalid_grant` and reads as a dead account.
    let rotated = outcome.rotated.is_some();
    if let Some(login) = &outcome.rotated {
        super::persist_login(ctx, id, slot, login)?;
        // Only now. The profile's seed marker records what the STORE holds, so
        // moving it before the persist would put it ahead of the store, and the
        // next launch would read the profile as a slot re-pointed at another
        // account and seed the older generation over the rotation.
        driver.commit_profile(&ctx.env, slot, login)?;
    }
    drop(session);
    if outcome.exit_code != 0 {
        return Err(SwapdError::new(
            ErrorCode::Http,
            format!("igniter exited {}", outcome.exit_code),
        ));
    }

    // The point of the whole verb: the window the run just opened is only
    // visible in a fetch made after it, so these ignore the serve TTL and the
    // slot's poll plan. Repeated while the endpoint still reads the account as
    // cold: it lags the request, and one fetch straight after the run reports
    // the board from before it.
    let forced = || {
        collect(
            ctx,
            driver,
            &CollectOpts {
                force_slots: vec![slot],
                ..CollectOpts::default()
            },
        )
    };
    let mut view = forced()?;
    let mut seen = window_seen(&view, slot, ctx.now());
    for secs in WINDOW_WAITS_S {
        if seen != Some(false) {
            break;
        }
        wait(Duration::from_secs(secs));
        view = forced()?;
        seen = window_seen(&view, slot, ctx.now());
    }
    Ok(IgniteOutput {
        list: ListPayload {
            schema_version: output::SCHEMA_VERSION,
            providers: vec![view],
        },
        ignited: Ignited {
            slot,
            at: format_ts(ctx.now()).unwrap_or_default(),
            rotated,
            window_seen: seen,
        },
    })
}

pub fn print_human(out: &IgniteOutput) {
    match out.ignited.window_seen {
        Some(false) => println!("ignited slot {} — window not visible yet", out.ignited.slot),
        _ => println!("ignited slot {}", out.ignited.slot),
    }
    super::list::print_human(&out.list);
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::contract::Window;
    use crate::core::collect::tests::{login_for, one_slot, FakeDriver};

    /// The fake clock reads 2025-09-04T15:33:20Z; these sit either side of it.
    const AHEAD: &str = "2025-09-04T19:00:00Z";
    const BEHIND: &str = "2025-09-04T09:00:00Z";

    fn five_hour(resets_at: Option<&str>) -> Vec<Window> {
        vec![Window {
            kind: WindowKind::FiveHour,
            name: None,
            pct: 1.0,
            resets_at: resets_at.map(str::to_string),
            pace: None,
            used: None,
            limit: None,
            currency: None,
        }]
    }

    fn scoped() -> Vec<Window> {
        vec![Window {
            kind: WindowKind::Scoped,
            name: Some("model".to_string()),
            pct: 1.0,
            resets_at: Some(AHEAD.to_string()),
            pace: None,
            used: None,
            limit: None,
            currency: None,
        }]
    }

    /// Runs the verb against a driver whose fetches answer `answers` in order
    /// (the last one repeating), and hands back the reply plus the waits taken.
    fn ignite_with(answers: Vec<Vec<Window>>) -> (IgniteOutput, Vec<u64>, u32) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"))
            .usable("rt-1")
            .installed()
            .ignitable()
            .usage_answers(answers);
        let waits = Mutex::new(Vec::new());
        let out = run(&ctx, &driver, "1", &|d| {
            waits.lock().unwrap().push(d.as_secs())
        })
        .unwrap();
        let fetches = *driver.usages.lock().unwrap();
        (out, waits.into_inner().unwrap(), fetches)
    }

    #[test]
    fn a_window_still_cold_after_the_run_is_re_fetched_until_it_shows() {
        let (out, waits, fetches) = ignite_with(vec![
            five_hour(None),
            five_hour(None),
            five_hour(Some(AHEAD)),
        ]);
        assert_eq!(out.ignited.window_seen, Some(true));
        assert_eq!(waits, vec![3, 7]);
        assert_eq!(fetches, 3);
        let account = &out.list.providers[0].accounts[0];
        assert_eq!(account.windows[0].resets_at.as_deref(), Some(AHEAD));
    }

    #[test]
    fn a_window_already_open_is_answered_from_the_first_fetch() {
        let (out, waits, fetches) = ignite_with(vec![five_hour(Some(AHEAD))]);
        assert_eq!(out.ignited.window_seen, Some(true));
        assert!(waits.is_empty());
        assert_eq!(fetches, 1);
    }

    #[test]
    fn a_window_that_never_shows_exhausts_the_waits_and_says_so() {
        // A reset in the past reads as cold too: the endpoint's last window
        // ended and the run has not shown up as a new one.
        let (out, waits, fetches) = ignite_with(vec![five_hour(Some(BEHIND))]);
        assert_eq!(out.ignited.window_seen, Some(false));
        assert_eq!(waits, vec![3, 7, 15, 30]);
        assert_eq!(fetches, 5);
    }

    #[test]
    fn a_provider_without_a_five_hour_window_does_not_wait() {
        let (out, waits, fetches) = ignite_with(vec![scoped()]);
        assert_eq!(out.ignited.window_seen, None);
        assert!(waits.is_empty());
        assert_eq!(fetches, 1);
    }

    #[test]
    fn the_reply_carries_window_seen_in_camel_case_and_omits_it_when_unknown() {
        let (out, _, _) = ignite_with(vec![five_hour(Some(AHEAD))]);
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["ignited"]["windowSeen"], true);
        let (out, _, _) = ignite_with(vec![scoped()]);
        let json = serde_json::to_value(&out).unwrap();
        assert!(json["ignited"].get("windowSeen").is_none(), "{json}");
    }
}
