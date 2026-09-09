//! `swapd run <ident> -- <args>` — run the provider's CLI as one account.
//!
//! The account's own run profile, not the live login: the CLI is pointed at a
//! config directory of its own, so a run as slot 3 changes nothing about which
//! account the next plain `claude` will be. Everything after `--` reaches the
//! CLI untouched, stdio is the user's, and the exit code is the child's.
//!
//! With one exception, and it is the whole reason the exception exists: the
//! account that is *already* the live login gets no profile at all (cswap's
//! same-account fast path, `session.py:536-551`). Two copies of one account
//! drift the moment the server rotates its refresh token — the profile's
//! rotation spends the generation `~/.claude` is still holding, and the user's
//! next plain `claude` is logged out with no explanation.

use std::io::IsTerminal;
use std::process::{Command, ExitStatus};

use crate::core::slots::{self, ProviderSlots};
use crate::core::switch::{match_slot, resolve};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

/// Answers the child's exit code; `main` exits with it.
pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    ident: &str,
    args: &[String],
    json: bool,
) -> Result<i32> {
    let id = driver.id();
    let slots = slots::load(&ctx.home, id)?;
    let slot = resolve(&slots, id, ident)?;
    if !driver.capabilities().run {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{id} cannot run an account"),
        ));
    }
    // Before the profile is built and before the login is refreshed: a refresh
    // token is single-use, and spending one for a run that cannot happen costs
    // the account a generation for nothing.
    let binary = driver.installed(&ctx.env).ok_or_else(|| {
        SwapdError::new(
            ErrorCode::ProviderNotInstalled,
            format!("{id} is not installed"),
        )
    })?;

    // The fast path is decided BEFORE the login is read, let alone refreshed:
    // refreshing the stored copy of the account that is currently live would
    // spend the very token `~/.claude` holds, which is the drift this path
    // exists to avoid.
    if let Some(dir) = ambient_config_dir(ctx) {
        // The ambient config dir is not the default login's, so "what a plain
        // `claude` would do here" is not the live login and the fast path
        // cannot reason about it. Say so instead: the profile is about to
        // replace the user's own setting for this launch (`session.py:528-536`).
        eprintln!(
            "warning: CLAUDE_CONFIG_DIR is set ({dir}); slot {slot}'s profile \
             overrides it for this launch"
        );
    } else if is_live_account(ctx, driver, &slots, slot) {
        if !json {
            note(&format!(
                "slot {slot} is already the live login; running the CLI directly, \
                 without a second copy of its credential"
            ));
        }
        // The ambient environment, deliberately untouched: this run is what
        // typing the CLI's own name would have done, so there is no profile to
        // seed, no `CLAUDE_CONFIG_DIR` to set and no rotation to read back —
        // the CLI rotates its live credential in place, where it belongs.
        let status = Command::new(&binary).args(args).status()?;
        return Ok(exit_code(&status));
    }

    let login = super::login_to_run(ctx, driver, slot)?;
    let profile = driver.run_profile(&ctx.env, slot, &login)?;

    let mut command = Command::new(&binary);
    command
        .args(args)
        // Exactly the environment swapd was started with, plus the profile's
        // overrides — never a merge with whatever the child would inherit.
        .env_clear()
        .envs(&ctx.env.vars)
        .envs(profile.env.iter().cloned());
    // Applied last: an exported API key makes the CLI bypass account OAuth
    // entirely, which would silently run this command as somebody else.
    for key in &profile.unset {
        command.env_remove(key);
    }
    // stdio is inherited and the working directory is the user's: this is the
    // user's own session, wearing one account.
    let status = command.status()?;

    // On ANY exit, clean or not. The CLI refreshes its token as it runs and
    // writes the new generation into the profile, where nothing else would ever
    // see it — and the one it replaced is already spent.
    //
    // Reported, never raised: the child is gone and its code is the answer to
    // the command the user actually gave. Turning a failure to *store* the
    // rotation into `exit 1` would lie about the run and hide the code a script
    // is branching on, so the loss is said out loud on stderr instead.
    if let Some(read_back) = &profile.read_back {
        let stored = read_back()
            .map_err(SwapdError::from)
            .and_then(|rotated| match rotated {
                Some(rotated) => super::persist_login(ctx, id, slot, &rotated),
                None => Ok(()),
            });
        if let Err(e) = stored {
            // Facts only, and deliberately no "try again": the read-back has
            // already advanced the profile's seed marker to the new generation,
            // so the next run of this slot sees a marker that disagrees with the
            // login it is handed and re-seeds the stored (older) copy over the
            // rotation. Telling the user to re-run would be telling them to
            // destroy it.
            eprintln!(
                "warning: the CLI rotated slot {slot}'s login and swapd could not store it \
                 ({e}); the store is now one generation behind the profile at {}, and the \
                 next run of this slot will re-seed the stored one over it",
                profile.dir.display()
            );
        }
    }
    Ok(exit_code(&status))
}

/// The `CLAUDE_CONFIG_DIR`-style override the user already has exported, if any.
///
/// Named generically on purpose at the call site: what it means is "the ambient
/// environment already selects a config dir of its own", which is the one state
/// in which the live login is not what a plain CLI run would use.
fn ambient_config_dir(ctx: &Ctx) -> Option<&str> {
    ctx.env
        .vars
        .get("CLAUDE_CONFIG_DIR")
        .map(String::as_str)
        .filter(|dir| !dir.is_empty())
}

/// Whether slot `slot` is the account the CLI is *already* logged in as.
///
/// The collector's own rule (`switch::match_slot`): identity first, fingerprint
/// for a credential that carries none. Any failure to read the live login
/// answers "no" — the fast path must never be taken on a guess, and the profile
/// route is correct for every account, including this one.
fn is_live_account(ctx: &Ctx, driver: &dyn Driver, slots: &ProviderSlots, slot: u32) -> bool {
    match driver.read_live(&ctx.env) {
        Ok(live) if !live.bytes.trim().is_empty() => match_slot(driver, slots, &live) == Some(slot),
        _ => false,
    }
}

/// An aside on stderr, dimmed when a terminal is there to render it. It is
/// about the run rather than of it, and the child owns stdout.
fn note(message: &str) {
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[2m{message}\x1b[0m");
    } else {
        eprintln!("{message}");
    }
}

/// The child's code, or the shell's convention for a signal (128 + signum) when
/// it was killed — so `$?` after a Ctrl-C reads the same as it would with no
/// swapd in the middle.
#[cfg(unix)]
fn exit_code(status: &ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(not(unix))]
fn exit_code(status: &ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}
