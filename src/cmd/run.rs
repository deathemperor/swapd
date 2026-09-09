//! `swapd run <ident> -- <args>` — run the provider's CLI as one account.
//!
//! The account's own run profile, not the live login: the CLI is pointed at a
//! config directory of its own, so a run as slot 3 changes nothing about which
//! account the next plain `claude` will be. Everything after `--` reaches the
//! CLI untouched, stdio is the user's, and the exit code is the child's.

use std::process::{Command, ExitStatus};

use crate::core::slots;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

/// Answers the child's exit code; `main` exits with it.
pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str, args: &[String]) -> Result<i32> {
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
    let binary = driver.installed().ok_or_else(|| {
        SwapdError::new(
            ErrorCode::ProviderNotInstalled,
            format!("{id} is not installed"),
        )
    })?;

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
    if let Some(read_back) = &profile.read_back {
        if let Some(rotated) = read_back()? {
            super::persist_login(ctx, id, slot, &rotated)?;
        }
    }
    Ok(exit_code(&status))
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
