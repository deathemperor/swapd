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

use crate::core::slots::{self, ProviderSlots, LOCK_TIMEOUT};
use crate::core::store::FileLock;
use crate::core::switch::{match_slot, resolve};
use crate::ctx::Ctx;
use crate::driver::{Driver, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::secrets::slot_key;

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

    // The KIND of the stored credential is settled before either path, which
    // is what makes it a guard (cswap calls `_ensure_not_api_key` right above
    // its fast path, `session.py:526`). A managed `sk-ant-api…` key cannot run
    // a session in either shape — but an API-key slot carrying the live
    // account's address matches the identity test below, and taking the fast
    // path would launch the CLI as that live OAuth credential: a different
    // account than the one the user named. Read, never refreshed: this asks
    // what is stored, and spending a refresh token to answer it would be
    // absurd.
    if let Some(login) = ctx
        .secrets
        .get(&slot_key(id, slot))?
        .map(|bytes| Login { bytes })
    {
        if driver.is_api_key(&login) {
            return Err(SwapdError::new(
                ErrorCode::Unsupported,
                format!("slot {slot} holds a managed API key; api-key logins cannot run"),
            ));
        }
    }

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

    // Marks the slot as in use from before its login is refreshed until the
    // child's rotation is read back: a renumber (`core::compact`) leaves a
    // slot whose lock is held where it is, so neither the refresh's persist
    // nor the read-back lands under a number that no longer names the account.
    let _session = FileLock::acquire_shared(&ctx.home.run_lock_base(id, slot), LOCK_TIMEOUT)?;
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
        match read_back().map_err(SwapdError::from) {
            // Distinct from the persist failure below: here the read itself
            // failed, so whether the CLI rotated anything is unknown. Say only
            // that much.
            Err(e) => eprintln!(
                "warning: swapd could not read slot {slot}'s login back out of the profile \
                 at {} ({}); if the CLI rotated it, that generation is still there and the \
                 next run reads it again",
                profile.dir.display(),
                e.message
            ),
            Ok(None) => {}
            Ok(Some(rotated)) => match super::persist_login(ctx, id, slot, &rotated) {
                Err(e) => stranded(slot, &profile.dir, &e.message),
                // Only after the store has it: the marker says what the STORE
                // holds, and a marker ahead of the store is what makes the next
                // launch seed the older generation over the rotation.
                Ok(()) => {
                    if let Err(e) = driver.commit_profile(&ctx.env, slot, &rotated) {
                        eprintln!(
                            "warning: slot {slot}'s rotated login was stored, but the profile \
                             at {} could not be marked ({e}); the next run re-seeds the stored \
                             copy, which is that same rotation",
                            profile.dir.display()
                        );
                    }
                }
            },
        }
    }
    Ok(exit_code(&status))
}

/// Say that the CLI's rotation is in the profile and nowhere else.
///
/// It is not lost: the marker still names the generation the store holds, so the
/// profile is not re-seeded and the next run reads the same rotation back —
/// which is why re-running is the right advice here and not a way to destroy it.
fn stranded(slot: u32, dir: &std::path::Path, why: &str) {
    eprintln!(
        "warning: the CLI rotated slot {slot}'s login and swapd could not store it ({why}); \
         the profile at {} still holds it — run `swapd run {slot}` again to pick it up",
        dir.display()
    );
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
///
/// Read under `engine.lock`, like every other live read: a torn pair mid-swap
/// (keychain = B, config = A) would answer "slot A is live" and run the child
/// as account B. A switch in flight means "no" and the profile route, which is
/// right whatever lands.
fn is_live_account(ctx: &Ctx, driver: &dyn Driver, slots: &ProviderSlots, slot: u32) -> bool {
    let Ok(_engine) = FileLock::acquire(&ctx.home.engine_lock_base(), slots::LOCK_TIMEOUT) else {
        return false;
    };
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
