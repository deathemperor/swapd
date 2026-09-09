//! `swapd ignite <ident>` — make an account's usage window start.
//!
//! One minimal run of the provider's CLI in the slot's own profile, then a
//! forced re-fetch of that account: the window opens the moment the account is
//! first used, so the numbers a rotation plans against do not exist until
//! something spends a token as it. The live login is never touched.

use serde::Serialize;

use crate::contract::ListPayload;
use crate::core::collect::{collect, CollectOpts};
use crate::core::slots;
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
}

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str) -> Result<IgniteOutput> {
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
    }
    if outcome.exit_code != 0 {
        return Err(SwapdError::new(
            ErrorCode::Http,
            format!("igniter exited {}", outcome.exit_code),
        ));
    }

    // The point of the whole verb: the window the run just opened is only
    // visible in a fetch made after it, so this one ignores the serve TTL and
    // the slot's poll plan.
    let view = collect(
        ctx,
        driver,
        &CollectOpts {
            force_slots: vec![slot],
            ..CollectOpts::default()
        },
    )?;
    Ok(IgniteOutput {
        list: ListPayload {
            schema_version: output::SCHEMA_VERSION,
            providers: vec![view],
        },
        ignited: Ignited {
            slot,
            at: format_ts(ctx.now()).unwrap_or_default(),
            rotated,
        },
    })
}

pub fn print_human(out: &IgniteOutput) {
    println!("ignited slot {}", out.ignited.slot);
    super::list::print_human(&out.list);
}
