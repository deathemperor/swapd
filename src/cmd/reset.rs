//! `swapd reset <ident>` — spend one of an account's banked limit resets.
//!
//! The provider banks a few resets per account (Claude's `/reset`, program
//! `cedar_ember`); `list` reports them on the row as `resets`. This verb
//! spends the one the provider names next, as that account, without touching
//! the live login — the same way `ignite` runs as a slot.
//!
//! The bank is read fresh before the claim rather than off the store: a reset
//! is also spendable by the CLI itself, and a stored count can be minutes old.
//! The provider's own refusal (`already_used`, `not_limited`, `cooldown`,
//! `ineligible`, `unavailable`) comes back as the error's message.

use crate::contract::{ListPayload, ResetHoldReason};
use crate::core::collect::{collect, CollectOpts};
use crate::core::refresh::{refresh_slot, Refreshed};
use crate::core::slots;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::{Driver, DriverError, Login, Usage};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str) -> Result<ListPayload> {
    let id = driver.id();
    let slots = slots::load(&ctx.home, id)?;
    let slot = resolve(&slots, id, ident)?;
    if !driver.capabilities().reset {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{id} banks no limit resets"),
        ));
    }
    let meta = slots
        .slots
        .get(&slot)
        .expect("resolve named a slot in this table");

    let mut login = super::login_to_run(ctx, driver, slot)?;
    let usage = usage_refreshing(ctx, driver, slot, &mut login)?;
    let bank = usage
        .resets
        .as_ref()
        .and_then(|bank| bank.view(ctx.now()))
        .ok_or_else(|| {
            SwapdError::new(
                ErrorCode::InvalidInput,
                format!("slot {slot} has no banked reset"),
            )
        })?;
    if let Some(hold) = &bank.hold {
        let why = match hold.reason {
            ResetHoldReason::NotAtLimit => {
                "it spends only once the account is at a limit".to_string()
            }
            ResetHoldReason::Cooldown => match &hold.until {
                Some(until) => format!("a reset was spent recently; the next may be at {until}"),
                None => "a reset was spent recently".to_string(),
            },
            ResetHoldReason::Blocked => "the provider names no spendable grant".to_string(),
        };
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("slot {slot}'s reset cannot be spent now: {why}"),
        ));
    }
    let grant = bank
        .next_grant_id
        .expect("a bank without a hold names its next grant");

    // The slot's own identity, read at `add`; the profile only when it was
    // captured without one.
    let organization = if meta.organization_uuid.is_empty() {
        driver.identity(&login)?.organization_uuid
    } else {
        meta.organization_uuid.clone()
    };
    let outcome = driver.reset(&login, &organization, &grant)?;
    if outcome.result != "reset" {
        return Err(SwapdError::new(
            ErrorCode::Http,
            format!("the provider refused the reset: {}", outcome.result),
        ));
    }

    // The board after the reset: the windows it cleared are only visible in
    // a fetch made after it, so this one ignores the serve TTL.
    let view = collect(
        ctx,
        driver,
        &CollectOpts {
            force_slots: vec![slot],
            ..CollectOpts::default()
        },
    )?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}

/// One usage read as `login`, refreshing it once under the slot's refresh
/// lock when the driver says it is (or the server finds it) expired.
/// `login_to_run` only refreshes past the stated expiry; the driver keeps
/// its own buffer ahead of it.
fn usage_refreshing(ctx: &Ctx, driver: &dyn Driver, slot: u32, login: &mut Login) -> Result<Usage> {
    match driver.usage(login) {
        Err(DriverError::NeedsRefresh) => {}
        other => return other.map_err(SwapdError::from),
    }
    match refresh_slot(ctx, driver, slot, login)? {
        Refreshed::Rotated(refreshed) | Refreshed::Adopted(refreshed) => *login = refreshed,
        Refreshed::Failed(DriverError::TokenDead) => return Err(SwapdError::new(
            ErrorCode::TokenDead,
            format!(
                "slot {slot}'s login is expired and its refresh token was rejected; log in again"
            ),
        )),
        Refreshed::Failed(e) => return Err(e.into()),
    }
    driver.usage(login).map_err(SwapdError::from)
}
