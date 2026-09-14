//! `swapd limit-hit <ident>` — record that the provider refused this account.
//!
//! swapd learns about spent quota from the usage endpoint, which budgets
//! requests per identity and so cannot be polled faster than
//! `poll_policy::MIN_INTERVAL_S`. A running CLI learns it from its own 429, at
//! once. This verb is how the second fact reaches swapd: the caller that saw
//! the refusal reports it, and every surface reads the account as spent from
//! the next pass on — no fetch, no waiting for the endpoint to catch up.
//!
//! It reports, it does not switch. The rule for what to do about a spent active
//! account (the threshold, the cooldown bypass, the anti-flap bar, the ranking)
//! belongs to `core::auto` and to `rotate`, and a second place deciding it is
//! how the two come to disagree. A supervised `swapd auto` is nudged separately
//! — a line on its stdin — so that it re-reads this the moment it lands rather
//! than on its next tick.

use crate::contract::ListPayload;
use crate::core::collect::{collect, CollectOpts};
use crate::core::poll_policy::parse_reset_ts;
use crate::core::slots;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;
use crate::secrets::slot_key;

/// `resets_at` is the refusal's own deadline in RFC 3339, when the caller can
/// read one off the error. Without it the stored 5-hour window's reset is used,
/// and with neither the report rests on the endpoint's lag horizon alone
/// (`usage_store::reported_limit_holds`).
pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    ident: &str,
    resets_at: Option<&str>,
) -> Result<ListPayload> {
    let id = driver.id();
    let resets_at = match resets_at {
        Some(raw) => Some(parse_reset_ts(Some(raw)).ok_or_else(|| {
            SwapdError::new(
                ErrorCode::InvalidInput,
                format!("--resets-at must be an RFC 3339 timestamp, got {raw:?}"),
            )
        })?),
        None => None,
    };

    let slots = slots::load(&ctx.home, id)?;
    let slot = resolve(&slots, id, ident)?;
    let meta = slots
        .slots
        .get(&slot)
        .expect("resolve named a slot in this table");
    ctx.store.record_reported_limit(
        &slot_key(id, slot),
        &meta.email,
        &meta.organization_uuid,
        resets_at,
    )?;

    // The same pass `list` makes, so the caller sees the account already
    // reading as spent in the board it knows how to render — and so a caller
    // that is about to ask for a switch decides on the post-report picture.
    let view = collect(ctx, driver, &CollectOpts::default())?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}
