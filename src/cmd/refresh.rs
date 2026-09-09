//! `swapd refresh` — fetch now, then report the same payload `list` does.

use crate::contract::ListPayload;
use crate::core::collect::{collect, CollectOpts};
use crate::core::slots::SlotsFile;
use crate::core::store::read_json;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// `--slot n` forces that one account past the serve TTL and its poll plan;
/// without it every account whose data is stale or whose plan is due is fetched.
pub fn run(ctx: &Ctx, driver: &dyn Driver, slot: Option<u32>) -> Result<ListPayload> {
    // Named before anything is fetched: a pass reads the live store and can
    // adopt a rotation from it, which a rejected command must not do.
    if let Some(slot) = slot {
        let slots: SlotsFile = read_json(&ctx.home.slots_file())?;
        let known = slots
            .providers
            .get(driver.id())
            .is_some_and(|p| p.slots.contains_key(&slot));
        if !known {
            return Err(SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("no slot {slot} for {}", driver.id()),
            ));
        }
    }
    let opts = match slot {
        Some(slot) => CollectOpts {
            force_slots: vec![slot],
            ..CollectOpts::default()
        },
        None => CollectOpts {
            all_stale: true,
            ..CollectOpts::default()
        },
    };
    let view = collect(ctx, driver, &opts)?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}
