//! `swapd refresh` — fetch now, then report the same payload `list` does.

use crate::contract::ListPayload;
use crate::core::collect::{collect, CollectOpts};
use crate::ctx::Ctx;
use crate::driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// `--slot n` forces that one account past the serve TTL and its poll plan;
/// without it every account whose data is stale or whose plan is due is fetched.
pub fn run(ctx: &Ctx, provider: &str, slot: Option<u32>) -> Result<ListPayload> {
    let driver = driver::by_id(provider).ok_or_else(|| {
        SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown provider: {provider}"),
        )
    })?;
    let opts = match slot {
        Some(slot) => CollectOpts {
            force_slots: vec![slot],
            all_stale: false,
        },
        None => CollectOpts {
            force_slots: Vec::new(),
            all_stale: true,
        },
    };
    let view = collect(ctx, driver.as_ref(), &opts)?;
    if let Some(slot) = slot {
        if !view.accounts.iter().any(|a| a.slot == slot) {
            return Err(SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("no slot {slot} for {provider}"),
            ));
        }
    }
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}
