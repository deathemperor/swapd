//! The verbs. Each `run` returns the payload its `--json` form emits, so the
//! human renderer and the machine one describe exactly the same pass.

pub mod add;
pub mod add_token;
pub mod alias;
pub mod config;
pub mod export;
pub mod history;
pub mod hold;
pub mod icon;
pub mod import;
pub mod list;
pub mod notify;
pub mod prefer;
pub mod refresh;
pub mod remove;
pub mod reorder;
pub mod rotate;
pub mod switch;

use crate::contract::ListPayload;
use crate::core::collect::{collect, CollectOpts};
use crate::core::slots::{self, ProviderSlots};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;
use crate::output;

/// Edit one provider's slot table under `slots.json`'s lock, then report the
/// same payload `list` does — every slots.json editor (`alias`, `icon`,
/// `prefer`, `hold`, `unhold`, `reorder`) is this plus its own `mutate`.
///
/// `<ident>` is resolved *inside* `mutate`, against the table as it stands
/// under the lock: resolving outside and writing inside is a check-then-act a
/// concurrent `remove` or `reorder` invalidates. `mutate` answers `false` when
/// it changed nothing, which skips the write.
pub fn edit_slots(
    ctx: &Ctx,
    driver: &dyn Driver,
    mutate: impl FnOnce(&mut ProviderSlots) -> Result<bool>,
) -> Result<ListPayload> {
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry(driver.id().to_string()).or_default();
        Ok((mutate(provider)?, ()))
    })?;
    // The same collection pass `list` makes, so the caller sees the edit in the
    // board it already knows how to render.
    let view = collect(ctx, driver, &CollectOpts::default())?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}
