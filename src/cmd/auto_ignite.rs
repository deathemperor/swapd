//! `swapd auto-ignite <ident> on|off` — keep an account's 5h window running.
//!
//! The flag the daemon reads (`core::auto`, "auto-ignite"): a flagged account
//! whose 5h window has gone cold is ignited on the next tick, so a switch onto
//! it lands on a clock that is already ticking. Each ignite is one short run
//! as that account (`cmd::ignite`), which costs it a little weekly quota.

use crate::contract::ListPayload;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str, state: &str) -> Result<ListPayload> {
    let id = driver.id();
    let wanted = match state.trim().to_lowercase().as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                format!("auto-ignite expects 'on' or 'off', got '{other}'"),
            ))
        }
    };
    if wanted && !driver.capabilities().ignite {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{id} cannot ignite an account"),
        ));
    }
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let target = resolve(slots, id, ident)?;
        let slot = slots
            .slots
            .get_mut(&target)
            .expect("resolve named a slot in this table");
        if slot.auto_ignite == wanted {
            return Ok(false);
        }
        slot.auto_ignite = wanted;
        Ok(true)
    })
}
