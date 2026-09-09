//! `swapd prefer <ident> on|off` — pin an account the rotation lands on first.
//!
//! The per-slot half of `settings.json`'s `<provider>.preferred` list: the
//! ranking honours either (`core::switch::is_preferred`), so a pin can be a
//! property of the account or a line in the policy file.

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
                format!("prefer expects 'on' or 'off', got '{other}'"),
            ))
        }
    };
    if wanted && !driver.capabilities().prefer {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{id} has no notion of a preferred account"),
        ));
    }
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let target = resolve(slots, id, ident)?;
        let slot = slots
            .slots
            .get_mut(&target)
            .expect("resolve named a slot in this table");
        if slot.preferred == wanted {
            return Ok(false);
        }
        slot.preferred = wanted;
        Ok(true)
    })
}
