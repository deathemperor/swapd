//! `swapd icon <ident> <emoji|--unset>` — a slot's icon.

use crate::contract::ListPayload;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    ident: &str,
    icon: Option<&str>,
    unset: bool,
) -> Result<ListPayload> {
    let id = driver.id();
    let wanted: Option<String> = match (icon, unset) {
        (Some(icon), false) => {
            let icon = icon.trim();
            if icon.is_empty() {
                return Err(invalid("an icon cannot be empty; pass --unset to clear it"));
            }
            Some(icon.to_string())
        }
        (None, true) => None,
        _ => {
            return Err(invalid(
                "give an icon or pass --unset, not both and not neither",
            ))
        }
    };
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let target = resolve(slots, id, ident)?;
        let slot = slots
            .slots
            .get_mut(&target)
            .expect("resolve named a slot in this table");
        if slot.icon == wanted {
            return Ok(false);
        }
        slot.icon = wanted.clone();
        Ok(true)
    })
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}
