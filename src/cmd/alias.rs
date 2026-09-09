//! `swapd alias <ident> <name|--unset>` — a slot's short name.

use crate::cmd::add::check_alias;
use crate::contract::ListPayload;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    ident: &str,
    name: Option<&str>,
    unset: bool,
) -> Result<ListPayload> {
    let id = driver.id();
    let wanted: Option<String> = match (name, unset) {
        (Some(name), false) => Some(name.trim().to_string()),
        (None, true) => None,
        _ => {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                "name a new alias or pass --unset, not both and not neither",
            ))
        }
    };
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let target = resolve(slots, id, ident)?;
        // `add`'s rule, so one alias means one account whichever verb set it:
        // never a number (which `resolve` reads as a slot) and never a name
        // another slot already answers to.
        if let Some(wanted) = &wanted {
            check_alias(slots, wanted, Some(target))?;
        }
        let slot = slots
            .slots
            .get_mut(&target)
            .expect("resolve named a slot in this table");
        if slot.alias == wanted {
            return Ok(false);
        }
        slot.alias = wanted.clone();
        Ok(true)
    })
}
