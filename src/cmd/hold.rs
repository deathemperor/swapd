//! `swapd hold <ident>` / `swapd unhold <ident>` — out of, and back into, the
//! rotation.
//!
//! A held account keeps its credential and is still polled; it is only barred
//! from being rotated onto (`collect::rotatable`), which is what makes it the
//! way to park an account without giving it up.

use crate::contract::ListPayload;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str, disabled: bool) -> Result<ListPayload> {
    let id = driver.id();
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let target = resolve(slots, id, ident)?;
        let slot = slots
            .slots
            .get_mut(&target)
            .expect("resolve named a slot in this table");
        if slot.disabled == disabled {
            return Ok(false);
        }
        slot.disabled = disabled;
        Ok(true)
    })
}
