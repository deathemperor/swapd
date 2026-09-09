//! `swapd reorder <ident>…` — the rotation order.
//!
//! The whole order, not a move: `next-available` resumes the order after the
//! active slot, so a partial list would leave the rest in an order the user
//! never chose. Every slot exactly once, named however they like (number,
//! alias or email).

use std::collections::BTreeSet;

use crate::contract::ListPayload;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};

pub fn run(ctx: &Ctx, driver: &dyn Driver, idents: &[String]) -> Result<ListPayload> {
    let id = driver.id();
    if idents.is_empty() {
        return Err(invalid("reorder takes the new order: every slot, once"));
    }
    crate::cmd::edit_slots(ctx, driver, |slots| {
        let mut order: Vec<u32> = Vec::with_capacity(idents.len());
        for ident in idents {
            let target = resolve(slots, id, ident)?;
            if order.contains(&target) {
                return Err(invalid(format!("slot {target} is named twice")));
            }
            order.push(target);
        }
        let named: BTreeSet<u32> = order.iter().copied().collect();
        let known: BTreeSet<u32> = slots.slots.keys().copied().collect();
        let missing: Vec<String> = known.difference(&named).map(u32::to_string).collect();
        if !missing.is_empty() {
            return Err(invalid(format!(
                "the new order leaves out slot {}; name every slot",
                missing.join(", ")
            )));
        }
        if slots.order == order {
            return Ok(false);
        }
        slots.order = order;
        Ok(true)
    })
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}
