//! `swapd switch <ident>` — make one slot the live login.

use serde::Serialize;

use crate::core::history::SlotRef;
use crate::core::slots;
use crate::core::switch::{self, SwitchResult};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchOutput {
    pub schema_version: u32,
    pub switched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<SlotRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<SlotRef>,
    pub warnings: Vec<String>,
}

pub fn run(ctx: &Ctx, provider: &dyn Driver, ident: &str) -> Result<SwitchOutput> {
    // Resolved from the file rather than from a collection pass: naming a slot
    // must not depend on the network being up.
    let slots = slots::load(&ctx.home, provider.id())?;
    let target = switch::resolve(&slots, provider.id(), ident)?;
    Ok(view(switch::perform(ctx, provider, target, "manual")?))
}

pub fn view(result: SwitchResult) -> SwitchOutput {
    SwitchOutput {
        schema_version: output::SCHEMA_VERSION,
        switched: result.switched,
        reason: result.reason,
        from: result.from,
        to: Some(result.to),
        warnings: result.warnings,
    }
}

pub fn print_human(out: &SwitchOutput) {
    match out.to.as_ref().filter(|_| out.switched) {
        Some(to) => println!(
            "switched to slot {} ({})",
            to.slot.map(|s| s.to_string()).unwrap_or_default(),
            to.email
        ),
        None => println!(
            "no switch: {}",
            out.reason.as_deref().unwrap_or("nothing to do")
        ),
    }
    for warning in &out.warnings {
        eprintln!("warning: {warning}");
    }
}
