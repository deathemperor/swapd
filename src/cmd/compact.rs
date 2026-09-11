//! `swapd compact` — renumber the slots 1…n (`core::compact`).
//!
//! Idempotent: a dense roster is nothing to do. The finish-later step a
//! `remove` names when a live session stopped its renumber, and the fix for
//! a roster imported with gaps.

use serde::Serialize;

use crate::core::compact::{self, Compacted};
use crate::core::slots;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactOutput {
    pub schema_version: u32,
    pub ok: bool,
    #[serde(flatten)]
    pub compacted: Compacted,
}

pub fn run(ctx: &Ctx, driver: &dyn Driver) -> Result<CompactOutput> {
    let id = driver.id();
    let compacted = slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry(id.to_string()).or_default();
        let compacted = compact::compact(ctx, driver, provider)?;
        Ok((!compacted.moves.is_empty(), compacted))
    })?;
    Ok(CompactOutput {
        schema_version: output::SCHEMA_VERSION,
        ok: true,
        compacted,
    })
}

pub fn print_human(out: &CompactOutput) {
    if out.compacted.moves.is_empty() && out.compacted.stopped_at.is_none() {
        println!("slots are already 1…n");
    }
    for m in &out.compacted.moves {
        println!("slot {} is now slot {}", m.from, m.to);
    }
    if let Some(stop) = &out.compacted.stopped_at {
        println!("{}", compact::stopped_note(stop));
    }
}
