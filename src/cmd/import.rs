//! `swapd import <file|->` — read an export back in.

use serde::Serialize;

use crate::core::import::{self, ImportResult};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutput {
    pub schema_version: u32,
    pub imported: Vec<u32>,
    /// Slots already holding the account whose credential the file replaced
    /// (a newer generation, or the stored one was missing).
    pub refreshed: Vec<u32>,
    pub skipped: Vec<SkippedView>,
    /// The slot the file called active. Reported, never activated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_slot: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedView {
    pub slot: u32,
    pub email: String,
    pub reason: String,
}

pub fn run(ctx: &Ctx, provider: &dyn Driver, path: &str, force: bool) -> Result<ImportOutput> {
    Ok(view(import::run(ctx, provider, path, force)?))
}

fn view(result: ImportResult) -> ImportOutput {
    ImportOutput {
        schema_version: output::SCHEMA_VERSION,
        imported: result.imported,
        refreshed: result.refreshed,
        skipped: result
            .skipped
            .into_iter()
            .map(|s| SkippedView {
                slot: s.slot,
                email: s.email,
                reason: s.reason,
            })
            .collect(),
        active_slot: result.active_slot,
    }
}

pub fn print_human(out: &ImportOutput) {
    println!("imported {} account(s)", out.imported.len());
    for slot in &out.imported {
        println!("  + slot {slot}");
    }
    for slot in &out.refreshed {
        println!("  ~ slot {slot} (credential refreshed from the file)");
    }
    for skipped in &out.skipped {
        println!(
            "  - slot {} {} ({})",
            skipped.slot, skipped.email, skipped.reason
        );
    }
}
