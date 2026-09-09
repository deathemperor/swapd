//! `swapd history` — the switch log, newest last.

use serde::Serialize;

use crate::core::history::{self, SwitchRecord};
use crate::ctx::Ctx;
use crate::errors::Result;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryOutput {
    pub schema_version: u32,
    pub switches: Vec<SwitchRecord>,
}

pub fn run(ctx: &Ctx, limit: Option<usize>) -> Result<HistoryOutput> {
    Ok(HistoryOutput {
        schema_version: output::SCHEMA_VERSION,
        switches: history::read(&ctx.home, limit)?,
    })
}

pub fn print_human(out: &HistoryOutput) {
    for record in &out.switches {
        let from = match &record.from {
            Some(from) => match from.slot {
                Some(slot) => format!("{slot} ({})", from.email),
                None => format!("unmanaged ({})", from.email),
            },
            None => "-".to_string(),
        };
        println!(
            "{} {} -> {} ({})",
            record.ts,
            from,
            match record.to.slot {
                Some(slot) => format!("{slot} ({})", record.to.email),
                None => record.to.email.clone(),
            },
            record.trigger,
        );
    }
}
