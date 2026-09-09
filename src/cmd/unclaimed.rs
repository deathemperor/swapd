//! `swapd unclaimed [--purge <id>]` — list, or drop, the logins
//! `core::switch::preserve_outgoing` stashed because they matched no slot
//! (`core::unclaimed`).
//!
//! Never prints the credential bytes or the secret key that names them: the
//! row exists so a stash is findable, not so its contents leak into a
//! terminal a purge's `--yes`-less sibling verbs don't even have.

use serde::Serialize;

use crate::core::unclaimed::{self, Entry};
use crate::ctx::Ctx;
use crate::errors::Result;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnclaimedRow {
    pub id: String,
    pub provider: String,
    pub stashed_at: String,
    pub email: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnclaimedOutput {
    pub schema_version: u32,
    pub entries: Vec<UnclaimedRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeOutput {
    pub schema_version: u32,
    pub purged: String,
}

pub fn list(ctx: &Ctx) -> Result<UnclaimedOutput> {
    // `core::unclaimed::list` already answers sorted by id (a `BTreeMap`);
    // nothing here needs to re-sort.
    let entries = unclaimed::list(ctx)?
        .into_iter()
        .map(|(id, entry)| row(id, &entry))
        .collect();
    Ok(UnclaimedOutput {
        schema_version: output::SCHEMA_VERSION,
        entries,
    })
}

pub fn purge(ctx: &Ctx, id: &str) -> Result<PurgeOutput> {
    unclaimed::purge(ctx, id)?;
    Ok(PurgeOutput {
        schema_version: output::SCHEMA_VERSION,
        purged: id.to_string(),
    })
}

fn row(id: String, entry: &Entry) -> UnclaimedRow {
    UnclaimedRow {
        id,
        provider: entry.provider.clone(),
        stashed_at: unclaimed::format_stashed_at(entry.stashed_at),
        email: entry.email.clone(),
        reason: entry.reason.clone(),
    }
}

pub fn print_human(out: &UnclaimedOutput) {
    if out.entries.is_empty() {
        println!("no unclaimed entries");
        return;
    }
    for e in &out.entries {
        let email = if e.email.is_empty() {
            "(no identity)"
        } else {
            &e.email
        };
        println!(
            "{}  {}  {}  {}  {}",
            e.id, e.provider, email, e.stashed_at, e.reason
        );
    }
}

pub fn print_purged(out: &PurgeOutput) {
    println!("purged {}", out.purged);
}
