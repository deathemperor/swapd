//! `swapd refresh` — fetch now, then report the same payload `list` does.

use serde::Serialize;

use crate::contract::{AccountView, ListPayload, ProviderView};
use crate::core::collect::{collect, CollectOpts};
use crate::core::slots::SlotsFile;
use crate::core::store::read_json;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// `list`'s payload plus what an explicit `--slot` actually managed to do.
///
/// A forced refresh that fetched nothing used to return the unchanged list,
/// which reads exactly like a refresh that succeeded and found the same
/// numbers — the user is told the data is current when it is hours old (#31).
/// `skipped` names the reason instead. Absent for a plain `refresh` (which
/// promises no particular slot) and for a forced one that did fetch.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshOutput {
    #[serde(flatten)]
    pub list: ListPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Skipped>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub slot: u32,
    /// `claimed` (another collector is spending this slot's token right now)
    /// or `token-dead` (quarantined lineage; only a re-login clears it) — the
    /// two gates a force deliberately does not override.
    pub reason: String,
}

/// `--slot n` forces that one account past the serve TTL, its poll plan and its
/// failure backoff; without it every account whose data is stale or whose plan
/// is due is fetched.
pub fn run(ctx: &Ctx, driver: &dyn Driver, slot: Option<u32>) -> Result<RefreshOutput> {
    // Named before anything is fetched: a pass reads the live store and can
    // adopt a rotation from it, which a rejected command must not do.
    if let Some(slot) = slot {
        let slots: SlotsFile = read_json(&ctx.home.slots_file())?;
        let known = slots
            .providers
            .get(driver.id())
            .is_some_and(|p| p.slots.contains_key(&slot));
        if !known {
            return Err(SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("no slot {slot} for {}", driver.id()),
            ));
        }
    }
    let opts = match slot {
        Some(slot) => CollectOpts {
            force_slots: vec![slot],
            ..CollectOpts::default()
        },
        None => CollectOpts {
            all_stale: true,
            ..CollectOpts::default()
        },
    };
    let before = slot.and_then(|slot| last_attempt_at(ctx, driver, slot));
    let view = collect(ctx, driver, &opts)?;
    let after = slot.and_then(|slot| last_attempt_at(ctx, driver, slot));
    let skipped = slot.and_then(|slot| skipped_reason(&view, slot, before, after));
    Ok(RefreshOutput {
        list: ListPayload {
            schema_version: output::SCHEMA_VERSION,
            providers: vec![view],
        },
        skipped,
    })
}

/// The slot's stored *attempt* stamp, which `reserve` writes at the moment a
/// claim is won — so it answers "did this pass get to fetch this slot at all",
/// which is the question, rather than "did the fetch succeed", which is not.
///
/// Read straight out of the usage table, not through a second `collect`: a
/// collection pass reads the live store and every slot's secret and can adopt a
/// rotation, none of which belongs in a "what did it say a moment ago" probe.
fn last_attempt_at(ctx: &Ctx, driver: &dyn Driver, slot: u32) -> Option<f64> {
    let slots: SlotsFile = read_json(&ctx.home.slots_file()).ok()?;
    let meta = slots.providers.get(driver.id())?.slots.get(&slot)?;
    let key = crate::secrets::slot_key(driver.id(), slot);
    let keys = [(
        key.clone(),
        meta.email.clone(),
        meta.organization_uuid.clone(),
    )];
    let entries = ctx.store.entries(&keys, &ctx.settings.models).ok()?;
    entries.get(&key)?.last_attempt_at
}

fn account(view: &ProviderView, slot: u32) -> Option<&AccountView> {
    view.accounts.iter().find(|a| a.slot == slot)
}

/// Why the forced slot went unfetched, or `None` when it was fetched.
///
/// Measured on the store's attempt stamp rather than threaded up from
/// `reserve`: the claim is won inside the pass and released by the time it
/// returns, so the stamp is the evidence that survives. An advanced stamp means
/// the pass got its turn — whether the fetch then succeeded or failed is a
/// different question, answered by `lastError`.
fn skipped_reason(
    view: &ProviderView,
    slot: u32,
    before: Option<f64>,
    after: Option<f64>,
) -> Option<Skipped> {
    let account = account(view, slot)?;
    if after != before {
        return None;
    }
    // The quarantine is the only gate that describes itself in the view; a
    // claim leaves no trace, so it is the remaining explanation.
    let reason = match account.usage_status {
        crate::contract::UsageStatus::ReloginRequired => "token-dead",
        _ => "claimed",
    };
    Some(Skipped {
        slot,
        reason: reason.to_string(),
    })
}

pub fn print_human(out: &RefreshOutput) {
    crate::cmd::list::print_human(&out.list);
    if let Some(skipped) = &out.skipped {
        let why = match skipped.reason.as_str() {
            "token-dead" => "its refresh-token lineage is dead — log in, then run: swapd add",
            _ => "another swapd process is fetching it right now; try again in a moment",
        };
        eprintln!("warning: slot {} was not fetched: {why}", skipped.slot);
    }
}
