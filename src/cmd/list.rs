//! `swapd list` — every provider's accounts, their usage, and the rotation.

use crate::contract::{ListPayload, ProviderView, UsageStatus, WindowKind};
use crate::core::collect::{collect, CollectOpts};
use crate::ctx::Ctx;
use crate::driver::{self, Driver};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

pub fn run(ctx: &Ctx, drivers: &[Box<dyn Driver>]) -> Result<ListPayload> {
    let providers = drivers
        .iter()
        .map(|driver| collect(ctx, driver.as_ref(), &CollectOpts::default()))
        .collect::<Result<Vec<_>>>()?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers,
    })
}

/// The registry, filtered to one provider when the caller named one. An
/// unknown name is a caller error, not an empty list: silently listing nothing
/// would read as "no accounts".
pub fn drivers_for(provider_filter: Option<&str>) -> Result<Vec<Box<dyn Driver>>> {
    let Some(id) = provider_filter else {
        return Ok(driver::registry());
    };
    let drivers: Vec<Box<dyn Driver>> = driver::registry()
        .into_iter()
        .filter(|d| d.id() == id)
        .collect();
    if drivers.is_empty() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown provider: {id}"),
        ));
    }
    Ok(drivers)
}

/// One line per account: `* 1 death2  ok  12% / 34%`.
pub fn print_human(payload: &ListPayload) {
    for provider in &payload.providers {
        println!("{}", provider.provider);
        for account in &provider.accounts {
            let mark = if account.active { "*" } else { " " };
            let label = account.alias.as_deref().unwrap_or(&account.email);
            println!(
                "{mark} {} {} {} {} / {}",
                account.slot,
                label,
                status_label(account.usage_status),
                pct(provider, account.slot, WindowKind::FiveHour),
                pct(provider, account.slot, WindowKind::SevenDay),
            );
        }
    }
}

/// A window's utilization, from the fresh measurement when there is one and
/// from the last-known-good otherwise (an age the status already reports).
fn pct(provider: &ProviderView, slot: u32, kind: WindowKind) -> String {
    let Some(account) = provider.accounts.iter().find(|a| a.slot == slot) else {
        return "-".to_string();
    };
    let windows = if account.windows.is_empty() {
        account.last_good.as_ref().map(|g| g.windows.as_slice())
    } else {
        Some(account.windows.as_slice())
    };
    windows
        .and_then(|windows| windows.iter().find(|w| w.kind == kind))
        .map(|w| format!("{:.0}%", w.pct))
        .unwrap_or_else(|| "-".to_string())
}

fn status_label(status: UsageStatus) -> &'static str {
    match status {
        UsageStatus::Ok => "ok",
        UsageStatus::Stale => "stale",
        UsageStatus::ReloginRequired => "relogin-required",
        UsageStatus::TokenExpired => "token-expired",
        UsageStatus::NoCredentials => "no-credentials",
        UsageStatus::ApiKey => "api-key",
        UsageStatus::Unsupported => "unsupported",
    }
}
