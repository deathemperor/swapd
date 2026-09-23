//! `swapd list` — every provider's accounts, their usage, and the rotation.

use std::time::Duration;

use crate::contract::{AccountView, ListPayload, UsageStatus, Window, WindowKind};
use crate::core::collect::{collect, CollectOpts};
use crate::core::gating::relevant;
use crate::ctx::Ctx;
use crate::driver::{self, Driver, Env};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

pub fn run(ctx: &Ctx, drivers: &[Box<dyn Driver>]) -> Result<ListPayload> {
    // A status verb behind the app's pump: it degrades
    // (`activeUnreadable: switch-in-progress`) after one second rather than
    // stalling the pump for the default `engine.lock` timeout.
    let opts = CollectOpts {
        lock_wait: Duration::from_secs(1),
        ..CollectOpts::default()
    };
    let providers = drivers
        .iter()
        .map(|driver| collect(ctx, driver.as_ref(), &opts))
        .collect::<Result<Vec<_>>>()?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers,
    })
}

/// The registry, filtered to one provider when the caller named one. An
/// unknown name is a caller error, not an empty list: silently listing nothing
/// would read as "no accounts".
pub fn drivers_for(provider_filter: Option<&str>, env: &Env) -> Result<Vec<Box<dyn Driver>>> {
    let Some(id) = provider_filter else {
        return Ok(driver::registry(env));
    };
    let drivers: Vec<Box<dyn Driver>> = driver::registry(env)
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

/// One line per account: `* 1 death2  ok  12% / 34%`, or
/// `* 1 g1  ok  gemini-2.5-pro 75%` for a provider with no account-wide window.
pub fn print_human(payload: &ListPayload) {
    for provider in &payload.providers {
        println!("{}", provider.provider);
        for account in &provider.accounts {
            let mark = if account.active { "*" } else { " " };
            let label = account.alias.as_deref().unwrap_or(&account.email);
            println!(
                "{mark} {} {} {} {}",
                account.slot,
                label,
                status_label(account.usage_status),
                usage_columns(account),
            );
        }
    }
}

/// The utilization columns of one row.
///
/// `12% / 34%` — the 5-hour and 7-day windows — for a provider that reports
/// them. An account that reports neither (the Gemini shape: one scoped bucket
/// per model) has no such number to print, and a row reading `- / -` said
/// "unmeasured" about an account swapd had just measured and was rotating on.
/// So that row names its *binding* window instead — the one at the highest
/// utilization, which is the one `headroom` gates the account by.
fn usage_columns(account: &AccountView) -> String {
    let windows = decision_windows(account);
    if windows
        .iter()
        .any(|w| matches!(w.kind, WindowKind::FiveHour | WindowKind::SevenDay))
    {
        return format!(
            "{} / {}",
            pct(windows, WindowKind::FiveHour),
            pct(windows, WindowKind::SevenDay)
        );
    }
    // The empty models list is not a shortcut: for an account with no
    // account-wide window `relevant` gates on every named bucket whatever the
    // setting says, so this picks the same window the engine does without the
    // verb having to carry the settings in.
    match binding(windows) {
        Some(w) => format!("{} {:.0}%", w.name.as_deref().unwrap_or("binding"), w.pct),
        None => "- / -".to_string(),
    }
}

/// The relevant window at the highest utilization — what `headroom` measures
/// the account by (`gating::relevant`).
fn binding(windows: &[Window]) -> Option<&Window> {
    relevant(windows, &[])
        .into_iter()
        .max_by(|a, b| a.pct.total_cmp(&b.pct))
}

/// The windows a row is printed from: the fresh measurement when there is one
/// and the last-known-good otherwise (an age the status already reports).
fn decision_windows(account: &AccountView) -> &[Window] {
    if account.windows.is_empty() {
        account
            .last_good
            .as_ref()
            .map(|g| g.windows.as_slice())
            .unwrap_or_default()
    } else {
        &account.windows
    }
}

fn pct(windows: &[Window], kind: WindowKind) -> String {
    windows
        .iter()
        .find(|w| w.kind == kind)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::LastGood;

    fn window(kind: WindowKind, name: Option<&str>, pct: f64) -> Window {
        Window {
            kind,
            name: name.map(str::to_string),
            pct,
            resets_at: None,
            pace: None,
            used: None,
            limit: None,
            currency: None,
        }
    }

    fn row(windows: Vec<Window>) -> AccountView {
        AccountView {
            slot: 1,
            email: "you@example.com".to_string(),
            organization_name: String::new(),
            organization_uuid: String::new(),
            plan: None,
            alias: None,
            icon: None,
            active: false,
            disabled: false,
            preferred: false,
            auto_ignite: false,
            usage_status: UsageStatus::Ok,
            fetched_at: None,
            age_seconds: None,
            windows,
            last_good: None,
            last_error: None,
            backoff_until: None,
            reported_limit_at: None,
            reported_limit_resets_at: None,
            resets: None,
        }
    }

    #[test]
    fn an_account_with_account_wide_windows_keeps_the_two_columns() {
        let account = row(vec![
            window(WindowKind::FiveHour, None, 12.0),
            window(WindowKind::SevenDay, None, 34.0),
            window(WindowKind::Scoped, Some("Fable"), 99.0),
        ]);
        assert_eq!(usage_columns(&account), "12% / 34%");

        // A Claude reply that carried only one of the two still reads as the
        // pair, with the missing half a dash.
        let account = row(vec![window(WindowKind::FiveHour, None, 12.0)]);
        assert_eq!(usage_columns(&account), "12% / -");
    }

    #[test]
    fn an_all_scoped_account_names_its_binding_bucket() {
        let account = row(vec![
            window(WindowKind::Scoped, Some("gemini-2.5-flash"), 10.0),
            window(WindowKind::Scoped, Some("gemini-2.5-pro"), 75.0),
        ]);
        assert_eq!(usage_columns(&account), "gemini-2.5-pro 75%");
    }

    #[test]
    fn a_stale_row_prints_its_last_known_good_windows() {
        let mut account = row(vec![]);
        account.usage_status = UsageStatus::Stale;
        account.last_good = Some(LastGood {
            fetched_at: "2026-09-09T01:11:03Z".to_string(),
            age_seconds: 900.0,
            windows: vec![window(WindowKind::Scoped, Some("gemini-2.5-pro"), 75.0)],
        });
        assert_eq!(usage_columns(&account), "gemini-2.5-pro 75%");
    }

    #[test]
    fn an_account_with_nothing_measured_reads_as_the_empty_pair() {
        assert_eq!(usage_columns(&row(vec![])), "- / -");
        // `spend` is not a gating window (`gating::relevant` excludes it), so an
        // account carrying only that one has no binding window to name.
        let account = row(vec![window(WindowKind::Spend, Some("credits"), 40.0)]);
        assert_eq!(usage_columns(&account), "- / -");
    }
}
