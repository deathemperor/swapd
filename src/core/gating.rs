//! Which of an account's windows gate it, and how much room is left in the
//! binding one.
//!
//! Port of cswap `oauth.py:505-541` (`relevant_windows`) and `oauth.py:543-561`
//! (`account_headroom`). This is core's own rule, not a provider's: every
//! collector and the `auto` engine judge exhaustion through it, over whatever
//! windows a driver reported. It lived under `driver/claude/` until #17, which
//! is how the all-scoped gap below went unnoticed until the Gemini driver's
//! final review.

use crate::contract::{Window, WindowKind};

/// Every window that gates this account (`oauth.py:505-541`).
///
/// Always the 5-hour and 7-day windows. When `models` is non-empty each named
/// per-model weekly window joins them (matched case-insensitively on display
/// name; the sentinel `all` matches every scoped window the account reports).
/// `spend` — pay-as-you-go extra-usage credits — is a separate axis and is
/// deliberately excluded.
///
/// An account that reports NO account-wide window at all — the Gemini shape,
/// one scoped bucket per model — is gated by every named bucket instead.
/// Otherwise nothing gates it, `headroom` is `None` forever and `auto` can
/// never judge it exhausted. A Claude reply always carries the 5-hour and
/// 7-day windows, so this arm never fires for it and `models` narrows there
/// exactly as before.
pub fn relevant<'a>(windows: &'a [Window], models: &[String]) -> Vec<&'a Window> {
    let wanted: Vec<String> = models.iter().map(|m| m.to_lowercase()).collect();
    let match_all = wanted.iter().any(|m| m == "all");
    let account_wide = windows
        .iter()
        .any(|w| matches!(w.kind, WindowKind::FiveHour | WindowKind::SevenDay));
    windows
        .iter()
        .filter(|w| match w.kind {
            WindowKind::FiveHour | WindowKind::SevenDay => true,
            WindowKind::Scoped => match &w.name {
                Some(name) => !account_wide || match_all || wanted.contains(&name.to_lowercase()),
                None => false,
            },
            _ => false,
        })
        .collect()
}

/// Remaining percentage before the *binding* window hits its limit
/// (`oauth.py:543-561`): `100 - max(pct)`, so `<= 0` means the account is at or
/// over a limit. `None` when no window data is available, which callers treat
/// as "unknown" — never as "skip".
pub fn headroom(windows: &[Window], models: &[String]) -> Option<f64> {
    let max = relevant(windows, models)
        .into_iter()
        .map(|w| w.pct)
        .fold(f64::NEG_INFINITY, f64::max);
    if max.is_finite() {
        Some(100.0 - max)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn models(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

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

    #[test]
    fn relevant_and_headroom_follow_the_models_list() {
        let windows = vec![
            window(WindowKind::FiveHour, None, 10.0),
            window(WindowKind::SevenDay, None, 20.0),
            window(WindowKind::Spend, None, 99.0),
            window(WindowKind::Scoped, Some("Fable"), 80.0),
        ];

        // No models: 5h + 7d only. Spend is a separate axis and never gates.
        let kinds: Vec<_> = relevant(&windows, &[]).iter().map(|w| w.kind).collect();
        assert_eq!(kinds, vec![WindowKind::FiveHour, WindowKind::SevenDay]);
        assert_eq!(headroom(&windows, &[]), Some(80.0));

        // A named model folds its weekly window in, case-insensitively.
        assert_eq!(relevant(&windows, &models(&["fable"])).len(), 3);
        assert_eq!(headroom(&windows, &models(&["fable"])), Some(20.0));
        // An unrelated model does not.
        assert_eq!(headroom(&windows, &models(&["opus"])), Some(80.0));
        // The `all` sentinel matches every scoped window.
        assert_eq!(headroom(&windows, &models(&["all"])), Some(20.0));

        // No window data at all is "unknown", not "wide open".
        assert_eq!(headroom(&[], &[]), None);
    }

    #[test]
    fn an_all_scoped_account_is_gated_by_every_named_bucket() {
        // A provider whose usage call reports only per-model buckets (Gemini):
        // with no account-wide window to gate on, every named bucket does.
        let windows = vec![
            window(WindowKind::Scoped, Some("gemini-2.5-pro"), 10.0),
            window(WindowKind::Scoped, Some("gemini-2.5-flash"), 75.0),
            window(WindowKind::Scoped, Some("CREDITS"), 40.0),
        ];
        assert_eq!(relevant(&windows, &[]).len(), 3);
        assert_eq!(headroom(&windows, &[]), Some(25.0));
    }

    #[test]
    fn models_still_narrow_an_account_with_a_five_hour_window() {
        let windows = vec![
            window(WindowKind::FiveHour, None, 10.0),
            window(WindowKind::Scoped, Some("opus"), 90.0),
            window(WindowKind::Scoped, Some("sonnet"), 50.0),
        ];
        assert_eq!(headroom(&windows, &[]), Some(90.0), "5h alone");
        assert_eq!(headroom(&windows, &models(&["opus"])), Some(10.0));
    }
}
