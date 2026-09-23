//! The usage endpoint: the raw request, its normalization into `Window`s, and
//! weekly pace.
//!
//! Port of cswap `oauth.py:364-374` (`request_usage_data`), `oauth.py:377-403`
//! (`_classify_usage_error`), `oauth.py:431-503` (`build_usage_result`), the
//! whole of `pace.py` (`compute_pace`, `projected_exhaustion_ts`,
//! `will_last_to_reset`) and `json_output.py:63-88` (`_pace_fields`, which
//! decides what of pace is exposed and how it is rounded).
//!
//! Which of these windows gate the account is not this module's business and
//! not Claude's — that rule is `core::gating`.
//!
//! cswap's normalized dict becomes a flat `Vec<Window>` here — one entry per
//! window, `kind` carrying what used to be the dict key. `resets_at` is copied
//! verbatim; the countdown/clock strings cswap precomputes are a rendering
//! concern and are not part of this contract.

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::contract::{Pace, Window, WindowKind};
use crate::driver::claude::oauth::{self, Endpoints};
use crate::driver::http_auth;
use crate::driver::{DriverError, ResetBank, ResetGrant, ResetOutcome};
use crate::timefmt::format_ts;

/// Weekly windows reset on a fixed 7-day cadence (`pace.py:26`).
const WEEKLY_PERIOD_S: f64 = 7.0 * 86400.0;
/// Keep a positive span for rate projections just after reset. The ahead
/// threshold already filters small overshoots; suppressing a whole day hides
/// meaningful usage during the first day of every weekly window.
const MIN_ELAPSED_S: f64 = 60.0;
/// Minimum (actual - expected) gap before a window counts as ahead of pace
/// (`pace.py:41`). Below it, "ahead" is within normal variance.
const AHEAD_THRESHOLD_PCT: f64 = 15.0;

/// Raw utilization data from the Anthropic usage API (`oauth.py:364-374`).
///
/// `Throttled` carries the server's `Retry-After` when it sent one — seconds
/// form only, as cswap parses (the HTTP-date form is rare enough to ignore), so
/// an absent or unparseable header is `retry_after: None` rather than a guess.
/// No error carries the response body.
pub fn fetch(ep: &Endpoints, access_token: &str) -> Result<Value, DriverError> {
    // Non-2xx is classified here (429 is a distinct outcome), not thrown.
    let reply = http_auth::get(
        oauth::usage_url(ep),
        oauth::READ_TIMEOUT_S,
        access_token,
        "usage",
        &[
            ("anthropic-beta", oauth::BETA_HEADER),
            ("user-agent", oauth::RESET_USER_AGENT),
        ],
    )?;

    if reply.status == 429 {
        let retry_after = reply
            .retry_after
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v.max(0.0));
        return Err(DriverError::Throttled { retry_after });
    }
    if reply.status == 401 {
        // The token the caller handed us is not (or no longer) good. Refreshing
        // here would spend a single-use refresh token whose rotation the caller
        // never sees, so the caller is told to do it and retry.
        return Err(DriverError::NeedsRefresh);
    }
    if reply.status != 200 {
        return Err(DriverError::Http(format!("usage: http-{}", reply.status)));
    }
    serde_json::from_str(&reply.body)
        .map_err(|_| DriverError::Http("usage: bad-response".to_string()))
}

/// `build_usage_result` against the current clock.
///
/// Normalize a raw usage response into the windows that describe it
/// (`oauth.py:431-503`), with weekly pace computed against `fetched_at`.
///
/// Pace lands on the 7-day and scoped windows only — never on the 5-hour one
/// (`json_output.usage_to_json`): a 5h window resets too fast for pace to mean
/// anything, and starts "ahead" almost by definition.
pub fn windows_at(raw: &Value, fetched_at: f64) -> Vec<Window> {
    let mut out = Vec::new();

    if let Some((pct, resets_at)) = utilization(raw.get("five_hour")) {
        out.push(Window {
            kind: WindowKind::FiveHour,
            name: None,
            pct,
            resets_at,
            pace: None,
            used: None,
            limit: None,
            currency: None,
        });
    }

    if let Some((pct, resets_at)) = utilization(raw.get("seven_day")) {
        out.push(Window {
            kind: WindowKind::SevenDay,
            name: None,
            pace: pace_fields(pct, resets_at.as_deref(), fetched_at),
            pct,
            resets_at,
            used: None,
            limit: None,
            currency: None,
        });
    }

    if let Some(spend) = spend_window(raw.get("extra_usage")) {
        out.push(spend);
    }

    // Per-model weekly limits live in the newer `limits` array; the legacy
    // five_hour/seven_day keys never expose them, so each is its own window.
    // Older responses simply carry no `limits` and yield none.
    if let Some(limits) = raw.get("limits").and_then(Value::as_array) {
        for limit in limits {
            let name = limit
                .pointer("/scope/model/display_name")
                .and_then(Value::as_str);
            let pct = limit.get("percent").and_then(Value::as_f64);
            let (Some(name), Some(pct)) = (name, pct) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let resets_at = resets_at(limit);
            out.push(Window {
                kind: WindowKind::Scoped,
                name: Some(name.to_string()),
                pace: pace_fields(pct, resets_at.as_deref(), fetched_at),
                pct,
                resets_at,
                used: None,
                limit: None,
                currency: None,
            });
        }
    }

    out
}

/// The `cedar_ember` block: the limit resets the provider has banked for
/// this account, kept as reported. `None` when the response carries none or
/// names no grant — an account the program does not cover.
pub fn reset_bank(raw: &Value) -> Option<ResetBank> {
    let block = raw.get("cedar_ember")?.as_object()?;
    let text = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let flag = |v: Option<&Value>| v.and_then(Value::as_bool).unwrap_or(false);
    let count = |v: Option<&Value>| v.and_then(Value::as_u64).unwrap_or(0) as u32;
    let grants: Vec<ResetGrant> = block
        .get("grants")
        .and_then(Value::as_array)
        .map(|grants| {
            grants
                .iter()
                .filter_map(|g| {
                    Some(ResetGrant {
                        id: text(g.get("id"))?,
                        label: text(g.get("label")),
                        resets_left: count(g.get("resets_left")),
                        resets_total: count(g.get("resets_total")),
                        ends_at: text(g.get("ends_at")),
                        paused: flag(g.get("paused")),
                        usable_now: flag(g.get("usable_now")),
                        use_requires_limit: flag(g.get("use_requires_limit")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if grants.is_empty() {
        return None;
    }
    Some(ResetBank {
        at_limit: flag(block.get("at_limit")),
        next_grant_id: text(block.get("next_grant_id")),
        cooldown_until: text(block.get("cooldown_until")),
        grants,
    })
}

/// Spend one banked reset: the CLI's `/reset` request, verbatim. The
/// provider's refusals come back as the outcome's own word; only transport
/// and auth failures are errors.
pub fn claim_reset(
    ep: &Endpoints,
    access_token: &str,
    organization_uuid: &str,
    grant_id: &str,
) -> Result<ResetOutcome, DriverError> {
    // One id per attempt, so a retry after a timeout cannot be taken for a
    // second claim; the server keys idempotency on it.
    let request_id = format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    );
    let reply = http_auth::post_json(
        oauth::reset_url(ep, organization_uuid),
        oauth::RESET_TIMEOUT_S,
        access_token,
        "reset",
        &[
            ("anthropic-beta", oauth::BETA_HEADER),
            ("user-agent", oauth::RESET_USER_AGENT),
        ],
        &serde_json::json!({
            "program": "cedar_ember",
            "grant_id": grant_id,
            "request_id": request_id,
        }),
    )?;
    if reply.status == 429 {
        let retry_after = reply
            .retry_after
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v.max(0.0));
        return Err(DriverError::Throttled { retry_after });
    }
    if reply.status == 401 {
        return Err(DriverError::NeedsRefresh);
    }
    if reply.status != 200 {
        return Err(DriverError::Http(format!("reset: http-{}", reply.status)));
    }
    let body: Value = serde_json::from_str(&reply.body)
        .map_err(|_| DriverError::Http("reset: bad-response".to_string()))?;
    let result = body
        .get("result")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DriverError::Http("reset: bad-response".to_string()))?;
    Ok(ResetOutcome {
        result: result.to_string(),
    })
}

/// `(utilization, resets_at)` of a `five_hour`/`seven_day` entry.
fn utilization(entry: Option<&Value>) -> Option<(f64, Option<String>)> {
    let entry = entry?;
    let pct = entry.get("utilization").and_then(Value::as_f64)?;
    Some((pct, resets_at(entry)))
}

/// A non-empty `resets_at` string, copied verbatim.
fn resets_at(entry: &Value) -> Option<String> {
    entry
        .get("resets_at")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The pay-as-you-go spend window (`oauth.py:459-484`).
///
/// Claude Code returns nullable `used_credits`, `monthly_limit` and
/// `utilization` (`monthly_limit = null` means unlimited). All three are needed
/// to describe spend, so when any is null the spend window is skipped and the
/// utilization windows go through unchanged. Credits are cents.
fn spend_window(entry: Option<&Value>) -> Option<Window> {
    let entry = entry?;
    if !entry
        .get("is_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let used = entry.get("used_credits").and_then(Value::as_f64)?;
    let limit = entry.get("monthly_limit").and_then(Value::as_f64)?;
    let pct = entry.get("utilization").and_then(Value::as_f64)?;
    Some(Window {
        kind: WindowKind::Spend,
        name: None,
        pct,
        resets_at: resets_at(entry),
        pace: None,
        used: Some(used / 100.0),
        limit: Some(limit / 100.0),
        currency: Some(
            entry
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or("USD")
                .to_string(),
        ),
    })
}

/// One weekly window's pace at the moment its snapshot was fetched
/// (`pace.py:66-113`).
struct PaceResult {
    expected_pct: f64,
    actual_pct: f64,
    /// Time since this window's current cycle started. Always
    /// `>= MIN_ELAPSED_S`, hence always positive — the guard below is
    /// what lets the projections downstream be total.
    elapsed_s: f64,
    period_s: f64,
    ahead: bool,
}

fn compute_pace(pct: f64, resets_at: Option<&str>, fetched_at: f64) -> Option<PaceResult> {
    let next_reset = OffsetDateTime::parse(resets_at?, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp() as f64)?;

    // `(next_reset - fetched_at) mod period` is the time left until the next
    // reset folded into [0, period); the period minus that is time elapsed
    // since the current window started. Correct however many whole cycles
    // `next_reset` is ahead of — or behind — `fetched_at`, including a stale
    // value that has not rolled forward yet.
    let remaining = (next_reset - fetched_at).rem_euclid(WEEKLY_PERIOD_S);
    let elapsed = if remaining == 0.0 {
        0.0
    } else {
        WEEKLY_PERIOD_S - remaining
    };
    if elapsed < MIN_ELAPSED_S {
        return None;
    }

    let expected_pct = (elapsed / WEEKLY_PERIOD_S * 100.0).min(100.0);
    Some(PaceResult {
        expected_pct,
        actual_pct: pct,
        elapsed_s: elapsed,
        period_s: WEEKLY_PERIOD_S,
        // Thresholded on the unrounded expectation, as cswap does; only the
        // exposed number is rounded.
        ahead: (pct - expected_pct) >= AHEAD_THRESHOLD_PCT,
    })
}

/// The exposed pace fields (`json_output.py:63-88`).
///
/// `exhausts_at` is a linear-rate ETA with wide error bars against real, bursty
/// usage — kept out of every human-facing surface and only ever machine-read.
/// `lasts_to_reset` is the same projection with no threshold, so a window can
/// report `false` while showing no ahead marker.
///
/// cswap's `will_last_to_reset` has a "no measurable rate" (`None`) arm for
/// `elapsed_s <= 0`; `compute_pace`'s minimum elapsed span makes that
/// unreachable here, which is why this returns a plain `bool` and the contract's
/// field is not optional.
fn pace_fields(pct: f64, resets_at: Option<&str>, fetched_at: f64) -> Option<Pace> {
    let pace = compute_pace(pct, resets_at, fetched_at)?;
    if pace.actual_pct <= 0.0 {
        // No usage yet — nothing to run out of before reset, and no rate to
        // project an exhaustion from.
        return Some(Pace {
            expected_pct: round1(pace.expected_pct),
            ahead: pace.ahead,
            exhausts_at: None,
            lasts_to_reset: true,
        });
    }
    let rate_pct_per_s = pace.actual_pct / pace.elapsed_s;
    let remaining_pct = 100.0 - pace.actual_pct;
    let eta = if remaining_pct <= 0.0 {
        fetched_at
    } else {
        fetched_at + remaining_pct / rate_pct_per_s
    };
    let projected_total = pace.actual_pct + rate_pct_per_s * (pace.period_s - pace.elapsed_s);
    Some(Pace {
        expected_pct: round1(pace.expected_pct),
        ahead: pace.ahead,
        exhausts_at: format_ts(eta),
        lasts_to_reset: projected_total <= 100.0,
    })
}

/// One decimal place, as `_pace_fields` rounds. (Python rounds half to even and
/// this rounds half away from zero; the inputs are continuous, so the tie is
/// not a case that occurs.)
fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Six days into a week that resets at `2026-09-15T10:59:59Z`.
    const RESET: &str = "2026-09-15T10:59:59Z";
    fn fetched_at(days_into_week: f64) -> f64 {
        let reset = OffsetDateTime::parse(RESET, &Rfc3339)
            .unwrap()
            .unix_timestamp() as f64;
        reset - WEEKLY_PERIOD_S + days_into_week * 86400.0
    }

    #[test]
    fn pace_starts_one_minute_after_reset() {
        let start = fetched_at(0.0);
        assert!(pace_fields(40.0, Some(RESET), start).is_none());
        assert!(pace_fields(40.0, Some(RESET), start + 59.0).is_none());
        assert!(pace_fields(40.0, Some(RESET), start + 60.0).is_some());
        // No resets_at, or an unparseable one, is never computable.
        assert!(pace_fields(40.0, None, fetched_at(3.0)).is_none());
        assert!(pace_fields(40.0, Some("not a date"), fetched_at(3.0)).is_none());
    }

    #[test]
    fn first_day_windows_carry_ahead_and_behind_pace() {
        let raw = serde_json::json!({
            "five_hour": {"utilization": 50.0, "resets_at": RESET},
            "seven_day": {"utilization": 33.0, "resets_at": RESET},
            "limits": [{"scope": {"model": {"display_name": "Fable"}},
                        "percent": 1.0, "resets_at": RESET}],
        });
        let windows = windows_at(&raw, fetched_at(0.5));
        assert!(windows[0].pace.is_none());
        let ahead = windows[1].pace.as_ref().unwrap();
        assert_eq!(ahead.expected_pct, 7.1);
        assert!(ahead.ahead);
        assert!(!ahead.lasts_to_reset);
        assert!(ahead.exhausts_at.is_some());
        let behind = windows[2].pace.as_ref().unwrap();
        assert_eq!(behind.expected_pct, 7.1);
        assert!(!behind.ahead);
        assert!(behind.lasts_to_reset);

        // A small overshoot still does not trigger the ahead effect.
        assert!(
            !pace_fields(10.0, Some(RESET), fetched_at(0.5))
                .unwrap()
                .ahead
        );
    }

    #[test]
    fn pace_expects_the_elapsed_fraction_of_the_week() {
        // Half the week gone -> 50% is "on schedule".
        let pace = pace_fields(50.0, Some(RESET), fetched_at(3.5)).unwrap();
        assert_eq!(pace.expected_pct, 50.0);
        assert!(!pace.ahead);
        assert!(pace.lasts_to_reset);
        // At an exactly-on-pace rate the projection lands on the reset itself.
        assert_eq!(pace.exhausts_at.as_deref(), Some(RESET));

        // 15 points over expectation is the threshold, and the projection then
        // overshoots the reset.
        let pace = pace_fields(65.0, Some(RESET), fetched_at(3.5)).unwrap();
        assert!(pace.ahead);
        assert!(!pace.lasts_to_reset);
        let pace = pace_fields(64.9, Some(RESET), fetched_at(3.5)).unwrap();
        assert!(!pace.ahead);
        // Under the marker's threshold but still over expected: the unthresholded
        // signal says it will not last.
        assert!(!pace.lasts_to_reset);
    }

    #[test]
    fn pace_without_usage_lasts_and_has_no_eta() {
        let pace = pace_fields(0.0, Some(RESET), fetched_at(3.5)).unwrap();
        assert!(pace.lasts_to_reset);
        assert_eq!(pace.exhausts_at, None);
    }

    #[test]
    fn pace_rolls_a_stale_reset_forward() {
        // A `resets_at` a whole cycle behind the fetch describes the same phase
        // of the week as one a cycle ahead.
        let fresh = pace_fields(50.0, Some(RESET), fetched_at(3.5)).unwrap();
        let stale = pace_fields(50.0, Some(RESET), fetched_at(3.5) + WEEKLY_PERIOD_S).unwrap();
        assert_eq!(fresh.expected_pct, stale.expected_pct);
    }

    #[test]
    fn a_response_becomes_one_window_per_reported_limit() {
        let raw = serde_json::json!({
            "five_hour": {"utilization": 10.0},
            "seven_day": {"utilization": 20.0},
            "extra_usage": {"is_enabled": true, "used_credits": 500,
                            "monthly_limit": 10000, "utilization": 99.0},
            "limits": [{"scope": {"model": {"display_name": "Fable"}}, "percent": 80.0}],
        });
        let windows = windows_at(&raw, fetched_at(3.5));
        let kinds: Vec<_> = windows.iter().map(|w| w.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WindowKind::FiveHour,
                WindowKind::SevenDay,
                WindowKind::Spend,
                WindowKind::Scoped
            ]
        );
        assert_eq!(windows[3].name.as_deref(), Some("Fable"));
        assert!((windows[3].pct - 80.0).abs() < 1e-9);
    }

    #[test]
    fn spend_is_skipped_when_any_of_the_three_is_null() {
        let base = |limit: Value| {
            serde_json::json!({
                "extra_usage": {"is_enabled": true, "used_credits": 500,
                                "monthly_limit": limit, "utilization": 5.0}
            })
        };
        assert!(windows_at(&base(Value::Null), 0.0).is_empty());
        assert_eq!(windows_at(&base(Value::from(10000)), 0.0).len(), 1);
        // Disabled extra usage yields nothing either.
        let off = serde_json::json!({
            "extra_usage": {"is_enabled": false, "used_credits": 500,
                            "monthly_limit": 10000, "utilization": 5.0}
        });
        assert!(windows_at(&off, 0.0).is_empty());
    }
}
