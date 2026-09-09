//! Cadence policy for the usage endpoint — every number in one place.
//!
//! Port of cswap `poll_policy.py` (the constants, `binding_pct`,
//! `limiting_reset_ts`, `earliest_future_reset_ts`, `parse_reset_ts`,
//! `plan_after_fetch`).
//!
//! The endpoint budgets *usage requests* on non-first-party clients: roughly a
//! trailing hour of ~28-30 requests per budget identity, capacity returning
//! only as old requests age out (measured 2026-07-11; see the Python module's
//! docstring for the probe detail). It is not a leaky bucket, so a burst
//! saturates the identity for up to a full hour and pausing does not restore
//! headroom early. Everything below leans only on the robust parts of that
//! shape: a sustained rate safely under the cap (target: one request per three
//! minutes per account) and an ~hour recovery horizon.
//!
//! Plans computed here are persisted per account by whichever collector
//! fetched (`core::usage_store`), so every surface inherits one cadence no
//! matter how often it repaints.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::contract::Window;
use crate::driver::claude::usage::{headroom, relevant};

/// Freshness floor shared by every collector: an entry younger than this is
/// served from the store without any fetch, so the maximum sustained rate on
/// one token is 1/`SERVE_TTL_S` regardless of how many surfaces are open.
pub const SERVE_TTL_S: f64 = 180.0;

/// Normal cadence floor — movement can halve an interval down to this, never
/// below.
pub const MIN_INTERVAL_S: f64 = 180.0;

/// Urgent mode: the ACTIVE account, within `ESCALATION_MARGIN_PCT` of the
/// switch threshold, with movement observed this poll. Bounded by
/// construction: either the threshold is crossed (the engine switches away) or
/// the movement stops (the next poll decays back to `MIN_INTERVAL_S`).
pub const URGENT_INTERVAL_S: f64 = 60.0;

/// Decay ceiling for an active account whose usage is not moving.
pub const ACTIVE_MAX_INTERVAL_S: f64 = 300.0;
/// Starting cadence for a candidate with no learned interval.
pub const CANDIDATE_DEFAULT_INTERVAL_S: f64 = 300.0;
/// Decay ceiling for an idle candidate: ten minutes.
pub const CANDIDATE_MAX_INTERVAL_S: f64 = 600.0;

/// Exhaustion is stable enough to poll slowly, but not to stop polling until a
/// reported reset: quota grants and provider-side corrections can make an
/// account usable early, and decision-grade status must not age into
/// "unavailable" while the scheduler waits.
pub const EXHAUSTED_INTERVAL_S: f64 = 600.0;

/// A window whose binding pct moved at least this much between polls is being
/// consumed somewhere (this machine, another PC, session mode) → tighten.
pub const MOVEMENT_DELTA_PCT: f64 = 1.0;

/// ±fraction applied to each scheduled interval so independent processes drift
/// apart instead of fetching in lockstep.
pub const JITTER_FRAC: f64 = 0.1;

/// Reaction to a 429 with `Retry-After: 0` (the saturated-window edge): probe
/// at most every 5 minutes so aging-out outpaces the probing.
pub const EDGE_BACKOFF_S: f64 = 300.0;
/// While any 429 was seen on the token recently, floor the planned cadence
/// here so freed capacity accumulates instead of being re-spent.
pub const POST_429_MIN_INTERVAL_S: f64 = 360.0;
/// How long a 429 keeps the post-429 cadence: a full trailing hour takes up to
/// 60 minutes to age out.
pub const RECENT_429_WINDOW_S: f64 = 3600.0;

/// AIMD growth factor while 429s recur. The budget is shared across every
/// machine polling the same account, none can see the others, and the endpoint
/// exposes no remaining-request count — so each success grows the interval
/// until the combined rate fits under the budget (TCP-style, no shared state).
pub const POST_429_BACKOFF_MULT: f64 = 1.5;
/// Ceiling for that growth — wider than the normal candidate ceiling so
/// several machines can each retreat far enough.
pub const POST_429_MAX_INTERVAL_S: f64 = 1800.0;

/// The engine escalates to a full candidate refresh when the active account is
/// within this margin of the threshold; urgent mode keys on the same band.
pub const ESCALATION_MARGIN_PCT: f64 = 15.0;

/// Never schedule a poll later than a known window reset (+ slack): stored
/// usage is obsolete the moment the window rolls over.
pub const RESET_SLACK_S: f64 = 60.0;

/// Utilization of the binding (worst) relevant window, or `None`
/// (`poll_policy.py:150-153`).
pub fn binding_pct(windows: &[Window], models: &[String]) -> Option<f64> {
    headroom(windows, models).map(|h| 100.0 - h)
}

/// Epoch when the last of the ≥100% relevant windows resets — i.e. when the
/// account is usable again (`poll_policy.py:156-166`).
pub fn limiting_reset_ts(windows: &[Window], models: &[String]) -> Option<f64> {
    let mut latest: Option<f64> = None;
    for w in relevant(windows, models) {
        if w.pct < 100.0 {
            continue;
        }
        if let Some(ts) = parse_reset_ts(w.resets_at.as_deref()) {
            if latest.is_none_or(|l| ts > l) {
                latest = Some(ts);
            }
        }
    }
    latest
}

/// Epoch of the next relevant-window reset ahead of `now`, any utilization
/// (`poll_policy.py:169-180`).
pub fn earliest_future_reset_ts(windows: &[Window], now: f64, models: &[String]) -> Option<f64> {
    let mut earliest: Option<f64> = None;
    for w in relevant(windows, models) {
        if let Some(ts) = parse_reset_ts(w.resets_at.as_deref()) {
            if ts > now && earliest.is_none_or(|e| ts < e) {
                earliest = Some(ts);
            }
        }
    }
    earliest
}

/// An RFC 3339 `resets_at` as unix seconds, `None` when absent or unparseable
/// (`poll_policy.py:183-192`).
pub fn parse_reset_ts(resets_at: Option<&str>) -> Option<f64> {
    let raw = resets_at?;
    if raw.is_empty() {
        return None;
    }
    OffsetDateTime::parse(raw, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp() as f64)
}

/// Everything `plan_after_fetch` reads about one just-fetched account.
pub struct PlanInput<'a> {
    /// The interval the previous plan chose, if any.
    pub prev_interval_s: Option<f64>,
    /// The windows the previous poll measured (movement is against these).
    pub prev: Option<&'a [Window]>,
    /// The windows this poll measured.
    pub new: &'a [Window],
    pub is_active: bool,
    /// The switch threshold, in percent used.
    pub threshold: f64,
    /// Configured scoped-window model names.
    pub models: &'a [String],
    /// Whether this token 429'd recently (`Entry::recent_429`).
    pub recent_429: bool,
    pub now: f64,
}

/// `(next_poll_at, interval_s)` for an account just fetched successfully
/// (`poll_policy.py:195-270`).
///
/// Movement (binding pct changed ≥ `MOVEMENT_DELTA_PCT` since the previous
/// poll) halves the interval, floored at `MIN_INTERVAL_S` — or drops to
/// `URGENT_INTERVAL_S` when the active account is moving inside the escalation
/// band. No movement backs off ×1.5 toward the account's ceiling; unknown
/// utilization uses the default. A recent 429 floors the cadence at
/// `POST_429_MIN_INTERVAL_S` (and suppresses urgent mode) and grows it
/// multiplicatively toward `POST_429_MAX_INTERVAL_S`. The scheduled time gets
/// `JITTER_FRAC` noise and is never later than the account's next window reset
/// (+ `RESET_SLACK_S`). An at-limit account keeps a bounded slow poll instead
/// of sleeping until that reset, so an early provider-side quota grant is
/// observed.
///
/// `rng` yields [0, 1) — production callers pass `rand::random`.
pub fn plan_after_fetch(i: PlanInput, mut rng: impl FnMut() -> f64) -> (f64, f64) {
    let default = if i.is_active {
        MIN_INTERVAL_S
    } else {
        CANDIDATE_DEFAULT_INTERVAL_S
    };
    let ceiling = if i.is_active {
        ACTIVE_MAX_INTERVAL_S
    } else {
        CANDIDATE_MAX_INTERVAL_S
    };
    // Python's `prev_interval_s or default`: a stored 0.0 is falsy there too.
    let base = match i.prev_interval_s {
        Some(v) if v != 0.0 => v,
        _ => default,
    };
    let prev_pct = i.prev.and_then(|w| binding_pct(w, i.models));
    let new_pct = binding_pct(i.new, i.models);

    let (moving, mut interval) = match (prev_pct, new_pct) {
        (Some(prev_pct), Some(new_pct)) if (new_pct - prev_pct).abs() >= MOVEMENT_DELTA_PCT => {
            (true, MIN_INTERVAL_S.max(base / 2.0))
        }
        (Some(_), Some(_)) => (
            // Floored so a sub-floor base (urgent mode's 60s) snaps straight
            // back to the normal cadence once movement stops, instead of
            // decaying through 90s/135s polls the budget never intended.
            false,
            ceiling.min(MIN_INTERVAL_S.max(base * 1.5)),
        ),
        _ => (false, default),
    };

    if i.is_active && moving && !i.recent_429 {
        if let Some(new_pct) = new_pct {
            if new_pct >= i.threshold - ESCALATION_MARGIN_PCT {
                interval = URGENT_INTERVAL_S;
            }
        }
    }
    if i.recent_429 {
        // AIMD additive-increase: grow the interval multiplicatively from the
        // last one toward the wider 429 ceiling, so machines sharing a
        // contended token each retreat until their combined rate fits the
        // budget. Floored at POST_429_MIN_INTERVAL_S for the first 429.
        let increased = (base * POST_429_BACKOFF_MULT).max(POST_429_MIN_INTERVAL_S);
        interval = POST_429_MAX_INTERVAL_S.min(interval.max(increased));
    }

    let head = headroom(i.new, i.models);
    let exhausted = head.is_some_and(|h| h <= 0.0);
    if exhausted {
        // Keep probing exhausted accounts: quota can be granted or reset
        // before the previously advertised timestamp. Preserve a wider
        // post-429 interval if congestion control already selected one.
        interval = interval.max(EXHAUSTED_INTERVAL_S);
    }

    let mut next_poll = i.now + interval * (1.0 + JITTER_FRAC * (2.0 * rng() - 1.0));
    if exhausted {
        if let Some(reset_ts) = limiting_reset_ts(i.new, i.models) {
            if reset_ts > i.now {
                next_poll = next_poll.min(reset_ts + RESET_SLACK_S);
            }
        }
    } else if let Some(reset_ts) = earliest_future_reset_ts(i.new, i.now, i.models) {
        next_poll = next_poll.min(reset_ts + RESET_SLACK_S);
    }
    (next_poll, interval)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::WindowKind;

    /// A 5-hour window at `pct`, with an optional reset stamp.
    fn window(pct: f64, resets_at: Option<&str>) -> Window {
        Window {
            kind: WindowKind::FiveHour,
            name: None,
            pct,
            resets_at: resets_at.map(str::to_string),
            pace: None,
            used: None,
            limit: None,
            currency: None,
        }
    }

    /// Jitter-free: `2 * 0.5 - 1 == 0`.
    fn no_jitter() -> impl FnMut() -> f64 {
        || 0.5
    }

    const NOW: f64 = 1_800_000_000.0;

    fn plan<'a>(
        prev_interval_s: Option<f64>,
        prev: Option<&'a [Window]>,
        new: &'a [Window],
        is_active: bool,
        recent_429: bool,
    ) -> (f64, f64) {
        plan_after_fetch(
            PlanInput {
                prev_interval_s,
                prev,
                new,
                is_active,
                threshold: 80.0,
                models: &[],
                recent_429,
                now: NOW,
            },
            no_jitter(),
        )
    }

    #[test]
    fn movement_halves_interval_floored_at_min() {
        let prev = [window(10.0, None)];
        let new = [window(20.0, None)];
        // A learned 600s candidate interval halves.
        let (next, interval) = plan(Some(600.0), Some(&prev), &new, false, false);
        assert_eq!(interval, 300.0);
        assert_eq!(next, NOW + 300.0);
        // The halving never goes below the floor.
        let (_, interval) = plan(Some(200.0), Some(&prev), &new, false, false);
        assert_eq!(interval, MIN_INTERVAL_S);
        // Sub-threshold movement is no movement.
        let barely = [window(10.5, None)];
        let (_, interval) = plan(Some(600.0), Some(&prev), &barely, false, false);
        assert_eq!(interval, CANDIDATE_MAX_INTERVAL_S);
    }

    #[test]
    fn no_movement_backs_off_1_5x_to_ceiling() {
        let prev = [window(10.0, None)];
        let new = [window(10.0, None)];
        let (_, interval) = plan(Some(200.0), Some(&prev), &new, false, false);
        assert_eq!(interval, 300.0);
        let (_, interval) = plan(Some(300.0), Some(&prev), &new, false, false);
        assert_eq!(interval, 450.0);
        // Capped at the candidate ceiling...
        let (_, interval) = plan(Some(450.0), Some(&prev), &new, false, false);
        assert_eq!(interval, CANDIDATE_MAX_INTERVAL_S);
        // ...and at the tighter active one.
        let (_, interval) = plan(Some(450.0), Some(&prev), &new, true, false);
        assert_eq!(interval, ACTIVE_MAX_INTERVAL_S);
        // A sub-floor base (urgent mode's 60s) snaps back to the floor rather
        // than decaying through 90s.
        let (_, interval) = plan(Some(URGENT_INTERVAL_S), Some(&prev), &new, true, false);
        assert_eq!(interval, MIN_INTERVAL_S);
        // Unknown utilization on either side uses the default, not the curve.
        let (_, interval) = plan(Some(450.0), None, &new, true, false);
        assert_eq!(interval, MIN_INTERVAL_S);
        let (_, interval) = plan(Some(450.0), Some(&prev), &[], false, false);
        assert_eq!(interval, CANDIDATE_DEFAULT_INTERVAL_S);
    }

    #[test]
    fn active_moving_near_threshold_is_urgent() {
        let prev = [window(60.0, None)];
        // Threshold 80, margin 15 → the band opens at 65%.
        let inside = [window(66.0, None)];
        let (_, interval) = plan(Some(300.0), Some(&prev), &inside, true, false);
        assert_eq!(interval, URGENT_INTERVAL_S);
        // Below the band: plain halving.
        let outside = [window(64.0, None)];
        let (_, interval) = plan(Some(300.0), Some(&prev), &outside, true, false);
        assert_eq!(interval, MIN_INTERVAL_S);
        // A candidate never goes urgent.
        let (_, interval) = plan(Some(300.0), Some(&prev), &inside, false, false);
        assert_eq!(interval, MIN_INTERVAL_S);
        // Nor does a token that 429'd recently.
        let (_, interval) = plan(Some(300.0), Some(&prev), &inside, true, true);
        assert!(interval >= POST_429_MIN_INTERVAL_S);
        // Movement is required: standing still in the band is not urgent.
        let (_, interval) = plan(Some(300.0), Some(&inside), &inside, true, false);
        assert_eq!(interval, ACTIVE_MAX_INTERVAL_S);
    }

    #[test]
    fn recent_429_floors_at_360_and_grows_1_5x() {
        let prev = [window(10.0, None)];
        let new = [window(10.0, None)];
        // Active base 180 → 1.5x is 270, floored to the post-429 minimum.
        let (_, interval) = plan(None, Some(&prev), &new, true, true);
        assert_eq!(interval, POST_429_MIN_INTERVAL_S);
        // Then AIMD growth compounds off the previous interval.
        let (_, interval) = plan(Some(360.0), Some(&prev), &new, true, true);
        assert_eq!(interval, 540.0);
        let (_, interval) = plan(Some(540.0), Some(&prev), &new, true, true);
        assert_eq!(interval, 810.0);
        let (_, interval) = plan(Some(810.0), Some(&prev), &new, true, true);
        assert_eq!(interval, 1215.0);
        // Capped at the wider 429 ceiling.
        let (_, interval) = plan(Some(1215.0), Some(&prev), &new, true, true);
        assert_eq!(interval, POST_429_MAX_INTERVAL_S);
        let (_, interval) = plan(Some(POST_429_MAX_INTERVAL_S), Some(&prev), &new, true, true);
        assert_eq!(interval, POST_429_MAX_INTERVAL_S);
    }

    #[test]
    fn exhausted_polls_every_600_capped_at_reset_plus_slack() {
        let prev = [window(99.0, None)];
        let reset = "2027-01-01T00:00:00Z";
        let reset_ts = parse_reset_ts(Some(reset)).unwrap();
        // At 100% the interval is at least the exhausted cadence, even though
        // movement would otherwise have halved it.
        let new = [window(100.0, Some(reset))];
        let now = reset_ts - 5000.0;
        let (next, interval) = plan_after_fetch(
            PlanInput {
                prev_interval_s: Some(300.0),
                prev: Some(&prev),
                new: &new,
                is_active: true,
                threshold: 80.0,
                models: &[],
                recent_429: false,
                now,
            },
            no_jitter(),
        );
        assert_eq!(interval, EXHAUSTED_INTERVAL_S);
        assert_eq!(next, now + EXHAUSTED_INTERVAL_S);
        // Close to the limiting reset the poll is pulled to it (+ slack).
        let now = reset_ts - 100.0;
        let (next, interval) = plan_after_fetch(
            PlanInput {
                prev_interval_s: Some(300.0),
                prev: Some(&prev),
                new: &new,
                is_active: true,
                threshold: 80.0,
                models: &[],
                recent_429: false,
                now,
            },
            no_jitter(),
        );
        assert_eq!(interval, EXHAUSTED_INTERVAL_S);
        assert_eq!(next, reset_ts + RESET_SLACK_S);
        // A limiting reset already in the past does not pull the poll back.
        let now = reset_ts + 10.0;
        let (next, _) = plan_after_fetch(
            PlanInput {
                prev_interval_s: Some(300.0),
                prev: Some(&prev),
                new: &new,
                is_active: true,
                threshold: 80.0,
                models: &[],
                recent_429: false,
                now,
            },
            no_jitter(),
        );
        assert_eq!(next, now + EXHAUSTED_INTERVAL_S);
    }

    #[test]
    fn next_poll_never_after_next_reset_plus_slack() {
        let reset = "2027-01-01T00:00:00Z";
        let reset_ts = parse_reset_ts(Some(reset)).unwrap();
        let prev = [window(10.0, Some(reset))];
        let new = [window(10.0, Some(reset))];
        // A healthy account 100s from its reset polls at the rollover, not at
        // its (much longer) planned interval.
        let now = reset_ts - 100.0;
        let (next, interval) = plan_after_fetch(
            PlanInput {
                prev_interval_s: Some(600.0),
                prev: Some(&prev),
                new: &new,
                is_active: false,
                threshold: 80.0,
                models: &[],
                recent_429: false,
                now,
            },
            no_jitter(),
        );
        assert_eq!(interval, CANDIDATE_MAX_INTERVAL_S);
        assert_eq!(next, reset_ts + RESET_SLACK_S);
        // A reset already past is not a deadline at all.
        let now = reset_ts + 10.0;
        let (next, _) = plan_after_fetch(
            PlanInput {
                prev_interval_s: Some(600.0),
                prev: Some(&prev),
                new: &new,
                is_active: false,
                threshold: 80.0,
                models: &[],
                recent_429: false,
                now,
            },
            no_jitter(),
        );
        assert_eq!(next, now + CANDIDATE_MAX_INTERVAL_S);
    }

    #[test]
    fn jitter_stays_within_the_fraction() {
        let prev = [window(10.0, None)];
        let new = [window(10.0, None)];
        // No movement off the 300s default: the interval decays to 450s, and
        // only the scheduled time carries the noise.
        for (r, expected) in [(0.0, 450.0 * 0.9), (1.0, 450.0 * 1.1)] {
            let (next, interval) = plan_after_fetch(
                PlanInput {
                    prev_interval_s: None,
                    prev: Some(&prev),
                    new: &new,
                    is_active: false,
                    threshold: 80.0,
                    models: &[],
                    recent_429: false,
                    now: NOW,
                },
                || r,
            );
            assert_eq!(interval, 450.0);
            assert!((next - (NOW + expected)).abs() < 1e-6, "{next}");
        }
    }

    #[test]
    fn reset_helpers_pick_the_right_window() {
        let windows = [
            window(100.0, Some("2027-01-01T00:00:00Z")),
            Window {
                kind: WindowKind::SevenDay,
                name: None,
                pct: 100.0,
                resets_at: Some("2027-01-03T00:00:00Z".to_string()),
                pace: None,
                used: None,
                limit: None,
                currency: None,
            },
        ];
        let five = parse_reset_ts(Some("2027-01-01T00:00:00Z")).unwrap();
        let seven = parse_reset_ts(Some("2027-01-03T00:00:00Z")).unwrap();
        // Usable again only once the LAST at-limit window resets...
        assert_eq!(limiting_reset_ts(&windows, &[]), Some(seven));
        // ...but the snapshot is obsolete at the FIRST reset ahead of now.
        assert_eq!(
            earliest_future_reset_ts(&windows, five - 1.0, &[]),
            Some(five)
        );
        assert_eq!(
            earliest_future_reset_ts(&windows, five + 1.0, &[]),
            Some(seven)
        );
        assert_eq!(earliest_future_reset_ts(&windows, seven + 1.0, &[]), None);
        // Under 100% a window does not gate recovery.
        let below = [window(99.9, Some("2027-01-01T00:00:00Z"))];
        assert_eq!(limiting_reset_ts(&below, &[]), None);
        // Unparseable or absent stamps contribute nothing.
        assert_eq!(parse_reset_ts(None), None);
        assert_eq!(parse_reset_ts(Some("")), None);
        assert_eq!(parse_reset_ts(Some("not a date")), None);
        assert_eq!(parse_reset_ts(Some("2027-01-01T00:00:00Z")), Some(five));
        assert_eq!(
            parse_reset_ts(Some("2027-01-01T00:00:00+00:00")),
            Some(five)
        );
    }
}
