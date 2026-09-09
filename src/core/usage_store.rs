//! Per-account usage table: last-known-good measurements + fetch/backoff state.
//!
//! Port of cswap `usage_store.py` (the constants, `UsageEntry`, `_earliest_reset`,
//! `_carry_weekly_reset`, `_rate_limited_trust_ok`, `_failure_backoff_s`,
//! `UsageStore`, `_row_eligible`, `due_candidate`, `plan_oversleeps_interval`).
//!
//! One failed round trip never blanks an account: a failure updates the
//! error/backoff fields and leaves the last-good measurement alone
//! (stale-on-error). The table is shared by the on-demand surfaces (`list`,
//! `status`) and the scheduled collector, so each learns from the other's
//! fetches.
//!
//! Locking protocol (the lock is never held across network I/O):
//! (a) lock → read, decide/claim the fetch set (stamp `claimUntil`) → unlock;
//! (b) fetch with no lock held;
//! (c) lock → re-read, merge the outcome fenced by the claim id, write →
//! unlock. The bounded lease lets a concurrent collector skip an account
//! another process is still fetching, and a crashed claimer's lease ages out.
//!
//! Rows hold windows and timestamps only — never a token, never a credential.

use std::collections::btree_map::Entry as MapEntry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::contract::{Window, WindowKind};
use crate::core::poll_policy::{
    self, parse_reset_ts, plan_after_fetch, PlanInput, EDGE_BACKOFF_S, RECENT_429_WINDOW_S,
    SERVE_TTL_S,
};
use crate::core::store::{read_json, write_json_atomic, FileLock};
use crate::driver::claude::usage::{format_ts, relevant};
use crate::errors::Result;

/// `usage.json`'s schema. A file at any other version (including a version-less
/// legacy one) is read as empty: its data had a serve-TTL shelf life anyway.
pub const SCHEMA_VERSION: u32 = 2;

/// Trusted for switch decisions; older → headroom unknown. Freshness is the
/// reader's judgment per purpose, not a global TTL — `SERVE_TTL_S` (fresher
/// than this → serve without fetching) doubles as the per-account
/// sustained-rate governor.
pub const STALE_OK_S: f64 = 300.0;

/// In-flight claim window: skip just-claimed accounts. Covers the bounded
/// refresh + usage path and the whole batch's stagger, so another surface
/// cannot reclaim a request that is still in flight; a crashed collector's
/// 90 s lease still ages out below the provider-safe polling interval.
pub const CLAIM_TTL_S: f64 = 90.0;

/// Deliberate staleness (failure backoff, scheduler-chosen cadence) extends
/// decision trust past `STALE_OK_S`, never past this: a forever-failing
/// account must eventually read as unknown so the unknown-path machinery takes
/// over. Deliberately overrides even a longer `Retry-After` — trust must never
/// be server-controlled and unbounded.
pub const TRUST_MAX_AGE_S: f64 = 3600.0;

/// Fallback ceiling for 429-stale data carrying no `resets_at`. A usage 429 is
/// a polling throttle, not a change in the account's real quota: usage only
/// rises within a window, so last-good stays a valid lower bound until that
/// window resets. Bounded anyway so it can't be trusted forever.
pub const RATE_LIMIT_TRUST_MAX_AGE_S: f64 = 7200.0;

/// Failure backoff when the server sent no `Retry-After`: 30 s · 2^(n-1),
/// capped at `BACKOFF_CAP_S`.
pub const BACKOFF_BASE_S: f64 = 30.0;
pub const BACKOFF_CAP_S: f64 = 600.0;
/// Exponent clamp: a permanently failing account increments its failure count
/// forever. The curve saturates at the cap by shift 5, so any clamp above that
/// is behaviour-preserving.
pub const BACKOFF_MAX_SHIFT: u32 = 32;

/// Honoring `Retry-After` exactly is not enough: the retry lands ON the
/// deadline, where the server is not reliably ready (measured over a full log:
/// 20 of 35 lapsed blocks re-blocked within 900 s of their own deadline, each
/// for a fresh hour). The margin is absolute, not a fraction of the ask — the
/// header counts down to a fixed deadline, so a machine polling into a block
/// another one opened sees only the remainder.
pub const RETRY_AFTER_MARGIN_S: f64 = 900.0;
/// Bounds `Retry-After` + margin so a pathological header cannot park a row for
/// hours: 40 of 41 observed blocks opened at exactly 3600 s, and 3600 + 900 is
/// this.
pub const RETRY_AFTER_FLOOR_CAP_S: f64 = 4500.0;

/// Strikes before the refresh-token lineage counts as dead. One
/// `invalid_grant` is already definitive — the server explicitly rejected the
/// grant, which no transient 429/timeout does — so there is nothing to gain by
/// retrying, and each retry with a dead token just draws a fresh 401/429.
pub const AUTH_DEAD_STRIKES: u32 = 1;

/// Fetch errors that prove the stored credential is permanently unusable (vs.
/// transient 429/timeout/network). Only these condemn a token; everything else
/// is no evidence the token is alive *or* dead.
pub const PERMANENT_AUTH_ERRORS: [&str; 2] = ["invalid_grant", "no_refresh_token"];

/// Anthropic's weekly window resets on a fixed per-account slot.
const WEEK_S: f64 = 7.0 * 24.0 * 3600.0;

/// Whether `kind` proves the stored credential is permanently unusable rather
/// than merely throttled — i.e. whether the failure also strikes the token.
pub fn is_permanent_auth_error(kind: &str) -> bool {
    PERMANENT_AUTH_ERRORS.contains(&kind)
}

/// One account's stored row. Windows and timestamps only — no secrets.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Row {
    /// The identity this row's measurements belong to. A row whose stored
    /// identity differs from the caller's is invisible to reads and replaced on
    /// write, so slot reuse never serves the previous account's usage.
    pub email: String,
    pub org: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_good: Option<Vec<Window>>,
    /// When `last_good` was measured — written on success only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<f64>,
    pub consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoff_until: Option<f64>,
    /// When this token last answered 429 (any `Retry-After`). Deliberately NOT
    /// cleared by a later success — see `Entry::recent_429`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_429_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_poll_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_until: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    /// Consecutive permanent-auth failures. At `AUTH_DEAD_STRIKES` the token is
    /// quarantined until a success or a credential rewrite.
    pub auth_dead_strikes: u32,
    /// Fingerprint of the credential generation the strikes condemned: strikes
    /// bind to it, so any credential-writing path heals them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_fingerprint: Option<String>,
}

/// `usage.json` as stored.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct UsageFile {
    schema_version: u32,
    rows: BTreeMap<String, Row>,
}

/// Read model of one account's usage state at collect time. `age_s` and
/// `trust_extended` are computed at snapshot time; everything else mirrors the
/// stored row.
///
/// cswap's `sentinel` overlay ("api key", "token expired", ...) is not here: it
/// is derived fresh by the collector on every pass and never persisted, so it
/// belongs to Task 9's read path, not to the store.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub last_good: Option<Vec<Window>>,
    pub fetched_at: Option<f64>,
    /// Age of `last_good`.
    pub age_s: Option<f64>,
    pub last_attempt_at: Option<f64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub backoff_until: Option<f64>,
    pub next_poll_at: Option<f64>,
    pub interval_s: Option<f64>,
    pub last_429_at: Option<f64>,
    pub auth_dead_strikes: u32,
    pub dead_fingerprint: Option<String>,
    /// Staleness past `STALE_OK_S` is still decision-trusted when it is
    /// *deliberate*: the server is refusing fresher data (failure state), or
    /// the scheduler itself chose the cadence. Capped at the trust ceiling.
    pub trust_extended: bool,
    pub claim_until: Option<f64>,
}

impl Entry {
    /// Fresh enough to serve without fetching (`usage_store.py:307`).
    // The collector asks `reserve` instead, which re-checks this under the lock;
    // the auto engine's own eligibility pass reads it directly.
    pub fn fresh(&self, now: f64) -> bool {
        self.fetched_at.is_some_and(|f| (now - f) <= SERVE_TTL_S)
    }

    // Same: `reserve` gates on it, the auto engine reports it.
    #[allow(dead_code)]
    pub fn in_backoff(&self, now: f64) -> bool {
        self.backoff_until.is_some_and(|b| now < b)
    }

    /// Whether this token 429'd recently enough to keep the post-429 cadence
    /// (`usage_store.py:313-341`).
    ///
    /// Recency is measured from when the 429's honored backoff *lifts*, not
    /// from the 429 itself: an hour-scale `Retry-After` is honored as one long
    /// backoff during which no attempt runs, so measuring from the stamp would
    /// make the first post-block success see a window that has already fully
    /// elapsed — the AIMD growth and the post-429 floor would never engage.
    /// The `last_error` guard keeps an unrelated later timeout (which rewrites
    /// `backoff_until`) from re-arming the cadence.
    pub fn recent_429(&self, now: f64) -> bool {
        let Some(stamp) = self.last_429_at else {
            return false;
        };
        let mut anchor = stamp;
        if self.last_error.as_deref() == Some("http-429") {
            if let Some(until) = self.backoff_until {
                if until > anchor {
                    anchor = until;
                }
            }
        }
        now < anchor + RECENT_429_WINDOW_S
    }

    /// Whether another collector's bounded fetch lease is still live.
    // Read by the auto engine; the collector's own claims come from `reserve`.
    #[allow(dead_code)]
    pub fn claimed(&self, now: f64) -> bool {
        live_claim(self.claim_until, now)
    }

    /// Whether the stored credential's refresh-token lineage is provably dead
    /// (`usage_store.py:349-374`).
    ///
    /// Strikes condemn the credential GENERATION that was POSTed, not the slot:
    /// when the caller passes the currently-stored credential's fingerprint and
    /// it differs from the struck one, the credential has been replaced since
    /// the verdict and the strike no longer applies.
    pub fn token_dead(&self, stored_fp: Option<&str>) -> bool {
        if self.auth_dead_strikes < AUTH_DEAD_STRIKES {
            return false;
        }
        // A strike recorded before fingerprints existed, or a caller with no
        // credential in hand, binds unconditionally.
        !matches!(
            (stored_fp, self.dead_fingerprint.as_deref()),
            (Some(stored), Some(struck)) if stored != struck
        )
    }

    /// The windows switch decisions run on (`usage_store.py:376-392`):
    /// last-good while it is recent enough to trust, else `None` (unknown).
    /// Display code reads `last_good`/`age_s` directly instead — it may show
    /// older data, annotated with its age.
    pub fn decision_windows(&self) -> Option<&[Window]> {
        let windows = self.last_good.as_deref()?;
        let age_s = self.age_s?;
        if age_s <= STALE_OK_S || self.trust_extended {
            Some(windows)
        } else {
            None
        }
    }
}

/// Whether a collector's fetch lease on a row is still live. The single source
/// of truth — `Entry::claimed`, `entries()` and `row_eligible` must all agree,
/// or concurrent collectors double-fetch. (cswap's `lastAttemptAt` fallback for
/// rows written by pre-lease collectors has no counterpart here: swapd has no
/// older writers.)
fn live_claim(claim_until: Option<f64>, now: f64) -> bool {
    claim_until.is_some_and(|until| now < until)
}

/// Whether a deadline cannot have come from the bounded planner
/// (`usage_store.py:395-421`).
///
/// Reset-parking stored a distant reset deadline while retaining the much
/// shorter learned interval. Detect that impossible shape structurally,
/// independent of the current model selection, so changing scoped models cannot
/// leave an otherwise usable account parked until the old reset.
// The scheduler (Task 12) passes this to its repair pass.
#[allow(dead_code)]
pub fn plan_oversleeps_interval(entry: &Entry, now: f64) -> bool {
    let Some(next_poll_at) = entry.next_poll_at else {
        return false;
    };
    let interval = entry
        .interval_s
        .unwrap_or(poll_policy::EXHAUSTED_INTERVAL_S)
        .max(poll_policy::EXHAUSTED_INTERVAL_S);
    let latest_normal_poll =
        now + interval * (1.0 + poll_policy::JITTER_FRAC) + poll_policy::RESET_SLACK_S;
    next_poll_at > latest_normal_poll
}

/// The due candidate with the stalest data, or `None` (`usage_store.py:424-467`).
///
/// Due = past its `next_poll_at` and not in failure backoff. A dead token is
/// quarantined; a perpetually failing account can't monopolize the slot,
/// because its backoff removes it from the due set between attempts. Shared by
/// every surface so all pick the same single alternate to poll per pass.
// The auto engine (Task 12) picks its candidate through this.
#[allow(dead_code)]
pub fn due_candidate(
    candidates: &[String],
    entries: &BTreeMap<String, Entry>,
    now: f64,
) -> Option<String> {
    let mut due: Vec<(u8, f64, &str)> = Vec::new();
    for key in candidates {
        let Some(entry) = entries.get(key) else {
            due.push((0, 0.0, key));
            continue;
        };
        if entry.token_dead(None) || entry.in_backoff(now) {
            continue;
        }
        if entry
            .next_poll_at
            .is_some_and(|next| now < next && !plan_oversleeps_interval(entry, now))
        {
            continue;
        }
        match entry.fetched_at {
            None => due.push((0, 0.0, key)),
            Some(at) => due.push((1, at, key)),
        }
    }
    due.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.total_cmp(&b.1))
            .then_with(|| a.2.cmp(b.2))
    });
    due.first().map(|(_, _, key)| (*key).to_string())
}

/// Epoch of the soonest relevant window to roll over (`usage_store.py:470-485`).
///
/// The soonest one is what matters: once it resets, usage there is zeroed and
/// the whole snapshot is obsolete, so a later window cannot rescue it. Windows
/// carrying no `resets_at` contribute nothing rather than a guess.
fn earliest_reset(windows: &[Window], models: &[String]) -> Option<f64> {
    relevant(windows, models)
        .into_iter()
        .filter_map(|w| parse_reset_ts(w.resets_at.as_deref()))
        .reduce(f64::min)
}

/// Pin a missing weekly `resets_at` from the previous measurement
/// (`usage_store.py:488-508`).
///
/// The usage endpoint omits `resets_at` for some tokens while utilization is 0,
/// but a window measured before pins the account's fixed weekly slot: step that
/// reset forward by whole weeks to the first instant after `now`. 7-day only —
/// the 5-hour window is rolling from first use, so there is nothing to infer.
///
/// (cswap also stamps `resets_at_inferred` and precomputed countdown/clock
/// strings; neither is part of this contract's `Window`.)
fn carry_weekly_reset(new: &mut [Window], previous: &[Window], now: f64) {
    let Some(target) = new
        .iter_mut()
        .find(|w| w.kind == WindowKind::SevenDay && w.resets_at.is_none())
    else {
        return;
    };
    let Some(mut ts) = previous
        .iter()
        .find(|w| w.kind == WindowKind::SevenDay)
        .and_then(|w| parse_reset_ts(w.resets_at.as_deref()))
    else {
        return;
    };
    while ts <= now {
        ts += WEEK_S;
    }
    target.resets_at = format_ts(ts);
}

/// Whether 429-stale `last_good` is still trustworthy for decisions
/// (`usage_store.py:511-550`).
///
/// Usage rises monotonically within a window, so a rate-limited (frozen)
/// last-good is a valid lower bound until its window resets — bounded by a
/// client-side ceiling so a far-future or malformed `resets_at` can never grant
/// unbounded trust:
///
/// `now < min(earliest future relevant-window reset, age ceiling)`
///
/// The *earliest* reset, not the latest: once the soonest window rolls over the
/// snapshot is obsolete regardless of any farther-future window. A window with
/// no `resets_at` contributes no timestamp, so partial metadata can only
/// tighten the bound, never loosen it.
fn rate_limited_trust_ok(
    last_good: Option<&[Window]>,
    age_s: Option<f64>,
    now: f64,
    models: &[String],
) -> bool {
    let Some(age_s) = age_s else {
        return false;
    };
    let ceiling = now + (RATE_LIMIT_TRUST_MAX_AGE_S - age_s);
    match last_good.and_then(|w| earliest_reset(w, models)) {
        Some(soonest) => now < soonest.min(ceiling),
        None => now < ceiling,
    }
}

/// Seconds to stay in backoff after a failed fetch (`usage_store.py:553-843`).
///
/// No header: the plain exponential curve. `Retry-After: 0` on a 429 is the
/// saturated-budget edge — wait `EDGE_BACKOFF_S` before probing again; on any
/// other error it is a "retry now" hint the edge evidence does not cover, so it
/// falls through to the curve. A positive ask is honored, plus
/// `RETRY_AFTER_MARGIN_S` when it is an hour-scale 429 block (the measured
/// re-block band). Every ask is finally bounded by the ceiling its own arm's
/// trust uses, so a pathological header cannot park a row past the point where
/// its data reads unknown.
fn failure_backoff_s(
    consecutive_failures: u32,
    retry_after_s: Option<f64>,
    rate_limited: bool,
) -> f64 {
    let shift = consecutive_failures
        .saturating_sub(1)
        .min(BACKOFF_MAX_SHIFT);
    let computed = (BACKOFF_BASE_S * 2f64.powi(shift as i32)).min(BACKOFF_CAP_S);
    let Some(asked) = retry_after_s else {
        return computed;
    };
    if asked == 0.0 {
        if !rate_limited {
            return computed;
        }
        return computed.clamp(EDGE_BACKOFF_S, BACKOFF_CAP_S);
    }
    // The margin is 429-only: it was measured on usage-endpoint blocks. Only
    // above the cap, because a short ask was separately measured as accurate.
    let asked = if asked > BACKOFF_CAP_S && rate_limited {
        asked + RETRY_AFTER_MARGIN_S
    } else {
        asked
    };
    // Park bound: how long a row may be held un-pollable, capped by the
    // ceiling its own arm's trust actually uses (429 rows keep trust to
    // RATE_LIMIT_TRUST_MAX_AGE_S, everything else to TRUST_MAX_AGE_S).
    let asked = asked.min(if rate_limited {
        RETRY_AFTER_FLOOR_CAP_S
    } else {
        TRUST_MAX_AGE_S
    });
    asked.max(computed)
}

/// Fetch eligibility of a stored row, evaluated under the write lock
/// (`usage_store.py:1215-1246`).
///
/// Always: not quarantined (dead token), not in failure backoff, not claimed
/// within `CLAIM_TTL_S`. Then by caller mode —
/// - `force` (an explicit `refresh --slot`): nothing else blocks.
/// - `respect_plans` (on-demand callers: list/status/switch): the row must be
///   stale *and* poll-due (or have no plan yet).
/// - otherwise (the scheduler's deliberate cadence): poll-due *or* stale — a
///   due row may be re-fetched inside the serve TTL, which is how the bounded
///   urgent cadence beats the TTL.
fn row_eligible(row: &Row, now: f64, respect_plans: bool, force: bool) -> bool {
    if row.auth_dead_strikes >= AUTH_DEAD_STRIKES {
        return false;
    }
    if row.backoff_until.is_some_and(|b| now < b) {
        return false;
    }
    if live_claim(row.claim_until, now) {
        return false;
    }
    if force {
        return true;
    }
    let stale = row.fetched_at.is_none_or(|f| (now - f) > SERVE_TTL_S);
    let poll_due = row.next_poll_at.is_some_and(|next| now >= next);
    if respect_plans {
        return stale && (poll_due || row.next_poll_at.is_none());
    }
    poll_due || stale
}

/// The `usage.json` table. Writes are read-modify-write under
/// `usage.json.lock`; reads are lock-free (writes are atomic replaces).
pub struct UsageStore {
    path: PathBuf,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
    /// Jitter source for the poll planner, in [0, 1).
    rng: Box<dyn Fn() -> f64 + Send + Sync>,
}

/// How long to wait for the table's lock before giving up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

impl UsageStore {
    /// The store at `path` (`Home::usage_file()`), on the system clock.
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            clock: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
            }),
            rng: Box::new(rand::random::<f64>),
        }
    }

    /// The store with an injected clock and jitter source (tests, replay).
    #[allow(dead_code)]
    pub fn with_clock(
        path: &Path,
        clock: Box<dyn Fn() -> f64 + Send + Sync>,
        rng: Box<dyn Fn() -> f64 + Send + Sync>,
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            clock,
            rng,
        }
    }

    pub fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Rows as stored. A file at another schema version reads as empty; a
    /// corrupt one is an error rather than a silent reset (cswap swallows both
    /// — swapd fails loud, so a broken file is fixed instead of overwritten).
    fn read_rows(&self) -> Result<BTreeMap<String, Row>> {
        let file: UsageFile = read_json(&self.path)?;
        if file.schema_version != SCHEMA_VERSION {
            return Ok(BTreeMap::new());
        }
        Ok(file.rows)
    }

    fn write_rows(&self, rows: BTreeMap<String, Row>) -> Result<()> {
        write_json_atomic(
            &self.path,
            &UsageFile {
                schema_version: SCHEMA_VERSION,
                rows,
            },
        )
    }

    fn lock(&self) -> Result<FileLock> {
        FileLock::acquire(&self.path, LOCK_TIMEOUT)
    }

    /// Identity-guarded snapshot for `keys` (`(key, email, org)` triples): an
    /// empty entry when the row is missing or belongs to a different account,
    /// so slot reuse never serves the previous account's usage.
    ///
    /// `models` are the configured scoped-window model names; they let the
    /// 429-stale trust bound honor per-model window resets too, matching the
    /// scheduler's view.
    pub fn entries(
        &self,
        keys: &[(String, String, String)],
        models: &[String],
    ) -> Result<BTreeMap<String, Entry>> {
        let now = self.now();
        let rows = self.read_rows()?;
        let mut out = BTreeMap::new();
        for (key, email, org) in keys {
            let Some(row) = rows.get(key).filter(|row| matches(row, email, org)) else {
                out.insert(key.clone(), Entry::default());
                continue;
            };
            let age_s = row.fetched_at.map(|at| now - at);
            let within_ceiling = if row.last_error.as_deref() == Some("http-429") {
                // A usage 429 throttles polling without moving the account's
                // real windows, so last-good stays a lower bound until the
                // window resets. A timeout/network error is no such evidence
                // and always uses the general ceiling.
                rate_limited_trust_ok(row.last_good.as_deref(), age_s, now, models)
            } else {
                age_s.is_some_and(|age| age <= TRUST_MAX_AGE_S)
            };
            // A live claim keeps the trust bridge up: when another collector
            // just won the fetch, this reader must not flip trusted → unknown
            // for the seconds the result is in flight. Strict `<` on
            // next_poll_at mirrors `row_eligible`: at next_poll_at the row is
            // due, and its staleness no longer scheduler-chosen.
            let trust_extended = within_ceiling
                && (row.consecutive_failures > 0
                    || row.next_poll_at.is_some_and(|next| now < next)
                    || live_claim(row.claim_until, now));
            out.insert(
                key.clone(),
                Entry {
                    last_good: row.last_good.clone(),
                    fetched_at: row.fetched_at,
                    age_s,
                    last_attempt_at: row.last_attempt_at,
                    consecutive_failures: row.consecutive_failures,
                    last_error: row.last_error.clone(),
                    backoff_until: row.backoff_until,
                    next_poll_at: row.next_poll_at,
                    interval_s: row.interval_s,
                    last_429_at: row.last_429_at,
                    auth_dead_strikes: row.auth_dead_strikes,
                    dead_fingerprint: row.dead_fingerprint.clone(),
                    trust_extended,
                    claim_until: row.claim_until,
                },
            );
        }
        Ok(out)
    }

    /// Atomically win the right to fetch: re-check eligibility and stamp a
    /// bounded lease in one locked pass, returning key → fencing id
    /// (`usage_store.py:1013-1094`).
    ///
    /// Deciding eligibility on a lock-free `entries()` read and then claiming
    /// separately lets two collectors both pass the check and both fetch; the
    /// re-check under the lock closes that window. `force` is `refresh --slot`:
    /// it ignores freshness and the plan, but still honors the failure backoff,
    /// a live claim and the dead-token quarantine.
    pub fn reserve(
        &self,
        keys: &[(String, String, String)],
        respect_plans: bool,
        force: bool,
    ) -> Result<BTreeMap<String, String>> {
        if keys.is_empty() {
            return Ok(BTreeMap::new());
        }
        let now = self.now();
        let _lock = self.lock()?;
        let mut rows = self.read_rows()?;
        let mut won = BTreeMap::new();
        for (key, email, org) in keys {
            let fresh = || Row {
                email: email.clone(),
                org: org.clone(),
                ..Row::default()
            };
            let row = match rows.entry(key.clone()) {
                MapEntry::Occupied(slot) if matches(slot.get(), email, org) => {
                    if !row_eligible(slot.get(), now, respect_plans, force) {
                        continue;
                    }
                    slot.into_mut()
                }
                // A row for another identity is the previous account's:
                // replace it wholesale rather than inherit its measurement,
                // its plan or its strikes.
                MapEntry::Occupied(mut slot) => {
                    slot.insert(fresh());
                    slot.into_mut()
                }
                MapEntry::Vacant(slot) => slot.insert(fresh()),
            };
            let claim_id = new_claim_id();
            row.last_attempt_at = Some(now);
            row.claim_id = Some(claim_id.clone());
            row.claim_until = Some(now + CLAIM_TTL_S);
            won.insert(key.clone(), claim_id);
        }
        if !won.is_empty() {
            self.write_rows(rows)?;
        }
        Ok(won)
    }

    /// Merge a successful fetch, fenced by the lease that produced it
    /// (`usage_store.py:1096-1166`). A late writer whose lease was replaced is
    /// ignored without touching the newer row.
    ///
    /// Writes `last_good`/`fetched_at` (an empty `windows` clears the stored
    /// measurement: the fetch succeeded and reported nothing), commits the new
    /// poll plan in the same transaction (so no collector can slip into a
    /// record→replan gap), and
    /// clears the error, the backoff and the dead-token strikes — a success
    /// proves the token alive. `last_429_at` survives: the planner keeps the
    /// cadence floored while the saturated window ages out.
    pub fn record_success(
        &self,
        key: &str,
        claim: &str,
        windows: Vec<Window>,
        is_active: bool,
        threshold: f64,
        models: &[String],
    ) -> Result<()> {
        let now = self.now();
        let _lock = self.lock()?;
        let mut rows = self.read_rows()?;
        let Some(row) = rows.get_mut(key).filter(|row| fenced(row, claim)) else {
            return Ok(());
        };

        // The plan reads the row's pre-update state: `recent_429` anchors on
        // the 429 backoff this success is about to clear, and movement is
        // measured against the last-good this success is about to replace.
        let previous = row.last_good.take().unwrap_or_default();
        let recent_429 = Entry {
            last_error: row.last_error.clone(),
            backoff_until: row.backoff_until,
            last_429_at: row.last_429_at,
            ..Entry::default()
        }
        .recent_429(now);
        let (next_poll_at, interval_s) = plan_after_fetch(
            PlanInput {
                prev_interval_s: row.interval_s,
                prev: Some(&previous),
                new: &windows,
                is_active,
                threshold,
                models,
                recent_429,
                now,
            },
            || (self.rng)(),
        );

        // The carry lands on the stored copy only: the plan is measured on
        // what the endpoint actually reported.
        let mut stored = windows;
        carry_weekly_reset(&mut stored, &previous, now);
        // A response carrying no window data is a successful fetch of nothing
        // (cswap's `lastGood = None`): the row is fresh, and its headroom is
        // unknown rather than the previous, now-superseded measurement.
        row.last_good = if stored.is_empty() {
            None
        } else {
            Some(stored)
        };
        row.fetched_at = Some(now);
        row.last_attempt_at = Some(now);
        row.next_poll_at = Some(next_poll_at);
        row.interval_s = Some(interval_s);
        row.consecutive_failures = 0;
        row.last_error = None;
        row.backoff_until = None;
        row.auth_dead_strikes = 0;
        release_claim(row);
        self.write_rows(rows)
    }

    /// Merge a failed fetch, fenced by its lease (`usage_store.py:1116-1137`).
    /// Never touches `last_good`/`fetched_at` — stale-on-error — so a failing
    /// account keeps its last measurement while its trust ages out.
    ///
    /// `kind` is the classified error (`"http-429"`, `"timeout"`, ...) and
    /// `retry_after` the server's header when it sent one. A permanent auth
    /// error (`is_permanent_auth_error`) additionally strikes the credential
    /// generation `struck_fp` was taken from: at `AUTH_DEAD_STRIKES` the
    /// account is quarantined, fetched no more until a success or a credential
    /// rewrite. A transient error is no evidence the token is alive *or* dead
    /// and leaves the strike count untouched.
    ///
    /// The strike lives here, inside the fence, rather than in a call of its
    /// own: unfenced it would let a writer whose lease has already been
    /// replaced quarantine the row (and drop the live holder's claim, so that
    /// holder's success would be rejected in turn) — recoverable only by hand,
    /// through `clear_dead`.
    pub fn record_failure(
        &self,
        key: &str,
        claim: &str,
        kind: &str,
        retry_after: Option<f64>,
        struck_fp: Option<&str>,
    ) -> Result<()> {
        let now = self.now();
        let _lock = self.lock()?;
        let mut rows = self.read_rows()?;
        let Some(row) = rows.get_mut(key).filter(|row| fenced(row, claim)) else {
            return Ok(());
        };
        let rate_limited = kind == "http-429";
        row.consecutive_failures += 1;
        row.last_error = Some(kind.to_string());
        row.last_attempt_at = Some(now);
        if rate_limited {
            // Kept across later successes: the planner floors the cadence
            // while a 429 is recent (see `Entry::recent_429`).
            row.last_429_at = Some(now);
        }
        row.backoff_until =
            Some(now + failure_backoff_s(row.consecutive_failures, retry_after, rate_limited));
        if is_permanent_auth_error(kind) {
            row.auth_dead_strikes += 1;
            // Always overwritten, never merged: a strike recorded with no
            // fingerprint must bind unconditionally rather than inherit an
            // earlier, already-healed one.
            row.dead_fingerprint = struck_fp.map(str::to_string);
        }
        release_claim(row);
        self.write_rows(rows)
    }

    /// Lift the dead-token quarantine after a re-login rewrote the credential
    /// (`usage_store.py:1185-1211`): the strikes — and the failure state riding
    /// with them — no longer reflect reality, and the account must become
    /// fetch-eligible so the next pass can prove the new token good.
    pub fn clear_dead(&self, key: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut rows = self.read_rows()?;
        let Some(row) = rows.get_mut(key) else {
            return Ok(());
        };
        row.auth_dead_strikes = 0;
        row.dead_fingerprint = None;
        row.consecutive_failures = 0;
        row.last_error = None;
        row.backoff_until = None;
        release_claim(row);
        self.write_rows(rows)
    }
}

fn matches(row: &Row, email: &str, org: &str) -> bool {
    row.email == email && row.org == org
}

/// Whether this writer still holds the row's lease.
fn fenced(row: &Row, claim: &str) -> bool {
    row.claim_id.as_deref() == Some(claim)
}

fn release_claim(row: &mut Row) {
    row.claim_id = None;
    row.claim_until = None;
}

/// `<pid>-<random u64>`: unique across processes and across claims within one.
fn new_claim_id() -> String {
    format!("{}-{:016x}", std::process::id(), rand::random::<u64>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::poll_policy::{
        CANDIDATE_DEFAULT_INTERVAL_S, MIN_INTERVAL_S, POST_429_MIN_INTERVAL_S,
    };
    use std::sync::{Arc, Mutex};

    const T0: f64 = 1_800_000_000.0;

    /// A clock the test advances by hand — nothing here ever sleeps.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<f64>>);

    impl TestClock {
        fn new() -> Self {
            TestClock(Arc::new(Mutex::new(T0)))
        }
        fn advance(&self, seconds: f64) {
            *self.0.lock().unwrap() += seconds;
        }
        fn set(&self, seconds: f64) {
            *self.0.lock().unwrap() = seconds;
        }
    }

    /// A store in a temp dir, on `clock`, with jitter pinned to zero.
    fn store(dir: &tempfile::TempDir, clock: &TestClock) -> UsageStore {
        let inner = clock.0.clone();
        UsageStore::with_clock(
            &dir.path().join("usage.json"),
            Box::new(move || *inner.lock().unwrap()),
            Box::new(|| 0.5),
        )
    }

    fn ident() -> Vec<(String, String, String)> {
        vec![(
            "claude:1".to_string(),
            "you@example.com".to_string(),
            "org-0000".to_string(),
        )]
    }

    fn window(kind: WindowKind, pct: f64, resets_at: Option<&str>) -> Window {
        Window {
            kind,
            name: None,
            pct,
            resets_at: resets_at.map(str::to_string),
            pace: None,
            used: None,
            limit: None,
            currency: None,
        }
    }

    fn five(pct: f64) -> Vec<Window> {
        vec![window(WindowKind::FiveHour, pct, None)]
    }

    fn entry(store: &UsageStore) -> Entry {
        store.entries(&ident(), &[]).unwrap()["claude:1"].clone()
    }

    /// Win a claim and record a success with it, as the active account.
    fn fetch_ok(store: &UsageStore, windows: Vec<Window>) {
        fetch_ok_as(store, windows, true);
    }

    fn fetch_ok_as(store: &UsageStore, windows: Vec<Window>, is_active: bool) {
        let claims = store.reserve(&ident(), false, true).unwrap();
        let claim = claims["claude:1"].clone();
        store
            .record_success("claude:1", &claim, windows, is_active, 80.0, &[])
            .unwrap();
    }

    #[test]
    fn reserve_skips_fresh_rows_when_respecting_plans() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        // A candidate's first plan is the 300s default; the serve TTL is 180s,
        // so the two edges are distinguishable.
        fetch_ok_as(&store, five(10.0), false);
        // Fetched a moment ago: an on-demand caller serves from the store.
        clock.advance(10.0);
        assert!(store.reserve(&ident(), true, false).unwrap().is_empty());
        // Still fresh at the TTL edge...
        clock.set(T0 + SERVE_TTL_S);
        assert!(store.reserve(&ident(), true, false).unwrap().is_empty());
        // ...and stale just past it — but the plan is not due yet, so a
        // plan-respecting caller still waits.
        clock.set(T0 + SERVE_TTL_S + 0.5);
        assert!(store.reserve(&ident(), true, false).unwrap().is_empty());
        // Past the plan's deadline it wins.
        clock.set(T0 + CANDIDATE_DEFAULT_INTERVAL_S + 0.5);
        assert_eq!(store.reserve(&ident(), true, false).unwrap().len(), 1);
    }

    #[test]
    fn reserve_force_takes_fresh_row() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        fetch_ok(&store, five(10.0));
        clock.advance(1.0);
        assert!(store.reserve(&ident(), true, false).unwrap().is_empty());
        assert_eq!(store.reserve(&ident(), false, true).unwrap().len(), 1);
    }

    #[test]
    fn reserve_never_double_claims_within_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        let first = store.reserve(&ident(), false, false).unwrap();
        assert_eq!(first.len(), 1);
        // A second collector sees the live lease and skips.
        clock.advance(1.0);
        assert!(store.reserve(&ident(), false, false).unwrap().is_empty());
        clock.set(T0 + CLAIM_TTL_S - 0.5);
        assert!(store.reserve(&ident(), false, false).unwrap().is_empty());
        // A crashed claimer's lease ages out.
        clock.set(T0 + CLAIM_TTL_S + 0.5);
        let second = store.reserve(&ident(), false, false).unwrap();
        assert_eq!(second.len(), 1);
        assert_ne!(second["claude:1"], first["claude:1"]);
        // Even `force` defers to a live lease.
        clock.advance(1.0);
        assert!(store.reserve(&ident(), true, true).unwrap().is_empty());
    }

    #[test]
    fn record_success_with_stale_claim_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        let stale = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        // The lease expires and another collector wins the row.
        clock.advance(CLAIM_TTL_S + 1.0);
        let live = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        assert_ne!(stale, live);

        // The late writer is dropped without touching the newer row.
        store
            .record_success("claude:1", &stale, five(42.0), true, 80.0, &[])
            .unwrap();
        assert_eq!(entry(&store).last_good, None);
        // A failure is fenced the same way.
        store
            .record_failure("claude:1", &stale, "timeout", None, None)
            .unwrap();
        assert_eq!(entry(&store).consecutive_failures, 0);

        // The lease holder's write lands.
        store
            .record_success("claude:1", &live, five(42.0), true, 80.0, &[])
            .unwrap();
        assert_eq!(entry(&store).last_good, Some(five(42.0)));
        // And the lease is released by recording.
        assert!(!entry(&store).claimed(store.now()));
    }

    #[test]
    fn failure_429_backoff_uses_retry_after_and_edge_floor() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        // `Retry-After: 0` is the saturated-budget edge: wait EDGE_BACKOFF_S.
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        store
            .record_failure("claude:1", &claim, "http-429", Some(0.0), None)
            .unwrap();
        let e = entry(&store);
        assert_eq!(e.backoff_until, Some(T0 + EDGE_BACKOFF_S));
        assert_eq!(e.last_429_at, Some(T0));
        assert!(e.in_backoff(T0 + 1.0));
        // Backoff blocks reserve, force included.
        assert!(store.reserve(&ident(), false, true).unwrap().is_empty());

        // A short positive ask is honored as measured — accurate, no margin.
        clock.set(T0 + EDGE_BACKOFF_S);
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        let now = store.now();
        store
            .record_failure("claude:1", &claim, "http-429", Some(120.0), None)
            .unwrap();
        assert_eq!(entry(&store).backoff_until, Some(now + 120.0));

        // An hour-scale block takes the re-block margin, bounded by the cap.
        clock.advance(120.0);
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        let now = store.now();
        store
            .record_failure("claude:1", &claim, "http-429", Some(3600.0), None)
            .unwrap();
        assert_eq!(entry(&store).backoff_until, Some(now + 4500.0));
    }

    #[test]
    fn failure_backoff_schedule_matches_the_curve() {
        // No header: 30s · 2^(n-1), capped at 600s.
        let curve: Vec<f64> = (1..=8).map(|n| failure_backoff_s(n, None, false)).collect();
        assert_eq!(
            curve,
            vec![30.0, 60.0, 120.0, 240.0, 480.0, 600.0, 600.0, 600.0]
        );
        // The exponent clamp keeps a forever-failing account on the cap.
        assert_eq!(failure_backoff_s(u32::MAX, None, true), BACKOFF_CAP_S);
        // `Retry-After: 0` on a non-429 is a "retry now" hint, not the edge.
        assert_eq!(failure_backoff_s(1, Some(0.0), false), 30.0);
        assert_eq!(failure_backoff_s(1, Some(0.0), true), EDGE_BACKOFF_S);
        // The edge floor never exceeds the curve's cap.
        assert_eq!(failure_backoff_s(9, Some(0.0), true), BACKOFF_CAP_S);
        // A positive ask below the cap is honored verbatim...
        assert_eq!(failure_backoff_s(1, Some(100.0), true), 100.0);
        // ...but never shortens our own curve.
        assert_eq!(failure_backoff_s(6, Some(100.0), true), BACKOFF_CAP_S);
        // Above the cap a 429 ask takes the margin, bounded by the park cap.
        assert_eq!(failure_backoff_s(1, Some(601.0), true), 1501.0);
        assert_eq!(
            failure_backoff_s(1, Some(3600.0), true),
            RETRY_AFTER_FLOOR_CAP_S
        );
        assert_eq!(
            failure_backoff_s(1, Some(86400.0), true),
            RETRY_AFTER_FLOOR_CAP_S
        );
        // A non-429 ask takes no margin and is bounded by its own arm's trust
        // ceiling, so it can never park a row past the point it reads unknown.
        assert_eq!(failure_backoff_s(1, Some(5000.0), false), TRUST_MAX_AGE_S);
    }

    #[test]
    fn token_dead_after_one_strike_blocks_reserve() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        // A permanent auth error strikes the credential generation it was
        // POSTed with, inside the same fenced write as the failure itself.
        assert!(is_permanent_auth_error("invalid_grant"));
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        store
            .record_failure(
                "claude:1",
                &claim,
                "invalid_grant",
                None,
                Some("sha256:fp-old"),
            )
            .unwrap();

        let e = entry(&store);
        assert_eq!(e.auth_dead_strikes, AUTH_DEAD_STRIKES);
        assert!(e.token_dead(None));
        // The strike condemns the generation it was POSTed with: a replaced
        // credential fingerprints differently and is not quarantined.
        assert!(e.token_dead(Some("sha256:fp-old")));
        assert!(!e.token_dead(Some("sha256:fp-new")));

        // Quarantined: no fetches, not even forced ones, once the backoff
        // itself has lapsed.
        clock.advance(BACKOFF_CAP_S + 1.0);
        assert!(store.reserve(&ident(), false, false).unwrap().is_empty());
        assert!(store.reserve(&ident(), false, true).unwrap().is_empty());

        // A credential rewrite lifts it, along with the failure state.
        store.clear_dead("claude:1").unwrap();
        let e = entry(&store);
        assert_eq!(e.auth_dead_strikes, 0);
        assert_eq!(e.dead_fingerprint, None);
        assert_eq!(e.consecutive_failures, 0);
        assert_eq!(e.last_error, None);
        assert_eq!(store.reserve(&ident(), false, false).unwrap().len(), 1);
    }

    #[test]
    fn a_transient_failure_never_strikes_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        // Even handed a fingerprint, a transient error is no evidence the
        // token is alive *or* dead and must not condemn it.
        for kind in ["timeout", "http-429", "network"] {
            clock.advance(BACKOFF_CAP_S + 1.0);
            let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
            store
                .record_failure("claude:1", &claim, kind, None, Some("sha256:fp"))
                .unwrap();
            let e = entry(&store);
            assert_eq!(e.auth_dead_strikes, 0, "{kind} struck the token");
            assert_eq!(e.dead_fingerprint, None);
            assert!(!e.token_dead(None));
        }
    }

    #[test]
    fn stale_writer_cannot_strike_the_row() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        let stale = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        // The lease expires; another collector takes the row.
        clock.advance(CLAIM_TTL_S + 1.0);
        let live = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();

        // The late writer's verdict is dropped: quarantining the row here
        // would need a manual `clear_dead` to undo...
        store
            .record_failure(
                "claude:1",
                &stale,
                "invalid_grant",
                None,
                Some("sha256:fp-old"),
            )
            .unwrap();
        let e = entry(&store);
        assert_eq!(e.auth_dead_strikes, 0);
        assert_eq!(e.dead_fingerprint, None);
        // ...and it must not drop the live holder's claim either, or that
        // holder's own outcome would be rejected in turn.
        assert!(e.claimed(store.now()));
        store
            .record_success("claude:1", &live, five(10.0), true, 80.0, &[])
            .unwrap();
        assert_eq!(entry(&store).last_good, Some(five(10.0)));
    }

    #[test]
    fn a_success_with_no_window_data_clears_the_measurement() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        fetch_ok(&store, five(10.0));
        assert_eq!(
            entry(&store).decision_windows(),
            Some(five(10.0).as_slice())
        );

        // A successful fetch that reported nothing: the row is fresh, and its
        // headroom is unknown rather than the superseded measurement.
        clock.advance(MIN_INTERVAL_S + 1.0);
        fetch_ok(&store, vec![]);
        let e = entry(&store);
        assert_eq!(e.last_good, None);
        assert_eq!(e.fetched_at, Some(store.now()));
        assert!(e.fresh(store.now()));
        assert_eq!(e.decision_windows(), None);
    }

    #[test]
    fn identity_mismatch_yields_empty_row() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        fetch_ok(&store, five(10.0));
        assert_eq!(entry(&store).last_good, Some(five(10.0)));

        // The same slot, a different account: the stored measurement is not
        // this account's and must not be served.
        let other = vec![(
            "claude:1".to_string(),
            "other@example.com".to_string(),
            "org-9999".to_string(),
        )];
        assert_eq!(
            store.entries(&other, &[]).unwrap()["claude:1"],
            Entry::default()
        );
        // Nor may it inherit the previous account's plan: the row is replaced
        // on the next claim, fresh though it looked.
        assert_eq!(store.reserve(&other, true, false).unwrap().len(), 1);
        assert_eq!(
            store.entries(&other, &[]).unwrap()["claude:1"].fetched_at,
            None
        );
        // ...and the old identity now sees an empty row in turn.
        assert_eq!(entry(&store), Entry::default());
    }

    #[test]
    fn success_clears_failure_state_and_plans_the_next_poll() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        store
            .record_failure("claude:1", &claim, "timeout", None, None)
            .unwrap();
        clock.advance(60.0);

        fetch_ok(&store, five(10.0));
        let e = entry(&store);
        assert_eq!(e.consecutive_failures, 0);
        assert_eq!(e.last_error, None);
        assert_eq!(e.backoff_until, None);
        assert_eq!(e.auth_dead_strikes, 0);
        assert_eq!(e.fetched_at, Some(T0 + 60.0));
        // First plan for an active account with no movement history: the
        // default interval, no jitter.
        assert_eq!(e.interval_s, Some(MIN_INTERVAL_S));
        assert_eq!(e.next_poll_at, Some(T0 + 60.0 + MIN_INTERVAL_S));

        // The next success plans off the stored interval and the stored
        // last-good: no movement, so the interval decays ×1.5.
        clock.advance(MIN_INTERVAL_S + 1.0);
        fetch_ok(&store, five(10.0));
        assert_eq!(entry(&store).interval_s, Some(270.0));
    }

    #[test]
    fn a_recent_429_is_anchored_on_the_backoff_it_installed() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        // An hour-scale block: no attempt runs during the wait, so measuring
        // recency from the 429 stamp alone would let the window elapse before
        // the first post-block success could see it.
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        store
            .record_failure("claude:1", &claim, "http-429", Some(3600.0), None)
            .unwrap();
        let backoff_end = T0 + 4500.0;
        clock.set(backoff_end + 1.0);
        assert!(entry(&store).recent_429(store.now()));
        // It clears once the saturated window has aged out past the anchor.
        clock.set(backoff_end + RECENT_429_WINDOW_S + 1.0);
        assert!(!entry(&store).recent_429(store.now()));

        // The first post-block success therefore takes the post-429 floor.
        clock.set(backoff_end + 1.0);
        fetch_ok(&store, five(10.0));
        assert_eq!(entry(&store).interval_s, Some(POST_429_MIN_INTERVAL_S));

        // An unrelated later timeout installs a backoff of its own; it must not
        // re-arm the post-429 cadence.
        let long_ago = Entry {
            last_429_at: Some(T0),
            last_error: Some("timeout".to_string()),
            backoff_until: Some(T0 + RECENT_429_WINDOW_S + 3600.0),
            ..Entry::default()
        };
        assert!(!long_ago.recent_429(T0 + RECENT_429_WINDOW_S + 1.0));
        // A `Retry-After: 0` block expires normally.
        let edge = Entry {
            last_429_at: Some(T0),
            last_error: Some("http-429".to_string()),
            backoff_until: Some(T0 + EDGE_BACKOFF_S),
            ..Entry::default()
        };
        assert!(edge.recent_429(T0 + EDGE_BACKOFF_S + RECENT_429_WINDOW_S - 1.0));
        assert!(!edge.recent_429(T0 + EDGE_BACKOFF_S + RECENT_429_WINDOW_S + 1.0));
    }

    #[test]
    fn rate_limited_trust_ends_at_the_soonest_reset_or_the_ceiling() {
        let reset = "2027-01-01T00:00:00Z";
        let reset_ts = parse_reset_ts(Some(reset)).unwrap();
        let windows = vec![
            window(WindowKind::FiveHour, 50.0, Some(reset)),
            window(WindowKind::SevenDay, 50.0, Some("2027-01-05T00:00:00Z")),
        ];
        // Trusted right up to the SOONEST reset — a later window cannot rescue
        // a snapshot whose first window has rolled over.
        assert!(rate_limited_trust_ok(
            Some(&windows),
            Some(60.0),
            reset_ts - 1.0,
            &[]
        ));
        assert!(!rate_limited_trust_ok(
            Some(&windows),
            Some(60.0),
            reset_ts + 1.0,
            &[]
        ));
        // The client-side ceiling binds first when the reset is far away.
        let far = vec![window(
            WindowKind::FiveHour,
            50.0,
            Some("2030-01-01T00:00:00Z"),
        )];
        assert!(rate_limited_trust_ok(
            Some(&far),
            Some(RATE_LIMIT_TRUST_MAX_AGE_S - 1.0),
            T0,
            &[]
        ));
        assert!(!rate_limited_trust_ok(
            Some(&far),
            Some(RATE_LIMIT_TRUST_MAX_AGE_S + 1.0),
            T0,
            &[]
        ));
        // No reset info at all falls back to the ceiling alone; no measurement
        // at all is never trusted.
        assert!(rate_limited_trust_ok(
            Some(&five(50.0)),
            Some(10.0),
            T0,
            &[]
        ));
        assert!(!rate_limited_trust_ok(Some(&five(50.0)), None, T0, &[]));
    }

    #[test]
    fn trust_is_extended_only_while_the_staleness_is_deliberate() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);

        fetch_ok(&store, five(10.0));
        // Inside the plan the staleness is the scheduler's own choice, so the
        // measurement stays decision-grade past STALE_OK_S...
        clock.advance(STALE_OK_S + 1.0);
        let e = entry(&store);
        assert!(!e.trust_extended);
        assert!(e.decision_windows().is_none());
        // ...but this plan (the active floor, 180s) has already lapsed, so
        // nothing extends it. A failure does: the server is refusing fresher
        // data.
        let claim = store.reserve(&ident(), false, false).unwrap()["claude:1"].clone();
        store
            .record_failure("claude:1", &claim, "timeout", None, None)
            .unwrap();
        let e = entry(&store);
        assert!(e.trust_extended);
        assert_eq!(e.decision_windows(), Some(five(10.0).as_slice()));
        // But never past the general ceiling.
        clock.set(T0 + TRUST_MAX_AGE_S + 1.0);
        let e = entry(&store);
        assert!(!e.trust_extended);
        assert!(e.decision_windows().is_none());
    }

    #[test]
    fn a_missing_weekly_reset_is_carried_from_the_previous_measurement() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);
        let reset = "2027-01-01T00:00:00Z";
        let reset_ts = parse_reset_ts(Some(reset)).unwrap();

        clock.set(reset_ts - 3600.0);
        fetch_ok(
            &store,
            vec![window(WindowKind::SevenDay, 40.0, Some(reset))],
        );

        // The window rolls over and the endpoint stops reporting a reset while
        // utilization is 0. The account's fixed weekly slot is known, so step
        // it forward by whole weeks to the first instant after now.
        clock.set(reset_ts + 3600.0);
        fetch_ok(&store, vec![window(WindowKind::SevenDay, 0.0, None)]);
        let carried = entry(&store).last_good.unwrap()[0].resets_at.clone();
        assert_eq!(parse_reset_ts(carried.as_deref()), Some(reset_ts + WEEK_S));

        // Two whole weeks later it steps twice, never landing in the past.
        clock.set(reset_ts + 2.0 * WEEK_S + 10.0);
        fetch_ok(&store, vec![window(WindowKind::SevenDay, 0.0, None)]);
        let carried = entry(&store).last_good.unwrap()[0].resets_at.clone();
        assert_eq!(
            parse_reset_ts(carried.as_deref()),
            Some(reset_ts + 3.0 * WEEK_S)
        );

        // A reported reset is never overwritten.
        let later = "2027-06-01T00:00:00Z";
        fetch_ok(&store, vec![window(WindowKind::SevenDay, 5.0, Some(later))]);
        let kept = entry(&store).last_good.unwrap()[0].resets_at.clone();
        assert_eq!(kept.as_deref(), Some(later));
    }

    #[test]
    fn due_candidate_takes_the_stalest_due_row() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "claude:1".to_string(),
            Entry {
                fetched_at: Some(T0 - 100.0),
                next_poll_at: Some(T0 - 1.0),
                ..Entry::default()
            },
        );
        entries.insert(
            "claude:2".to_string(),
            Entry {
                fetched_at: Some(T0 - 500.0),
                next_poll_at: Some(T0 - 1.0),
                ..Entry::default()
            },
        );
        let all = vec!["claude:1".to_string(), "claude:2".to_string()];
        assert_eq!(
            due_candidate(&all, &entries, T0).as_deref(),
            Some("claude:2")
        );

        // Never measured beats measured-but-stale.
        entries.insert("claude:3".to_string(), Entry::default());
        let all3 = vec![
            "claude:1".to_string(),
            "claude:2".to_string(),
            "claude:3".to_string(),
        ];
        assert_eq!(
            due_candidate(&all3, &entries, T0).as_deref(),
            Some("claude:3")
        );

        // Backoff, a live plan and a dead token each remove a row from the set.
        entries.insert(
            "claude:3".to_string(),
            Entry {
                backoff_until: Some(T0 + 10.0),
                ..Entry::default()
            },
        );
        entries.get_mut("claude:2").unwrap().next_poll_at = Some(T0 + 10.0);
        assert_eq!(
            due_candidate(&all3, &entries, T0).as_deref(),
            Some("claude:1")
        );
        entries.get_mut("claude:1").unwrap().auth_dead_strikes = AUTH_DEAD_STRIKES;
        assert_eq!(due_candidate(&all3, &entries, T0), None);

        // A plan that oversleeps the interval it was written with is obsolete,
        // so the row is due anyway.
        entries.insert(
            "claude:2".to_string(),
            Entry {
                fetched_at: Some(T0 - 500.0),
                interval_s: Some(300.0),
                next_poll_at: Some(T0 + 86400.0),
                ..Entry::default()
            },
        );
        assert!(plan_oversleeps_interval(&entries["claude:2"], T0));
        assert_eq!(
            due_candidate(&all3, &entries, T0).as_deref(),
            Some("claude:2")
        );
    }

    #[test]
    fn a_legacy_or_future_schema_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::new();
        let store = store(&dir, &clock);
        fetch_ok(&store, five(10.0));

        let path = dir.path().join("usage.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"schemaVersion\": 2"), "{raw}");
        std::fs::write(
            &path,
            raw.replace("\"schemaVersion\": 2", "\"schemaVersion\": 1"),
        )
        .unwrap();
        assert_eq!(entry(&store), Entry::default());
    }
}
