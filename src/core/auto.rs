//! The switching daemon: poll usage, decide, switch, sleep — and say so.
//!
//! Port of cswap's `AutoSwitchEngine` (`autoswitch.py`): `_tick_inner`
//! (999-1620) for the decision, `_rank_candidates` (2016-2235) for the choice,
//! `_no_return_account`/`_left_account_recovered` (1620-2015) for the anti-flap
//! bar, `_perform` (2393+) for the commit and `_next_delay` (2779+) for the
//! cadence. Three of its jobs are NOT here, by design: the stopped-session
//! resume, the remote-control re-arm and the away-mode push all belong to
//! Infinitus, which owns the sessions and the notification channels.
//!
//! Policy in one paragraph, unchanged from cswap: when the active account's
//! binding window (the worst of its 5h/7d/scoped windows) crosses
//! `threshold`, switch to the candidate with the most headroom — proactively,
//! while the old login is still valid, so a running CLI picks the new one up.
//! A candidate must beat the active account by `hysteresisPct` so two accounts
//! hovering at the line cannot ping-pong, `cooldownSeconds` bounds the switch
//! rate (bypassed when the active account is hard at its limit), and the
//! account this engine just left is barred until it is provably a different
//! proposition from the one it was when we left it.
//!
//! What this module deliberately does NOT do is decide anything about usage
//! FETCHING: freshness, backoff, claims and the per-account cadence all come
//! from `collect` and the usage store, which every other surface shares. The
//! engine asks for a collection pass and reads the store's own verdict.
//!
//! Two locks, and they are not the same lock. `auto.lock` is the daemon mutex
//! — one engine per data dir, held for the process's lifetime (see
//! `cmd::auto`). `engine.lock` fences one switch and is taken inside
//! `switch::perform`, so it is free between ticks and a manual `swapd switch`
//! keeps working while the daemon runs.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::contract::{AccountView, ProviderView, UsageStatus, Window};
use crate::core::collect::{collect, CollectOpts};
use crate::core::events::{window_label, Emit, Event};
use crate::core::history::SlotRef;
use crate::core::poll_policy::{
    self, binding_pct, limiting_reset_ts, parse_reset_ts, ESCALATION_MARGIN_PCT, RESET_SLACK_S,
};
use crate::core::settings::{self, Settings};
use crate::core::slots;
use crate::core::store::{read_json, write_json_atomic, FileLock};
use crate::core::switch;
use crate::core::usage_store::{due_candidate, plan_oversleeps_interval, Entry};
use crate::ctx::Ctx;
use crate::driver::claude::usage::{format_ts, relevant};
use crate::driver::{Driver, Login};
use crate::errors::{ErrorCode, Result};
use crate::secrets::slot_key;

/// `auto-state.json`'s layout.
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// How long a state-file read-modify-write waits for its lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Anti-flap margin on the recovery axis: a target must come back at least
/// this much sooner than the account we are leaving (`autoswitch.py:124`).
const RECOVERY_HYSTERESIS_S: f64 = 300.0;

/// Horizon past which a sooner reset stops being worth real headroom
/// (`autoswitch.py:134`): a 5h window can be up to five hours out, so a peer
/// bound by one 4-5h away falls back to headroom ranking.
const RECOVERY_HORIZON_S: f64 = 4.0 * 3600.0;

/// Anti-flap margin on the headroom axis, as a RATIO (`autoswitch.py:141`):
/// strictly-more is no margin at all — one point moves the engine, the target
/// burns it back, and it ping-pongs.
const HORIZON_HEADROOM_RATIO: f64 = 2.0;

/// Below this an account is spent and headroom comparisons compare noise (a
/// point is under two poll intervals of work) — rank by reset instead
/// (`autoswitch.py:157`).
const SPENT_HEADROOM_PCT: f64 = 3.0;

/// Idle-hold cap (`autoswitch.py:110`): an owned-and-expired active token
/// normally means the CLI is idle and will self-heal on next use, but a dead
/// refresh token with an active user looks identical forever, so after this
/// long the engine falls back to normal unhealthy counting.
const IDLE_HOLD_MAX_S: f64 = 30.0 * 60.0;

/// Longest inter-tick sleep, even toward a known reset (`autoswitch.py:104`):
/// quota can be granted before the advertised time, and a long sleep must not
/// suppress the fetch that would discover it.
const MAX_SLEEP_S: f64 = poll_policy::EXHAUSTED_INTERVAL_S;

/// Blocked with no known recovery: crawl rather than poll at full cadence.
const NO_RESET_FALLBACK_S: f64 = 300.0;

/// Outcome of one evaluation tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    Switched,
    Error,
    NoAction,
    /// Wanted to switch and could not: no viable target, or everything spent.
    Blocked,
}

/// `auto-state.json`: what one tick has to remember for the next one.
///
/// Port of cswap's `autoswitch_state.json` (`autoswitch.py:800-870`), reduced
/// to the three facts a decision reads back — when the cooldown lifts, which
/// slots are quarantined, and what the last departure looked like.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AutoState {
    pub schema_version: u32,
    /// Epoch before which no proactive/consume-first switch may fire.
    pub cooldown_until: Option<f64>,
    /// Slot (as a string, because JSON object keys are) → why it is out.
    pub quarantine: BTreeMap<String, Quarantine>,
    /// The last switch this engine made, as the account it left looked at the
    /// moment it left. The no-return bar's whole evidence base.
    pub left_at_limit: Option<Departure>,
}

/// One quarantined slot. The fingerprint is the point: strikes condemn the
/// credential GENERATION that failed, so a re-login that replaces it releases
/// the quarantine on its own.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Quarantine {
    pub reason: String,
    /// RFC 3339, for a human reading the file.
    pub since: String,
    pub fingerprint: Option<String>,
}

/// Where the last switch came from, and what it looked like there.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Departure {
    /// The slot we left — the one the no-return bar refuses to undo onto.
    pub from: u32,
    /// The slot we landed on. The bar applies only while we are still
    /// standing where that switch put us: a manual switch away has already
    /// undone the move, so there is nothing left to refuse.
    pub to: u32,
    pub trigger: String,
    /// The left account's headroom at departure, `None` when unmeasured.
    pub headroom: Option<f64>,
    /// When its binding window was due back, `None` for unknown/never
    /// (`inf` is not portable JSON).
    pub recovery_at: Option<f64>,
}

/// The decision-grade picture of one tick, derived from the collection pass
/// and the usage store — never re-derived from the raw view, so the engine and
/// `list` cannot disagree about which measurements are still trusted.
struct Snapshot {
    /// Slot → headroom pct, `None` where this tick has no trusted measurement.
    headroom: BTreeMap<u32, Option<f64>>,
    /// Slot → the windows that headroom was read from.
    windows: BTreeMap<u32, Vec<Window>>,
    /// Slot → the classified cause of an unknown headroom.
    fetch_errors: BTreeMap<u32, String>,
    /// Slot → whether its measurement is fresh enough to act on right now
    /// (the consume-first commit gate).
    fresh: BTreeMap<u32, bool>,
}

impl Snapshot {
    fn headroom(&self, slot: u32) -> Option<f64> {
        self.headroom.get(&slot).copied().flatten()
    }

    fn windows(&self, slot: u32) -> &[Window] {
        self.windows.get(&slot).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// The engine. Owns its `Ctx` because it re-reads `settings.json` into it
/// every tick (so `swapd config set` takes effect without a restart) and every
/// layer below — the collector, the poll planner, the health gate — decides on
/// `ctx.settings`.
pub struct AutoEngine<'a> {
    ctx: Ctx,
    driver: &'a dyn Driver,
    on_event: Box<dyn FnMut(&Emit) + 'a>,
    /// Consecutive ticks whose active account had no readable usage.
    unhealthy_ticks: u32,
    /// When the current idle-hold started (an active token expired while the
    /// CLI owns it), `None` when not holding.
    idle_hold_since: Option<f64>,
    /// Set per tick: a known-reset sleep target, whether a BLOCKED outcome is
    /// static enough to wait longer than the interval, and whether the tick
    /// ended in an idle-hold.
    sleep_until: Option<f64>,
    blocked_wait_long: bool,
    idle_hold_slow: bool,
    /// One-shot `model` typo guard, re-armed when the setting changes.
    model_check_done: bool,
    model_check_for: Option<Vec<String>>,
}

impl<'a> AutoEngine<'a> {
    pub fn new(ctx: Ctx, driver: &'a dyn Driver, on_event: Box<dyn FnMut(&Emit) + 'a>) -> Self {
        AutoEngine {
            ctx,
            driver,
            on_event,
            unhealthy_ticks: 0,
            idle_hold_since: None,
            sleep_until: None,
            blocked_wait_long: false,
            idle_hold_slow: false,
            model_check_done: false,
            model_check_for: None,
        }
    }

    fn emit(&mut self, event: Event) {
        let emit = Emit {
            ts: format_ts(self.ctx.now()).unwrap_or_default(),
            provider: self.driver.id().to_string(),
            event,
        };
        (self.on_event)(&emit);
    }

    /// Evaluate once. Never fails: a tick that could not run is an `error`
    /// event and an `Error` outcome, because a daemon that exits on the first
    /// unreadable keychain is worse than one that retries.
    pub fn tick(&mut self) -> TickOutcome {
        match self.tick_inner() {
            Ok(outcome) => outcome,
            Err(e) => {
                self.emit(Event::Error {
                    message: e.message,
                    transient: true,
                });
                TickOutcome::Error
            }
        }
    }

    fn tick_inner(&mut self) -> Result<TickOutcome> {
        self.sleep_until = None;
        self.blocked_wait_long = false;
        self.idle_hold_slow = false;

        // Re-read every tick, into the context itself: `config set` must take
        // effect without a restart, and the threshold and model axes the
        // decision uses are the same ones the collector fetches, plans and
        // gates with (`ctx.settings`). Loading a second copy here would leave
        // the two halves of one tick deciding on different policy.
        self.ctx.settings = settings::load(&self.ctx.home, self.driver.id());
        let settings = self.ctx.settings.clone();
        // The `model` typo guard is one-shot per configured value — and the
        // value can change under a running daemon, so it re-arms when it does.
        if self.model_check_for.as_ref() != Some(&settings.models) {
            self.model_check_for = Some(settings.models.clone());
            self.model_check_done = settings.models.is_empty();
        }

        let mut state = self.read_state();
        self.release_recovered_quarantines(&mut state)?;
        let quarantined: BTreeSet<u32> = state
            .quarantine
            .keys()
            .filter_map(|slot| slot.parse::<u32>().ok())
            .collect();

        let (view, snap) = self.collect_scheduled(&settings, &quarantined)?;

        let Some(current) = view.active_slot else {
            self.emit(Event::Poll {
                active: None,
                headroom: BTreeMap::new(),
                threshold: settings.threshold,
                fetch_errors: BTreeMap::new(),
                windows: BTreeMap::new(),
            });
            // A live login nothing manages is never acted on: switching would
            // overwrite a credential no slot holds a copy of.
            let (reason, detail) = if self.has_live_login() {
                (
                    "unmanaged-active-account",
                    "run `swapd add` to include it in the rotation",
                )
            } else {
                ("no-active-account", "log in and run `swapd add` first")
            };
            self.emit(Event::NoSwitch {
                reason: reason.to_string(),
                detail: detail.to_string(),
            });
            return Ok(TickOutcome::NoAction);
        };

        self.emit(Event::Poll {
            active: Some(account_ref(&view, current)),
            headroom: snap.headroom.clone(),
            threshold: settings.threshold,
            fetch_errors: snap.fetch_errors.clone(),
            windows: self.poll_windows(&snap),
        });

        if !self.model_check_done {
            self.check_model_names(&view, &snap, &quarantined);
        }

        // The master switch, checked AFTER the poll event so usage keeps
        // flowing to every display while switching is off.
        if !settings.enabled {
            self.emit(Event::NoSwitch {
                reason: "disabled".to_string(),
                detail: "enabled is off — usage polling continues".to_string(),
            });
            return Ok(TickOutcome::NoAction);
        }

        let active = account_of(&view, current);
        if active.is_some_and(|a| a.usage_status == UsageStatus::ApiKey)
            && !settings.include_api_key_accounts
        {
            self.emit(Event::NoSwitch {
                reason: "active-api-key".to_string(),
                detail: "API-key accounts have no quota to watch".to_string(),
            });
            return Ok(TickOutcome::NoAction);
        }

        let active_headroom = snap.headroom(current);
        let trigger = match self.classify(&settings, &snap, current, active_headroom, &view) {
            Classified::Hold(outcome) => return Ok(outcome),
            Classified::Trigger(trigger) => trigger,
        };

        if matches!(trigger, "proactive" | "consume-first") && self.in_cooldown(&state) {
            self.emit(Event::NoSwitch {
                reason: "cooldown".to_string(),
                detail: String::new(),
            });
            return Ok(TickOutcome::NoAction);
        }

        // -- candidate selection ------------------------------------------
        // A census of what EXISTS, taken after the trigger: the no-return bar
        // is a statement about the choice and lives in the ranking, so nothing
        // here decides anything beyond "could we land on it at all".
        let candidates: Vec<u32> = view
            .accounts
            .iter()
            .filter(|a| a.slot != current && !quarantined.contains(&a.slot) && switchable(a))
            .map(|a| a.slot)
            .collect();
        let oauth_candidates: Vec<u32> = candidates
            .iter()
            .copied()
            .filter(|slot| account_of(&view, *slot).is_some_and(|a| !is_api_key(a)))
            .collect();
        // Kept apart, and never ranked: cswap lands on a metered API-key
        // account as a last resort, but swapd's driver refuses to make a
        // managed key the live login, so the engine says so instead of
        // offering a target that would fail.
        let api_key_candidates: Vec<u32> = candidates
            .iter()
            .copied()
            .filter(|slot| account_of(&view, *slot).is_some_and(is_api_key))
            .collect();

        if trigger == "consume-first" && oauth_candidates.is_empty() && active_headroom.is_some() {
            // A healthy account with no peer to compare against — the same
            // state `best` reports as below-threshold before it ever reaches
            // candidate selection. The detail cannot claim "below threshold":
            // consume-first reaches here at any utilization under 100%.
            self.emit(Event::NoSwitch {
                reason: "below-threshold".to_string(),
                detail: format!(
                    "{:.0}% used, no peer to consume ahead of it",
                    100.0 - active_headroom.unwrap_or(0.0)
                ),
            });
            return Ok(TickOutcome::NoAction);
        }
        if oauth_candidates.is_empty() && api_key_candidates.is_empty() {
            // Nothing changes until the user adds or recovers an account.
            self.blocked_wait_long = true;
            self.emit(Event::NoSwitch {
                reason: "no-candidates".to_string(),
                detail: String::new(),
            });
            return Ok(TickOutcome::Blocked);
        }

        let consume_first = settings.strategy == "consume-first";
        let decided_now = self.ctx.now();
        let preferred = self.preferred_slots(&view, &oauth_candidates);
        let (ordered, any_known, active_reset_ts) = self.rank(
            &state,
            RankInput {
                trigger,
                consume_first,
                candidates: &oauth_candidates,
                snap: &snap,
                current,
                active_headroom,
                settings: &settings,
                preferred: &preferred,
                now: decided_now,
            },
        );

        if ordered.is_empty() {
            return Ok(self.nothing_to_take(
                &settings,
                &snap,
                trigger,
                &oauth_candidates,
                &api_key_candidates,
                any_known,
                active_reset_ts,
            ));
        }

        // -- switch ---------------------------------------------------------
        // The departure snapshot, taken from the same picture the ranking just
        // decided on: the no-return bar's release compares against it.
        let left = (
            active_headroom,
            binding_recovery_ts(snap.windows(current), &settings.models, decided_now),
        );
        let mut transient = false;
        let mut unsupported: Option<String> = None;
        for target in ordered {
            if trigger == "consume-first" && !snap.fresh.get(&target).copied().unwrap_or(false) {
                // consume-first is opportunistic, not an escape: it decides
                // below the threshold, where a stored measurement can be a
                // full candidate interval old. Never act on stale data and
                // never slide to a worse-ranked target — hold and retry.
                self.emit(Event::NoSwitch {
                    reason: "stale-usage".to_string(),
                    detail: format!(
                        "slot {target}'s usage could not be refreshed this tick \
                         (backoff or a concurrent poller); retrying"
                    ),
                });
                return Ok(TickOutcome::NoAction);
            }
            let email = account_of(&view, target)
                .map(|a| a.email.clone())
                .unwrap_or_default();
            match switch::perform(&self.ctx, self.driver, target, trigger) {
                Ok(result) if result.switched => {
                    // The live login has already changed. Bookkeeping that
                    // fails after that point is a warning, not an error —
                    // `switch::perform` makes the same call for its own
                    // post-landing writes. Turning it into one would drop the
                    // `switch` event, leaving a supervisor believing the old
                    // account is still active.
                    let mut warnings = result.warnings;
                    if let Err(e) = self.record_switch(target, result.from.as_ref(), trigger, left)
                    {
                        warnings.push(format!(
                            "the switch landed but its cooldown and no-return bar were not \
                             recorded ({}); the next tick may switch again sooner than the \
                             cooldown asks",
                            e.message
                        ));
                    }
                    self.emit(Event::Switch {
                        trigger: trigger.to_string(),
                        from: result.from,
                        to: result.to,
                        warnings,
                    });
                    return Ok(TickOutcome::Switched);
                }
                // The live login moved between the collection pass and here
                // (a concurrent `swapd switch`, the CLI's own `/login`).
                Ok(result) => {
                    self.emit(Event::NoSwitch {
                        reason: "already-active".to_string(),
                        detail: result.reason.unwrap_or_default(),
                    });
                    return Ok(TickOutcome::NoAction);
                }
                // The target's refresh token was rejected: the lineage is
                // dead, and no retry can revive it. Quarantined rather than
                // retried every tick — released automatically when the user
                // logs in again and the credential changes.
                Err(e) if e.code == ErrorCode::TokenDead => {
                    self.quarantine(target, &email, "invalid_grant")?;
                }
                // A fact about the machine or the upstream, not about this
                // account: try the next candidate, report it if none work.
                Err(e) if matches!(e.code, ErrorCode::RefreshDenied | ErrorCode::Http) => {
                    transient = true;
                }
                // `can_activate` refused it (a managed API key cannot be made
                // the live login in phase 1).
                Err(e) if e.code == ErrorCode::Unsupported => unsupported = Some(e.message),
                Err(e) => return Err(e),
            }
        }

        if let Some(message) = unsupported.filter(|_| !transient) {
            self.emit(Event::NoSwitch {
                reason: "unsupported".to_string(),
                detail: message,
            });
            return Ok(TickOutcome::Blocked);
        }
        if transient {
            self.emit(Event::Error {
                message: "could not freshen any candidate (network?)".to_string(),
                transient: true,
            });
            return Ok(TickOutcome::Error);
        }
        self.emit(Event::NoSwitch {
            reason: "no-viable-target".to_string(),
            detail: String::new(),
        });
        Ok(TickOutcome::Blocked)
    }

    /// What this tick's active account asks for: a trigger, or the reason
    /// nothing happens (`autoswitch.py:1099-1265`).
    fn classify(
        &mut self,
        settings: &Settings,
        snap: &Snapshot,
        current: u32,
        active_headroom: Option<f64>,
        view: &ProviderView,
    ) -> Classified {
        let Some(headroom) = active_headroom else {
            let expired = account_of(view, current)
                .is_some_and(|a| a.usage_status == UsageStatus::TokenExpired);
            if expired {
                // Expired and unrefreshable this pass (lock contention, the
                // row's failure backoff). The CLI refreshes it itself on next
                // use, so there is no quota burn and nothing to switch for
                // yet: crawl instead of burning failover ticks.
                let now = self.ctx.now();
                let since = *self.idle_hold_since.get_or_insert(now);
                if now - since <= IDLE_HOLD_MAX_S {
                    self.unhealthy_ticks = 0;
                    self.idle_hold_slow = true;
                    self.emit(Event::NoSwitch {
                        reason: "active-idle".to_string(),
                        detail: "token expired while the CLI is idle; resumes on next use"
                            .to_string(),
                    });
                    return Classified::Hold(TickOutcome::NoAction);
                }
                // Held far longer than any idle nap needs — likely a dead
                // refresh token with an active user. Fall through to normal
                // unhealthy counting so failover can still happen.
            } else {
                self.idle_hold_since = None;
            }
            self.unhealthy_ticks += 1;
            if self.unhealthy_ticks < settings.unhealthy_ticks {
                self.emit(Event::NoSwitch {
                    reason: "active-usage-unknown".to_string(),
                    detail: format!(
                        "{}/{} before failover",
                        self.unhealthy_ticks, settings.unhealthy_ticks
                    ),
                });
                return Classified::Hold(TickOutcome::NoAction);
            }
            return Classified::Trigger("failover");
        };

        self.unhealthy_ticks = 0;
        self.idle_hold_since = None;
        let utilization = 100.0 - headroom;
        // When the active account AND every measured peer are at or over the
        // threshold, "land somewhere healthy" has no answer and the ranking
        // switches to soonest-recovery. Holding for a sooner reset is
        // pointless in that state, so consume-first gives way to it.
        let peers: Vec<u32> = snap
            .headroom
            .keys()
            .copied()
            .filter(|slot| *slot != current)
            .collect();
        let all_peers_above =
            every_account_above_threshold(&peers, snap, active_headroom, settings.threshold);
        let consume_first = settings.strategy == "consume-first";

        if utilization < settings.threshold || (consume_first && headroom > 0.0 && !all_peers_above)
        {
            if !consume_first {
                self.emit(Event::NoSwitch {
                    reason: "below-threshold".to_string(),
                    detail: format!("{utilization:.10}% < {:.10}%", settings.threshold),
                });
                return Classified::Hold(TickOutcome::NoAction);
            }
            // A pinned account is never traded for a sooner-resetting peer:
            // it is left only when it must be (at its limit, on failover, or
            // once the whole fleet is over the threshold).
            if account_of(view, current)
                .is_some_and(|a| switch::is_preferred(a, &settings.preferred))
            {
                self.emit(Event::NoSwitch {
                    reason: "preferred-active".to_string(),
                    detail: "the active account is preferred; it is left only at its limit"
                        .to_string(),
                });
                return Classified::Hold(TickOutcome::NoAction);
            }
            // consume-first: below the threshold we still move to whichever
            // account's weekly window resets soonest, to burn the most
            // perishable quota first. The ranking decides whether such an
            // account actually exists.
            return Classified::Trigger("consume-first");
        }
        Classified::Trigger(if headroom <= 0.0 {
            "at-limit"
        } else {
            "proactive"
        })
    }

    /// Nothing qualified: which of the five ways that can happen this is
    /// (`autoswitch.py:1441-1522`).
    #[allow(clippy::too_many_arguments)]
    fn nothing_to_take(
        &mut self,
        settings: &Settings,
        snap: &Snapshot,
        trigger: &str,
        oauth_candidates: &[u32],
        api_key_candidates: &[u32],
        any_known: bool,
        active_reset_ts: Option<f64>,
    ) -> TickOutcome {
        // cswap's last resort is to land on a metered API-key account. swapd
        // cannot: the driver refuses to make a managed key the live login, so
        // saying why beats offering a target that would fail.
        if !api_key_candidates.is_empty() && trigger != "consume-first" {
            self.emit(Event::NoSwitch {
                reason: "unsupported".to_string(),
                detail: format!(
                    "the only candidates left are managed API-key accounts \
                     (slots {}), which cannot be made the live login",
                    api_key_candidates
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
            return TickOutcome::Blocked;
        }
        if !any_known {
            self.emit(Event::NoSwitch {
                reason: "no-comparison".to_string(),
                detail: "no candidate has readable usage".to_string(),
            });
            return TickOutcome::Blocked;
        }
        if trigger == "consume-first" {
            // Below the threshold and healthy: staying put is a correct
            // outcome, never a block.
            let (reason, detail) = match active_reset_ts {
                None => (
                    "reset-unknown",
                    "the active account's weekly reset time is unknown; \
                     consume-first is idle until it is reported",
                ),
                Some(_) => (
                    "already-consuming-soonest",
                    "no sooner-resetting account with room to spare",
                ),
            };
            self.emit(Event::NoSwitch {
                reason: reason.to_string(),
                detail: detail.to_string(),
            });
            return TickOutcome::NoAction;
        }
        // "All exhausted" — and its bounded reset-aware sleep — only when it
        // is literally true: every candidate's usage is known and at its
        // limit. A candidate that merely failed the hysteresis gate, or whose
        // usage is unreadable this tick, can become viable at any moment.
        let truly_exhausted = oauth_candidates
            .iter()
            .all(|slot| snap.headroom(*slot).is_some_and(|h| h <= 0.0));
        if !truly_exhausted {
            self.emit(Event::NoSwitch {
                reason: "no-qualifying-candidate".to_string(),
                detail: "no candidate is below the threshold and better than the active \
                         account by the hysteresis margin, or usage is unreadable this tick"
                    .to_string(),
            });
            return TickOutcome::Blocked;
        }
        self.blocked_wait_long = true;
        let earliest = self.earliest_recovery(snap, &settings.models);
        if let Some(at) = earliest {
            self.sleep_until = Some(at + RESET_SLACK_S);
        }
        self.emit(Event::AllExhausted {
            earliest_reset_at: earliest.and_then(format_ts),
        });
        TickOutcome::Blocked
    }

    // -- the collection schedule -------------------------------------------

    /// The tick's usage collection: an O(1) baseline, escalated only when a
    /// switch could be near (`autoswitch.py:2249-2393`).
    ///
    /// Phase A fetches the ACTIVE account when its persisted plan says it is
    /// due, plus the ONE stalest due candidate; everybody else is served from
    /// the store. Phase B refetches the whole fleet, but only when the decision
    /// could actually turn on it: the active account is within
    /// `ESCALATION_MARGIN_PCT` of the threshold, or its usage is unreadable
    /// (failover must not choose a target from plan-old numbers). Every other
    /// tick therefore costs at most two usage requests no matter how many
    /// accounts are in the rotation — fetching all of them every tick would
    /// spend the endpoint's hourly budget on accounts nothing was going to
    /// choose between.
    ///
    /// Nothing here re-implements fetch policy: the engine nominates, and
    /// `reserve` — under the table's lock — decides who is actually fetched.
    fn collect_scheduled(
        &mut self,
        settings: &Settings,
        quarantined: &BTreeSet<u32>,
    ) -> Result<(ProviderView, Snapshot)> {
        // Phase A's baseline picture, fetching nothing: the nomination is
        // computed from the same rows `reserve` will judge, so a slot is
        // nominated and fetched on one view of the table rather than two.
        let pre = collect(
            &self.ctx,
            self.driver,
            &CollectOpts {
                only: Some(Vec::new()),
                ..CollectOpts::default()
            },
        )?;
        let Some(current) = pre.active_slot else {
            // No active account is nothing to schedule around: the tick reports
            // that and stops, so no request is spent on it.
            let snap = self.snapshot(&pre)?;
            return Ok((pre, snap));
        };

        let now = self.ctx.now();
        let entries = self.entries(&pre)?;
        // A quarantined account can never be a target, so spending the single
        // alternate poll slot on one is a wasted request.
        let candidates: Vec<u32> = pre
            .accounts
            .iter()
            .filter(|a| a.slot != current && !quarantined.contains(&a.slot) && switchable(a))
            .map(|a| a.slot)
            .collect();

        let mut plan: Vec<u32> = Vec::new();
        if active_is_due(entries.get(&self.key_of(current)), now, &settings.models) {
            plan.push(current);
        }
        // No candidate is polled during an idle-hold: the engine is waiting for
        // a CLI that is not running, and nothing it learns about a candidate
        // can be acted on until it is.
        if self.idle_hold_since.is_none() {
            let keys: Vec<String> = candidates.iter().map(|slot| self.key_of(*slot)).collect();
            if let Some(pick) = due_candidate(&keys, &entries, now) {
                if let Some(slot) = candidates.iter().find(|slot| self.key_of(**slot) == pick) {
                    plan.push(*slot);
                }
            }
        }

        let mut view = self.fetch_planned(&plan, pre)?;
        let mut snap = self.snapshot(&view)?;

        // Phase B. An owned-and-expired active account is the deliberate
        // exception: it idle-holds, and a post-hold failover may run on the
        // baseline rather than paying for a fleet-wide refresh first.
        let active_headroom = snap.headroom(current);
        let expired =
            account_of(&view, current).is_some_and(|a| a.usage_status == UsageStatus::TokenExpired);
        let escalate = !candidates.is_empty()
            && match active_headroom {
                None => !expired,
                Some(h) => 100.0 - h >= settings.threshold - ESCALATION_MARGIN_PCT,
            };
        if !escalate {
            return Ok((view, snap));
        }
        let entries = self.entries(&view)?;
        // Escalation may beat an ordinary candidate plan, but never a wide one
        // parked on an exhausted account: that row's measurement is still
        // decision-trusted, it cannot be a target while it reads spent, and
        // re-fetching it is exactly the token the post-429 cadence is trying to
        // rest.
        let escalation: Vec<u32> = std::iter::once(current)
            .chain(candidates.iter().copied())
            .filter(|slot| {
                !parked_exhausted(entries.get(&self.key_of(*slot)), snap.headroom(*slot), now)
            })
            .collect();
        view = self.fetch_planned(&escalation, view)?;
        snap = self.snapshot(&view)?;
        Ok((view, snap))
    }

    /// One collection pass restricted to `plan`.
    ///
    /// Inside the plan the rule is the scheduler's own — due OR stale — so an
    /// urgent 60 s cadence actually beats the 180 s serve TTL; outside it
    /// nothing is fetched. An empty plan is not a pass at all: the picture
    /// already in hand is the answer.
    fn fetch_planned(&self, plan: &[u32], served: ProviderView) -> Result<ProviderView> {
        if plan.is_empty() {
            return Ok(served);
        }
        collect(
            &self.ctx,
            self.driver,
            &CollectOpts {
                all_stale: true,
                only: Some(plan.to_vec()),
                ..CollectOpts::default()
            },
        )
    }

    fn key_of(&self, slot: u32) -> String {
        slot_key(self.driver.id(), slot)
    }

    /// The usage table's rows for the slots in this view.
    fn entries(&self, view: &ProviderView) -> Result<BTreeMap<String, Entry>> {
        let keys: Vec<(String, String, String)> = view
            .accounts
            .iter()
            .map(|a| {
                (
                    self.key_of(a.slot),
                    a.email.clone(),
                    a.organization_uuid.clone(),
                )
            })
            .collect();
        self.ctx.store.entries(&keys, &self.ctx.settings.models)
    }

    // -- the snapshot ------------------------------------------------------

    /// The decision-grade picture of every account.
    ///
    /// Headroom comes from the usage store's own `decision_windows` — the
    /// measurement it still trusts — and is `None` for any account carrying a
    /// sentinel, which is cswap's `decision_value()` returning a sentinel
    /// string instead of a usage dict. Deciding from the contract view's
    /// `lastGood` instead would call a measurement the store has stopped
    /// trusting authoritative, and the engine would rank slots `list` reports
    /// as unknown.
    fn snapshot(&self, view: &ProviderView) -> Result<Snapshot> {
        let now = self.ctx.now();
        let entries = self.entries(view)?;

        let mut snap = Snapshot {
            headroom: BTreeMap::new(),
            windows: BTreeMap::new(),
            fetch_errors: BTreeMap::new(),
            fresh: BTreeMap::new(),
        };
        for account in &view.accounts {
            let entry = entries.get(&self.key_of(account.slot));
            let measurable = matches!(account.usage_status, UsageStatus::Ok | UsageStatus::Stale);
            let windows: Vec<Window> = measurable
                .then(|| entry.and_then(|e| e.decision_windows()))
                .flatten()
                .map(<[Window]>::to_vec)
                .unwrap_or_default();
            let headroom = binding_pct(&windows, &self.ctx.settings.models).map(|pct| 100.0 - pct);
            if headroom.is_none() {
                if let Some(kind) = entry.and_then(|e| e.last_error.clone()) {
                    snap.fetch_errors.insert(account.slot, kind);
                }
            }
            snap.fresh
                .insert(account.slot, entry.is_some_and(|entry| entry.fresh(now)));
            snap.headroom.insert(account.slot, headroom);
            snap.windows.insert(account.slot, windows);
        }
        Ok(snap)
    }

    /// The poll event's per-slot window breakdown: the windows the DECISION
    /// read, in report order. Deliberately restricted to those — showing an
    /// unconfigured scoped window at 100% next to a switch onto that account
    /// would look like a bug when the engine correctly ignored it.
    fn poll_windows(&self, snap: &Snapshot) -> BTreeMap<u32, Vec<(String, f64)>> {
        snap.windows
            .iter()
            .map(|(slot, windows)| {
                let pcts: Vec<(String, f64)> = relevant(windows, &self.ctx.settings.models)
                    .into_iter()
                    .map(|w| (window_label(w), w.pct))
                    .collect();
                (*slot, pcts)
            })
            .filter(|(_, pcts)| !pcts.is_empty())
            .collect()
    }

    /// Earliest moment any account becomes usable again, or `None` when that
    /// cannot be proven (`autoswitch.py:2721-2757`).
    ///
    /// Per account it is the LATEST reset among its ≥100% windows — an account
    /// blocked on both its 5h and a weekly limit is not usable when the 5h
    /// rolls over — then the minimum across accounts. One blocked account
    /// whose exhausted windows carry no reset at all makes the whole answer
    /// unprovable: it could recover at any moment, and sleeping toward another
    /// account's later reset would miss it.
    fn earliest_recovery(&self, snap: &Snapshot, models: &[String]) -> Option<f64> {
        let now = self.ctx.now();
        let mut earliest: Option<f64> = None;
        for windows in snap.windows.values() {
            if !relevant(windows, models).iter().any(|w| w.pct >= 100.0) {
                continue;
            }
            let usable_at = limiting_reset_ts(windows, models)?;
            if usable_at <= now {
                return None;
            }
            earliest = Some(earliest.map_or(usable_at, |e: f64| e.min(usable_at)));
        }
        earliest
    }

    /// One-shot `model` typo guard (`autoswitch.py:2675-2719`): a configured
    /// name no account reports means the filter looks active while gating
    /// nothing. Only provable once every relevant account has readable usage —
    /// adaptive polling legitimately leaves gaps before that.
    fn check_model_names(
        &mut self,
        view: &ProviderView,
        snap: &Snapshot,
        quarantined: &BTreeSet<u32>,
    ) {
        let wanted: Vec<String> = self
            .ctx
            .settings
            .models
            .iter()
            .filter(|m| m.to_lowercase() != "all")
            .cloned()
            .collect();
        if wanted.is_empty() {
            self.model_check_done = true; // a bare `all` needs no name match
            return;
        }
        let relevant_slots: Vec<u32> = view
            .accounts
            .iter()
            .filter(|a| !quarantined.contains(&a.slot) && !is_api_key(a) && switchable(a))
            .map(|a| a.slot)
            .collect();
        if relevant_slots.is_empty()
            || relevant_slots
                .iter()
                .any(|slot| snap.windows(*slot).is_empty())
        {
            return; // not every account observed yet — re-check next tick
        }
        let seen: BTreeSet<String> = relevant_slots
            .iter()
            .flat_map(|slot| snap.windows(*slot))
            .filter_map(|w| w.name.as_ref())
            .map(|name| name.to_lowercase())
            .collect();
        self.model_check_done = true;
        let missing: Vec<String> = wanted
            .into_iter()
            .filter(|name| !seen.contains(&name.to_lowercase()))
            .collect();
        if !missing.is_empty() {
            self.emit(Event::ConfigWarning {
                message: format!(
                    "model: {} matches no account's usage windows — only the 5h/7d \
                     limits are being watched for it (typo?)",
                    missing.join(", ")
                ),
            });
        }
    }

    /// The candidates `preferred` names, by slot number, alias or email.
    fn preferred_slots(&self, view: &ProviderView, candidates: &[u32]) -> BTreeSet<u32> {
        candidates
            .iter()
            .copied()
            .filter(|slot| {
                account_of(view, *slot)
                    .is_some_and(|a| switch::is_preferred(a, &self.ctx.settings.preferred))
            })
            .collect()
    }

    /// Whether the CLI holds a live login no slot claims.
    fn has_live_login(&self) -> bool {
        self.driver
            .read_live(&self.ctx.env)
            .is_ok_and(|login| !login.bytes.trim().is_empty())
    }

    // -- the choice --------------------------------------------------------

    /// Rank with the no-return bar, and again WITHOUT it when the bar leaves
    /// nothing AND the barred account has genuinely recovered
    /// (`autoswitch.py:1315-1390`).
    ///
    /// Emptiness alone cannot be the release: on two accounts there is exactly
    /// one candidate, so barring it always empties the list and an
    /// emptiness-only release fires every tick — the bar would be inert at
    /// exactly the fleet size flapping was reported on.
    fn rank(&self, state: &AutoState, input: RankInput) -> (Vec<u32>, bool, Option<f64>) {
        let recovered = self.left_account_recovered(state, &input);
        let no_return = self.no_return_account(state, &input, recovered);
        let ranked = self.rank_candidates(&input, no_return);
        if no_return.is_some() && ranked.0.is_empty() && recovered {
            let unbarred = self.rank_candidates(&input, None);
            if !unbarred.0.is_empty() {
                return unbarred;
            }
        }
        ranked
    }

    /// Filter and rank the candidates for this tick's trigger
    /// (`autoswitch.py:2016-2235`). Pure: no events, no state writes.
    ///
    /// Answers `(ordered, any_known, active_reset_ts)`.
    fn rank_candidates(
        &self,
        input: &RankInput,
        no_return: Option<u32>,
    ) -> (Vec<u32>, bool, Option<f64>) {
        let RankInput {
            trigger,
            consume_first,
            candidates,
            snap,
            current,
            active_headroom,
            settings,
            preferred,
            now,
        } = *input;
        let models = &settings.models;

        // consume-first ranks by soonest weekly reset; a below-threshold
        // target must reset strictly sooner than where we are.
        let active_reset_ts = consume_first
            .then(|| seven_day_reset_ts(snap.windows(current), now))
            .flatten();
        // When NOTHING is below the threshold, "land somewhere healthy" has no
        // answer and holding out for one costs the user the session: the goal
        // changes from "most headroom" to "soonest back".
        let all_above =
            every_account_above_threshold(candidates, snap, active_headroom, settings.threshold);
        // Is anything worth having? The most headroom any READABLE candidate
        // offers. Unknown headroom is skipped rather than counted as zero — a
        // row we cannot read is not evidence of an empty account. The barred
        // account counts too: this asks whether the FLEET has quota, and the
        // bar is about where to move, not about what exists.
        let best_candidate_headroom = candidates
            .iter()
            .filter_map(|slot| snap.headroom(*slot))
            .fold(0.0_f64, f64::max);
        let active_recovery_ts = if all_above {
            binding_recovery_ts(snap.windows(current), models, now)
        } else {
            0.0
        };
        let proactive = matches!(trigger, "proactive" | "consume-first");

        let mut qualifying: Vec<(Key, usize, u32)> = Vec::new();
        let mut fallback: Vec<(Key, usize, u32)> = Vec::new();
        let mut any_known = false;
        for (index, slot) in candidates.iter().copied().enumerate() {
            let Some(h) = snap.headroom(slot) else {
                continue;
            };
            any_known = true; // it exists and is readable, either way
            if h <= 0.0 {
                continue; // itself at its limit — never a target
            }
            if Some(slot) == no_return {
                continue; // the account we just left
            }
            let reset_ts = consume_first
                .then(|| seven_day_reset_ts(snap.windows(slot), now))
                .flatten();
            let recovery_ts = if all_above {
                binding_recovery_ts(snap.windows(slot), models, now)
            } else {
                0.0
            };
            let active_h = active_headroom.unwrap_or(0.0);
            let mut by_recovery = false;
            if proactive {
                // Landing must be healthy: an account at or over the threshold
                // would re-trigger on the very next tick. at-limit and
                // failover are escapes and skip this whole block — any account
                // with real headroom beats a blocked or dead one.
                if (100.0 - h) >= settings.threshold && !all_above {
                    continue;
                }
                if all_above {
                    // Which axis this pair ranks on is decided per candidate,
                    // in one place: deciding it once, globally, left holes.
                    by_recovery = recovery_is_useful(
                        recovery_ts,
                        active_recovery_ts,
                        active_h,
                        best_candidate_headroom,
                        now,
                    );
                    if by_recovery {
                        // Hysteresis on the axis we actually rank by: the
                        // target must come back meaningfully sooner.
                        if recovery_ts >= active_recovery_ts - RECOVERY_HYSTERESIS_S {
                            continue;
                        }
                    } else if h < active_h * HORIZON_HEADROOM_RATIO {
                        // Headroom axis, with a RATIO margin — a rate bound,
                        // not impossibility. The one-way fallback re-admits a
                        // candidate that missed the margin but is the only
                        // thing left, which is what stops the visible-but-
                        // unchoosable band from parking the engine.
                        if active_h <= SPENT_HEADROOM_PCT
                            && h >= active_h
                            && recovery_ts < active_recovery_ts - RECOVERY_HYSTERESIS_S
                        {
                            fallback.push((Key::recovery_tier(recovery_ts, h), index, slot));
                        }
                        continue;
                    }
                } else if consume_first {
                    // Purely proactive on reset ordering: below the threshold,
                    // only move to accounts whose weekly window resets sooner
                    // than the active one. A preferred account is exempt —
                    // pinned means the engine returns to it as soon as it has
                    // room, whatever its reset.
                    if trigger == "consume-first"
                        && !preferred.contains(&slot)
                        && match (reset_ts, active_reset_ts) {
                            (Some(reset), Some(active)) => reset >= active,
                            _ => true,
                        }
                    {
                        continue;
                    }
                } else if let Some(active_h) = active_headroom {
                    // best: the candidate must beat the active account by the
                    // full hysteresis margin (a one-way move like 99%→89%
                    // qualifies; near-line pairs cannot flap back).
                    if h - active_h < settings.hysteresis_pct {
                        continue;
                    }
                }
            }

            let mut key = if all_above && proactive {
                // Tiered so the two axes stay comparable: a candidate
                // returning inside the horizon beats one that does not,
                // whatever its headroom. Untiered, a raw headroom and an epoch
                // were compared elementwise and headroom won on magnitude.
                if by_recovery {
                    Key::recovery_tier(recovery_ts, h)
                } else {
                    Key::headroom_tier(h, recovery_ts)
                }
            } else if consume_first {
                // Soonest weekly reset first (unknown sorts last), most
                // headroom breaks ties.
                Key::new(&[reset_ts.unwrap_or(f64::INFINITY), -h])
            } else {
                Key::new(&[-h])
            };
            // `preferred` picks which SOUND target to take among the ones the
            // gates already admitted; it can never land somewhere that
            // re-triggers. The recovery-tier keys are left alone on purpose:
            // when every account is spent, soonest-back is the whole point.
            if !preferred.is_empty() && !(all_above && proactive) {
                key = key.behind(if preferred.contains(&slot) { 0.0 } else { 1.0 });
            }
            qualifying.push((key, index, slot));
        }

        let mut ranked = if qualifying.is_empty() {
            fallback
        } else {
            qualifying
        };
        // Ascending by the strategy's key; rotation order breaks ties.
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        (
            ranked.into_iter().map(|(_, _, slot)| slot).collect(),
            any_known,
            active_reset_ts,
        )
    }

    /// The account this engine most recently left, while it is still barred
    /// (`autoswitch.py:1601-1750`).
    ///
    /// NEVER UNDO THE PREVIOUS MOVE. Each anti-flap gate is one-way on its own
    /// axis, but the axis is a property of the pair's state and burn changes
    /// that state — so a burning pair crosses the boundary repeatedly and each
    /// crossing re-opens a move.
    fn no_return_account(
        &self,
        state: &AutoState,
        input: &RankInput,
        recovered: bool,
    ) -> Option<u32> {
        let departure = state.left_at_limit.as_ref()?;
        let barred = departure.from;
        // The bar is for the discretionary triggers; an at-limit or failover
        // escape MUST move and may go anywhere — except back onto an account
        // whose own at-limit departure has not reset yet.
        if !matches!(input.trigger, "proactive" | "consume-first")
            && !left_at_limit_holds(departure, input.now)
        {
            return None;
        }
        // Only while we are still standing where that switch put us: a manual
        // switch away has already undone the move.
        if departure.to != input.current {
            return None;
        }
        if !recovered {
            return Some(barred); // the ratio below burns true on its own
        }
        // A pinned account is pinned: once it has genuinely recovered the
        // engine goes back to it without asking it to dominate the active.
        if input.preferred.contains(&barred) {
            return None;
        }
        if let Some(left) = input.snap.headroom(barred) {
            match input.active_headroom {
                // It beats us outright; taking it is not a flip.
                Some(active) if left >= active * HORIZON_HEADROOM_RATIO => return None,
                // An unreadable active must not be silently scored as "the
                // peer does not beat it": ask whether the peer would be a
                // healthy place to land at all.
                None if left > 100.0 - input.settings.threshold => return None,
                _ => {}
            }
        }
        Some(barred)
    }

    /// Is the account we left a better proposition than when we left it
    /// (`autoswitch.py:1764-2014`)?
    ///
    /// This is the release the bar needs and the ranking cannot supply: "the
    /// bar leaves nothing" is also what every flap looks like on two accounts,
    /// so lifting on emptiness alone lifts always. The distinction is not in
    /// the present state but between the present and the moment of departure,
    /// which is why `record_switch` stores that moment.
    fn left_account_recovered(&self, state: &AutoState, input: &RankInput) -> bool {
        let Some(departure) = state.left_at_limit.as_ref() else {
            return true; // no evidence either way: release
        };
        let barred = departure.from;
        // Proven spent by its own at-limit departure and not yet reset: until
        // then no usage reading can release it, because the API lags a real
        // limit by up to a poll interval.
        if left_at_limit_holds(departure, input.now) {
            return false;
        }
        let models = &input.settings.models;
        let h = input.snap.headroom(barred);

        if departure.trigger == "failover" {
            // A failover departure measured nothing, so there is no baseline
            // to diff against and the active's headroom cannot be read here.
            // Two legs instead, both against current state: would the ranking
            // accept this peer as a landing spot at all, and is its binding
            // reset meaningfully sooner than the active's?
            if h.is_some_and(|h| h > 100.0 - input.settings.threshold) {
                return true;
            }
            let peer = binding_recovery_ts(input.snap.windows(barred), models, input.now);
            let active = binding_recovery_ts(input.snap.windows(input.current), models, input.now);
            // The active's reset must be a REAL measurement: `inf` means both
            // "never" and "unknown", and reading it as "never" released onto a
            // peer arbitrarily far out on no evidence. A peer already inside
            // the horizon is admitted regardless, because two of `inf`'s five
            // causes are ordinary shapes for an active that is plainly alive.
            return (active.is_finite() || peer - input.now <= RECOVERY_HORIZON_S)
                && peer < active - RECOVERY_HYSTERESIS_S;
        }

        // Dominance over the ACTIVE. A peer moved away from for a reason other
        // than headroom (consume-first's reset ordering) can dominate from the
        // moment it was left, and self-improvement against its own baseline
        // never fires for an account that had nothing to improve on.
        if let Some(h) = h {
            match input.active_headroom {
                Some(active) if h > active * HORIZON_HEADROOM_RATIO + SPENT_HEADROOM_PCT => {
                    return true
                }
                // Unreadable active: fall back to the landing-eligible test,
                // rather than silently reading "unreadable" as "no dominance".
                None if h > 100.0 - input.settings.threshold => return true,
                _ => {}
            }
        }
        // Self-improvement against the departure baseline, with the margin the
        // headroom axis already uses.
        if let (Some(left), Some(h)) = (departure.headroom, h) {
            if h >= (left + SPENT_HEADROOM_PCT).min(100.0) {
                return true;
            }
        }
        // Or its binding window comes back meaningfully sooner than it did at
        // departure. `None` is the JSON-safe spelling of "unknown or already
        // past": moving off that onto a real reset IS the improvement.
        let was = departure.recovery_at.unwrap_or(f64::INFINITY);
        binding_recovery_ts(input.snap.windows(barred), models, input.now)
            < was - RECOVERY_HYSTERESIS_S
    }

    // -- state -------------------------------------------------------------

    /// The state file, or an empty state.
    ///
    /// Lenient on purpose (cswap `_read_state`): this file is a memo one tick
    /// leaves the next, and a corrupt one must not park the daemon. The worst
    /// a reset costs is one forgotten cooldown and one re-earned quarantine.
    fn read_state(&self) -> AutoState {
        match read_json::<AutoState>(&self.ctx.home.auto_state_file()) {
            Ok(state) => state,
            Err(e) => {
                eprintln!(
                    "warning: {}: {}; starting from an empty state",
                    self.ctx.home.auto_state_file().display(),
                    e.message
                );
                AutoState::default()
            }
        }
    }

    /// Read-modify-write the state under its own lock, so a tick's quarantine
    /// write cannot lose a cooldown written a moment earlier.
    fn mutate_state(&self, mutate: impl FnOnce(&mut AutoState)) -> Result<AutoState> {
        let path = self.ctx.home.auto_state_file();
        let _lock = FileLock::acquire(&path, LOCK_TIMEOUT)?;
        let mut state = self.read_state();
        state.schema_version = STATE_SCHEMA_VERSION;
        mutate(&mut state);
        write_json_atomic(&path, &state)?;
        Ok(state)
    }

    fn in_cooldown(&self, state: &AutoState) -> bool {
        state
            .cooldown_until
            .is_some_and(|until| self.ctx.now() < until)
    }

    /// Take a slot out of the rotation until its credential is replaced.
    fn quarantine(&mut self, slot: u32, email: &str, reason: &str) -> Result<()> {
        let fingerprint = self.stored_fingerprint(slot)?;
        let since = format_ts(self.ctx.now()).unwrap_or_default();
        let entry = Quarantine {
            reason: reason.to_string(),
            since,
            fingerprint,
        };
        self.mutate_state(|state| {
            state.quarantine.insert(slot.to_string(), entry);
        })?;
        self.emit(Event::Quarantined {
            account: SlotRef::numbered(slot, email),
            reason: reason.to_string(),
        });
        Ok(())
    }

    /// Drop quarantine entries whose credential has been replaced since
    /// (`autoswitch.py:838-870`).
    ///
    /// A changed fingerprint means the user logged in again and re-captured
    /// the account: the dead lineage is gone, so the slot re-enters rotation.
    /// A slot that no longer has a stored login at all (removed, or removed
    /// and re-added) reads the same way, which is the answer we want.
    fn release_recovered_quarantines(&mut self, state: &mut AutoState) -> Result<()> {
        if state.quarantine.is_empty() {
            return Ok(());
        }
        let slots = slots::load(&self.ctx.home, self.driver.id())?;
        let mut released: Vec<(u32, String)> = Vec::new();
        for (key, entry) in &state.quarantine {
            let Ok(slot) = key.parse::<u32>() else {
                continue;
            };
            if self.stored_fingerprint(slot)? != entry.fingerprint {
                let email = slots
                    .slots
                    .get(&slot)
                    .map(|s| s.email.clone())
                    .unwrap_or_default();
                released.push((slot, email));
            }
        }
        if released.is_empty() {
            return Ok(());
        }
        *state = self.mutate_state(|state| {
            for (slot, _) in &released {
                state.quarantine.remove(&slot.to_string());
            }
        })?;
        for (slot, email) in released {
            self.emit(Event::Unquarantined {
                account: SlotRef::numbered(slot, email),
                reason: "credentials-replaced".to_string(),
            });
        }
        Ok(())
    }

    fn stored_fingerprint(&self, slot: u32) -> Result<Option<String>> {
        Ok(self
            .ctx
            .secrets
            .get(&slot_key(self.driver.id(), slot))?
            .filter(|bytes| !bytes.trim().is_empty())
            .map(|bytes| Login { bytes }.fingerprint()))
    }

    /// Record a landed switch: the cooldown it starts, and the departure the
    /// next tick's no-return bar reads (`autoswitch.py:2435-2456`).
    ///
    /// cswap holds its state lock across the whole recheck → switch → record
    /// sequence so a cron `--once` and a loop cannot double-switch. swapd does
    /// not need to: `auto.lock` already admits one engine per data dir, and a
    /// manual `swapd switch` never touches this file.
    fn record_switch(
        &self,
        target: u32,
        from: Option<&SlotRef>,
        trigger: &str,
        left: (Option<f64>, f64),
    ) -> Result<()> {
        let now = self.ctx.now();
        let cooldown = self.ctx.settings.cooldown_seconds;
        let (headroom, recovery) = left;
        // A live login no slot claims cannot be barred: there is nothing to
        // refuse to switch back to.
        let departure = from.and_then(|from| from.slot).map(|slot| Departure {
            from: slot,
            to: target,
            trigger: trigger.to_string(),
            headroom,
            recovery_at: recovery.is_finite().then_some(recovery),
        });
        self.mutate_state(|state| {
            state.cooldown_until = Some(now + cooldown);
            state.left_at_limit = departure;
        })?;
        Ok(())
    }

    // -- cadence -----------------------------------------------------------

    /// How long to wait before the next tick, and the `sleep` event that says
    /// so (`autoswitch.py:2779-2810`).
    ///
    /// Jitter (±10%) keeps several machines from synchronizing their upstream
    /// hits. cswap also shortens a sleep to the usage store's own next-poll
    /// time; swapd's collector re-checks due-ness on every tick from the
    /// stored plans, so that shortening is left out.
    pub fn schedule(&mut self, outcome: TickOutcome, rng: impl FnOnce() -> f64) -> f64 {
        let interval = self.ctx.settings.interval_seconds;
        let delay = match outcome {
            TickOutcome::Blocked => match self.sleep_until {
                // A known reset: wait for it, but never past the bounded
                // exhausted-account cadence — quota can be granted early.
                Some(until) => (until - self.ctx.now()).max(interval).min(MAX_SLEEP_S),
                // Truly exhausted with no known reset, or no candidates at
                // all. Anything else that blocks can resolve on any tick
                // (hysteresis, unreadable usage), so it keeps the cadence.
                None if self.blocked_wait_long => interval.max(NO_RESET_FALLBACK_S),
                None => interval,
            },
            // Idle-hold: the CLI is idle on an expired token, so nothing
            // changes until the user comes back. Crawl.
            TickOutcome::NoAction if self.idle_hold_slow => interval.max(NO_RESET_FALLBACK_S),
            _ => interval * (0.9 + 0.2 * rng()),
        };
        let until = format_ts(self.ctx.now() + delay).unwrap_or_default();
        self.emit(Event::Sleep {
            seconds: delay,
            until,
        });
        delay
    }
}

/// What `classify` decided.
enum Classified {
    /// Nothing happens this tick, and the reason has been emitted.
    Hold(TickOutcome),
    /// cswap's trigger names, which are also the history log's.
    Trigger(&'static str),
}

/// Everything the ranking reads. Grouped because the consume-first path in
/// cswap re-ranks with a second snapshot, and a caller must not be able to
/// pass half of one picture and half of another.
#[derive(Clone, Copy)]
struct RankInput<'a> {
    trigger: &'a str,
    consume_first: bool,
    candidates: &'a [u32],
    snap: &'a Snapshot,
    current: u32,
    active_headroom: Option<f64>,
    settings: &'a Settings,
    preferred: &'a BTreeSet<u32>,
    now: f64,
}

/// One candidate's sort key: up to four `f64` components compared in order.
///
/// A tuple per strategy would be four types; every branch of the ranking sorts
/// candidates that all took the SAME branch, so one shape with unused
/// components zeroed compares exactly as cswap's tuples do.
struct Key([f64; 4]);

impl Key {
    fn new(parts: &[f64]) -> Key {
        let mut key = [0.0; 4];
        key[..parts.len()].copy_from_slice(parts);
        Key(key)
    }

    /// The all-above recovery tier: soonest back first.
    fn recovery_tier(recovery_ts: f64, headroom: f64) -> Key {
        Key::new(&[0.0, recovery_ts, -headroom])
    }

    /// The all-above headroom tier: most headroom first, soonest reset breaks
    /// ties.
    fn headroom_tier(headroom: f64, recovery_ts: f64) -> Key {
        Key::new(&[1.0, -headroom, recovery_ts])
    }

    /// The same key with one component in front of it (`preferred`).
    fn behind(self, first: f64) -> Key {
        Key([first, self.0[0], self.0[1], self.0[2]])
    }

    fn cmp(&self, other: &Key) -> std::cmp::Ordering {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| a.total_cmp(b))
            .find(|o| o.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

/// Rank THIS candidate by soonest reset rather than by headroom
/// (`autoswitch.py:172-250`)?
///
/// Reset wins when everything worth having is spent — below
/// `SPENT_HEADROOM_PCT` a headroom edge is under two poll intervals, so the
/// only real question is which account returns first. It also wins when either
/// side of the pair is back soon: the axis is a property of the PAIR, which is
/// what stops a switch (which swaps who is "active") from flipping the axis
/// with it and letting each leg of a flap pass a different gate.
fn recovery_is_useful(
    candidate_recovery_ts: f64,
    active_recovery_ts: f64,
    active_headroom: f64,
    best_candidate_headroom: f64,
    now: f64,
) -> bool {
    if active_headroom <= SPENT_HEADROOM_PCT && best_candidate_headroom <= SPENT_HEADROOM_PCT {
        return true;
    }
    candidate_recovery_ts - now <= RECOVERY_HORIZON_S
        || active_recovery_ts - now <= RECOVERY_HORIZON_S
}

/// Whether the active account and every measured candidate are at or over the
/// threshold — the state where "land somewhere healthy" has no answer
/// (`autoswitch.py:683-703`).
///
/// The active account's own headroom must be known: without it we do not know
/// we are in this state, and guessing would relax the landing rule on an
/// ordinary tick. An unmeasured candidate does not block the verdict — it
/// cannot be chosen either — as long as at least one candidate was measured.
fn every_account_above_threshold(
    candidates: &[u32],
    snap: &Snapshot,
    active_headroom: Option<f64>,
    threshold: f64,
) -> bool {
    let Some(active) = active_headroom else {
        return false;
    };
    if (100.0 - active) < threshold {
        return false;
    }
    let measured: Vec<f64> = candidates
        .iter()
        .filter_map(|slot| snap.headroom(*slot))
        .collect();
    !measured.is_empty() && measured.iter().all(|h| (100.0 - h) >= threshold)
}

/// The account we left was PROVEN spent — it left at its limit — and its
/// window has not reset yet (`autoswitch.py:1753-1762`). Until then no usage
/// reading can release it: the API lags a real limit by up to a poll interval,
/// and that reading is exactly what would make a spent account look best.
fn left_at_limit_holds(departure: &Departure, now: f64) -> bool {
    departure.trigger == "at-limit" && departure.recovery_at.is_some_and(|until| now < until)
}

/// When this account's BINDING window comes back, as a sort key
/// (`autoswitch.py:648-680`).
///
/// The binding window is the one holding the account back — the same set
/// headroom is measured on, so ranking and headroom can never disagree about
/// which window matters. Picked first, THEN asked for its reset: filtering on
/// the reset first lets a lower window win whenever the binding one's reset is
/// unknown. `inf` for unknown or already past, so such accounts sort last
/// rather than masquerading as "back immediately".
fn binding_recovery_ts(windows: &[Window], models: &[String], now: f64) -> f64 {
    let relevant = relevant(windows, models);
    let Some(binding) = relevant.iter().max_by(|a, b| a.pct.total_cmp(&b.pct)) else {
        return f64::INFINITY;
    };
    match parse_reset_ts(binding.resets_at.as_deref()) {
        Some(ts) if ts > now => ts,
        _ => f64::INFINITY,
    }
}

/// Epoch of an account's weekly reset, or `None` when unknown or already past
/// (`autoswitch.py:627-646`).
///
/// consume-first ranks by this — the weekly window is the perishable quota.
/// A stale snapshot can carry a `resets_at` that has since elapsed; treated as
/// a real instant it would sort the just-rolled-over account (the least
/// perishable quota of all) as "soonest", so past means unknown.
fn seven_day_reset_ts(windows: &[Window], now: f64) -> Option<f64> {
    windows
        .iter()
        .find(|w| w.kind == crate::contract::WindowKind::SevenDay)
        .and_then(|w| parse_reset_ts(w.resets_at.as_deref()))
        .filter(|ts| *ts > now)
}

fn account_of(view: &ProviderView, slot: u32) -> Option<&AccountView> {
    view.accounts.iter().find(|a| a.slot == slot)
}

fn account_ref(view: &ProviderView, slot: u32) -> SlotRef {
    SlotRef::numbered(
        slot,
        account_of(view, slot)
            .map(|a| a.email.clone())
            .unwrap_or_default(),
    )
}

fn is_api_key(account: &AccountView) -> bool {
    account.usage_status == UsageStatus::ApiKey
}

/// Whether the rotation may consider this account at all (cswap
/// `switchable_account_numbers`): the collector's own rule.
/// Is the ACTIVE account nominated for this tick's baseline fetch
/// (`autoswitch.py:2303-2331`)?
///
/// Never measured, no plan yet and past the cadence floor, plan due, a
/// deadline no bounded planner could have written (reset-parking from an older
/// release), or a candidate-style plan left on the slot by a role change the
/// engine never saw — a manual `/login` makes the active account inherit the
/// slower cadence, and without this clause it would keep it forever.
fn active_is_due(entry: Option<&Entry>, now: f64, models: &[String]) -> bool {
    let Some(entry) = entry else {
        return true;
    };
    let Some(age) = entry.age_s else {
        return true;
    };
    let stale_candidate_plan = age >= poll_policy::ACTIVE_MAX_INTERVAL_S
        && entry.interval_s.unwrap_or(0.0) > poll_policy::ACTIVE_MAX_INTERVAL_S
        && binding_pct(entry.last_good.as_deref().unwrap_or(&[]), models).unwrap_or(0.0) < 100.0;
    if stale_candidate_plan || plan_oversleeps_interval(entry, now) {
        return true;
    }
    match entry.next_poll_at {
        Some(next) => now >= next,
        None => age >= poll_policy::MIN_INTERVAL_S,
    }
}

/// A row resting on a plan wider than the exhausted cadence, on an account
/// that reads spent: escalation leaves it alone (`autoswitch.py:2367-2388`).
fn parked_exhausted(entry: Option<&Entry>, headroom: Option<f64>, now: f64) -> bool {
    let Some(entry) = entry else {
        return false;
    };
    entry.next_poll_at.is_some_and(|next| now < next)
        && entry.interval_s.unwrap_or(0.0) > poll_policy::EXHAUSTED_INTERVAL_S
        && headroom.is_some_and(|h| h <= 0.0)
}

fn switchable(account: &AccountView) -> bool {
    !account.disabled
        && !matches!(
            account.usage_status,
            UsageStatus::NoCredentials | UsageStatus::ReloginRequired | UsageStatus::Unsupported
        )
}

#[cfg(test)]
#[path = "auto/tests.rs"]
mod tests;
