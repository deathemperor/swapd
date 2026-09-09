//! The NDJSON stream `swapd auto` writes: one JSON object per line, one line
//! per decision the engine made.
//!
//! Port of cswap's event classes (`autoswitch.py:296-580`), with three kinds
//! deliberately left out — `session-resumed`, `remote-control-rearmed` and
//! `away-notified` describe work Infinitus owns (the resume/nudge mechanism
//! and the notification channels), not work an engine does.
//!
//! Every line is `{"schemaVersion":1,"event":<kind>,"ts":<rfc3339>,
//! "provider":<id>, …fields}`. Payloads are ADDITIVE: a reader must ignore
//! kinds and fields it does not know, which is what lets a later task add an
//! event without breaking the app's decoder.
//!
//! An account is always named the same way — `{"number":n,"slot":n,"email"}`.
//! `number` is cswap's spelling and the app's existing decoder reads it;
//! `slot` is swapd's, and both carry the same value so neither reader has to
//! learn the other's vocabulary.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::core::history::SlotRef;
use crate::output::SCHEMA_VERSION;

/// One window's label as the poll event names it: `5h`, `7d`, or the scoped
/// window's own display name.
pub fn window_label(window: &crate::contract::Window) -> String {
    use crate::contract::WindowKind::*;
    match window.kind {
        FiveHour => "5h".to_string(),
        SevenDay => "7d".to_string(),
        Daily => "daily".to_string(),
        Monthly => "monthly".to_string(),
        Spend => "spend".to_string(),
        Scoped => window.name.clone().unwrap_or_else(|| "scoped".to_string()),
    }
}

/// What the engine has to say. One variant per event kind; the wire shape is
/// `Emit::to_json`.
pub enum Event {
    Poll {
        /// The active account, or `None` when nothing manages the live login.
        active: Option<SlotRef>,
        /// Slot → headroom pct, `None` where this tick could not measure it.
        headroom: BTreeMap<u32, Option<f64>>,
        threshold: f64,
        /// Slot → the classified cause of an unknown headroom.
        fetch_errors: BTreeMap<u32, String>,
        /// Slot → the windows the DECISION read, in report order. The binding
        /// pct alone hides which window binds (cswap #115 was filed off that
        /// ambiguity).
        windows: BTreeMap<u32, Vec<(String, f64)>>,
    },
    Switch {
        trigger: String,
        from: Option<SlotRef>,
        to: SlotRef,
        warnings: Vec<String>,
    },
    NoSwitch {
        reason: String,
        detail: String,
    },
    Quarantined {
        account: SlotRef,
        reason: String,
    },
    Unquarantined {
        account: SlotRef,
        reason: String,
    },
    AllExhausted {
        earliest_reset_at: Option<String>,
    },
    Sleep {
        seconds: f64,
        until: String,
    },
    Error {
        message: String,
        transient: bool,
    },
    EngineRefused {
        message: String,
    },
    ConfigWarning {
        message: String,
    },
}

/// One event, stamped: the moment it describes (the engine's clock, so a
/// replayed or tested run stamps its own time) and the provider it is about.
pub struct Emit {
    pub ts: String,
    pub provider: String,
    pub event: Event,
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Poll { .. } => "poll",
            Event::Switch { .. } => "switch",
            Event::NoSwitch { .. } => "no-switch",
            Event::Quarantined { .. } => "account-quarantined",
            Event::Unquarantined { .. } => "account-unquarantined",
            Event::AllExhausted { .. } => "all-exhausted",
            Event::Sleep { .. } => "sleep",
            Event::Error { .. } => "error",
            Event::EngineRefused { .. } => "engine-refused",
            Event::ConfigWarning { .. } => "config-warning",
        }
    }

    fn fields(&self) -> Map<String, Value> {
        let mut out = Map::new();
        match self {
            Event::Poll {
                active,
                headroom,
                threshold,
                fetch_errors,
                windows,
            } => {
                out.insert("active".into(), account_ref(active.as_ref()));
                out.insert("headroomPct".into(), by_slot(headroom, |h| json!(h)));
                out.insert("threshold".into(), json!(threshold));
                out.insert(
                    "fetchErrors".into(),
                    by_slot(fetch_errors, |kind| json!(kind)),
                );
                out.insert(
                    "windows".into(),
                    by_slot(windows, |pcts| {
                        Value::Object(
                            pcts.iter()
                                .map(|(label, pct)| (label.clone(), json!(pct)))
                                .collect(),
                        )
                    }),
                );
            }
            Event::Switch {
                trigger,
                from,
                to,
                warnings,
            } => {
                out.insert("trigger".into(), json!(trigger));
                out.insert("from".into(), account_ref(from.as_ref()));
                out.insert("to".into(), account_ref(Some(to)));
                out.insert("warnings".into(), json!(warnings));
                // Phase 1 has no dry-run mode; the field is here because the
                // app's decoder reads it and a missing key is not a `false`.
                out.insert("dryRun".into(), json!(false));
            }
            Event::NoSwitch { reason, detail } => {
                out.insert("reason".into(), json!(reason));
                out.insert("detail".into(), json!(detail));
            }
            Event::Quarantined { account, reason } | Event::Unquarantined { account, reason } => {
                out.insert("number".into(), json!(account.slot));
                out.insert("slot".into(), json!(account.slot));
                out.insert("email".into(), json!(account.email));
                out.insert("reason".into(), json!(reason));
            }
            Event::AllExhausted { earliest_reset_at } => {
                out.insert("earliestResetAt".into(), json!(earliest_reset_at));
            }
            Event::Sleep { seconds, until } => {
                out.insert("seconds".into(), json!((seconds * 10.0).round() / 10.0));
                out.insert("until".into(), json!(until));
            }
            Event::Error { message, transient } => {
                out.insert("message".into(), json!(message));
                out.insert("transient".into(), json!(transient));
            }
            Event::EngineRefused { message } | Event::ConfigWarning { message } => {
                out.insert("message".into(), json!(message));
            }
        }
        out
    }
}

impl Emit {
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("schemaVersion".into(), json!(SCHEMA_VERSION));
        out.insert("event".into(), json!(self.event.kind()));
        out.insert("ts".into(), json!(self.ts));
        out.insert("provider".into(), json!(self.provider));
        out.extend(self.event.fields());
        Value::Object(out)
    }

    /// One line for a human watching the stream.
    pub fn human(&self) -> String {
        match &self.event {
            Event::Poll {
                active,
                headroom,
                threshold,
                fetch_errors,
                windows,
            } => {
                let Some(active) = active else {
                    return "poll: no active account".to_string();
                };
                let slot = active.slot.unwrap_or_default();
                let used = match headroom.get(&slot).copied().flatten() {
                    Some(h) => format!("{:.0}% used", 100.0 - h),
                    None => match fetch_errors.get(&slot) {
                        Some(kind) => format!("usage unknown ({kind})"),
                        None => "usage unknown".to_string(),
                    },
                };
                let others: Vec<String> = headroom
                    .keys()
                    .filter(|n| **n != slot)
                    .map(|n| format!("#{n}: {}", describe(*n, headroom, fetch_errors, windows)))
                    .collect();
                let tail = if others.is_empty() {
                    String::new()
                } else {
                    format!(" | others: {}", others.join(", "))
                };
                format!(
                    "slot {slot} ({}): {used} (switch at {}%){tail}",
                    active.email,
                    pct_label(*threshold),
                )
            }
            Event::Switch {
                trigger, from, to, ..
            } => {
                let src = match from {
                    Some(from) => label(from),
                    None => "(none)".to_string(),
                };
                format!("switched {src} -> {} ({trigger})", label(to))
            }
            Event::NoSwitch { reason, detail } => {
                if detail.is_empty() {
                    format!("no switch: {reason}")
                } else {
                    format!("no switch: {reason} ({detail})")
                }
            }
            Event::Quarantined { account, reason } => format!(
                "{} quarantined: {reason}. Log in as it and run \
                 `swapd add --slot {}` to recover.",
                label(account),
                account.slot.unwrap_or_default()
            ),
            Event::Unquarantined { account, reason } => {
                format!("{} back in rotation ({reason})", label(account))
            }
            Event::AllExhausted { earliest_reset_at } => match earliest_reset_at {
                Some(at) => format!("all accounts exhausted; earliest reset {at}"),
                None => "all accounts exhausted; no reset time known".to_string(),
            },
            Event::Sleep { seconds, until } => {
                format!("sleeping {:.0}m (until {until})", seconds / 60.0)
            }
            Event::Error { message, transient } => {
                let tail = if *transient { " (will retry)" } else { "" };
                format!("error: {message}{tail}")
            }
            Event::EngineRefused { message } => format!("not starting: {message}"),
            Event::ConfigWarning { message } => format!("warning: {message}"),
        }
    }
}

/// A percentage as configured rather than as rounded: `85.555555` stays
/// itself and `99.9` never renders as a lying `100` (cswap `pct_label`).
fn pct_label(value: f64) -> String {
    let text = format!("{value:.10}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    text.to_string()
}

fn label(account: &SlotRef) -> String {
    match account.slot {
        Some(slot) => format!("slot {slot} ({})", account.email),
        None => format!("({})", account.email),
    }
}

/// One other account's state, in the same order the poll event reports it:
/// its windows if they are known, else its binding pct, else why not.
fn describe(
    slot: u32,
    headroom: &BTreeMap<u32, Option<f64>>,
    fetch_errors: &BTreeMap<u32, String>,
    windows: &BTreeMap<u32, Vec<(String, f64)>>,
) -> String {
    if let Some(pcts) = windows.get(&slot).filter(|w| !w.is_empty()) {
        return pcts
            .iter()
            .map(|(name, pct)| format!("{name} {pct:.0}%"))
            .collect::<Vec<_>>()
            .join(" · ");
    }
    if let Some(h) = headroom.get(&slot).copied().flatten() {
        return format!("{:.0}%", 100.0 - h);
    }
    match fetch_errors.get(&slot) {
        Some(kind) => format!("? ({kind})"),
        None => "?".to_string(),
    }
}

fn account_ref(account: Option<&SlotRef>) -> Value {
    match account {
        Some(account) => json!({
            "number": account.slot,
            "slot": account.slot,
            "email": account.email,
        }),
        None => Value::Null,
    }
}

/// A slot-keyed map as JSON: the keys are strings, because JSON object keys
/// always are.
fn by_slot<T>(map: &BTreeMap<u32, T>, value: impl Fn(&T) -> Value) -> Value {
    Value::Object(
        map.iter()
            .map(|(slot, v)| (slot.to_string(), value(v)))
            .collect(),
    )
}
