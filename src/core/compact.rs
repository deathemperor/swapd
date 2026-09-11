//! Renumber a provider's slots 1…n (deathemperor/swapd#22).
//!
//! The user's rule: "slots numbers must always sequential when an account is
//! removed." `remove` calls this after deleting its target, and `compact` runs
//! it on its own for a roster that is sparse for any other reason (an import
//! of a gapped cswap roster, a compaction that stopped at a live session).
//!
//! Every move is downward and processed ascending, so a slot is always moved
//! into a number that is already vacant: the gap itself, or a number whose
//! own account moved down one step earlier. A move carries everything keyed by
//! the number — the row (alias, icon, disabled, preferred, fingerprint…), its
//! place in `order`, `activeSlot`, the stored credential, the usage-store row,
//! the run profile (directory plus, on the Claude driver, the keychain item
//! Claude Code names after that directory), the auto loop's quarantine entry
//! and any `autoswitch.preferred` pin that names the number. The switch
//! history is a log of what happened and keeps the numbers it was written
//! with.
//!
//! Runs INSIDE a `slots::update` closure, so the whole renumber is one
//! `slots.json` lock cycle: a concurrent `add` cannot take a number that is
//! about to be vacated, and `list` never observes an account in two slots.
//! Each moving slot's refresh lock is held across the closure too, so a
//! refresh in flight cannot persist a successor token under a key that is
//! being copied out of or written into. The credential copies happen under the
//! lock and the vacated tail key is deleted under it as well, for the reason
//! `remove` gives: outside it, the tail key is exactly the one `next_free()`
//! hands the next `add`.
//!
//! An account with a live `run`/`ignite` session cannot move: the CLI is
//! reading and rotating the credential inside that slot's profile. The verbs
//! hold a shared lock on the slot's run lock for the child's lifetime, and a
//! move first tries the exclusive side of it without waiting. A busy slot
//! stops the renumber there — moving the slots above it would break their
//! relative order — and the caller says so, naming `compact` as the way to
//! finish once the session ends.
//!
//! A move that fails half-way stops the renumber the same way, and is never
//! an error: `remove` has already deleted its target's login and profile by
//! the time the renumber runs, and an `Err` out of the closure would keep
//! the row that pointed at them. Every step of a move is safe to repeat (the
//! copy overwrites, the relocations skip what already moved, the row moves
//! last), so `compact` finishes it. The one crash window is the same: a row
//! still under its old number while the bytes under that number are already
//! its lower neighbour's; the row's fingerprint no longer matches them.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;

use crate::core::auto;
use crate::core::settings;
use crate::core::slots::{ProviderSlots, LOCK_TIMEOUT};
use crate::core::store::FileLock;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::secrets::slot_key;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Move {
    pub from: u32,
    pub to: u32,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Compacted {
    pub moves: Vec<Move>,
    /// Where the renumber stopped, if it did. Every slot from there up kept
    /// its number.
    pub stopped_at: Option<Stop>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Stop {
    pub slot: u32,
    pub reason: String,
}

/// The moves that close every gap, ascending: the i-th occupied slot goes to
/// number i.
pub fn plan(provider: &ProviderSlots) -> Vec<Move> {
    provider
        .slots
        .keys()
        .enumerate()
        .filter_map(|(i, &from)| {
            let to = i as u32 + 1;
            (from != to).then_some(Move { from, to })
        })
        .collect()
}

/// Close every gap in `provider`'s numbering (see the module docs). Call
/// inside a `slots::update` closure; answers what moved and where it stopped.
pub fn compact(ctx: &Ctx, driver: &dyn Driver, provider: &mut ProviderSlots) -> Result<Compacted> {
    let id = driver.id();
    let plan = plan(provider);
    if plan.is_empty() {
        return Ok(Compacted::default());
    }
    // Every key a move reads or writes, fenced against an in-flight refresh
    // before the first move — the gap's own key included, so a refresh of
    // the account that just left it cannot persist a successor under the
    // number its neighbour is about to take.
    let keys: BTreeSet<u32> = plan.iter().flat_map(|m| [m.from, m.to]).collect();
    let refresh_locks: Result<Vec<FileLock>> = keys
        .iter()
        .map(|&n| FileLock::acquire(&ctx.home.refresh_lock_base(id, n), LOCK_TIMEOUT))
        .collect();
    let _refresh_locks = match refresh_locks {
        Ok(locks) => locks,
        Err(e) => return Ok(stopped(Vec::new(), plan[0].from, e.message)),
    };

    let mut done = Vec::new();
    let mut stopped_at = None;
    for m in plan {
        // The exclusive side of the run lock, without waiting: a live session
        // holds the shared side for as long as the CLI runs.
        let session = match FileLock::acquire(&ctx.home.run_lock_base(id, m.from), Duration::ZERO) {
            Ok(lock) => lock,
            Err(e) if e.code == ErrorCode::Locked => {
                stopped_at = Some(Stop {
                    slot: m.from,
                    reason: "a live session is using its profile".to_string(),
                });
                break;
            }
            Err(e) => return Ok(stopped(done, m.from, e.message)),
        };
        if let Err(e) = move_slot(ctx, driver, provider, &m) {
            return Ok(stopped(done, m.from, e.message));
        }
        drop(session);
        done.push(m);
    }
    if done.is_empty() {
        return Ok(Compacted {
            moves: done,
            stopped_at,
        });
    }
    // The tail: every number that was moved out of and nothing moved into.
    // Unreferenced bytes if the delete fails, so only a warning.
    let landed: BTreeSet<u32> = done.iter().map(|m| m.to).collect();
    for m in &done {
        if !landed.contains(&m.from) {
            if let Err(e) = ctx.secrets.delete(&slot_key(id, m.from)) {
                eprintln!(
                    "warning: slot {}'s old credential could not be deleted: {}",
                    m.from, e.message
                );
            }
        }
    }
    // The pins and the quarantine name numbers; the rows are the truth they
    // follow, so a rewrite that fails is a warning, not a lost renumber.
    let pairs: Vec<(u32, u32)> = done.iter().map(|m| (m.from, m.to)).collect();
    if let Err(e) = settings::renumber_preferred(&ctx.home, id, |n| {
        Some(
            pairs
                .iter()
                .find(|(from, _)| *from == n)
                .map_or(n, |(_, to)| *to),
        )
    }) {
        eprintln!(
            "warning: autoswitch.preferred still names the old slot numbers: {}",
            e.message
        );
    }
    if let Err(e) = auto::renumber_quarantine(&ctx.home, &pairs) {
        eprintln!(
            "warning: the auto loop's quarantine still names the old slot numbers: {}",
            e.message
        );
    }
    Ok(Compacted {
        moves: done,
        stopped_at,
    })
}

fn stopped(moves: Vec<Move>, slot: u32, reason: String) -> Compacted {
    Compacted {
        moves,
        stopped_at: Some(Stop { slot, reason }),
    }
}

fn move_slot(ctx: &Ctx, driver: &dyn Driver, provider: &mut ProviderSlots, m: &Move) -> Result<()> {
    let id = driver.id();
    // The credential first, as `claim` writes it: a row pointing at bytes that
    // never landed is a slot that cannot authenticate. A slot with no stored
    // credential must not inherit whatever the number held before it.
    match ctx.secrets.get(&slot_key(id, m.from))? {
        Some(bytes) => ctx.secrets.set(&slot_key(id, m.to), &bytes)?,
        None => ctx.secrets.delete(&slot_key(id, m.to))?,
    }
    ctx.store
        .relocate(&slot_key(id, m.from), &slot_key(id, m.to))?;
    // Outside the profile directory before the directory itself, as `remove`
    // orders `forget_profile` before `remove_dir_all`: the keychain item is
    // named after the directory's exact path, so it has to follow the rename.
    driver.relocate_profile(&ctx.env, m.from, m.to)?;
    let profiles = ctx.home.profiles_dir().join(id);
    let from = profiles.join(m.from.to_string());
    let to = profiles.join(m.to.to_string());
    match std::fs::rename(&from, &to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(SwapdError::new(
                ErrorCode::Io,
                format!("{} -> {}: {e}", from.display(), to.display()),
            ))
        }
    }
    let row = provider
        .slots
        .remove(&m.from)
        .expect("the plan named an occupied slot");
    provider.slots.insert(m.to, row);
    for n in provider.order.iter_mut() {
        if *n == m.from {
            *n = m.to;
        }
    }
    if provider.active_slot == Some(m.from) {
        provider.active_slot = Some(m.to);
    }
    Ok(())
}

/// How `remove`'s and `compact`'s human output describe a stop.
pub fn stopped_note(stop: &Stop) -> String {
    format!(
        "slot {} kept its number ({}), as did every slot above it; `swapd compact` finishes the renumber",
        stop.slot, stop.reason
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::slots::Slot;

    fn slot(email: &str) -> Slot {
        Slot {
            email: email.to_string(),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            alias: None,
            icon: None,
            disabled: false,
            preferred: false,
            added: None,
            fingerprint: None,
        }
    }

    #[test]
    fn plan_closes_every_gap_ascending() {
        let mut ps = ProviderSlots::default();
        for n in [1, 2, 4, 5, 7] {
            ps.insert(n, slot(&format!("{n}@example.com")));
        }
        let moves: Vec<(u32, u32)> = plan(&ps).iter().map(|m| (m.from, m.to)).collect();
        assert_eq!(moves, vec![(4, 3), (5, 4), (7, 5)]);

        let mut dense = ProviderSlots::default();
        for n in [1, 2, 3] {
            dense.insert(n, slot(&format!("{n}@example.com")));
        }
        assert!(plan(&dense).is_empty());
        assert!(plan(&ProviderSlots::default()).is_empty());
    }
}
