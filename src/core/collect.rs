//! One collection pass over a provider's slots: what each account's usage is,
//! who is active, who is next.
//!
//! Port of cswap `switcher.py:4731-4858` (`_collect_usage_entries`) and the
//! fetch path it drives (`switcher.py:3940-4100`), reduced to swapd's shape:
//! the store decides eligibility atomically (`reserve`), the driver never
//! refreshes behind our back, and every sentinel is re-derived here on every
//! pass rather than persisted.
//!
//! The order is load-bearing:
//!  1. slots + the live login, read once;
//!  2. static sentinels (no credential, API key) — no network;
//!  3. the stored table, then the dead-token quarantine — no network;
//!  4. `reserve`, which is what actually decides who is fetched;
//!  5. the fetches, in parallel, each `usage` → (`refresh` → persist) → `usage`;
//!  6. re-read the table and build the views;
//!  7. the rotation's next candidate and the earliest recovery.

use std::collections::BTreeMap;

use crate::contract::{AccountView, LastGood, NextRecovery, ProviderView, UsageStatus, Window};
use crate::core::poll_policy::{binding_pct, limiting_reset_ts};
use crate::core::slots::{self, ProviderSlots, Slot, SlotsFile};
use crate::core::store::read_json;
use crate::core::usage_store::{Entry, STALE_OK_S};
use crate::ctx::Ctx;
use crate::driver::claude::usage::format_ts;
use crate::driver::{Driver, DriverError, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::secrets::slot_key;

/// Most usage fetches in flight at once. Each is one short HTTPS round trip and
/// the accounts are independent, so the cap is about being a good citizen of
/// the upstream, not about throughput.
const MAX_FETCH_THREADS: usize = 4;

/// What a caller wants fetched this pass, on top of what the store's plans say.
#[derive(Default)]
pub struct CollectOpts {
    /// Slots to fetch regardless of freshness or plan (`refresh --slot n`).
    /// Backoff, claims and the dead-token quarantine still apply.
    pub force_slots: Vec<u32>,
    /// Fetch every account whose plan is due *or* whose data is stale
    /// (`refresh`), rather than the on-demand "stale and due" rule.
    pub all_stale: bool,
}

/// One slot's state for this pass: the credential it would be fetched with, and
/// the sentinel (if any) that says it must not be.
struct SlotState {
    slot: u32,
    meta: Slot,
    /// The account's row key in the usage table, and its secret's key.
    key: String,
    /// The credential this pass uses: the live login for the active slot, the
    /// stored copy for every other.
    login: Option<Login>,
    fingerprint: Option<String>,
    active: bool,
    /// The live store holds an OLDER generation than this slot's stored copy:
    /// the fetch heals the divergence before it uses the credential.
    heal_live: bool,
    sentinel: Option<UsageStatus>,
}

pub fn collect(ctx: &Ctx, provider: &dyn Driver, opts: &CollectOpts) -> Result<ProviderView> {
    let id = provider.id();
    let slots_file: SlotsFile = read_json(&ctx.home.slots_file())?;
    let slots = slots_file.providers.get(id).cloned().unwrap_or_default();
    let order = rotation_order(&slots);

    // 1. The live login, read once for the whole pass.
    //
    // A keychain that cannot be read is not an empty login: it says nothing
    // about the accounts, so the pass continues without an active slot rather
    // than failing every slot's usage with it (the one slot that *is* affected
    // is held back below). Any other error is a real fault and propagates.
    let mut keychain_down = false;
    let mut live = match provider.read_live(&ctx.env) {
        Ok(login) => Some(login),
        Err(DriverError::NoLogin) => None,
        Err(DriverError::KeychainUnavailable) => {
            eprintln!("warning: {id}: the live login is unreadable (keychain unavailable)");
            keychain_down = true;
            None
        }
        Err(e) => return Err(e.into()),
    };
    let live_fingerprint = live.as_ref().map(Login::fingerprint);
    // With the live store down, the slot `slots.json` calls active is the one
    // whose credential we cannot see: it is served from the table and not
    // fetched, instead of being fetched with a stored copy the CLI may have
    // rotated past. Every other slot is unaffected and fetches normally.
    let unreadable_active = keychain_down.then_some(slots.active_slot).flatten();

    // The active slot is an IDENTITY match against the live login (cswap
    // `_build_accounts_info`): the same refresh-token lineage can be rotated by
    // Claude Code itself, so a fingerprint alone loses the slot the moment the
    // CLI refreshes. The fingerprint is the fallback for a login that carries
    // no identity of its own.
    let live_identity = live
        .as_ref()
        .and_then(|login| provider.identity_offline(login))
        .map(|i| (i.email.to_lowercase(), i.organization_uuid));
    let active_slot = order.iter().copied().find(|n| {
        let Some(meta) = slots.slots.get(n) else {
            return false;
        };
        match &live_identity {
            Some((email, org)) => {
                meta.email.to_lowercase() == *email
                    && (org.is_empty() || meta.organization_uuid == *org)
            }
            None => false,
        }
    });

    // 2. Every slot's credential, and the sentinels derivable without a fetch.
    let mut states = Vec::new();
    // Slots whose stored credential this pass replaced from the live store: a
    // dead-token quarantine bound to the generation they used to hold no longer
    // describes them (step 3 lifts it).
    let mut adopted = Vec::new();
    for slot in &order {
        let Some(meta) = slots.slots.get(slot).cloned() else {
            continue;
        };
        let key = slot_key(id, *slot);
        let stored = ctx
            .secrets
            .get(&key)?
            .filter(|bytes| !bytes.trim().is_empty())
            .map(|bytes| Login { bytes });
        let stored_fingerprint = stored.as_ref().map(Login::fingerprint);

        // `live.is_some()` is the "not already claimed" guard: two slots holding
        // the same credential must not both read as active.
        let active = live.is_some()
            && (active_slot == Some(*slot)
                || (active_slot.is_none() && stored_fingerprint == live_fingerprint));
        let mut heal_live = false;
        let (login, fingerprint) = if active {
            // The active account's credential is Claude Code's live one; every
            // other slot reads its stored copy. When the CLI rotated the
            // lineage itself the stored copy is a spent token — but the reverse
            // happens too (a `write_live` that failed after we persisted a
            // rotation), and adopting there would overwrite the successor with
            // the token the endpoint has already spent. So the adopt is
            // GENERATIONAL: the live login wins unless it is provably the older
            // generation, in which case the stored copy is used and written
            // back to heal the divergence.
            let live = live.take().expect("`active` is gated on a live login");
            let older = stored
                .as_ref()
                .is_some_and(|stored| crate::driver::live_is_older(provider, &live, stored));
            match (older, stored, stored_fingerprint) {
                (true, Some(stored), fingerprint) => {
                    heal_live = true;
                    (Some(stored), fingerprint)
                }
                (_, _, fingerprint) => {
                    if fingerprint != live_fingerprint {
                        ctx.secrets.set(&key, &live.bytes)?;
                        record_slot_fingerprint(ctx, id, *slot, live_fingerprint.as_deref())?;
                        adopted.push(key.clone());
                    }
                    (Some(live), live_fingerprint.clone())
                }
            }
        } else {
            (stored, stored_fingerprint)
        };

        let sentinel = match &login {
            _ if unreadable_active == Some(*slot) => Some(UsageStatus::Stale),
            None => Some(UsageStatus::NoCredentials),
            Some(login) if provider.is_api_key(login) => Some(UsageStatus::ApiKey),
            Some(_) => None,
        };

        states.push(SlotState {
            slot: *slot,
            meta,
            key,
            login,
            fingerprint,
            active,
            heal_live,
            sentinel,
        });
    }

    // 3. The stored table, then the dead-token quarantine: a struck refresh
    //    lineage is never fetched again until a credential rewrite heals it.
    let keys: Vec<(String, String, String)> = states
        .iter()
        .map(|st| {
            (
                st.key.clone(),
                st.meta.email.clone(),
                st.meta.organization_uuid.clone(),
            )
        })
        .collect();
    let mut entries = ctx.store.entries(&keys, &ctx.settings.models)?;
    // A slot whose credential this pass replaced is not the slot the strikes
    // condemned. Clearing the sentinel is not enough: `reserve` gates on the
    // raw strike count, so a row left struck would never be fetched again and
    // the account would freeze at its last-known-good measurement forever.
    let healed: Vec<&String> = adopted
        .iter()
        .filter(|key| entry_of(&entries, key).auth_dead_strikes > 0)
        .collect();
    if !healed.is_empty() {
        for key in healed {
            ctx.store.clear_dead(key)?;
        }
        entries = ctx.store.entries(&keys, &ctx.settings.models)?;
    }
    for st in &mut states {
        if st.sentinel.is_some() {
            continue;
        }
        if entry_of(&entries, &st.key).token_dead(st.fingerprint.as_deref()) {
            st.sentinel = Some(UsageStatus::ReloginRequired);
        }
    }

    // 4. Who actually gets fetched — decided atomically, under the table's lock.
    let force = !opts.force_slots.is_empty();
    let candidates: Vec<(String, String, String)> = states
        .iter()
        .filter(|st| st.sentinel.is_none())
        .filter(|st| !force || opts.force_slots.contains(&st.slot))
        .map(|st| {
            (
                st.key.clone(),
                st.meta.email.clone(),
                st.meta.organization_uuid.clone(),
            )
        })
        .collect();
    let claims = ctx.store.reserve(&candidates, !opts.all_stale, force)?;

    // An expired ACTIVE credential the fetch gate kept out of this pass —
    // failure backoff, another collector's claim, the poll plan — still has to
    // surface as expired (`switcher.py:4810-4830`), or a caller reads a stale
    // `ok` and counts the gap as a healthy account. When the gate lifts, the
    // fetch path refreshes it and the sentinel clears itself.
    let now = ctx.now();
    for st in &mut states {
        if st.sentinel.is_some() || !st.active || claims.contains_key(&st.key) {
            continue;
        }
        let expired = st
            .login
            .as_ref()
            .and_then(|login| provider.expires_at(login))
            .is_some_and(|expires_at| expires_at < now);
        if expired || st.heal_live {
            st.sentinel = Some(UsageStatus::TokenExpired);
        }
    }

    // 5. The fetches.
    if !claims.is_empty() {
        let jobs: Vec<(usize, &str)> = states
            .iter()
            .enumerate()
            .filter_map(|(i, st)| claims.get(&st.key).map(|claim| (i, claim.as_str())))
            .collect();
        for (i, sentinel) in fetch_all(ctx, provider, &states, &jobs, keychain_down)? {
            states[i].sentinel = states[i].sentinel.or(sentinel);
        }

        // 6. What the fetches wrote, plus the quarantine they may have just
        //    earned — surfaced in this pass rather than the next one.
        entries = ctx.store.entries(&keys, &ctx.settings.models)?;
        for st in &mut states {
            if st.sentinel.is_some() {
                continue;
            }
            if entry_of(&entries, &st.key).token_dead(st.fingerprint.as_deref()) {
                st.sentinel = Some(UsageStatus::ReloginRequired);
            }
        }
    }

    let accounts: Vec<AccountView> = states
        .iter()
        .map(|st| account_view(st, entry_of(&entries, &st.key), now))
        .collect();

    Ok(ProviderView {
        provider: id.to_string(),
        installed: provider.installed().is_some(),
        active_slot: states.iter().find(|st| st.active).map(|st| st.slot),
        next_candidate: next_candidate(ctx, &states, &entries),
        next_recovery: next_recovery(ctx, &states, &entries),
        accounts,
    })
}

/// Every slot once, rotation order first (a slot missing from `order` is a
/// slots file written by hand or by an older release — it still gets collected).
fn rotation_order(slots: &ProviderSlots) -> Vec<u32> {
    let mut out: Vec<u32> = slots
        .order
        .iter()
        .copied()
        .filter(|n| slots.slots.contains_key(n))
        .collect();
    let extra: Vec<u32> = slots
        .slots
        .keys()
        .copied()
        .filter(|n| !out.contains(n))
        .collect();
    out.extend(extra);
    out
}

fn entry_of<'a>(entries: &'a BTreeMap<String, Entry>, key: &str) -> &'a Entry {
    static EMPTY: std::sync::OnceLock<Entry> = std::sync::OnceLock::new();
    entries
        .get(key)
        .unwrap_or_else(|| EMPTY.get_or_init(Entry::default))
}

/// Re-stamp one slot's credential fingerprint in `slots.json`, under its lock.
///
/// The stored fingerprint is what heals a dead-token strike (`Entry::token_dead`
/// compares against it), so leaving it pointing at a generation the CLI has
/// already rotated past would make the quarantine unhealable on one side and
/// invisible on the other.
pub fn record_slot_fingerprint(
    ctx: &Ctx,
    provider: &str,
    slot: u32,
    fingerprint: Option<&str>,
) -> Result<()> {
    slots::update(&ctx.home.slots_file(), |file| {
        let Some(entry) = file
            .providers
            .get_mut(provider)
            .and_then(|p| p.slots.get_mut(&slot))
        else {
            return Ok((false, ()));
        };
        let fingerprint = fingerprint.map(str::to_string);
        if entry.fingerprint == fingerprint {
            return Ok((false, ()));
        }
        entry.fingerprint = fingerprint;
        Ok((true, ()))
    })
}

/// Run the claimed fetches on at most `MAX_FETCH_THREADS` threads, returning the
/// sentinel each one earned (if any).
///
/// Nothing is shared but the usage table and the secret store, both of which
/// serialize their own writes; every thread owns its claims outright.
fn fetch_all(
    ctx: &Ctx,
    provider: &dyn Driver,
    states: &[SlotState],
    jobs: &[(usize, &str)],
    keychain_down: bool,
) -> Result<Vec<(usize, Option<UsageStatus>)>> {
    let chunk = jobs.len().div_ceil(MAX_FETCH_THREADS).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(i, claim)| {
                            let done = fetch_one(ctx, provider, &states[*i], claim, keychain_down)?;
                            Ok((*i, done))
                        })
                        .collect::<Result<Vec<_>>>()
                })
            })
            .collect();
        let mut out = Vec::new();
        for handle in handles {
            let done = handle
                .join()
                .map_err(|_| SwapdError::new(ErrorCode::Io, "usage fetch panicked"))?;
            out.extend(done?);
        }
        Ok(out)
    })
}

/// One account's fetch: `usage`, and on `NeedsRefresh` the refresh the driver
/// deliberately refuses to do on its own.
fn fetch_one(
    ctx: &Ctx,
    provider: &dyn Driver,
    st: &SlotState,
    claim: &str,
    keychain_down: bool,
) -> Result<Option<UsageStatus>> {
    let login = st
        .login
        .as_ref()
        .expect("a slot with no credential is sentinelled before it can be claimed");

    // The live store holds an older generation than this slot's copy: heal it
    // before the credential is used, while the claim still fences a failure.
    if st.heal_live {
        if let Err(e) = provider.write_live(&ctx.env, login) {
            return Ok(Some(degrade_write_live(ctx, st, claim, &e)?));
        }
    }

    match provider.usage(login) {
        Ok(usage) => {
            record_success(ctx, st, claim, usage.windows)?;
            Ok(None)
        }
        Err(DriverError::NeedsRefresh) if keychain_down => {
            // No pass may spend a refresh token it cannot write back: with the
            // live store unreadable there is no way to tell whether the
            // credential in hand is still the one Claude Code holds.
            ctx.store
                .record_failure(&st.key, claim, "keychain-unavailable", None, None)?;
            Ok(Some(UsageStatus::Stale))
        }
        Err(DriverError::NeedsRefresh) => refresh_then_usage(ctx, provider, st, claim, login),
        Err(e) => {
            record_failure(ctx, st, claim, &e)?;
            Ok(None)
        }
    }
}

/// A live-store write that failed is one account's problem, never the verb's:
/// the credential itself is safe in the secret store, and every other account's
/// freshly fetched result still has to reach the caller.
fn degrade_write_live(
    ctx: &Ctx,
    st: &SlotState,
    claim: &str,
    err: &DriverError,
) -> Result<UsageStatus> {
    eprintln!(
        "warning: slot {}: the live login could not be replaced ({err})",
        st.slot
    );
    ctx.store
        .record_failure(&st.key, claim, "write-live", None, None)?;
    Ok(UsageStatus::TokenExpired)
}

/// The refresh half of the fetch, run exactly once per pass.
///
/// A Claude refresh token is single-use: the rotation is persisted — to the
/// secret store first, then to the CLI's own live store for the active slot —
/// before the retry can fail, so no path can drop a generation the token
/// endpoint has already spent.
fn refresh_then_usage(
    ctx: &Ctx,
    provider: &dyn Driver,
    st: &SlotState,
    claim: &str,
    login: &Login,
) -> Result<Option<UsageStatus>> {
    let refreshed = match provider.refresh(login) {
        Ok(refreshed) => refreshed,
        Err(DriverError::TokenDead) => {
            // Strikes condemn the credential generation that was POSTed, not
            // the slot: a re-login writing a new one heals the quarantine.
            ctx.store.record_failure(
                &st.key,
                claim,
                "invalid_grant",
                None,
                Some(&login.fingerprint()),
            )?;
            return Ok(Some(UsageStatus::ReloginRequired));
        }
        Err(_) => {
            ctx.store
                .record_failure(&st.key, claim, "refresh", None, None)?;
            // An expired ACTIVE credential nothing could refresh this pass is
            // the state the auto engine must idle-hold on, not a failed fetch
            // (`switcher.py:4810-4830`).
            return Ok(st.active.then_some(UsageStatus::TokenExpired));
        }
    };

    ctx.secrets.set(&st.key, &refreshed.bytes)?;
    let live_write = if st.active {
        provider.write_live(&ctx.env, &refreshed)
    } else {
        Ok(())
    };
    // Every persisted rotation is stamped, active or not: `slots.json`'s
    // fingerprint is the stored login's, and a stale one both hides a
    // quarantine and refuses to heal. Stamped even when the live write failed —
    // the secret store already holds this generation.
    record_slot_fingerprint(ctx, provider.id(), st.slot, Some(&refreshed.fingerprint()))?;
    if let Err(e) = live_write {
        return Ok(Some(degrade_write_live(ctx, st, claim, &e)?));
    }

    // Once per pass: a second `NeedsRefresh` is recorded as the 401 it is
    // rather than spending another refresh token on it.
    match provider.usage(&refreshed) {
        Ok(usage) => {
            record_success(ctx, st, claim, usage.windows)?;
            Ok(None)
        }
        Err(e) => {
            record_failure(ctx, st, claim, &e)?;
            Ok(None)
        }
    }
}

fn record_success(ctx: &Ctx, st: &SlotState, claim: &str, windows: Vec<Window>) -> Result<()> {
    ctx.store.record_success(
        &st.key,
        claim,
        windows,
        st.active,
        ctx.settings.threshold,
        &ctx.settings.models,
    )
}

fn record_failure(ctx: &Ctx, st: &SlotState, claim: &str, err: &DriverError) -> Result<()> {
    let (kind, retry_after) = failure_kind(err);
    ctx.store
        .record_failure(&st.key, claim, &kind, retry_after, None)
}

/// The store's classified error kind for a driver error, plus the server's
/// `Retry-After` when it sent one.
///
/// `http-429` is spelled exactly as the store expects it (its post-429 cadence
/// keys on the string). Nothing here ever yields a permanent auth kind: those
/// are recorded by `refresh_then_usage`, which knows which credential
/// generation to condemn.
fn failure_kind(err: &DriverError) -> (String, Option<f64>) {
    match err {
        DriverError::Throttled { retry_after } => ("http-429".to_string(), *retry_after),
        DriverError::NeedsRefresh => ("http-401".to_string(), None),
        DriverError::Http(message) => (
            message
                .strip_prefix("usage: ")
                .unwrap_or(message)
                .to_string(),
            None,
        ),
        DriverError::Io(_) => ("io".to_string(), None),
        DriverError::Locked(_) => ("locked".to_string(), None),
        DriverError::KeychainUnavailable => ("keychain-unavailable".to_string(), None),
        DriverError::TokenDead => ("token-dead".to_string(), None),
        DriverError::NoLogin => ("no-credentials".to_string(), None),
        DriverError::NotInstalled => ("not-installed".to_string(), None),
        DriverError::Unsupported(_) => ("unsupported".to_string(), None),
        DriverError::Invalid(_) => ("invalid".to_string(), None),
    }
}

/// One account as the contract describes it.
///
/// `windows` (with the `fetched_at`/`age_seconds` that describe it) is the
/// account's CURRENT utilization, and only an `ok` account has one: anything
/// else — too old to serve, quarantined, expired, held back — reports its
/// measurement as `last_good`, annotated with the age the reader is meant to
/// judge it by. One shape per status, so a reader never has to look in two
/// places for the same number.
fn account_view(st: &SlotState, entry: &Entry, now: f64) -> AccountView {
    let fresh = entry.age_s.is_some_and(|age| age <= STALE_OK_S);
    let status = st.sentinel.unwrap_or(if fresh {
        UsageStatus::Ok
    } else {
        UsageStatus::Stale
    });
    let current = status == UsageStatus::Ok;
    let last_good = match (current, entry.fetched_at, entry.last_good.as_ref()) {
        (false, Some(fetched_at), Some(windows)) => Some(LastGood {
            fetched_at: format_ts(fetched_at).unwrap_or_default(),
            age_seconds: now - fetched_at,
            windows: windows.clone(),
        }),
        _ => None,
    };
    AccountView {
        slot: st.slot,
        email: st.meta.email.clone(),
        organization_name: st.meta.organization_name.clone(),
        organization_uuid: st.meta.organization_uuid.clone(),
        plan: st.meta.plan.clone(),
        alias: st.meta.alias.clone(),
        icon: st.meta.icon.clone(),
        active: st.active,
        disabled: st.meta.disabled,
        preferred: st.meta.preferred,
        usage_status: status,
        fetched_at: current
            .then(|| entry.fetched_at.and_then(format_ts))
            .flatten(),
        age_seconds: current.then_some(entry.age_s).flatten(),
        windows: if current {
            entry.last_good.clone().unwrap_or_default()
        } else {
            Vec::new()
        },
        last_good,
    }
}

/// The rotation's next healthy slot after the active one.
///
/// Unknown headroom is not a reason to skip: an account nobody has measured yet
/// is a candidate, and proving it is what the switch does.
fn next_candidate(
    ctx: &Ctx,
    states: &[SlotState],
    entries: &BTreeMap<String, Entry>,
) -> Option<u32> {
    if states.is_empty() {
        return None;
    }
    let start = states
        .iter()
        .position(|st| st.active)
        .map(|i| i + 1)
        .unwrap_or(0);
    (0..states.len())
        .map(|offset| &states[(start + offset) % states.len()])
        .filter(|st| !st.active)
        .find(|st| healthy(ctx, st, entry_of(entries, &st.key)))
        .map(|st| st.slot)
}

/// Whether the rotation may land on this slot at all — before any question of
/// how much headroom it has. A disabled slot is out by the user's choice; a
/// slot with no usable credential is out until someone logs in again.
fn rotatable(st: &SlotState) -> bool {
    !st.meta.disabled
        && !matches!(
            st.sentinel,
            Some(
                UsageStatus::NoCredentials
                    | UsageStatus::ApiKey
                    | UsageStatus::ReloginRequired
                    | UsageStatus::Unsupported
            )
        )
}

fn healthy(ctx: &Ctx, st: &SlotState, entry: &Entry) -> bool {
    rotatable(st) && within_threshold(ctx, entry.decision_windows().unwrap_or(&[]))
}

/// The slots a rotation may land on, by the rule AND the inputs
/// `nextCandidate` is computed from.
///
/// The rule alone is not enough to agree with `list`: `nextCandidate` decides
/// on `Entry::decision_windows()`, which drops a measurement past the store's
/// trust ceiling and answers *unknown* — still a candidate. The contract view
/// carries `lastGood` at any age and cannot express that, so a ranker deciding
/// from the view calls an hour-old 95% reading authoritative while `list` calls
/// it unknown, and the two name different slots. Hence the verdict is exposed
/// here rather than re-derived over there.
///
/// `nextCandidate` is the head of this list among the non-active slots;
/// `rotate` needs the whole of it, because a candidate can fail.
pub fn healthy_slots(ctx: &Ctx, provider: &str, view: &ProviderView) -> Result<Vec<u32>> {
    let keys: Vec<(String, String, String)> = view
        .accounts
        .iter()
        .map(|a| {
            (
                slot_key(provider, a.slot),
                a.email.clone(),
                a.organization_uuid.clone(),
            )
        })
        .collect();
    let entries = ctx.store.entries(&keys, &ctx.settings.models)?;
    Ok(view
        .accounts
        .iter()
        .filter(|a| {
            let entry = entry_of(&entries, &slot_key(provider, a.slot));
            within_threshold(ctx, entry.decision_windows().unwrap_or(&[]))
        })
        .map(|a| a.slot)
        .collect())
}

/// Whether an account's measured headroom leaves the rotation willing to land
/// on it: its binding window is below the configured threshold.
///
/// Unknown headroom passes. An account nobody has measured yet is a candidate,
/// and proving it is what the switch does — the same rule `nextCandidate` and
/// `rotate --strategy next-available` both answer with, which is why they share
/// this function rather than each spelling the comparison out.
pub fn within_threshold(ctx: &Ctx, windows: &[crate::contract::Window]) -> bool {
    binding_pct(windows, &ctx.settings.models).is_none_or(|pct| pct < ctx.settings.threshold)
}

/// The earliest moment an exhausted account becomes usable again.
fn next_recovery(
    ctx: &Ctx,
    states: &[SlotState],
    entries: &BTreeMap<String, Entry>,
) -> Option<NextRecovery> {
    states
        .iter()
        // An account nobody can switch to is no recovery, however its windows
        // read — and a quarantined row keeps serving them long past the stale
        // bound, because its failures extend the trust bridge.
        .filter(|st| rotatable(st))
        .filter_map(|st| {
            let windows = entry_of(entries, &st.key).decision_windows()?;
            let at = limiting_reset_ts(windows, &ctx.settings.models)?;
            Some((at, st.slot))
        })
        .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
        .and_then(|(at, slot)| {
            Some(NextRecovery {
                slot,
                at: format_ts(at)?,
            })
        })
}
