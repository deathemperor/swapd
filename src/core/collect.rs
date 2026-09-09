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
use std::time::Duration;

use crate::contract::{AccountView, LastGood, NextRecovery, ProviderView, UsageStatus, Window};
use crate::core::poll_policy::{binding_pct, limiting_reset_ts};
use crate::core::slots::{ProviderSlots, Slot, SlotsFile};
use crate::core::store::{read_json, write_json_atomic, FileLock};
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

/// How long to wait for `slots.json`'s lock when a live rotation has to be
/// written back to it.
const SLOTS_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

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
        .and_then(|login| provider.identity(login).ok())
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
        let (login, fingerprint) = if active {
            // The active account's credential is Claude Code's live one; every
            // other slot reads its stored copy. When the CLI rotated the
            // lineage itself the stored copy is a spent token: replace it now,
            // before anything can POST it.
            let live = live.take().expect("`active` is gated on a live login");
            let fingerprint = live_fingerprint.clone();
            if stored_fingerprint != fingerprint {
                ctx.secrets.set(&key, &live.bytes)?;
                record_slot_fingerprint(ctx, id, *slot, fingerprint.as_deref())?;
            }
            (Some(live), fingerprint)
        } else {
            (stored, stored_fingerprint)
        };

        let sentinel = match &login {
            _ if unreadable_active == Some(*slot) => Some(UsageStatus::Stale),
            None => Some(UsageStatus::NoCredentials),
            Some(login) if looks_like_api_key(&login.bytes) => Some(UsageStatus::ApiKey),
            Some(_) => None,
        };

        states.push(SlotState {
            slot: *slot,
            meta,
            key,
            login,
            fingerprint,
            active,
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

    // 5. The fetches.
    if !claims.is_empty() {
        let jobs: Vec<(usize, &str)> = states
            .iter()
            .enumerate()
            .filter_map(|(i, st)| claims.get(&st.key).map(|claim| (i, claim.as_str())))
            .collect();
        for (i, sentinel) in fetch_all(ctx, provider, &states, &jobs)? {
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

    let now = ctx.now();
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

/// A managed API key rather than an OAuth login: no subscription quota to
/// fetch (`switcher.py:4604-4606`).
fn looks_like_api_key(bytes: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(bytes) {
        Ok(value) => value.get("claudeAiOauth").is_none() && bytes.trim().starts_with("sk-ant-"),
        Err(_) => bytes.trim().starts_with("sk-ant-"),
    }
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
fn record_slot_fingerprint(
    ctx: &Ctx,
    provider: &str,
    slot: u32,
    fingerprint: Option<&str>,
) -> Result<()> {
    let path = ctx.home.slots_file();
    let _lock = FileLock::acquire(&path, SLOTS_LOCK_TIMEOUT)?;
    let mut file: SlotsFile = read_json(&path)?;
    let Some(entry) = file
        .providers
        .get_mut(provider)
        .and_then(|p| p.slots.get_mut(&slot))
    else {
        return Ok(());
    };
    let fingerprint = fingerprint.map(str::to_string);
    if entry.fingerprint == fingerprint {
        return Ok(());
    }
    entry.fingerprint = fingerprint;
    write_json_atomic(&path, &file)
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
) -> Result<Vec<(usize, Option<UsageStatus>)>> {
    let chunk = jobs.len().div_ceil(MAX_FETCH_THREADS).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(i, claim)| Ok((*i, fetch_one(ctx, provider, &states[*i], claim)?)))
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
) -> Result<Option<UsageStatus>> {
    let login = st
        .login
        .as_ref()
        .expect("a slot with no credential is sentinelled before it can be claimed");
    match provider.usage(login) {
        Ok(usage) => {
            record_success(ctx, st, claim, usage.windows)?;
            Ok(None)
        }
        Err(DriverError::NeedsRefresh) => refresh_then_usage(ctx, provider, st, claim, login),
        Err(e) => {
            record_failure(ctx, st, claim, &e)?;
            Ok(None)
        }
    }
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
    if st.active {
        provider.write_live(&ctx.env, &refreshed)?;
    }
    // Every persisted rotation is stamped, active or not: `slots.json`'s
    // fingerprint is the stored login's, and a stale one both hides a
    // quarantine and refuses to heal.
    record_slot_fingerprint(ctx, provider.id(), st.slot, Some(&refreshed.fingerprint()))?;

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
/// `fetched_at`/`age_seconds` describe `windows`, so they are reported together
/// or not at all: a measurement too old to serve moves into `last_good`, where
/// its age is what the reader is meant to judge it by.
fn account_view(st: &SlotState, entry: &Entry, now: f64) -> AccountView {
    let fresh = entry.age_s.is_some_and(|age| age <= STALE_OK_S);
    let stored = entry.last_good.clone().unwrap_or_default();
    let status = st.sentinel.unwrap_or(if fresh {
        UsageStatus::Ok
    } else {
        UsageStatus::Stale
    });
    let last_good = match (fresh, entry.fetched_at, entry.last_good.as_ref()) {
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
        fetched_at: fresh
            .then(|| entry.fetched_at.and_then(format_ts))
            .flatten(),
        age_seconds: fresh.then_some(entry.age_s).flatten(),
        windows: if fresh { stored } else { Vec::new() },
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

fn healthy(ctx: &Ctx, st: &SlotState, entry: &Entry) -> bool {
    if st.meta.disabled {
        return false;
    }
    if matches!(
        st.sentinel,
        Some(
            UsageStatus::NoCredentials
                | UsageStatus::ApiKey
                | UsageStatus::ReloginRequired
                | UsageStatus::Unsupported
        )
    ) {
        return false;
    }
    entry
        .decision_windows()
        .and_then(|windows| binding_pct(windows, &ctx.settings.models))
        .is_none_or(|pct| pct < ctx.settings.threshold)
}

/// The earliest moment an exhausted account becomes usable again.
fn next_recovery(
    ctx: &Ctx,
    states: &[SlotState],
    entries: &BTreeMap<String, Entry>,
) -> Option<NextRecovery> {
    states
        .iter()
        .filter(|st| !st.meta.disabled)
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
