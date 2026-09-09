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
//!
//! Steps 1-3 are `prepare` and steps 4-7 are `execute`, because the expensive
//! half is the first one and a caller can want the second half more than once
//! over the same picture (the auto tick's phases).

use std::collections::BTreeMap;

use crate::contract::{AccountView, LastGood, NextRecovery, ProviderView, UsageStatus, Window};
use crate::core::poll_policy::{binding_pct, limiting_reset_ts};
use crate::core::refresh::{refresh_slot, Refreshed};
use crate::core::slots::{self, ProviderSlots, Slot, SlotsFile};
use crate::core::store::{read_json, FileLock};
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
///
/// `lock_wait` belongs to the preamble, which is the only half that takes
/// `engine.lock`; everything else is the fetch half's, so a caller that
/// prepares once and fetches several times (the auto tick) varies a
/// `FetchOpts` and leaves the preamble alone.
#[derive(Default)]
pub struct FetchOpts {
    /// Slots to fetch regardless of freshness or plan (`refresh --slot n`).
    /// Backoff, claims and the dead-token quarantine still apply.
    pub force_slots: Vec<u32>,
    /// Fetch every account whose plan is due *or* whose data is stale
    /// (`refresh`), rather than the on-demand "stale and due" rule.
    pub all_stale: bool,
    /// Restrict the fetch to these slots (the auto engine's schedule, cswap's
    /// `usage_entries_by_account(fetch=…)`). `None` leaves every slot eligible;
    /// `Some(empty)` fetches nothing at all and serves the whole pass from the
    /// store. Whether a listed slot is actually fetched is still `reserve`'s
    /// call — plans, freshness, backoff and claims all apply.
    pub only: Option<Vec<u32>>,
}

/// What a caller wants of a whole pass — the preamble's knob and the fetch
/// half's, kept as one shape because every verb but the auto engine wants both
/// at once (`collect`).
pub struct CollectOpts {
    /// Slots to fetch regardless of freshness or plan (`refresh --slot n`).
    /// Backoff, claims and the dead-token quarantine still apply.
    pub force_slots: Vec<u32>,
    /// Fetch every account whose plan is due *or* whose data is stale
    /// (`refresh`), rather than the on-demand "stale and due" rule.
    pub all_stale: bool,
    /// Restrict the fetch to these slots (the auto engine's schedule, cswap's
    /// `usage_entries_by_account(fetch=…)`). `None` leaves every slot eligible;
    /// `Some(empty)` fetches nothing at all and serves the whole pass from the
    /// store. Whether a listed slot is actually fetched is still `reserve`'s
    /// call — plans, freshness, backoff and claims all apply.
    pub only: Option<Vec<u32>>,
    /// How long to wait for `engine.lock` before degrading to
    /// `active_unreadable: switch-in-progress` (step 1 of `prepare`). `list`
    /// is a status verb behind a pump that must not stall, so it waits a
    /// short beat instead of the default; every other caller keeps the full
    /// `slots::LOCK_TIMEOUT` so a real switch has time to land.
    pub lock_wait: std::time::Duration,
}

impl Default for CollectOpts {
    fn default() -> Self {
        CollectOpts {
            force_slots: Vec::new(),
            all_stale: false,
            only: None,
            lock_wait: slots::LOCK_TIMEOUT,
        }
    }
}

impl From<&CollectOpts> for FetchOpts {
    fn from(opts: &CollectOpts) -> Self {
        FetchOpts {
            force_slots: opts.force_slots.clone(),
            all_stale: opts.all_stale,
            only: opts.only.clone(),
        }
    }
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
    /// The live login's fingerprint as this pass read it, for the active slot
    /// only. Every write back into the live store is guarded on it: the pass
    /// may only replace the generation it measured, never one a switch or
    /// Claude Code's own refresh put there in the meantime.
    live_fingerprint: Option<String>,
    /// The live store holds an OLDER generation than this slot's stored copy:
    /// the fetch heals the divergence before it uses the credential.
    heal_live: bool,
    sentinel: Option<UsageStatus>,
}

impl SlotState {
    /// A copy for one fetch pass to mark up.
    ///
    /// The sentinels `execute` derives are pass-specific — `TokenExpired` on an
    /// expired active slot means "the fetch gate kept it out of THIS pass" —
    /// so they are set on a copy and thrown away with it. A `Prepared` reused
    /// by a second pass therefore starts from what the preamble established and
    /// nothing else: a slot the first pass could not claim must be fetchable by
    /// the second.
    fn for_pass(&self) -> SlotState {
        SlotState {
            slot: self.slot,
            meta: self.meta.clone(),
            key: self.key.clone(),
            login: self.login.as_ref().map(|login| Login {
                bytes: login.bytes.clone(),
            }),
            fingerprint: self.fingerprint.clone(),
            active: self.active,
            live_fingerprint: self.live_fingerprint.clone(),
            heal_live: self.heal_live,
            sentinel: self.sentinel,
        }
    }
}

/// What one pass's preamble established: every slot's credential, the sentinels
/// derivable without a fetch, and the usage table they were judged against.
///
/// The point of naming it is that it can be reused. The preamble is the
/// expensive half — `engine.lock`, the live login, one secret store read per
/// slot (one `/usr/bin/security` spawn each on macOS) — and the numbers it
/// produces do not change between two fetch passes of the same tick. The engine
/// lock is deliberately NOT part of it: `prepare` drops the lock where `collect`
/// always did, so holding a `Prepared` never fences a switch.
pub struct Prepared {
    states: Vec<SlotState>,
    /// `(row key, email, org)` for every slot, in `states` order — how the
    /// usage table is read and reserved.
    keys: Vec<(String, String, String)>,
    /// The usage table as of the last read: the preamble's, replaced by every
    /// `execute` that actually fetched. A pass that fetches nothing serves from
    /// this copy, which is sound because the only writer in between is
    /// `reserve`, and nothing a view is built from — `account_view`,
    /// `next_candidate`, `next_recovery`, `Entry::token_dead` — reads a claim.
    entries: BTreeMap<String, Entry>,
    /// The slot whose credential this pass cannot see (an unreadable keychain,
    /// a switch in flight, a busy CLI), if any.
    unreadable_active: Option<u32>,
    /// The reason `active_unreadable` reports to `list --json`.
    active_unreadable: Option<String>,
    keychain_down: bool,
}

/// One whole pass: the preamble, then one fetch set over it.
pub fn collect(ctx: &Ctx, provider: &dyn Driver, opts: &CollectOpts) -> Result<ProviderView> {
    let mut prepared = prepare(ctx, provider, opts.lock_wait)?;
    execute(ctx, provider, &mut prepared, &opts.into())
}

/// Steps 1–3: the live login, every slot's credential, and the stored table
/// they are judged against — everything a fetch pass needs and nothing that
/// depends on which slots it fetches.
pub fn prepare(
    ctx: &Ctx,
    provider: &dyn Driver,
    lock_wait: std::time::Duration,
) -> Result<Prepared> {
    let id = provider.id();
    let slots_file: SlotsFile = read_json(&ctx.home.slots_file())?;
    let slots = slots_file.providers.get(id).cloned().unwrap_or_default();
    let order = rotation_order(&slots);

    // 1. The live login, read once for the whole pass — under `engine.lock`,
    //    together with the adopt in step 2.
    //
    // The read is two unrelated reads (the credential, then the identity its
    // config advertises) and a switch's write is the same two in the same
    // order, so an unfenced pass can see account B's token beside account A's
    // identity and adopt B's credential into slot A — losing A's only unspent
    // generation. The lock is the fence; a switch in flight is a normal state
    // for a status verb, so failing to take it degrades the pass instead of
    // failing it.
    let engine = match FileLock::acquire(&ctx.home.engine_lock_base(), lock_wait) {
        Ok(lock) => Some(lock),
        Err(e) if e.code == ErrorCode::Locked => None,
        Err(e) => return Err(e),
    };
    let switch_in_flight = engine.is_none();

    // A keychain that cannot be read is not an empty login: it says nothing
    // about the accounts, so the pass continues without an active slot rather
    // than failing every slot's usage with it (the one slot that *is* affected
    // is held back below). Any other error is a real fault and propagates.
    let mut keychain_down = false;
    // The CLI is mid-write of its own login pair (its `/login`), which is the
    // same torn read `engine.lock` fences swapd's own switches against.
    let mut cli_busy = false;
    // A switch owns the live store right now: whatever is in it is a
    // half-written pair, and no answer derived from it is worth having. Not
    // read at all, rather than read and distrusted.
    let mut live = if switch_in_flight {
        eprintln!(
            "warning: {id}: a switch is in flight; the active account is served from the store"
        );
        None
    } else {
        // Under the CLI's OWN locks too: `engine.lock` fences swapd's writers,
        // and the CLI's `/login` is a writer it knows nothing about. Same
        // degradation when the CLI holds them — a busy CLI is a normal state,
        // and a status verb that stalls on it is worse than one that serves the
        // active slot from the store.
        match provider.read_live_locked(&ctx.env) {
            Ok(login) => Some(login),
            Err(DriverError::NoLogin) => None,
            Err(DriverError::KeychainUnavailable) => {
                eprintln!("warning: {id}: the live login is unreadable (keychain unavailable)");
                keychain_down = true;
                None
            }
            Err(DriverError::Locked(why)) => {
                eprintln!(
                    "warning: {id}: the CLI holds its own login locks ({why}); \
                     the active account is served from the store"
                );
                cli_busy = true;
                None
            }
            Err(e) => return Err(e.into()),
        }
    };
    let live_fingerprint = live.as_ref().map(Login::fingerprint);
    // With the live store down — unreadable, or fenced off by a switch — the
    // slot `slots.json` calls active is the one whose credential we cannot see:
    // it is served from the table and not fetched, instead of being fetched
    // with a stored copy the CLI may have rotated past. Every other slot is
    // unaffected and fetches normally.
    let unreadable_active = (keychain_down || switch_in_flight || cli_busy)
        .then_some(slots.active_slot)
        .flatten();
    // The reason `active_unreadable` reports to `list --json`, in the same
    // priority as the blocks above: a switch in flight is the most specific
    // fact (`engine.lock` says exactly who owns the store), so it wins over
    // a merely-unreadable keychain, which in turn wins over a busy CLI.
    let active_unreadable = unreadable_active.map(|_| {
        if switch_in_flight {
            "switch-in-progress"
        } else if keychain_down {
            "keychain-unavailable"
        } else {
            "cli-busy"
        }
        .to_string()
    });

    // The active slot is an IDENTITY match against the live login (cswap
    // `_build_accounts_info`): the same refresh-token lineage can be rotated by
    // Claude Code itself, so a fingerprint alone loses the slot the moment the
    // CLI refreshes. The fingerprint is the fallback for a login that carries
    // no identity of its own.
    let live_identity = live
        .as_ref()
        .and_then(|login| provider.identity_offline(login));
    let active_slot = order
        .iter()
        .copied()
        .find(|n| match (&live_identity, slots.slots.get(n)) {
            (Some(identity), Some(meta)) => slots::same_account(identity, meta),
            _ => false,
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

        let sentinel = credential_sentinel(provider, *slot, login.as_ref(), unreadable_active);

        states.push(SlotState {
            slot: *slot,
            meta,
            key,
            login,
            fingerprint,
            active,
            live_fingerprint: active.then(|| live_fingerprint.clone()).flatten(),
            heal_live,
            sentinel,
        });
    }

    // The fence covers exactly the live read and the adopt it feeds. Released
    // before the usage table is touched: everything below is per-account
    // bookkeeping and network, and holding a switch off for the length of a
    // fetch pass would make `swapd switch` wait on `swapd list`.
    drop(engine);

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

    Ok(Prepared {
        states,
        keys,
        entries,
        unreadable_active,
        active_unreadable,
        keychain_down,
    })
}

/// Steps 4–7 over a prepared pass: who gets fetched, the fetches themselves,
/// and the views they produce.
///
/// `prepared` is taken by `&mut` because a fetch changes what it describes: the
/// usage table it was judged against, and — for the slots this pass claimed —
/// the credential itself.
pub fn execute(
    ctx: &Ctx,
    provider: &dyn Driver,
    prepared: &mut Prepared,
    opts: &FetchOpts,
) -> Result<ProviderView> {
    let id = provider.id();
    // Marked up and thrown away: see `SlotState::for_pass`.
    let mut states: Vec<SlotState> = prepared.states.iter().map(SlotState::for_pass).collect();

    // 4. Who actually gets fetched — decided atomically, under the table's lock.
    let force = !opts.force_slots.is_empty();
    let candidates: Vec<(String, String, String)> = states
        .iter()
        .filter(|st| st.sentinel.is_none())
        .filter(|st| !force || opts.force_slots.contains(&st.slot))
        .filter(|st| {
            opts.only
                .as_ref()
                .is_none_or(|only| only.contains(&st.slot))
        })
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
        let mut fetched = Vec::new();
        for (i, done) in fetch_all(ctx, provider, &states, &jobs, prepared.keychain_down)? {
            states[i].sentinel = states[i].sentinel.or(done.sentinel);
            fetched.push((i, done.live_synced));
        }

        // 6. What the fetches wrote, plus the quarantine they may have just
        //    earned — surfaced in this pass rather than the next one.
        prepared.entries = ctx.store.entries(&prepared.keys, &ctx.settings.models)?;
        for st in &mut states {
            if st.sentinel.is_some() {
                continue;
            }
            if entry_of(&prepared.entries, &st.key).token_dead(st.fingerprint.as_deref()) {
                st.sentinel = Some(UsageStatus::ReloginRequired);
            }
        }

        // 7. The successors, for the slots this pass claimed — see
        //    `adopt_successor`. Strictly after the marking above, which is
        //    about the generation that was just SPENT.
        let Prepared {
            states: base,
            entries,
            unreadable_active,
            ..
        } = &mut *prepared;
        for (i, live_synced) in fetched {
            adopt_successor(
                ctx,
                provider,
                &mut base[i],
                entries,
                *unreadable_active,
                live_synced,
            )?;
        }
    }

    let accounts: Vec<AccountView> = states
        .iter()
        .map(|st| account_view(st, entry_of(&prepared.entries, &st.key), now))
        .collect();

    Ok(ProviderView {
        provider: id.to_string(),
        installed: provider.installed(&ctx.env).is_some(),
        active_slot: states.iter().find(|st| st.active).map(|st| st.slot),
        active_unreadable: prepared.active_unreadable.clone(),
        next_candidate: next_candidate(ctx, &states, &prepared.entries),
        next_recovery: next_recovery(ctx, &states, &prepared.entries),
        accounts,
    })
}

/// Re-read one claimed slot's credential into the `Prepared`, so a second fetch
/// pass over it uses the generation the first one left behind.
///
/// A fetch can rotate the slot's token — `refresh_then_usage` persists the
/// successor through `core::refresh` before anything downstream can fail — and
/// it can heal the live store. A `Prepared` that still described the spent
/// generation would hand the next pass a token the endpoint has already
/// consumed: at best a wasted round trip through `refresh_slot`'s
/// compare-and-swap, at worst a `TokenExpired` sentinel on an account that was
/// refreshed moments ago (the expiry is read off the login this struct holds),
/// which is what the auto engine idle-holds on. So the slots this pass CLAIMED
/// are re-read here — a handful of secret reads, not the fleet, which is the
/// whole point of preparing once — and everything derived from the credential
/// is recomputed with them. Slots this pass did not claim cannot have moved,
/// and are left alone.
fn adopt_successor(
    ctx: &Ctx,
    provider: &dyn Driver,
    st: &mut SlotState,
    entries: &BTreeMap<String, Entry>,
    unreadable_active: Option<u32>,
    live_synced: bool,
) -> Result<()> {
    let stored = ctx
        .secrets
        .get(&st.key)?
        .filter(|bytes| !bytes.trim().is_empty())
        .map(|bytes| Login { bytes });
    st.fingerprint = stored.as_ref().map(Login::fingerprint);
    st.login = stored;
    // The live store holds this slot's current credential: there is nothing
    // left to heal, and the generation a later guarded write must succeed is
    // the one that is live now. Without the write, what this pass measured is
    // still what is live, so both stand.
    if live_synced {
        st.heal_live = false;
        st.live_fingerprint = st.fingerprint.clone();
    }
    st.sentinel = credential_sentinel(provider, st.slot, st.login.as_ref(), unreadable_active)
        .or_else(|| {
            entry_of(entries, &st.key)
                .token_dead(st.fingerprint.as_deref())
                .then_some(UsageStatus::ReloginRequired)
        });
    Ok(())
}

/// The sentinel a slot carries before the usage table has been consulted:
/// everything the credential alone (or the absence of one) decides.
fn credential_sentinel(
    provider: &dyn Driver,
    slot: u32,
    login: Option<&Login>,
    unreadable_active: Option<u32>,
) -> Option<UsageStatus> {
    match login {
        _ if unreadable_active == Some(slot) => Some(UsageStatus::Stale),
        None => Some(UsageStatus::NoCredentials),
        Some(login) if provider.is_api_key(login) => Some(UsageStatus::ApiKey),
        Some(_) => None,
    }
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

/// Run the claimed fetches on at most `MAX_FETCH_THREADS` threads, returning
/// what each one left behind.
///
/// Nothing is shared but the usage table and the secret store, both of which
/// serialize their own writes; every thread owns its claims outright.
fn fetch_all(
    ctx: &Ctx,
    provider: &dyn Driver,
    states: &[SlotState],
    jobs: &[(usize, &str)],
    keychain_down: bool,
) -> Result<Vec<(usize, Fetched)>> {
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

/// What one slot's fetch left behind.
struct Fetched {
    /// The sentinel it earned, if any.
    sentinel: Option<UsageStatus>,
    /// The live store ends the fetch holding this slot's current credential —
    /// a heal or a refresh's guarded write landed. What tells the next pass
    /// there is nothing left to heal (`adopt_successor`).
    live_synced: bool,
}

/// One account's fetch: `usage`, and on `NeedsRefresh` the refresh the driver
/// deliberately refuses to do on its own.
fn fetch_one(
    ctx: &Ctx,
    provider: &dyn Driver,
    st: &SlotState,
    claim: &str,
    keychain_down: bool,
) -> Result<Fetched> {
    let login = st
        .login
        .as_ref()
        .expect("a slot with no credential is sentinelled before it can be claimed");

    // The live store holds an older generation than this slot's copy: heal it
    // before the credential is used, while the claim still fences a failure.
    let mut live_synced = false;
    if st.heal_live {
        match write_live_guarded(ctx, provider, st, login, st.live_fingerprint.as_deref())? {
            LiveWrite::Done => live_synced = true,
            LiveWrite::Moved => {}
            LiveWrite::Failed(e) => {
                return Ok(Fetched {
                    sentinel: Some(degrade_write_live(ctx, st, claim, &e)?),
                    live_synced: false,
                })
            }
        }
    }

    match provider.usage(login) {
        Ok(usage) => {
            record_success(ctx, st, claim, usage.windows)?;
            Ok(Fetched {
                sentinel: None,
                live_synced,
            })
        }
        Err(DriverError::NeedsRefresh) if keychain_down => {
            // No pass may spend a refresh token it cannot write back: with the
            // live store unreadable there is no way to tell whether the
            // credential in hand is still the one Claude Code holds.
            ctx.store
                .record_failure(&st.key, claim, "keychain-unavailable", None, None)?;
            Ok(Fetched {
                sentinel: Some(UsageStatus::Stale),
                live_synced,
            })
        }
        Err(DriverError::NeedsRefresh) => {
            refresh_then_usage(ctx, provider, st, claim, login, live_synced)
        }
        Err(e) => {
            record_failure(ctx, st, claim, &e)?;
            Ok(Fetched {
                sentinel: None,
                live_synced,
            })
        }
    }
}

/// What a guarded live write did.
enum LiveWrite {
    /// The live store holds `login`.
    Done,
    /// The live login is no longer the one this pass measured — a switch
    /// landed, or the user ran `/login` — so there was nothing here to replace.
    /// The credential itself is safe in the slot's secret; the next pass adopts
    /// whatever is live now.
    Moved,
    /// The write was attempted and the driver refused it.
    Failed(DriverError),
}

/// Replace the live login with `login`, but only if the live store still holds
/// `expected` — the generation this write is the successor of.
///
/// `expected` is the CALLER's, not the pass's: a heal writes the stored login
/// over the older live one, so a refresh that follows a heal in the same fetch
/// succeeds the login the heal left there, not the one the pass first read.
/// Reading the pass's snapshot here would refuse that write and leave a spent
/// generation live.
///
/// The fetch path decides "slot X is active" before it goes to the network, and
/// a switch to Y that completes while the POST is in flight would otherwise be
/// silently reverted: the user asked for Y, `~/.claude` would say X, and the
/// history would say Y. So the write re-reads the live login under
/// `engine.lock` and goes ahead only when it is still the same account AND the
/// same generation the refresh consumed.
///
/// Only ever reached for the ACTIVE slot (the refresh's live write, and the
/// heal that precedes a fetch), and a pass has at most one of those — which is
/// why taking `engine.lock` here cannot make two fetch threads of the same pass
/// wait on each other.
fn write_live_guarded(
    ctx: &Ctx,
    provider: &dyn Driver,
    st: &SlotState,
    login: &Login,
    expected: Option<&str>,
) -> Result<LiveWrite> {
    let _engine = match FileLock::acquire(&ctx.home.engine_lock_base(), slots::LOCK_TIMEOUT) {
        Ok(lock) => lock,
        // A switch is landing right now: it is the newer intent by definition.
        Err(e) if e.code == ErrorCode::Locked => {
            return Ok(moved(st, "a switch holds the engine lock"))
        }
        Err(e) => return Err(e),
    };

    let live = match provider.read_live(&ctx.env) {
        Ok(live) => live,
        // Nothing readable to compare against is nothing we may overwrite: a
        // logged-out CLI must not be logged back in by a status pass.
        Err(e) => {
            return Ok(moved(
                st,
                &format!("the live login could not be re-read ({e})"),
            ))
        }
    };
    let live_fingerprint = live.fingerprint();
    if live_fingerprint == login.fingerprint() {
        return Ok(LiveWrite::Done); // already there (another refresher wrote it)
    }
    // The same fallback every other identity match has (`match_slot`,
    // `export`): a credential whose envelope carries no `oauthAccount` is
    // matched by fingerprint alone — which is exactly what `expected` checks
    // below. Without it a fingerprint-matched active slot could never be
    // healed, and its live copy would stay on the spent generation forever.
    let same_account = match provider.identity_offline(&live) {
        Some(identity) if !identity.email.is_empty() => slots::same_account(&identity, &st.meta),
        _ => true,
    };
    if !same_account || expected != Some(live_fingerprint.as_str()) {
        return Ok(moved(
            st,
            "the live login is not the one this pass measured",
        ));
    }

    match provider.write_live(&ctx.env, login) {
        Ok(()) => Ok(LiveWrite::Done),
        Err(e) => Ok(LiveWrite::Failed(e)),
    }
}

fn moved(st: &SlotState, why: &str) -> LiveWrite {
    eprintln!(
        "warning: slot {}: the live login was left alone ({why})",
        st.slot
    );
    LiveWrite::Moved
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
    healed: bool,
) -> Result<Fetched> {
    // Under the slot's own refresh lock (`core::refresh`), so a `switch` or a
    // `run` racing this pass cannot POST the same single-use token: the loser
    // of that race gets `invalid_grant` and would quarantine an account whose
    // successor the winner had just persisted.
    let refreshed = match refresh_slot(ctx, provider, st.slot, login)? {
        // The rotation is already persisted (secret + fingerprint), by us or by
        // whoever held the lock first.
        Refreshed::Rotated(refreshed) | Refreshed::Adopted(refreshed) => refreshed,
        Refreshed::Failed(DriverError::TokenDead) => {
            // Strikes condemn the credential generation that was POSTed, not
            // the slot: a re-login writing a new one heals the quarantine.
            ctx.store.record_failure(
                &st.key,
                claim,
                "invalid_grant",
                None,
                Some(&login.fingerprint()),
            )?;
            return Ok(Fetched {
                sentinel: Some(UsageStatus::ReloginRequired),
                live_synced: healed,
            });
        }
        // Another process is spending this slot's token right now. That is not
        // a failed fetch: no strike, no backoff, and not `token-expired` — the
        // account is simply unmeasured this pass. The claim goes back so the
        // next pass (the winner will be done by then) fetches it.
        Refreshed::Failed(DriverError::Locked(_)) => {
            ctx.store.release(&st.key, claim)?;
            return Ok(Fetched {
                sentinel: Some(UsageStatus::Stale),
                live_synced: healed,
            });
        }
        Refreshed::Failed(_) => {
            ctx.store
                .record_failure(&st.key, claim, "refresh", None, None)?;
            // An expired ACTIVE credential nothing could refresh this pass is
            // the state the auto engine must idle-hold on, not a failed fetch
            // (`switcher.py:4810-4830`).
            return Ok(Fetched {
                sentinel: st.active.then_some(UsageStatus::TokenExpired),
                live_synced: healed,
            });
        }
    };

    // The secret and the slot's fingerprint are already written — `refresh_slot`
    // persists before it returns, because the token that produced this
    // generation is spent whether or not anything downstream succeeds. What is
    // left is the ACTIVE slot's live store, and that write is guarded: the pass
    // may only replace the generation it measured.
    // The generation this refresh succeeds — which after a heal is the login
    // the heal itself wrote live, NOT the one the pass first measured.
    let spent = login.fingerprint();
    // The rotation supersedes whatever the heal put live, so this write — not
    // the heal's — is what says the live store holds the slot's credential.
    let mut live_synced = false;
    if st.active {
        match write_live_guarded(ctx, provider, st, &refreshed, Some(spent.as_str()))? {
            LiveWrite::Done => live_synced = true,
            LiveWrite::Moved => {}
            LiveWrite::Failed(e) => {
                return Ok(Fetched {
                    sentinel: Some(degrade_write_live(ctx, st, claim, &e)?),
                    live_synced: false,
                })
            }
        }
    }

    // Once per pass: a second `NeedsRefresh` is recorded as the 401 it is
    // rather than spending another refresh token on it.
    match provider.usage(&refreshed) {
        Ok(usage) => {
            record_success(ctx, st, claim, usage.windows)?;
            Ok(Fetched {
                sentinel: None,
                live_synced,
            })
        }
        Err(e) => {
            record_failure(ctx, st, claim, &e)?;
            Ok(Fetched {
                sentinel: None,
                live_synced,
            })
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
    rotatable_status(st.sentinel, st.meta.disabled)
}

/// The rule itself, over the two facts it needs, so the collector (which asks
/// it of a `SlotState` mid-pass) and the ranker (which asks it of the
/// `AccountView` the pass produced) cannot drift into naming different slots.
///
/// `None` is "no sentinel yet": a slot whose status is still being decided is
/// as rotatable as an `ok` one.
pub fn rotatable_status(status: Option<UsageStatus>, disabled: bool) -> bool {
    !disabled
        && !matches!(
            status,
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

#[cfg(test)]
pub mod tests;
