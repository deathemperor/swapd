//! Landing a slot on the live store, and choosing which slot to land.
//!
//! Port of cswap `_perform_switch` (`switcher.py:6633-7195`), reduced to the
//! part swapd owns: the credential swap itself. cswap's per-slot config backup
//! has no counterpart here — a swapd `Login` is Claude Code's credential blob
//! *plus* the `oauthAccount` it advertises (see `driver::claude::live`), so the
//! slot's stored login already carries what cswap kept in a second file, and
//! `write_live` splits it again on the way out.
//!
//! The order is the invariant, not the code shape:
//!  1. resolve the target, and refuse a switch that would do nothing;
//!  2. refresh the target if it is expired — network, and therefore BEFORE
//!     any lock is taken;
//!  3. under `engine.lock`: read the live login, put it somewhere it survives
//!     (its own slot, or the stash), write the target, record the landing.
//!
//! Nothing between (3)'s first and last step touches the network, so the lock
//! is held for local I/O only.

use crate::contract::{AccountView, ProviderView, UsageStatus};
use crate::core::collect::record_slot_fingerprint;
use crate::core::history::{self, SlotRef, SwitchRecord};
use crate::core::poll_policy::{binding_pct, parse_reset_ts};
use crate::core::slots::{self, ProviderSlots, SlotsFile};
use crate::core::store::{read_json, FileLock};
use crate::ctx::Ctx;
use crate::driver::claude::usage::format_ts;
use crate::driver::{Driver, DriverError, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::secrets::slot_key;

/// What a switch did, or why it did nothing.
pub struct SwitchResult {
    pub switched: bool,
    /// Set only when `switched` is false: `already-active`, `no-candidate`.
    pub reason: Option<String>,
    pub from: Option<SlotRef>,
    pub to: SlotRef,
    pub warnings: Vec<String>,
}

/// How `rotate` picks a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Soonest weekly reset first: spend the quota that expires first.
    ConsumeFirst,
    /// Most headroom first.
    Best,
    /// Rotation order after the active slot; the first healthy account wins.
    NextAvailable,
}

impl Strategy {
    pub fn parse(name: &str) -> Result<Strategy> {
        match name {
            "consume-first" => Ok(Strategy::ConsumeFirst),
            "best" => Ok(Strategy::Best),
            "next-available" => Ok(Strategy::NextAvailable),
            other => Err(SwapdError::new(
                ErrorCode::InvalidInput,
                format!(
                    "unknown strategy: {other} \
                     (consume-first, best, next-available)"
                ),
            )),
        }
    }
}

/// Which slot `<ident>` names: a slot number, else an alias, else an email
/// (both case-insensitive).
///
/// Ambiguity is `invalid-input` rather than a silent pick — two accounts
/// answering to one name is a question only the user can settle.
pub fn resolve(slots: &ProviderSlots, provider: &str, ident: &str) -> Result<u32> {
    if let Ok(n) = ident.parse::<u32>() {
        return slots.slots.contains_key(&n).then_some(n).ok_or_else(|| {
            SwapdError::new(ErrorCode::NoSuchSlot, format!("no slot {n} for {provider}"))
        });
    }
    let wanted = ident.to_lowercase();
    let by_alias: Vec<u32> = slots
        .slots
        .iter()
        .filter(|(_, s)| s.alias.as_deref().map(str::to_lowercase) == Some(wanted.clone()))
        .map(|(n, _)| *n)
        .collect();
    let matches = if by_alias.is_empty() {
        slots
            .slots
            .iter()
            .filter(|(_, s)| s.email.to_lowercase() == wanted)
            .map(|(n, _)| *n)
            .collect()
    } else {
        by_alias
    };
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(SwapdError::new(
            ErrorCode::NoSuchSlot,
            format!("no account matches '{ident}' for {provider}"),
        )),
        many => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!(
                "'{ident}' matches slots {}; name one by number",
                many.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Make `target` the live login.
///
/// `trigger` names the author of the switch in the history log (`manual`,
/// `rotate`, and later the auto loop).
pub fn perform(
    ctx: &Ctx,
    provider: &dyn Driver,
    target: u32,
    trigger: &str,
) -> Result<SwitchResult> {
    let id = provider.id();
    let file: SlotsFile = read_json(&ctx.home.slots_file())?;
    let slots = file.providers.get(id).cloned().unwrap_or_default();
    let meta = slots.slots.get(&target).cloned().ok_or_else(|| {
        SwapdError::new(ErrorCode::NoSuchSlot, format!("no slot {target} for {id}"))
    })?;
    let to = SlotRef::numbered(target, meta.email.clone());

    let key = slot_key(id, target);
    let target_login = ctx
        .secrets
        .get(&key)?
        .filter(|bytes| !bytes.trim().is_empty())
        .map(|bytes| Login { bytes })
        .ok_or_else(|| {
            SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("slot {target} has no stored login; log in and run `swapd add`"),
            )
        })?;

    // Refused here, before the engine lock and before the outgoing login is
    // touched: `write_live` rejects a managed key anyway (Claude Code holds it
    // on a different axis), and failing there would mean saying so only after
    // the previous login had already been backed up or stashed.
    if target_login.bytes.trim().starts_with("sk-ant-api") {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!(
                "slot {target} holds a managed API key; activating Claude Code's \
                 API-key axis is not implemented"
            ),
        ));
    }

    // Already there? Asked of the LIVE login, not of `slots.json`'s record of
    // it: the record can lag (Claude Code's own `/login`, another tool), and a
    // switch that reports "already-active" against a stale record would leave
    // the user on an account they did not ask for.
    let live = read_live_for_switch(provider, &ctx.env)?;
    if let Some(live) = &live {
        if match_slot(provider, &slots, live) == Some(target) {
            return Ok(SwitchResult {
                switched: false,
                reason: Some("already-active".to_string()),
                from: Some(to.clone()),
                to,
                warnings: Vec::new(),
            });
        }
    }

    // The only network in the verb, and it happens before any lock: an expired
    // target would otherwise land as a login the next request has to refresh
    // anyway, and the refresh writes a single-use rotation that must be
    // persisted before it can be spent.
    let mut warnings = Vec::new();
    let target_login =
        refresh_if_expired(ctx, provider, target, &key, target_login, &mut warnings)?;

    let _engine = FileLock::acquire(&ctx.home.engine_lock_base(), slots::LOCK_TIMEOUT)?;

    // Re-read under the lock: this is the copy that gets backed up, and it is
    // the reason the lock exists (a refresh landing mid-swap must not hand us a
    // superseded generation).
    let live = read_live_for_switch(provider, &ctx.env)?;
    let from = match &live {
        Some(live) => Some(preserve_outgoing(
            ctx,
            provider,
            &slots,
            live,
            &mut warnings,
        )?),
        None => None,
    };

    if let Err(e) = provider.write_live(&ctx.env, &target_login) {
        // The live store is where the user's next `claude` reads from, so it
        // must never be left holding a half-written swap. Restoring is
        // best-effort by necessity — if it fails too, the original error is
        // still the one that describes what went wrong.
        if let Some(live) = &live {
            if let Err(restore) = provider.write_live(&ctx.env, live) {
                return Err(SwapdError::new(
                    ErrorCode::Io,
                    format!(
                        "switch to slot {target} failed ({e}) and the previous live \
                         login could not be restored ({restore}); it is preserved in \
                         swapd's store"
                    ),
                ));
            }
        }
        return Err(e.into());
    }

    slots::update(&ctx.home.slots_file(), |file| {
        let entry = file.providers.entry(id.to_string()).or_default();
        entry.active_slot = Some(target);
        Ok((true, ()))
    })?;

    history::append(
        &ctx.home,
        &SwitchRecord {
            ts: format_ts(ctx.now()).unwrap_or_default(),
            from: from.clone(),
            to: to.clone(),
            trigger: trigger.to_string(),
        },
    )?;

    Ok(SwitchResult {
        switched: true,
        reason: None,
        from,
        to,
        warnings,
    })
}

/// The live login, or `None` when there genuinely is not one.
///
/// A live store that *errors* is not an empty store: overwriting it would
/// destroy a credential we could not read, so the switch stops instead.
fn read_live_for_switch(provider: &dyn Driver, env: &crate::driver::Env) -> Result<Option<Login>> {
    match provider.read_live(env) {
        Ok(login) if login.bytes.trim().is_empty() => Ok(None),
        Ok(login) => Ok(Some(login)),
        Err(DriverError::NoLogin) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Refresh an expired target before the locks, persisting the rotation.
///
/// A dead refresh token is fatal — landing it would make the next request fail
/// as an authentication error the user cannot read. Any other failure is not:
/// the login is merely stale, Claude Code refreshes it itself on first use, and
/// refusing to switch over a transient network fault would be worse than
/// switching.
fn refresh_if_expired(
    ctx: &Ctx,
    provider: &dyn Driver,
    slot: u32,
    key: &str,
    login: Login,
    warnings: &mut Vec<String>,
) -> Result<Login> {
    let expired = provider
        .expires_at(&login)
        .is_some_and(|expires_at| expires_at < ctx.now());
    if !expired {
        return Ok(login);
    }
    match provider.refresh(&login) {
        Ok(refreshed) => {
            // Persisted before it can be spent: the token that produced it is
            // single-use, so a rotation we drop is a generation nothing can
            // ever get back.
            ctx.secrets.set(key, &refreshed.bytes)?;
            record_slot_fingerprint(ctx, provider.id(), slot, Some(&refreshed.fingerprint()))?;
            Ok(refreshed)
        }
        Err(DriverError::TokenDead) => Err(SwapdError::new(
            ErrorCode::TokenDead,
            format!("slot {slot}'s login is expired and its refresh token was rejected; log in again and run `swapd add`"),
        )),
        Err(e) => {
            warnings.push(format!(
                "slot {slot}'s login is expired and could not be refreshed ({e}); \
                 switching to it anyway"
            ));
            Ok(login)
        }
    }
}

/// Put the outgoing live login somewhere it survives the swap, and say where
/// it came from.
///
/// Its own slot when one owns it — identity first, fingerprint second (Task 9's
/// rule: the CLI rotates the lineage itself, so a fingerprint alone loses the
/// slot the moment it does). Otherwise the stash, which is the *license* to
/// overwrite the live store: a stash that fails aborts the switch rather than
/// destroying a credential that exists nowhere else.
fn preserve_outgoing(
    ctx: &Ctx,
    provider: &dyn Driver,
    slots: &ProviderSlots,
    live: &Login,
    warnings: &mut Vec<String>,
) -> Result<SlotRef> {
    let id = provider.id();
    let email = provider
        .identity_offline(live)
        .map(|i| i.email)
        .unwrap_or_default();

    let Some(slot) = match_slot(provider, slots, live) else {
        let stash_key = stash_key(id, ctx.now(), live);
        ctx.secrets.set(&stash_key, &live.bytes)?;
        warnings.push(format!(
            "the live login does not match a managed account; it was preserved as \
             '{stash_key}' and not written into any slot. If you need that account, \
             log in as it and run `swapd add`"
        ));
        return Ok(SlotRef::unmanaged(email));
    };

    // The rotated token is the point: the live copy is by definition the
    // current generation of this slot's lineage, so it replaces the stored one.
    let key = slot_key(id, slot);
    let stored = ctx.secrets.get(&key)?;
    if stored.as_deref() != Some(live.bytes.as_str()) {
        ctx.secrets.set(&key, &live.bytes)?;
        record_slot_fingerprint(ctx, id, slot, Some(&live.fingerprint()))?;
        // A quarantine condemned the generation this slot used to hold, not the
        // one it holds now.
        ctx.store.clear_dead(&key)?;
    }
    let email = slots
        .slots
        .get(&slot)
        .map(|s| s.email.clone())
        .unwrap_or(email);
    Ok(SlotRef::numbered(slot, email))
}

/// `FileSecrets` folds `:` to `_` and rejects `/`, so the stash lives under
/// `<provider>:unclaimed-<unix-ts>-<fp>` rather than the `unclaimed/<ts>` the
/// design note wrote.
///
/// The fingerprint tail is not decoration: the timestamp is whole seconds, and
/// `set` truncates, so two switches inside one second would otherwise have the
/// second stash overwrite the first — discarding a login that exists nowhere
/// else, which is the one thing this path must never do.
fn stash_key(provider: &str, now: f64, login: &Login) -> String {
    let fp = login.fingerprint();
    let short: String = fp
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .chars()
        .take(8)
        .collect();
    format!("{provider}:unclaimed-{}-{}", now as u64, short)
}

/// The slot a login belongs to: identity (email + org) first, fingerprint
/// second for a login that carries no identity of its own.
fn match_slot(provider: &dyn Driver, slots: &ProviderSlots, login: &Login) -> Option<u32> {
    if let Some(identity) = provider.identity_offline(login) {
        let email = identity.email.to_lowercase();
        if !email.is_empty() {
            let found = slots.slots.iter().find(|(_, s)| {
                s.email.to_lowercase() == email
                    && (identity.organization_uuid.is_empty()
                        || s.organization_uuid == identity.organization_uuid)
            });
            if let Some((slot, _)) = found {
                return Some(*slot);
            }
        }
    }
    let fingerprint = login.fingerprint();
    if fingerprint.is_empty() {
        return None;
    }
    slots
        .slots
        .iter()
        .find(|(_, s)| s.fingerprint.as_deref() == Some(fingerprint.as_str()))
        .map(|(slot, _)| *slot)
}

/// The slots `rotate` may land on, best first.
///
/// Simplified from cswap's `_rank_candidates` (`autoswitch.py:2016-2235`) to
/// the part a one-shot rotate needs: no hysteresis, no no-return bar, no
/// two-phase re-verification — those bound the flap RATE of a loop that runs
/// every tick, and a rotate the user (or a single auto pass) asked for once has
/// no rate to bound.
///
/// An account nobody has measured yet is a candidate: unknown headroom is not
/// evidence of an empty account, and proving it is what the switch does.
pub fn rank(ctx: &Ctx, view: &ProviderView, strategy: Strategy, preferred: &[String]) -> Vec<u32> {
    let rotation: Vec<&AccountView> = view
        .accounts
        .iter()
        .filter(|a| !a.active && rotatable(a) && headroom(ctx, a).is_none_or(|h| h > 0.0))
        .collect();

    if strategy == Strategy::NextAvailable {
        // Rotation order, resumed after the active slot: `view.accounts` is
        // already in it (the collector builds from `slots.order`).
        let start = view
            .accounts
            .iter()
            .position(|a| a.active)
            .map(|i| i + 1)
            .unwrap_or(0);
        let len = view.accounts.len();
        return (0..len)
            .map(|offset| &view.accounts[(start + offset) % len])
            .filter(|a| rotation.iter().any(|c| c.slot == a.slot))
            .map(|a| a.slot)
            .collect();
    }

    let mut ranked: Vec<(RankKey, u32)> = rotation
        .iter()
        .map(|a| {
            let head = headroom(ctx, a);
            let key = match strategy {
                // Soonest weekly reset first (unknown resets last), most
                // headroom breaks ties.
                Strategy::ConsumeFirst => RankKey {
                    preferred: !is_preferred(a, preferred),
                    first: seven_day_reset(a).unwrap_or(f64::INFINITY),
                    second: -head.unwrap_or(100.0),
                },
                Strategy::Best => RankKey {
                    preferred: !is_preferred(a, preferred),
                    first: -head.unwrap_or(100.0),
                    second: 0.0,
                },
                Strategy::NextAvailable => unreachable!("handled above"),
            };
            (key, a.slot)
        })
        .collect();
    // Slot order breaks every remaining tie, so the answer is deterministic.
    ranked.sort_by(|a, b| {
        a.0.preferred
            .cmp(&b.0.preferred)
            .then(a.0.first.total_cmp(&b.0.first))
            .then(a.0.second.total_cmp(&b.0.second))
            .then(a.1.cmp(&b.1))
    });
    ranked.into_iter().map(|(_, slot)| slot).collect()
}

/// One candidate's sort key. `preferred` is a `bool` inverted at construction
/// (`false` sorts first), so the whole key compares in one direction.
struct RankKey {
    preferred: bool,
    first: f64,
    second: f64,
}

/// Whether the rotation may land here at all — the collector's own rule
/// (`collect::rotatable`), applied to the view it produced.
fn rotatable(account: &AccountView) -> bool {
    !account.disabled
        && !matches!(
            account.usage_status,
            UsageStatus::NoCredentials
                | UsageStatus::ApiKey
                | UsageStatus::ReloginRequired
                | UsageStatus::Unsupported
        )
}

/// The account's remaining percent on its binding window, `None` when nothing
/// has measured it.
fn headroom(ctx: &Ctx, account: &AccountView) -> Option<f64> {
    binding_pct(decision_windows(account), &ctx.settings.models).map(|pct| 100.0 - pct)
}

/// The windows a decision is made on: the current measurement when the account
/// has one, its last-known-good otherwise (the status already says which).
fn decision_windows(account: &AccountView) -> &[crate::contract::Window] {
    if account.windows.is_empty() {
        account
            .last_good
            .as_ref()
            .map(|g| g.windows.as_slice())
            .unwrap_or_default()
    } else {
        &account.windows
    }
}

fn seven_day_reset(account: &AccountView) -> Option<f64> {
    decision_windows(account)
        .iter()
        .find(|w| w.kind == crate::contract::WindowKind::SevenDay)
        .and_then(|w| parse_reset_ts(w.resets_at.as_deref()))
}

/// The slot's own `preferred` flag, or a settings list naming it by number,
/// alias or email.
fn is_preferred(account: &AccountView, preferred: &[String]) -> bool {
    account.preferred
        || preferred.iter().any(|name| {
            let name = name.to_lowercase();
            name == account.slot.to_string()
                || name == account.email.to_lowercase()
                || account.alias.as_deref().map(str::to_lowercase) == Some(name)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::slots::Slot;
    use crate::driver::Identity;

    fn slot(email: &str, alias: Option<&str>) -> Slot {
        Slot {
            email: email.to_string(),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            alias: alias.map(str::to_string),
            icon: None,
            disabled: false,
            preferred: false,
            added: None,
            fingerprint: None,
        }
    }

    #[test]
    fn resolve_prefers_alias_over_email_and_reports_ambiguity() {
        let mut slots = ProviderSlots::default();
        slots.insert(1, slot("one@example.com", Some("work")));
        slots.insert(2, slot("two@example.com", Some("one@example.com")));

        assert_eq!(resolve(&slots, "claude", "1").unwrap(), 1);
        assert_eq!(resolve(&slots, "claude", "WORK").unwrap(), 1);
        // The alias wins outright: nothing is ambiguous when only one kind matches.
        assert_eq!(resolve(&slots, "claude", "one@example.com").unwrap(), 2);

        let err = resolve(&slots, "claude", "9").unwrap_err();
        assert_eq!(err.code, ErrorCode::NoSuchSlot);
    }

    #[test]
    fn resolve_refuses_two_slots_with_one_email() {
        let mut slots = ProviderSlots::default();
        slots.insert(1, slot("same@example.com", None));
        slots.insert(2, slot("same@example.com", None));
        let err = resolve(&slots, "claude", "same@example.com").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn stash_key_avoids_the_slash_file_secrets_rejects() {
        let login = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-a"}}"#.to_string(),
        };
        let key = stash_key("claude", 1_757_000_000.7, &login);
        assert!(key.starts_with("claude:unclaimed-1757000000-"), "{key}");
        assert!(!key.contains('/'));

        // Same second, different login: the keys must not collide, or the
        // second stash would overwrite the first.
        let other = Login {
            bytes: r#"{"claudeAiOauth":{"refreshToken":"rt-b"}}"#.to_string(),
        };
        assert_ne!(key, stash_key("claude", 1_757_000_000.7, &other));
    }

    /// A driver whose live store is a `Mutex<String>` and whose `write_live`
    /// can be told to fail.
    ///
    /// The restore-on-failure path cannot be reached through the real Claude
    /// driver from a test: with the file live store its only post-write failure
    /// is the `~/.claude.json` splice, and every portable way to break that
    /// write (an unwritable `$HOME`) breaks Claude Code's own lock directories
    /// first, so the driver fails before it has written anything. The
    /// integration suite therefore proves the invariant — a failed switch
    /// leaves the live login byte-identical — and this proves the mechanism.
    struct FakeDriver {
        live: std::sync::Mutex<Option<String>>,
        fail_write: bool,
        writes: std::sync::Mutex<Vec<String>>,
    }

    impl FakeDriver {
        fn new(live: &str, fail_write: bool) -> Self {
            FakeDriver {
                live: std::sync::Mutex::new(Some(live.to_string())),
                fail_write,
                writes: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl Driver for FakeDriver {
        fn id(&self) -> &'static str {
            "claude"
        }
        fn installed(&self) -> Option<std::path::PathBuf> {
            None
        }
        fn read_live(&self, _env: &crate::driver::Env) -> std::result::Result<Login, DriverError> {
            match self.live.lock().unwrap().clone() {
                Some(bytes) => Ok(Login { bytes }),
                None => Err(DriverError::NoLogin),
            }
        }
        fn write_live(
            &self,
            _env: &crate::driver::Env,
            login: &Login,
        ) -> std::result::Result<(), DriverError> {
            self.writes.lock().unwrap().push(login.bytes.clone());
            if self.fail_write && self.writes.lock().unwrap().len() == 1 {
                // Only the FIRST write fails: the restore that follows has to
                // be able to succeed, or the test could not tell a restore
                // apart from a driver that rejects everything.
                return Err(DriverError::Invalid("write refused".to_string()));
            }
            *self.live.lock().unwrap() = Some(login.bytes.clone());
            Ok(())
        }
        fn identity(&self, login: &Login) -> std::result::Result<Identity, DriverError> {
            self.identity_offline(login)
                .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
        }
        fn identity_offline(&self, login: &Login) -> Option<Identity> {
            let value: serde_json::Value = serde_json::from_str(&login.bytes).ok()?;
            Some(Identity {
                email: value.get("email")?.as_str()?.to_string(),
                organization_uuid: String::new(),
                organization_name: String::new(),
                plan: None,
                uuid: None,
            })
        }
        fn expires_at(&self, _login: &Login) -> Option<f64> {
            None
        }
        fn refresh(&self, _login: &Login) -> std::result::Result<Login, DriverError> {
            Err(DriverError::TokenDead)
        }
        fn usage(&self, _login: &Login) -> std::result::Result<crate::driver::Usage, DriverError> {
            Err(DriverError::Unsupported("usage"))
        }
        fn ignite(
            &self,
            _env: &crate::driver::Env,
            _slot: u32,
            _login: &Login,
        ) -> std::result::Result<crate::driver::IgniteOutcome, DriverError> {
            Err(DriverError::Unsupported("ignite"))
        }
        fn run_profile(
            &self,
            _env: &crate::driver::Env,
            _slot: u32,
            _login: &Login,
        ) -> std::result::Result<crate::driver::RunProfile, DriverError> {
            Err(DriverError::Unsupported("run"))
        }
        fn capabilities(&self) -> crate::driver::Caps {
            crate::driver::Caps {
                ignite: true,
                add_token: true,
                prefer: true,
                refresh: true,
                run: true,
            }
        }
    }

    /// A `Ctx` over a temp home, an in-memory secret store and a fixed clock.
    fn ctx_for(dir: &std::path::Path) -> Ctx {
        let home = crate::paths::Home {
            root: dir.to_path_buf(),
        };
        home.ensure().unwrap();
        let store = crate::core::usage_store::UsageStore::new(&home.usage_file());
        Ctx {
            env: crate::driver::Env {
                home: home.root.clone(),
                vars: Default::default(),
            },
            home,
            secrets: Box::new(crate::secrets::MemorySecrets::new()),
            clock: Box::new(|| 1_757_000_000.0),
            settings: Default::default(),
            store,
        }
    }

    fn login_for(email: &str, token: &str) -> String {
        format!(r#"{{"email":"{email}","claudeAiOauth":{{"refreshToken":"{token}"}}}}"#)
    }

    /// Seed two slots, each with a stored login, and return the ctx.
    fn two_slots(dir: &std::path::Path) -> Ctx {
        let ctx = ctx_for(dir);
        for (n, email, token) in [
            (1, "one@example.com", "rt-1"),
            (2, "two@example.com", "rt-2"),
        ] {
            ctx.secrets
                .set(&slot_key("claude", n), &login_for(email, token))
                .unwrap();
            slots::update(&ctx.home.slots_file(), |file| {
                file.providers
                    .entry("claude".to_string())
                    .or_default()
                    .insert(n, slot(email, None));
                Ok((true, ()))
            })
            .unwrap();
        }
        ctx
    }

    #[test]
    fn switch_restores_live_on_write_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = two_slots(dir.path());
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"), true);

        // Matched rather than `unwrap_err`: `SwitchResult` has no `Debug`, so
        // nothing it carries can reach a panic message.
        match perform(&ctx, &driver, 2, "manual") {
            Err(e) => assert_eq!(e.code, ErrorCode::InvalidInput),
            Ok(_) => panic!("a refused write must fail the switch"),
        }

        // Two writes: the target, then the original put back — and the live
        // store ends up holding the original.
        let writes = driver.writes.lock().unwrap().clone();
        assert_eq!(writes.len(), 2, "the restore must be attempted");
        assert!(writes[0].contains("rt-2"), "the target is written first");
        assert_eq!(
            writes[1],
            login_for("one@example.com", "rt-1"),
            "the restore writes the login that was there"
        );
        assert_eq!(
            driver.live.lock().unwrap().clone().unwrap(),
            login_for("one@example.com", "rt-1")
        );

        // And nothing recorded a switch that did not happen.
        assert!(crate::core::history::read(&ctx.home, None)
            .unwrap()
            .is_empty());
        let file: SlotsFile = read_json(&ctx.home.slots_file()).unwrap();
        assert_eq!(file.providers["claude"].active_slot, None);
    }

    #[test]
    fn a_switch_lands_the_target_and_records_the_landing() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = two_slots(dir.path());
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-rotated"), false);

        let result = perform(&ctx, &driver, 2, "manual").unwrap();
        assert!(result.switched);
        assert_eq!(result.from.as_ref().unwrap().slot, Some(1));
        assert_eq!(result.to.slot, Some(2));
        assert!(result.warnings.is_empty());

        // The outgoing rotation replaced slot 1's older stored copy.
        assert_eq!(
            ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
            login_for("one@example.com", "rt-rotated")
        );
        let file: SlotsFile = read_json(&ctx.home.slots_file()).unwrap();
        assert_eq!(file.providers["claude"].active_slot, Some(2));
        assert_eq!(
            crate::core::history::read(&ctx.home, None).unwrap().len(),
            1
        );
    }

    #[test]
    fn switching_to_a_managed_key_slot_is_refused_before_any_side_effect() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = two_slots(dir.path());
        ctx.secrets
            .set(&slot_key("claude", 2), "sk-ant-api03-managed")
            .unwrap();
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"), false);

        match perform(&ctx, &driver, 2, "manual") {
            Err(e) => assert_eq!(e.code, ErrorCode::Unsupported),
            Ok(_) => panic!("the managed-key axis is not implemented; the switch must fail"),
        }

        // Refused early: nothing was written, and the outgoing login was
        // neither backed up nor stashed.
        assert!(driver.writes.lock().unwrap().is_empty());
        assert_eq!(
            ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
            login_for("one@example.com", "rt-1")
        );
        let file: SlotsFile = read_json(&ctx.home.slots_file()).unwrap();
        assert_eq!(file.providers["claude"].active_slot, None);
    }

    #[test]
    fn switching_to_the_live_account_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = two_slots(dir.path());
        let driver = FakeDriver::new(&login_for("two@example.com", "rt-2"), false);

        let result = perform(&ctx, &driver, 2, "manual").unwrap();
        assert!(!result.switched);
        assert_eq!(result.reason.as_deref(), Some("already-active"));
        assert!(
            driver.writes.lock().unwrap().is_empty(),
            "a no-op switch touches nothing"
        );
    }
}
