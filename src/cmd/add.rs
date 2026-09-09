//! `swapd add` — capture the login Claude Code is holding right now into a slot.
//!
//! Port of cswap `add_account` (`switcher.py:3332`), minus the interactive
//! overwrite prompt: swapd's verbs are non-interactive, so an occupied slot is
//! refused with the flag that would allow it rather than a question.

use serde::Serialize;

use crate::core::slots::{self, ProviderSlots, Slot};
use crate::core::store::FileLock;
use crate::ctx::Ctx;
use crate::driver::{live_is_older, Driver, DriverError, Identity, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;
use crate::secrets::slot_key;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddOutput {
    pub schema_version: u32,
    pub slot: u32,
    pub email: String,
    /// False when an existing slot for this account was refreshed in place.
    pub created: bool,
}

pub struct AddOpts {
    pub slot: Option<u32>,
    pub alias: Option<String>,
    pub force: bool,
}

pub fn run(ctx: &Ctx, provider: &dyn Driver, opts: &AddOpts) -> Result<AddOutput> {
    let id = provider.id();
    // The capture reads the live login and writes it into a slot, so it is
    // fenced by the same lock a switch takes: an unfenced read can pair one
    // account's credential with another's identity while a swap is half
    // written, and file that credential under the wrong address.
    let mut engine = Some(FileLock::acquire(
        &ctx.home.engine_lock_base(),
        slots::LOCK_TIMEOUT,
    )?);
    let login = read_live(ctx, provider)?;
    // cswap `_reject_live_api_key_capture` (`switcher.py:3146`): a live managed
    // key has no identity to file it under, and capturing it as an OAuth
    // account would give the slot a credential that cannot be told from one.
    if provider.is_api_key(&login) {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the active login is an API key; add it with `swapd add-token -` instead",
        ));
    }

    // `identity` is the envelope's own `oauthAccount` when it has one (what
    // `~/.claude.json` advertises) and the profile endpoint only when it does
    // not — the one place `add` may touch the network, and never under a lock.
    // So the lock is dropped for the call and retaken, and the login is re-read
    // to prove it is still the same bytes: identifying one login and then
    // filing another under its name is exactly what the fence is for.
    let identity = match provider.identity_offline(&login) {
        Some(identity) => identity,
        None => {
            drop(engine.take());
            let identity = provider.identity(&login)?;
            engine = Some(FileLock::acquire(
                &ctx.home.engine_lock_base(),
                slots::LOCK_TIMEOUT,
            )?);
            if read_live(ctx, provider)?.bytes != login.bytes {
                return Err(SwapdError::new(
                    ErrorCode::InvalidInput,
                    "the live login changed while it was being identified; run `swapd add` again",
                ));
            }
            identity
        }
    };
    if identity.email.is_empty() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the active login does not name an account; log in again",
        ));
    }

    // Everything below decides *and* writes under `slots.json`'s lock, in one
    // cycle: the slot number a free-slot capture lands in is only true for as
    // long as the lock is held. The live login IS this account, so the same
    // cycle records the slot as active (cswap's `activeAccountNumber` update,
    // `switcher.py:3552`) — Task 9's keychain-down hold-back reads that field.
    let (slot, created) = slots::claim(ctx, id, true, |existing| {
        let owner = existing
            .slots
            .iter()
            .find(|(_, s)| {
                s.email.to_lowercase() == identity.email.to_lowercase()
                    && (identity.organization_uuid.is_empty()
                        || s.organization_uuid == identity.organization_uuid)
            })
            .map(|(n, s)| (*n, s.clone()));

        // The account already has a slot, and that slot may hold a NEWER
        // generation than the live login does: a rotation the collector
        // persisted whose `write_live` then failed leaves the live copy spent
        // and the stored one the only unspent generation of the lineage.
        // Capturing over it would strand it, so the capture is refused and the
        // heal — which `list` does on its next pass — is named instead.
        if let Some((slot, _)) = &owner {
            let stored = ctx
                .secrets
                .get(&slot_key(id, *slot))?
                .filter(|bytes| !bytes.trim().is_empty())
                .map(|bytes| Login { bytes });
            if stored
                .as_ref()
                .is_some_and(|stored| live_is_older(provider, &login, stored))
            {
                return Err(SwapdError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "slot {slot} already holds a newer generation of this account's                          login than the live one; run `swapd list`, which heals the live                          login from the slot, instead of capturing over it"
                    ),
                ));
            }
        }

        if let Some(alias) = &opts.alias {
            check_alias(existing, alias, owner.as_ref().map(|(n, _)| *n))?;
        }

        // An explicit `--slot` decides; otherwise the account's own slot
        // refreshes in place and a new account takes the next free one.
        let (slot, created, prior) = match (opts.slot, owner) {
            (None, Some((slot, meta))) => (slot, false, Some(meta)),
            (None, None) => (existing.next_free(), true, None),
            (Some(slot), owner) => {
                if slot < 1 {
                    return Err(SwapdError::new(
                        ErrorCode::InvalidInput,
                        "slot numbers start at 1",
                    ));
                }
                let same_account = owner.as_ref().is_some_and(|(n, _)| *n == slot);
                let occupant = existing.slots.get(&slot).cloned();
                if let Some(occupant) = &occupant {
                    if !same_account && !opts.force {
                        return Err(SwapdError::new(
                            ErrorCode::InvalidInput,
                            format!(
                                "slot {slot} holds {}; pass --force to overwrite it",
                                occupant.email
                            ),
                        ));
                    }
                }
                (slot, occupant.is_none(), occupant)
            }
        };

        let meta = compose(&identity, prior.as_ref(), opts.alias.as_deref(), ctx.now());
        Ok((slot, meta, login, created))
    })?;

    drop(engine);

    Ok(AddOutput {
        schema_version: output::SCHEMA_VERSION,
        slot,
        email: identity.email,
        created,
    })
}

/// The live login, or the refusal that says there is none to capture.
///
/// `invalid-input`, not `no-such-slot`: no slot is in play at all, and a
/// machine consumer reading the token would look for one.
fn read_live(ctx: &Ctx, provider: &dyn Driver) -> Result<Login> {
    match provider.read_live(&ctx.env) {
        Ok(login) if !login.bytes.trim().is_empty() => Ok(login),
        Ok(_) | Err(DriverError::NoLogin) => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("no active {} login found; log in first", provider.id()),
        )),
        Err(e) => Err(e.into()),
    }
}

/// The slot row for a captured login: the identity's fields, over whatever the
/// slot already carried. A refresh in place keeps the alias, icon, and the
/// user's disabled/preferred choices — re-capturing a credential says nothing
/// about them.
pub fn compose(identity: &Identity, prior: Option<&Slot>, alias: Option<&str>, now: f64) -> Slot {
    Slot {
        email: identity.email.clone(),
        organization_uuid: identity.organization_uuid.clone(),
        organization_name: identity.organization_name.clone(),
        plan: identity.plan.clone(),
        alias: alias
            .map(str::to_string)
            .or_else(|| prior.and_then(|p| p.alias.clone())),
        icon: prior.and_then(|p| p.icon.clone()),
        disabled: prior.is_some_and(|p| p.disabled),
        preferred: prior.is_some_and(|p| p.preferred),
        added: prior
            .and_then(|p| p.added.clone())
            .or_else(|| crate::driver::claude::usage::format_ts(now)),
        fingerprint: None,
    }
}

/// An alias must name one account (cswap `_alias_in_use`) and must not be a
/// number, which would be read as a slot before it could ever be read as an
/// alias.
///
/// It must not be another slot's EMAIL either. `resolve` tries aliases before
/// emails, so `alias 2 three@example.com` would make every `<ident>` verb —
/// including `remove` — hit slot 2 when the user named slot 3 by its address.
pub fn check_alias(slots: &ProviderSlots, alias: &str, owner: Option<u32>) -> Result<()> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "an alias cannot be empty",
        ));
    }
    if alias.parse::<u32>().is_ok() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("'{alias}' would be read as a slot number, not an alias"),
        ));
    }
    let wanted = alias.to_lowercase();
    let clash = slots
        .slots
        .iter()
        .find(|(n, s)| {
            Some(**n) != owner
                && (s.alias.as_deref().map(str::to_lowercase) == Some(wanted.clone())
                    || s.email.to_lowercase() == wanted)
        })
        .map(|(n, s)| (*n, s.email.to_lowercase() == wanted));
    match clash {
        Some((n, is_email)) => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            if is_email {
                format!("alias '{alias}' is slot {n}'s email address")
            } else {
                format!("alias '{alias}' is already used by slot {n}")
            },
        )),
        None => Ok(()),
    }
}

pub fn print_human(out: &AddOutput) {
    let verb = if out.created { "Added" } else { "Updated" };
    println!("{verb} slot {}: {}", out.slot, out.email);
}
