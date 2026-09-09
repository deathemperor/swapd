//! `swapd add` — capture the login Claude Code is holding right now into a slot.
//!
//! Port of cswap `add_account` (`switcher.py:3332`), minus the interactive
//! overwrite prompt: swapd's verbs are non-interactive, so an occupied slot is
//! refused with the flag that would allow it rather than a question.

use serde::Serialize;

use crate::core::slots::{self, Slot, SlotsFile};
use crate::core::store::read_json;
use crate::ctx::Ctx;
use crate::driver::{Driver, DriverError, Identity};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

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
    let login = match provider.read_live(&ctx.env) {
        Ok(login) if !login.bytes.trim().is_empty() => login,
        Ok(_) | Err(DriverError::NoLogin) => {
            return Err(SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("no active {id} login found; log in first"),
            ))
        }
        Err(e) => return Err(e.into()),
    };
    // cswap `_reject_live_api_key_capture` (`switcher.py:3146`): a live managed
    // key has no identity to file it under, and capturing it as an OAuth
    // account would give the slot a credential that cannot be told from one.
    if login.bytes.trim().starts_with("sk-ant-api") {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the active login is an API key; add it with `swapd add-token -` instead",
        ));
    }

    // `identity` is the envelope's own `oauthAccount` when it has one (what
    // `~/.claude.json` advertises) and the profile endpoint only when it does
    // not — the one place `add` may touch the network, and never under a lock.
    let identity = provider.identity(&login)?;
    if identity.email.is_empty() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the active login does not name an account; log in again",
        ));
    }

    let file: SlotsFile = read_json(&ctx.home.slots_file())?;
    let existing = file.providers.get(id).cloned().unwrap_or_default();
    let owner = existing
        .slots
        .iter()
        .find(|(_, s)| {
            s.email.to_lowercase() == identity.email.to_lowercase()
                && (identity.organization_uuid.is_empty()
                    || s.organization_uuid == identity.organization_uuid)
        })
        .map(|(n, s)| (*n, s.clone()));

    if let Some(alias) = &opts.alias {
        check_alias(&existing, alias, owner.as_ref().map(|(n, _)| *n))?;
    }

    // An explicit `--slot` decides; otherwise the account's own slot refreshes
    // in place and a new account takes the next free one.
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
    slots::write_slot(ctx, id, slot, meta, &login)?;
    // The live login IS this account, so the slot it just landed in is the
    // active one (cswap's `activeAccountNumber` update, `switcher.py:3552`).
    slots::update(&ctx.home.slots_file(), |file| {
        file.providers
            .entry(id.to_string())
            .or_default()
            .active_slot = Some(slot);
        Ok((true, ()))
    })?;

    Ok(AddOutput {
        schema_version: output::SCHEMA_VERSION,
        slot,
        email: identity.email,
        created,
    })
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
pub fn check_alias(
    slots: &crate::core::slots::ProviderSlots,
    alias: &str,
    owner: Option<u32>,
) -> Result<()> {
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
    let clash = slots
        .slots
        .iter()
        .find(|(n, s)| {
            Some(**n) != owner
                && s.alias.as_deref().map(str::to_lowercase) == Some(alias.to_lowercase())
        })
        .map(|(n, _)| *n);
    match clash {
        Some(n) => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("alias '{alias}' is already used by slot {n}"),
        )),
        None => Ok(()),
    }
}

pub fn print_human(out: &AddOutput) {
    let verb = if out.created { "Added" } else { "Updated" };
    println!("{verb} slot {}: {}", out.slot, out.email);
}
