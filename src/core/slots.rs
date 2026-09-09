use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::store::{read_json, write_json_atomic, FileLock};
use crate::ctx::Ctx;
use crate::driver::Login;
use crate::errors::Result;

/// How long to wait for `slots.json`'s lock. Every writer waits the same.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SlotsFile {
    pub schema_version: u32,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderSlots>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSlots {
    pub active_slot: Option<u32>,
    #[serde(default)]
    pub order: Vec<u32>, // rotation order, every slot once
    #[serde(default)]
    pub slots: BTreeMap<u32, Slot>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slot {
    pub email: String,
    #[serde(default)]
    pub organization_uuid: String,
    #[serde(default)]
    pub organization_name: String,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub preferred: bool,
    #[serde(default)]
    pub added: Option<String>, // RFC 3339
    #[serde(default)]
    pub fingerprint: Option<String>, // "sha256:…" of the stored login
}

/// Read-modify-write `slots.json` under `<slots.json>.lock`.
///
/// The one way anything mutates the file. Every writer re-reads inside the
/// lock, so a switch landing while the collector re-stamps a fingerprint sees
/// that stamp instead of overwriting it with the copy it read before waiting.
/// `mutate` returns `false` when it changed nothing, which skips the write.
pub fn update<T>(
    path: &Path,
    mutate: impl FnOnce(&mut SlotsFile) -> Result<(bool, T)>,
) -> Result<T> {
    let _lock = FileLock::acquire(path, LOCK_TIMEOUT)?;
    let mut file: SlotsFile = read_json(path)?;
    let (dirty, out) = mutate(&mut file)?;
    if dirty {
        file.schema_version = SCHEMA_VERSION;
        write_json_atomic(path, &file)?;
    }
    Ok(out)
}

/// The `slots.json` layout this build writes.
pub const SCHEMA_VERSION: u32 = 1;

/// One provider's table, or an empty one when the file (or the provider) is
/// not there yet. Every read path outside `update` goes through this.
pub fn load(home: &crate::paths::Home, provider: &str) -> Result<ProviderSlots> {
    let file: SlotsFile = read_json(&home.slots_file())?;
    Ok(file.providers.get(provider).cloned().unwrap_or_default())
}

/// Decide which slot a login lands in and write it, both under
/// `slots.json`'s lock.
///
/// `decide` sees the provider's table as it stands *inside* the lock and
/// answers with the slot to write, its row, the credential, the OTHER slot to
/// vacate (when this capture is `add --slot n` MOVING an account that already
/// owns a different slot, rather than duplicating it there), and whatever the
/// caller wants to report (`created`, the resolved email). Deciding outside
/// the lock and writing inside it is a check-then-act: two concurrent `add`s
/// both compute the same `next_free()` and the second silently overwrites the
/// first's row.
///
/// What lands is a trio, as in cswap (`add_account`, `add_account_from_token`
/// and `import_accounts` all end in it): the secret, the slot row stamped with
/// the login's fingerprint, and the lifting of any dead-token quarantine the
/// slot's PREVIOUS credential earned — a slot holding new bytes under an old
/// quarantine reads as "re-login needed" forever and never fetches again
/// (`switcher.py:3535`).
///
/// The secret is written BEFORE the row (a row pointing at bytes that never
/// landed is a slot that cannot authenticate, while bytes without a row are
/// merely unreferenced) and inside the lock, because the slot number it is
/// keyed by is only decided there. The vacated slot's row is removed in the
/// SAME lock cycle (so a concurrent `list` never observes the account sitting
/// in both slots at once), but its secret and usage-store rows follow outside
/// the lock, exactly like `clear_dead` — a crash between the two leaves the
/// account owning only the new slot with its old secret still around, which
/// the next `add` simply overwrites again, never a lost account.
///
/// `activate` records the slot as the provider's active one in the same cycle,
/// for the verb whose write IS the live login (`add`).
pub fn claim<T>(
    ctx: &Ctx,
    provider: &str,
    activate: bool,
    decide: impl FnOnce(&ProviderSlots) -> Result<(u32, Slot, Login, Option<u32>, T)>,
) -> Result<(u32, Option<u32>, T)> {
    let (n, vacated, extra) = update(&ctx.home.slots_file(), |file| {
        let existing = file.providers.entry(provider.to_string()).or_default();
        let (n, mut meta, login, vacate, extra) = decide(existing)?;
        ctx.secrets
            .set(&crate::secrets::slot_key(provider, n), &login.bytes)?;
        meta.fingerprint = Some(login.fingerprint());
        existing.insert(n, meta);
        let vacated = vacate.filter(|m| *m != n);
        if let Some(m) = vacated {
            existing.remove(m);
        }
        if activate {
            existing.active_slot = Some(n);
        }
        Ok((true, (n, vacated, extra)))
    })?;
    if let Some(m) = vacated {
        ctx.secrets.delete(&crate::secrets::slot_key(provider, m))?;
        ctx.store.relocate(
            &crate::secrets::slot_key(provider, m),
            &crate::secrets::slot_key(provider, n),
        )?;
    }
    ctx.store
        .clear_dead(&crate::secrets::slot_key(provider, n))?;
    Ok((n, vacated, extra))
}

/// Whether `identity` is the account `slot` holds.
///
/// The ONE spelling of the question, which the collector's active-slot match,
/// `switch`'s `match_slot`, `add`'s capture, `export` and `import` had five of
/// between them — and one of those (export's) was missing the empty-org escape,
/// so a slot recorded before swapd knew the organization never matched its own
/// live login.
///
/// Email is case-insensitive; an identity that names no organization matches on
/// the address alone (a cswap import, an older release, a login whose envelope
/// carries no org); an identity that names no account matches nothing at all —
/// a caller with a fingerprint to fall back on says so itself.
pub fn same_account(identity: &crate::driver::Identity, slot: &Slot) -> bool {
    !identity.email.is_empty()
        && identity.email.to_lowercase() == slot.email.to_lowercase()
        && (identity.organization_uuid.is_empty()
            || slot.organization_uuid == identity.organization_uuid)
}

// (Resolving an `<ident>` to a slot is `core::switch::resolve`, which is the
// one resolver: it tries alias before email and reports ambiguity.)
impl ProviderSlots {
    pub fn next_free(&self) -> u32 {
        (1..).find(|n| !self.slots.contains_key(n)).unwrap()
    }

    pub fn insert(&mut self, n: u32, slot: Slot) {
        self.slots.insert(n, slot);
        if !self.order.contains(&n) {
            self.order.push(n);
        }
    }

    pub fn remove(&mut self, n: u32) {
        self.slots.remove(&n);
        self.order.retain(|x| *x != n);
        if self.active_slot == Some(n) {
            self.active_slot = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(email: &str, alias: Option<&str>) -> Slot {
        Slot {
            email: email.to_string(),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            alias: alias.map(|a| a.to_string()),
            icon: None,
            disabled: false,
            preferred: false,
            added: None,
            fingerprint: None,
        }
    }

    #[test]
    fn next_free_skips_taken() {
        let mut ps = ProviderSlots::default();
        ps.insert(1, slot("a@example.com", None));
        ps.insert(2, slot("b@example.com", None));
        assert_eq!(ps.next_free(), 3);
        ps.remove(1);
        assert_eq!(ps.next_free(), 1);
    }
}
