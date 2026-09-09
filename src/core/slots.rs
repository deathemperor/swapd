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

/// Put a login in slot `n` and record the account it belongs to: the secret,
/// the slot row (stamped with the login's fingerprint), and the lifting of any
/// dead-token quarantine the slot's PREVIOUS credential earned.
///
/// The three go together in cswap too (`add_account`, `add_account_from_token`
/// and `import_accounts` all end in the same trio): a slot holding new bytes
/// under an old quarantine is an account that reads as "re-login needed"
/// forever and never fetches again (`switcher.py:3535`).
///
/// The secret is written BEFORE the row: a row pointing at a fingerprint whose
/// bytes never landed is a slot that cannot authenticate, while bytes without a
/// row are merely unreferenced.
pub fn write_slot(ctx: &Ctx, provider: &str, n: u32, mut meta: Slot, login: &Login) -> Result<()> {
    let key = crate::secrets::slot_key(provider, n);
    ctx.secrets.set(&key, &login.bytes)?;
    meta.fingerprint = Some(login.fingerprint());
    update(&ctx.home.slots_file(), |file| {
        file.providers
            .entry(provider.to_string())
            .or_default()
            .insert(n, meta);
        Ok((true, ()))
    })?;
    ctx.store.clear_dead(&key)
}

// `remove` waits for the slots verbs (`rm`); the rest are wired up.
#[allow(dead_code)]
impl ProviderSlots {
    pub fn next_free(&self) -> u32 {
        (1..).find(|n| !self.slots.contains_key(n)).unwrap()
    }

    pub fn resolve(&self, ident: &str) -> Option<u32> {
        // number, then exact email (case-insensitive), then alias
        if let Ok(n) = ident.parse::<u32>() {
            return self.slots.contains_key(&n).then_some(n);
        }
        let l = ident.to_lowercase();
        self.slots
            .iter()
            .find(|(_, s)| s.email.to_lowercase() == l)
            .map(|(n, _)| *n)
            .or_else(|| {
                self.slots
                    .iter()
                    .find(|(_, s)| s.alias.as_deref().map(|a| a.to_lowercase()) == Some(l.clone()))
                    .map(|(n, _)| *n)
            })
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

    #[test]
    fn resolve_by_number_email_alias() {
        let mut ps = ProviderSlots::default();
        ps.insert(1, slot("Alice@Example.com", Some("work")));
        ps.insert(2, slot("bob@example.com", None));

        assert_eq!(ps.resolve("1"), Some(1));
        assert_eq!(ps.resolve("3"), None);
        assert_eq!(ps.resolve("alice@example.com"), Some(1));
        assert_eq!(ps.resolve("BOB@EXAMPLE.COM"), Some(2));
        assert_eq!(ps.resolve("Work"), Some(1));
        assert_eq!(ps.resolve("nobody"), None);
    }
}
