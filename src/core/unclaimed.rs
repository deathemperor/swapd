//! The unclaimed stash manifest: `<home>/unclaimed.json`.
//!
//! `core::switch::preserve_outgoing` stashes an outgoing live login that
//! matches no managed slot under a secret key the keychain backend cannot
//! enumerate — `security` has no "list every item this service owns", so a
//! stash without a record beside it is unrecoverable by name. This is that
//! record: one row per stash, naming the secret key that holds the bytes,
//! so `swapd unclaimed` can list, and `--purge` can delete, what a switch
//! would otherwise leave as an orphan only `doctor`-level spelunking finds.
//!
//! Same read-modify-write shape as `core::slots`: a lock on the `.lock`
//! sibling around a full read, mutate, atomic write. `list` skips the lock —
//! `write_json_atomic`'s rename makes a bare read safe, and every other
//! reader in this codebase (`slots::load`) does the same.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::core::slots::LOCK_TIMEOUT;
use crate::core::store::{read_json, write_json_atomic, FileLock};
use crate::ctx::Ctx;
use crate::errors::{ErrorCode, Result, SwapdError};

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct ManifestFile {
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
}

/// One stashed login the switch that displaced it could not place in any
/// slot.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub provider: String,
    /// Whole seconds, Unix epoch — the same value `stash_key`'s timestamp
    /// tail encodes, so the id and this field never disagree.
    pub stashed_at: u64,
    /// Empty for a login with no offline identity of its own.
    pub email: String,
    pub fingerprint: String,
    pub reason: String,
    /// `<provider>:unclaimed-<id>` — where the bytes actually live. Never
    /// shown to a user; only `purge` reads it.
    pub secret_key: String,
}

/// Add one row under the manifest's lock. The caller has already put the
/// bytes in `entry.secret_key`; this only makes them findable by `id`.
pub fn record(ctx: &Ctx, id: &str, entry: Entry) -> Result<()> {
    let path = ctx.home.unclaimed_file();
    let _lock = FileLock::acquire(&path, LOCK_TIMEOUT)?;
    let mut file: ManifestFile = read_json(&path)?;
    file.entries.insert(id.to_string(), entry);
    write_json_atomic(&path, &file)
}

/// Every stashed entry, keyed by id. A missing manifest reads as empty,
/// same as every other JSON store here.
pub fn list(ctx: &Ctx) -> Result<BTreeMap<String, Entry>> {
    let file: ManifestFile = read_json(&ctx.home.unclaimed_file())?;
    Ok(file.entries)
}

/// Delete one entry for good: the secret first, then the row.
///
/// The secret leads because purging is destructive by design — a row left
/// behind with no secret behind it merely says so, which is the truth,
/// while a secret left behind with no row is unrecoverable by name again,
/// which is the bug this manifest exists to fix. `Secrets::delete` already
/// treats a missing key as success, so a secret gone by other means (a
/// stash whose row survived an earlier partial purge) does not block this.
pub fn purge(ctx: &Ctx, id: &str) -> Result<Entry> {
    let path = ctx.home.unclaimed_file();
    let _lock = FileLock::acquire(&path, LOCK_TIMEOUT)?;
    let mut file: ManifestFile = read_json(&path)?;
    let entry = file.entries.get(id).cloned().ok_or_else(|| {
        SwapdError::new(ErrorCode::InvalidInput, format!("no unclaimed entry {id}"))
    })?;
    ctx.secrets.delete(&entry.secret_key)?;
    file.entries.remove(id);
    write_json_atomic(&path, &file)?;
    Ok(entry)
}

/// `stashed_at` as RFC 3339 UTC with a `Z` offset rather than `+00:00` — the
/// same shape `driver::claude::usage::format_ts` writes. Shared rather than
/// duplicated: `swapd unclaimed` and `export` both render this field, and
/// both must render it identically.
pub fn format_stashed_at(seconds: u64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds as i64)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .map(|s| s.replace("+00:00", "Z"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::Env;

    fn ctx_for(dir: &std::path::Path) -> Ctx {
        let home = crate::paths::Home {
            root: dir.to_path_buf(),
        };
        home.ensure().unwrap();
        let store = crate::core::usage_store::UsageStore::new(&home.usage_file());
        Ctx {
            env: Env {
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

    fn entry(secret_key: &str) -> Entry {
        Entry {
            provider: "claude".to_string(),
            stashed_at: 1_757_000_000,
            email: "a@b.c".to_string(),
            fingerprint: "sha256:deadbeef".to_string(),
            reason: "switch: live login matched no slot".to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    #[test]
    fn record_then_list_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());

        record(
            &ctx,
            "1757000000-abcd1234",
            entry("claude:unclaimed-1757000000-abcd1234"),
        )
        .unwrap();

        let entries = list(&ctx).unwrap();
        assert_eq!(entries.len(), 1);
        let got = &entries["1757000000-abcd1234"];
        assert_eq!(got.provider, "claude");
        assert_eq!(got.email, "a@b.c");
        assert_eq!(got.secret_key, "claude:unclaimed-1757000000-abcd1234");
    }

    #[test]
    fn purge_removes_the_secret_and_the_row() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let key = "claude:unclaimed-1757000000-abcd1234";
        ctx.secrets.set(key, "the-bytes").unwrap();
        record(&ctx, "1757000000-abcd1234", entry(key)).unwrap();

        let purged = purge(&ctx, "1757000000-abcd1234").unwrap();
        assert_eq!(purged.secret_key, key);

        assert!(ctx.secrets.get(key).unwrap().is_none());
        assert!(list(&ctx).unwrap().is_empty());
    }

    #[test]
    fn purge_unknown_id_is_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());

        let err = purge(&ctx, "nope").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn the_manifest_lock_file_is_named_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());

        record(
            &ctx,
            "1757000000-abcd1234",
            entry("claude:unclaimed-1757000000-abcd1234"),
        )
        .unwrap();

        assert!(dir.path().join("unclaimed.json.lock").exists());
        assert!(dir.path().join("unclaimed.json").exists());
    }
}
