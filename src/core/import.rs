//! Reading an export back in.
//!
//! Port of cswap `import_accounts` (`transfer.py:316`), plus swapd's own
//! envelope (`{"format":"swapd/1"}`, which `cmd::export` writes). Both carry
//! the same per-account shape, so one reader serves them; they differ only in
//! where the list hangs — cswap's is flat and always Claude's, swapd's is
//! grouped per provider (see `accounts_for`).
//!
//! Two passes, as cswap has: everything is validated before anything is
//! written, so a malformed account late in the file cannot leave the ones
//! before it half-imported.
//!
//! One deliberate difference from cswap. cswap stores a slot's credential and
//! its `~/.claude.json` in two files and the envelope carries both; a swapd
//! `Login` is one envelope holding the credential *plus* the `oauthAccount`
//! Claude Code advertises for it (see `driver::claude::live`). So the imported
//! `config.oauthAccount` is spliced into the login rather than stored beside
//! it — without it the slot would have no offline identity, and switching to it
//! would leave `~/.claude.json` naming the previous account. Only that member is
//! kept: the rest of a per-account `config` is dropped, so an `export` must not
//! put anything else there expecting it to survive a round trip.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use serde_json::{Map, Value};

use crate::core::slots::{self, Slot};
use crate::ctx::Ctx;
use crate::driver::{Driver, Identity, Login};
use crate::errors::{ErrorCode, Result, SwapdError};

/// What an import did.
pub struct ImportResult {
    pub imported: Vec<u32>,
    /// Slots that already held the account and whose credential the file
    /// replaced: the stored copy was provably an older generation
    /// (`driver::live_is_older`) or missing altogether. The row is rewritten
    /// from the file too, as `--force` would.
    pub refreshed: Vec<u32>,
    /// Slots that already held the account, kept their stored credential (the
    /// file's copy was not provably newer), and took the file's row metadata —
    /// alias, icon, held, preferred — because it differed. The exporter is
    /// where the user labels accounts in phase 1, and a label it changed after
    /// the first import otherwise never reached swapd.
    pub updated: Vec<u32>,
    pub skipped: Vec<Skipped>,
    /// The slot the envelope called active. Recorded for the caller, never
    /// activated: an import is not a switch, and the machine's live login is
    /// whatever it already was.
    pub active_slot: Option<u32>,
}

/// What pass 3 does with one entry.
enum Fate {
    /// A free slot: credential and row from the file.
    New,
    /// The slot's account, with a newer credential in the file: both rewritten.
    Refresh,
    /// The slot's account, credential kept: the occupant's row with the file's
    /// metadata.
    Update(Slot),
}

pub struct Skipped {
    pub slot: u32,
    pub email: String,
    pub reason: String,
}

/// One validated account, ready to write.
struct Entry {
    slot: u32,
    email: String,
    organization_uuid: String,
    organization_name: String,
    alias: Option<String>,
    icon: Option<String>,
    plan: Option<String>,
    disabled: bool,
    preferred: bool,
    added: Option<String>,
    login: Login,
}

impl Entry {
    /// Whether the file's labels and choices differ from the row's.
    fn metadata_differs(&self, slot: &Slot) -> bool {
        self.alias != slot.alias
            || self.icon != slot.icon
            || self.disabled != slot.disabled
            || self.preferred != slot.preferred
    }

    /// The account this row names, so the occupied-slot check asks the same
    /// question every other identity match in swapd asks.
    fn identity(&self) -> Identity {
        Identity {
            email: self.email.clone(),
            organization_uuid: self.organization_uuid.clone(),
            organization_name: self.organization_name.clone(),
            plan: self.plan.clone(),
            uuid: None,
        }
    }
}

pub fn run(ctx: &Ctx, provider: &dyn Driver, path: &str, force: bool) -> Result<ImportResult> {
    let id = provider.id();
    let text = read_source(path)?;
    let envelope: Value = serde_json::from_str(&text)
        .map_err(|e| invalid(format!("export file is not valid JSON: {e}")))?;
    let envelope = envelope
        .as_object()
        .ok_or_else(|| invalid("export file must be a JSON object"))?;
    check_format(envelope)?;

    let (accounts, active_slot) = accounts_for(envelope, id)?;

    // Pass 1: validate. Nothing below this point may fail on the file's
    // contents — only on the environment (disk, keychain).
    let mut entries = Vec::new();
    let mut seen: BTreeMap<u32, String> = BTreeMap::new();
    for raw in accounts {
        let entry = validate(provider, raw)?;
        if let Some(other) = seen.insert(entry.slot, entry.email.clone()) {
            return Err(invalid(format!(
                "export names slot {} twice ({other}, {})",
                entry.slot, entry.email
            )));
        }
        entries.push(entry);
    }

    // Pass 2: decide every account's fate against the table as it stands under
    // the lock, and refuse the whole import before anything is written. A
    // refusal is a fact about the file and the table, so it is knowable without
    // writing — and discovering it half way would leave the accounts before it
    // with credentials on disk that nothing refers to.
    //
    // Pass 3: write, in the same lock cycle. All the rows go in one
    // `slots::update`, so an import lands as a table rather than as N separate
    // ones.
    let slots_file = ctx.home.slots_file();
    let (imported, refreshed, updated, skipped, failure) = slots::update(&slots_file, |file| {
        let existing = file.providers.entry(id.to_string()).or_default();
        let mut skipped: Vec<Skipped> = Vec::new();
        let mut writing: Vec<(Entry, Fate)> = Vec::new();

        for entry in entries {
            let mut fate = Fate::New;
            if let Some(occupant) = existing.slots.get(&entry.slot) {
                let same = slots::same_account(&entry.identity(), occupant);
                if same {
                    // The slot already holds this account. Its credential is
                    // taken from the file when the stored copy is provably an
                    // older generation of the lineage, or is missing: the
                    // exporter (cswap, in phase 1) refreshes logins swapd
                    // never sees otherwise, and an expired stored copy would
                    // read `token-expired` until it did. A copy the file cannot
                    // prove older is left alone, so an import never writes a
                    // spent generation over its successor. `--force` rewrites
                    // regardless, as before.
                    if !force {
                        let key = crate::secrets::slot_key(id, entry.slot);
                        let stored = ctx
                            .secrets
                            .get(&key)?
                            .filter(|bytes| !bytes.trim().is_empty())
                            .map(|bytes| Login { bytes });
                        let newer = match &stored {
                            None => true,
                            Some(stored) => {
                                crate::driver::live_is_older(provider, stored, &entry.login)
                            }
                        };
                        if newer {
                            fate = Fate::Refresh;
                        } else if entry.metadata_differs(occupant) {
                            fate = Fate::Update(occupant.clone());
                        } else {
                            skipped.push(Skipped {
                                slot: entry.slot,
                                email: entry.email,
                                reason: "already-present".to_string(),
                            });
                            continue;
                        }
                    }
                } else if !force {
                    // Refused rather than reported: silently skipping would
                    // leave the user believing an account they can see in the
                    // file is importable, and overwriting it unasked would
                    // destroy a login that may exist nowhere else.
                    return Err(invalid(format!(
                        "slot {} holds {} ({}); pass --force to overwrite it",
                        entry.slot,
                        occupant.email,
                        if occupant.organization_uuid.is_empty() {
                            "personal"
                        } else {
                            &occupant.organization_uuid
                        },
                    )));
                }
            }
            writing.push((entry, fate));
        }

        let mut imported: Vec<u32> = Vec::new();
        let mut refreshed: Vec<u32> = Vec::new();
        let mut updated: Vec<u32> = Vec::new();
        let mut rows: Vec<(u32, Slot)> = Vec::new();
        let mut failure = None;
        for (entry, fate) in writing {
            if let Fate::Update(occupant) = fate {
                // The credential stays, so the row keeps the occupant's
                // fingerprint and `added`: a fingerprint taken from the file's
                // bytes would read as "credentials replaced" on the next
                // collector pass for a login that never changed.
                let mut row = occupant;
                row.alias = entry.alias;
                row.icon = entry.icon;
                row.disabled = entry.disabled;
                row.preferred = entry.preferred;
                rows.push((entry.slot, row));
                updated.push(entry.slot);
                continue;
            }
            // Secrets first, rows after: bytes without a row are unreferenced,
            // a row without bytes is a slot that cannot authenticate. A keychain
            // that fails part way therefore stops the import here and reports
            // which slots did land, rather than aborting the whole closure and
            // leaving the credentials it already wrote with nothing pointing at
            // them.
            let key = crate::secrets::slot_key(id, entry.slot);
            if let Err(e) = ctx.secrets.set(&key, &entry.login.bytes) {
                failure = Some(SwapdError::new(
                    e.code,
                    format!(
                        "slot {}'s credential could not be stored ({}); {}",
                        entry.slot,
                        e.message,
                        if imported.is_empty() {
                            "nothing was imported".to_string()
                        } else {
                            format!(
                                "already imported: {}",
                                imported
                                    .iter()
                                    .map(u32::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        }
                    ),
                ));
                break;
            }
            let meta = Slot {
                email: entry.email.clone(),
                organization_uuid: entry.organization_uuid.clone(),
                organization_name: entry.organization_name.clone(),
                plan: entry.plan.clone(),
                alias: entry.alias.clone(),
                icon: entry.icon.clone(),
                disabled: entry.disabled,
                preferred: entry.preferred,
                added: entry.added.clone(),
                fingerprint: Some(entry.login.fingerprint()),
            };
            rows.push((entry.slot, meta));
            if matches!(fate, Fate::Refresh) {
                refreshed.push(entry.slot);
            } else {
                imported.push(entry.slot);
            }
        }

        let dirty = !rows.is_empty();
        for (slot, meta) in rows {
            existing.insert(slot, meta);
        }
        Ok((dirty, (imported, refreshed, updated, skipped, failure)))
    })?;

    // Outside the lock, so the usage store's is never nested inside it: a slot
    // holding new bytes under the quarantine its previous credential earned
    // would read as "re-login needed" forever (`switcher.py:3535`).
    // The credential failure is the one that describes what went wrong and
    // names what landed, so it wins: a `clear_dead` that also failed would
    // otherwise replace it with an unrelated message about a slot that imported
    // fine. Every slot is still attempted — one quarantine that cannot be
    // lifted must not skip the rest.
    let mut quarantine = None;
    for slot in imported.iter().chain(&refreshed) {
        if let Err(e) = ctx.store.clear_dead(&crate::secrets::slot_key(id, *slot)) {
            quarantine.get_or_insert(e);
        }
    }
    if let Some(failure) = failure.or(quarantine) {
        return Err(failure);
    }

    Ok(ImportResult {
        imported,
        refreshed,
        updated,
        skipped,
        active_slot,
    })
}

/// `-` is stdin; anything else is a file.
fn read_source(path: &str) -> Result<String> {
    if path == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        return Ok(text);
    }
    let path = Path::new(path);
    std::fs::read_to_string(path)
        .map_err(|e| SwapdError::new(ErrorCode::Io, format!("{}: {e}", path.display())))
}

/// Accept swapd's own envelope and cswap's, and refuse anything else by name
/// rather than by falling through to "no accounts".
fn check_format(envelope: &Map<String, Value>) -> Result<()> {
    if envelope.get("encrypted") == Some(&Value::Bool(true)) {
        return Err(invalid(
            "encrypted exports are not supported — decrypt before piping",
        ));
    }
    match envelope.get("format").and_then(Value::as_str) {
        Some("swapd/1") => return Ok(()),
        Some(other) => return Err(invalid(format!("unsupported export format: {other}"))),
        None => {}
    }
    match envelope.get("version").and_then(Value::as_u64) {
        Some(1) => Ok(()),
        Some(other) => Err(invalid(format!("unsupported export version: {other}"))),
        None => Err(invalid(
            "not an export: expected a 'format' or 'version' member",
        )),
    }
}

/// The accounts this provider's import reads, and the slot the envelope calls
/// active.
///
/// cswap's envelope carries one flat `accounts` list, which is always Claude's;
/// swapd's own groups them per provider (spec §9), because one export covers
/// every engine the machine has. A `providers` array with no section for this
/// provider is named as such rather than reported as "no accounts": the file is
/// fine, it is simply about somebody else.
fn accounts_for<'a>(
    envelope: &'a Map<String, Value>,
    provider: &str,
) -> Result<(&'a Vec<Value>, Option<u32>)> {
    if let Some(flat) = envelope.get("accounts").and_then(Value::as_array) {
        return non_empty(flat).map(|accounts| (accounts, active_slot(envelope)));
    }
    let section = envelope
        .get("providers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("export file has no accounts to import"))?
        .iter()
        .filter_map(Value::as_object)
        .find(|p| p.get("provider").and_then(Value::as_str) == Some(provider))
        .ok_or_else(|| invalid(format!("export file carries no {provider} accounts")))?;
    let accounts = section
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("the {provider} section has no accounts")))?;
    Ok((non_empty(accounts)?, active_slot(section)))
}

fn non_empty(accounts: &Vec<Value>) -> Result<&Vec<Value>> {
    if accounts.is_empty() {
        return Err(invalid("export file has no accounts to import"));
    }
    Ok(accounts)
}

/// The envelope's active slot, under either spelling.
fn active_slot(envelope: &Map<String, Value>) -> Option<u32> {
    envelope
        .get("activeSlot")
        .or_else(|| envelope.get("activeAccountNumber"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

/// One account entry, validated whole (`_validate_imported_account`,
/// `transfer.py:59`).
fn validate(provider: &dyn Driver, raw: &Value) -> Result<Entry> {
    let account = raw
        .as_object()
        .ok_or_else(|| invalid("account entry must be a JSON object"))?;

    let email = account
        .get("email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|e| valid_email(e))
        .ok_or_else(|| invalid("invalid or missing email in imported account"))?
        .to_string();

    let slot = account
        .get("number")
        .or_else(|| account.get("slot"))
        .and_then(Value::as_u64)
        .filter(|n| *n >= 1)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| invalid(format!("invalid or missing slot number for {email}")))?;

    let text = |key: &str| -> Result<String> {
        match account.get(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(invalid(format!("{key} for {email} must be a string"))),
        }
    };
    let organization_uuid = text("organizationUuid")?;
    let organization_name = text("organizationName")?;
    let added = Some(text("added")?).filter(|s| !s.is_empty());
    let alias = Some(text("alias")?)
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty());
    // The user's own labels and choices, carried whole: an export that
    // remembers a pinned, held or renamed account and an import that quietly
    // dropped it would leave the two machines describing different rotations.
    // Absent (cswap's envelope has none of these) is the row's default.
    let icon = Some(text("icon")?)
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty());
    let plan = Some(text("plan")?).filter(|p| !p.is_empty());
    let flag = |key: &str| -> Result<bool> {
        match account.get(key) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(invalid(format!("{key} for {email} must be true or false"))),
        }
    };
    let disabled = flag("disabled")?;
    let preferred = flag("preferred")?;

    let login = login_of(provider, account, &email)?;
    Ok(Entry {
        slot,
        email,
        organization_uuid,
        organization_name,
        alias,
        icon,
        plan,
        disabled,
        preferred,
        added,
        login,
    })
}

/// The account's credential as a swapd `Login`: a raw `sk-ant-api…` string for
/// a managed key, else the credential object with the export's
/// `config.oauthAccount` spliced in (see the module docs).
fn login_of(provider: &dyn Driver, account: &Map<String, Value>, email: &str) -> Result<Login> {
    match account.get("credentials") {
        Some(Value::String(key)) => {
            let login = Login {
                bytes: key.trim().to_string(),
            };
            // The driver's own predicate: a string credential is only ever a
            // managed key, and what one looks like is the engine's business.
            if !provider.is_api_key(&login) {
                return Err(invalid(format!(
                    "string credentials for {email} must be a raw managed API key"
                )));
            }
            Ok(login)
        }
        Some(Value::Object(credentials)) => {
            let mut credentials = credentials.clone();
            if let Some(oauth_account) = account
                .get("config")
                .and_then(Value::as_object)
                .and_then(|config| config.get("oauthAccount"))
                .filter(|value| value.is_object())
            {
                credentials.insert("oauthAccount".to_string(), oauth_account.clone());
            }
            Ok(Login {
                bytes: Value::Object(credentials).to_string(),
            })
        }
        _ => Err(invalid(format!(
            "credentials for {email} must be a JSON object or a raw API key"
        ))),
    }
}

/// cswap's own bar (`_validate_email`): enough structure that the value cannot
/// be a path fragment or a display string, and no more — the address is a
/// label here, never something swapd sends mail to.
pub fn valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.contains(['/', '\\', ' ', ':'])
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cswap_and_swapd_envelopes_are_both_accepted() {
        let cswap = json!({"version": 1, "accounts": []});
        check_format(cswap.as_object().unwrap()).unwrap();
        let swapd = json!({"format": "swapd/1", "accounts": []});
        check_format(swapd.as_object().unwrap()).unwrap();

        let err = check_format(json!({"version": 2}).as_object().unwrap()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        let err = check_format(json!({"nothing": true}).as_object().unwrap()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn a_providers_envelope_is_read_per_provider() {
        // swapd's own export groups accounts per provider; the flat cswap list
        // is always Claude's.
        let mine = json!({
            "format": "swapd/1",
            "providers": [{"provider": "claude", "activeSlot": 2, "accounts": [{"slot": 2}]}],
        });
        let (accounts, active) = accounts_for(mine.as_object().unwrap(), "claude").unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(active, Some(2));

        let theirs = json!({
            "format": "swapd/1",
            "providers": [{"provider": "codex", "accounts": [{"slot": 1}]}],
        });
        let err = accounts_for(theirs.as_object().unwrap(), "claude").unwrap_err();
        assert!(
            err.message.contains("no claude accounts"),
            "{}",
            err.message
        );

        let cswap = json!({"version": 1, "activeAccountNumber": 3, "accounts": [{"slot": 3}]});
        let (accounts, active) = accounts_for(cswap.as_object().unwrap(), "claude").unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(active, Some(3));
    }

    #[test]
    fn encrypted_exports_are_refused() {
        let envelope = json!({"version": 1, "encrypted": true, "accounts": []});
        let err = check_format(envelope.as_object().unwrap()).unwrap_err();
        assert!(err.message.contains("encrypted"), "{}", err.message);
    }

    /// An `Env` with no variables: these tests only need a driver that can
    /// parse a credential, and reading the process environment would let a
    /// developer's `SWAPD_LIVE_STORE` change what they exercise.
    fn test_env() -> crate::driver::Env {
        crate::driver::Env {
            home: std::path::PathBuf::new(),
            vars: Default::default(),
        }
    }

    #[test]
    fn the_config_oauth_account_travels_into_the_login() {
        let account = json!({
            "number": 1,
            "email": "one@example.com",
            "credentials": {"claudeAiOauth": {"refreshToken": "rt-1"}},
            "config": {"oauthAccount": {"emailAddress": "one@example.com"}},
        });
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform(&test_env());
        let entry = validate(&driver, &account).unwrap();
        let value: Value = serde_json::from_str(&entry.login.bytes).unwrap();
        assert_eq!(value["oauthAccount"]["emailAddress"], "one@example.com");
        assert_eq!(value["claudeAiOauth"]["refreshToken"], "rt-1");
    }

    /// A `Ctx` over a temp home, an in-memory secret store and a fixed clock.
    fn ctx_for(dir: &std::path::Path) -> Ctx {
        let home = crate::paths::Home {
            root: dir.to_path_buf(),
        };
        home.ensure().unwrap();
        let store = crate::core::usage_store::UsageStore::new(&home.usage_file());
        Ctx {
            env: test_env(),
            home,
            secrets: Box::new(crate::secrets::MemorySecrets::new()),
            clock: Box::new(|| 1_757_000_000.0),
            settings: Default::default(),
            store,
        }
    }

    /// A cswap export naming one account in slot 1, whose access token
    /// expires at `expires_at` (ms); the refresh token — the lineage — is the
    /// same across generations, as a Claude refresh keeps it.
    fn export_with(dir: &std::path::Path, expires_at: i64) -> String {
        let path = dir.join(format!("export-{expires_at}.json"));
        let envelope = json!({
            "version": 1,
            "accounts": [{
                "number": 1,
                "email": "one@example.com",
                "credentials": {"claudeAiOauth": {
                    "accessToken": format!("at-{expires_at}"),
                    "refreshToken": "rt-1",
                    "expiresAt": expires_at,
                }},
            }],
        });
        std::fs::write(&path, envelope.to_string()).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn stored_expiry(ctx: &Ctx) -> Option<i64> {
        let bytes = ctx
            .secrets
            .get(&crate::secrets::slot_key("claude", 1))
            .unwrap()?;
        let value: Value = serde_json::from_str(&bytes).unwrap();
        value["claudeAiOauth"]["expiresAt"].as_i64()
    }

    #[test]
    fn an_already_present_account_takes_the_files_newer_generation_only() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform(&test_env());

        // First import: the slot is new.
        let first = run(&ctx, &driver, &export_with(dir.path(), 2_000), false).unwrap();
        assert_eq!((first.imported, first.refreshed), (vec![1], vec![]));
        assert_eq!(stored_expiry(&ctx), Some(2_000));

        // The same file again: nothing newer, so nothing written.
        let again = run(&ctx, &driver, &export_with(dir.path(), 2_000), false).unwrap();
        assert!(again.imported.is_empty() && again.refreshed.is_empty());
        assert_eq!(again.skipped.len(), 1);
        assert_eq!(again.skipped[0].reason, "already-present");

        // An older generation is never written over the stored one.
        let older = run(&ctx, &driver, &export_with(dir.path(), 1_000), false).unwrap();
        assert!(
            older.refreshed.is_empty(),
            "a spent generation must not replace its successor"
        );
        assert_eq!(stored_expiry(&ctx), Some(2_000));

        // The exporter's rotation: a provably newer copy replaces the stored one.
        let newer = run(&ctx, &driver, &export_with(dir.path(), 3_000), false).unwrap();
        assert_eq!((newer.imported, newer.refreshed), (vec![], vec![1]));
        assert!(newer.skipped.is_empty());
        assert_eq!(stored_expiry(&ctx), Some(3_000));

        // A row whose credential is gone takes the file's copy whatever its age.
        ctx.secrets
            .set(&crate::secrets::slot_key("claude", 1), "")
            .unwrap();
        let restored = run(&ctx, &driver, &export_with(dir.path(), 1_000), false).unwrap();
        assert_eq!(restored.refreshed, vec![1]);
        assert_eq!(stored_expiry(&ctx), Some(1_000));
    }

    #[test]
    fn an_already_present_account_takes_the_files_labels_and_keeps_its_credential() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform(&test_env());
        let export = |alias: &str, preferred: bool| {
            let path = dir.path().join(format!("export-{alias}-{preferred}.json"));
            let envelope = json!({
                "version": 1,
                "accounts": [{
                    "number": 1,
                    "email": "one@example.com",
                    "alias": alias,
                    "preferred": preferred,
                    "credentials": {"claudeAiOauth": {
                        "accessToken": "at-2000",
                        "refreshToken": "rt-1",
                        "expiresAt": 2_000,
                    }},
                }],
            });
            std::fs::write(&path, envelope.to_string()).unwrap();
            path.to_string_lossy().into_owned()
        };
        let row = |ctx: &Ctx| slots::load(&ctx.home, "claude").unwrap().slots[&1].clone();

        run(&ctx, &driver, &export("", false), false).unwrap();
        let before = row(&ctx);
        assert_eq!(before.alias, None);

        // The exporter renamed and pinned the account since: same generation,
        // so the credential stays, but the row follows the file.
        let out = run(&ctx, &driver, &export("hiep", true), false).unwrap();
        assert_eq!(
            (out.imported, out.refreshed, out.updated),
            (vec![], vec![], vec![1])
        );
        assert!(out.skipped.is_empty());
        let after = row(&ctx);
        assert_eq!(after.alias.as_deref(), Some("hiep"));
        assert!(after.preferred);
        assert_eq!(
            after.fingerprint, before.fingerprint,
            "the credential never changed"
        );
        assert_eq!(after.added, before.added);
        assert_eq!(stored_expiry(&ctx), Some(2_000));

        // The same file again is a no-op.
        let again = run(&ctx, &driver, &export("hiep", true), false).unwrap();
        assert!(again.updated.is_empty());
        assert_eq!(again.skipped[0].reason, "already-present");
    }

    #[test]
    fn a_string_credential_must_be_an_api_key() {
        let account = json!({
            "number": 1,
            "email": "one@example.com",
            "credentials": "not-a-key",
        });
        // Not `unwrap_err`: `Entry` deliberately has no `Debug`, so a
        // credential can never reach a panic message.
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform(&test_env());
        match validate(&driver, &account) {
            Err(e) => assert_eq!(e.code, ErrorCode::InvalidInput),
            Ok(_) => panic!("a non-key string credential must be refused"),
        }
    }

    #[test]
    fn email_validation_rejects_path_fragments() {
        assert!(valid_email("one@example.com"));
        assert!(!valid_email("../escape@example.com"));
        assert!(!valid_email("no-at-sign"));
        assert!(!valid_email("two@@example.com"));
        assert!(!valid_email("one@localhost"));
    }
}
