//! Reading an export back in.
//!
//! Port of cswap `import_accounts` (`transfer.py:316`), plus swapd's own
//! envelope (`{"format":"swapd/1"}`, which Task 11's `export` writes). Both
//! carry the same per-account shape, so one reader serves them.
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
use crate::driver::{Driver, Login};
use crate::errors::{ErrorCode, Result, SwapdError};

/// What an import did.
pub struct ImportResult {
    pub imported: Vec<u32>,
    pub skipped: Vec<Skipped>,
    /// The slot the envelope called active. Recorded for the caller, never
    /// activated: an import is not a switch, and the machine's live login is
    /// whatever it already was.
    pub active_slot: Option<u32>,
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
    added: Option<String>,
    login: Login,
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

    let accounts = envelope
        .get("accounts")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty())
        .ok_or_else(|| invalid("export file has no accounts to import"))?;

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
    let (imported, skipped, failure) = slots::update(&ctx.home.slots_file(), |file| {
        let existing = file.providers.entry(id.to_string()).or_default();
        let mut skipped: Vec<Skipped> = Vec::new();
        let mut writing: Vec<Entry> = Vec::new();

        for entry in entries {
            if let Some(occupant) = existing.slots.get(&entry.slot) {
                let same = occupant.email.to_lowercase() == entry.email.to_lowercase()
                    && occupant.organization_uuid == entry.organization_uuid;
                if same {
                    // Nothing to decide: the slot already holds this account.
                    // `--force` still rewrites it, which is how a fresher
                    // credential for an account you already have gets in.
                    if !force {
                        skipped.push(Skipped {
                            slot: entry.slot,
                            email: entry.email,
                            reason: "already-present".to_string(),
                        });
                        continue;
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
            writing.push(entry);
        }

        let mut imported: Vec<u32> = Vec::new();
        let mut rows: Vec<(u32, Slot)> = Vec::new();
        let mut failure = None;
        for entry in writing {
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
                plan: None,
                alias: entry.alias.clone(),
                icon: None,
                disabled: false,
                preferred: false,
                added: entry.added.clone(),
                fingerprint: Some(entry.login.fingerprint()),
            };
            rows.push((entry.slot, meta));
            imported.push(entry.slot);
        }

        let dirty = !rows.is_empty();
        for (slot, meta) in rows {
            existing.insert(slot, meta);
        }
        Ok((dirty, (imported, skipped, failure)))
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
    for slot in &imported {
        if let Err(e) = ctx.store.clear_dead(&crate::secrets::slot_key(id, *slot)) {
            quarantine.get_or_insert(e);
        }
    }
    if let Some(failure) = failure.or(quarantine) {
        return Err(failure);
    }

    Ok(ImportResult {
        imported,
        skipped,
        active_slot: active_slot(envelope),
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

    let login = login_of(provider, account, &email)?;
    Ok(Entry {
        slot,
        email,
        organization_uuid,
        organization_name,
        alias,
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
    fn encrypted_exports_are_refused() {
        let envelope = json!({"version": 1, "encrypted": true, "accounts": []});
        let err = check_format(envelope.as_object().unwrap()).unwrap_err();
        assert!(err.message.contains("encrypted"), "{}", err.message);
    }

    #[test]
    fn the_config_oauth_account_travels_into_the_login() {
        let account = json!({
            "number": 1,
            "email": "one@example.com",
            "credentials": {"claudeAiOauth": {"refreshToken": "rt-1"}},
            "config": {"oauthAccount": {"emailAddress": "one@example.com"}},
        });
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform();
        let entry = validate(&driver, &account).unwrap();
        let value: Value = serde_json::from_str(&entry.login.bytes).unwrap();
        assert_eq!(value["oauthAccount"]["emailAddress"], "one@example.com");
        assert_eq!(value["claudeAiOauth"]["refreshToken"], "rt-1");
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
        let driver = crate::driver::claude::live::ClaudeDriver::default_for_platform();
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
