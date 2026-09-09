//! `swapd export <path|-> [--slot n] [--full]` — the swapd envelope.
//!
//! Port of cswap's `export_accounts` (`transfer.py:164`) onto spec §9's shape:
//! `{"format":"swapd/1","exportedAt",…,"providers":[{provider, activeSlot,
//! accounts:[…]}]}`, which `import` reads back (`core::import`).
//!
//! Two rules carried over from cswap. The ACTIVE slot's credential is read
//! from the live login rather than from the store: the CLI refreshes in place,
//! so the live copy is the newest generation of that token family and the
//! stored one may already be spent. And a slot whose credential cannot be
//! found is skipped with a warning when the export covers everything — one
//! damaged slot must not poison a whole backup — but is an error when the user
//! named it with `--slot`.
//!
//! What lands in `credentials` is the login exactly as swapd stores it: an
//! object for an OAuth blob (with the `oauthAccount` swapd splices in, which
//! is what gives an imported slot an offline identity) and the raw key string
//! for a managed API key. `--full` adds the `~/.claude.json` snapshot as
//! `config`, for the active slot only — it is the only account whose config
//! this machine has.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::core::slots::{self, Slot};
use crate::core::store::{write_json_atomic, FileLock};
use crate::ctx::Ctx;
use crate::driver::{Driver, DriverError, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;
use crate::secrets::slot_key;

pub struct ExportOpts {
    /// Export this slot alone. A slot it cannot read is an error rather than a
    /// warning: the user named it.
    pub slot: Option<u32>,
    /// Same-machine backup: also carry the `~/.claude.json` snapshot.
    pub full: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOutput {
    pub schema_version: u32,
    pub path: String,
    pub accounts: usize,
    pub warnings: Vec<String>,
}

/// Write the envelope. `Ok(None)` means it went to stdout and IS the output,
/// so the caller has nothing left to print.
pub fn run(
    ctx: &Ctx,
    driver: &dyn Driver,
    destination: &str,
    opts: &ExportOpts,
) -> Result<Option<ExportOutput>> {
    let id = driver.id();
    let table = slots::load(&ctx.home, id)?;
    if table.slots.is_empty() {
        return Err(invalid(format!("no {id} accounts to export")));
    }
    let targets: Vec<u32> = match opts.slot {
        Some(slot) => {
            if !table.slots.contains_key(&slot) {
                return Err(SwapdError::new(
                    ErrorCode::NoSuchSlot,
                    format!("no slot {slot} for {id}"),
                ));
            }
            vec![slot]
        }
        // The rotation order, so an export reads the way `list` does.
        None => table
            .order
            .iter()
            .copied()
            .filter(|n| table.slots.contains_key(n))
            .chain(
                table
                    .slots
                    .keys()
                    .copied()
                    .filter(|n| !table.order.contains(n)),
            )
            .collect(),
    };

    let mut warnings: Vec<String> = Vec::new();
    let mut accounts: Vec<Value> = Vec::new();
    for slot in targets {
        let meta = table.slots.get(&slot).expect("named above");
        let active = table.active_slot == Some(slot);
        let (login, from_live) = match credential(ctx, driver, slot, meta, active, &mut warnings)? {
            Some(pair) => pair,
            None => {
                let reason = format!("slot {slot} ({}) has no stored login", meta.email);
                // The slot exists — `list` reports it as `no-credentials` — so
                // it is `invalid-input`, never `no-such-slot`: that answer is
                // reserved for a slot number that is not in the table at all,
                // and conflating the two tells the user to look for the wrong
                // problem.
                if opts.slot.is_some() {
                    return Err(invalid(format!("{reason}; nothing to export")));
                }
                warnings.push(format!("{reason}; skipped"));
                continue;
            }
        };
        let mut entry = entry(driver, slot, meta, &login)?;
        // Only for a credential that actually came from the live login: the
        // config on this machine describes whoever is logged in right now, and
        // pairing it with a credential read from the store would file one
        // account's identity beside another's token (import splices
        // `config.oauthAccount` into the login).
        if opts.full && from_live {
            match driver.live_config_text(&ctx.env) {
                Ok(Some(text)) => match serde_json::from_str::<Value>(&text) {
                    Ok(config) => {
                        entry.insert("config".to_string(), config);
                    }
                    Err(e) => warnings.push(format!("slot {slot}'s config is not JSON ({e})")),
                },
                Ok(None) => warnings.push(format!("slot {slot} has no config to export")),
                Err(e) => warnings.push(format!("slot {slot}'s config could not be read ({e})")),
            }
        }
        accounts.push(Value::Object(entry));
    }
    if accounts.is_empty() {
        return Err(invalid(format!(
            "no exportable {id} accounts — every slot is missing its stored login"
        )));
    }

    // Only when the active slot is actually in the payload: an envelope naming
    // an account it does not carry is one `import` would report as active and
    // never have (`transfer.py:285`).
    let exported: Vec<u32> = accounts
        .iter()
        .filter_map(|a| a.get("slot").and_then(Value::as_u64))
        .map(|n| n as u32)
        .collect();
    let active_slot = table.active_slot.filter(|n| exported.contains(n));

    let envelope = json!({
        "format": "swapd/1",
        "exportedAt": crate::driver::claude::usage::format_ts(ctx.now()),
        "providers": [{
            "provider": id,
            "activeSlot": active_slot,
            "accounts": accounts,
        }],
    });

    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    if destination == "-" {
        output::emit_json(&envelope);
        return Ok(None);
    }
    let path = PathBuf::from(destination);
    // 0600 and atomic, like every other file swapd writes that holds a login.
    write_json_atomic(&path, &envelope)?;
    Ok(Some(ExportOutput {
        schema_version: output::SCHEMA_VERSION,
        path: path.to_string_lossy().into_owned(),
        accounts: exported.len(),
        warnings,
    }))
}

/// The credential to export for one slot, and whether it came from the live
/// login (which is what decides `--full`'s config snapshot).
///
/// The active slot's comes from the live login (`transfer.py:222`) — the CLI
/// refreshes in place, so that copy is the newest generation. When the live
/// login turns out to belong to somebody else (the user ran `/login` behind
/// swapd's back), the stored copy is used instead and the mismatch is
/// reported: exporting the live bytes under this slot's name would file one
/// account's credential under another's address.
fn credential(
    ctx: &Ctx,
    driver: &dyn Driver,
    slot: u32,
    meta: &Slot,
    active: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<(Login, bool)>> {
    if active {
        // Under the same fence a switch takes: an unfenced read can pair one
        // account's credential with another's identity mid-swap, and an export
        // is a file the user restores from. A switch in flight is not a reason
        // to fail the backup — the stored copy is exported instead.
        match live_under_lock(ctx, driver) {
            Ok(live) => {
                if is_same_account(driver, &live, meta) {
                    return Ok(Some((live, true)));
                }
                warnings.push(format!(
                    "the live login is not slot {slot} ({}) any more; exporting the stored copy",
                    meta.email
                ));
            }
            // cswap fails the whole export here (`transfer.py:222`); swapd
            // falls back, because one unreadable live store must not cost the
            // user a backup of the credentials it still holds.
            Err(e) => warnings.push(format!(
                "slot {slot}'s live login could not be read ({e}); exporting the stored copy"
            )),
        }
    }
    Ok(ctx
        .secrets
        .get(&slot_key(driver.id(), slot))?
        .map(|bytes| (Login { bytes }, false)))
}

/// The live login, read while `engine.lock` is held.
fn live_under_lock(ctx: &Ctx, driver: &dyn Driver) -> std::result::Result<Login, DriverError> {
    let _engine = FileLock::acquire(&ctx.home.engine_lock_base(), slots::LOCK_TIMEOUT)
        .map_err(|e| DriverError::Locked(e.message))?;
    driver.read_live(&ctx.env)
}

/// Whether a login is the account a slot claims to hold — its own identity
/// when the credential carries one, else the fingerprint the slot recorded.
fn is_same_account(driver: &dyn Driver, login: &Login, meta: &Slot) -> bool {
    if let Some(identity) = driver.identity_offline(login) {
        return identity.email.to_lowercase() == meta.email.to_lowercase()
            && identity.organization_uuid == meta.organization_uuid;
    }
    meta.fingerprint.as_deref() == Some(login.fingerprint().as_str())
}

/// One account entry, in spec §9's shape.
fn entry(driver: &dyn Driver, slot: u32, meta: &Slot, login: &Login) -> Result<Map<String, Value>> {
    let credentials = if driver.is_api_key(login) {
        Value::String(login.bytes.trim().to_string())
    } else {
        match serde_json::from_str::<Value>(&login.bytes) {
            Ok(value @ Value::Object(_)) => value,
            _ => {
                return Err(invalid(format!(
                    "slot {slot} ({})'s stored login is neither a JSON object nor a managed key",
                    meta.email
                )))
            }
        }
    };
    let mut entry = Map::new();
    entry.insert("slot".to_string(), json!(slot));
    entry.insert("email".to_string(), json!(meta.email));
    entry.insert(
        "organizationUuid".to_string(),
        json!(meta.organization_uuid),
    );
    entry.insert(
        "organizationName".to_string(),
        json!(meta.organization_name),
    );
    entry.insert("plan".to_string(), json!(meta.plan));
    entry.insert("alias".to_string(), json!(meta.alias));
    entry.insert("icon".to_string(), json!(meta.icon));
    entry.insert("disabled".to_string(), json!(meta.disabled));
    entry.insert("preferred".to_string(), json!(meta.preferred));
    entry.insert("added".to_string(), json!(meta.added));
    entry.insert("credentials".to_string(), credentials);
    Ok(entry)
}

pub fn print_human(out: &ExportOutput) {
    println!("exported {} account(s) to {}", out.accounts, out.path);
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}
