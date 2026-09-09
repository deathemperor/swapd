//! `swapd remove <ident> --yes` — forget an account.
//!
//! The only way an account leaves a slot (`add --slot n` refuses to migrate
//! one), and the deletion is unrecoverable when the credential lives nowhere
//! else: `--yes` is the confirmation, and the active slot is refused outright
//! so a `remove` can never leave the machine logged into an account swapd no
//! longer knows.

use serde::Serialize;

use crate::core::slots;
use crate::core::switch::resolve;
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;
use crate::secrets::slot_key;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveOutput {
    pub schema_version: u32,
    pub ok: bool,
    pub slot: u32,
    pub email: String,
}

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str, yes: bool) -> Result<RemoveOutput> {
    let id = driver.id();
    if !yes {
        return Err(invalid(
            "removing an account deletes its stored login; pass --yes to confirm",
        ));
    }
    // The row goes first, under the lock. Bytes without a row are merely
    // unreferenced, while a row whose credential has been deleted is a slot
    // that cannot authenticate — so the order that survives a failure halfway
    // is row, then secret, then profile.
    let (slot, email) = slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry(id.to_string()).or_default();
        let target = resolve(provider, id, ident)?;
        if provider.active_slot == Some(target) {
            return Err(invalid(format!(
                "slot {target} is the live login; switch away first"
            )));
        }
        let email = provider
            .slots
            .get(&target)
            .expect("resolve named a slot in this table")
            .email
            .clone();
        provider.remove(target);
        Ok((true, (target, email)))
    })?;

    ctx.secrets.delete(&slot_key(id, slot))?;
    // The slot's run profile holds a copy of the credential (and whatever
    // Claude Code wrote beside it), so forgetting the account has to take the
    // profile with it. Already gone is fine.
    let profile = ctx.home.profiles_dir().join(id).join(slot.to_string());
    match std::fs::remove_dir_all(&profile) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(SwapdError::new(
                ErrorCode::Io,
                format!("{}: {e}", profile.display()),
            ))
        }
    }

    // The usage row is left: rows are identity-guarded (`UsageStore::entries`
    // matches email and org), so a slot number reused by another account never
    // serves the removed one's numbers.
    Ok(RemoveOutput {
        schema_version: output::SCHEMA_VERSION,
        ok: true,
        slot,
        email,
    })
}

pub fn print_human(out: &RemoveOutput) {
    println!("removed slot {} ({})", out.slot, out.email);
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}
