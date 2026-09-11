//! `swapd remove <ident> --yes` — forget an account.
//!
//! The only way an account leaves a slot (`add --slot n` refuses to migrate
//! one), and the deletion is unrecoverable when the credential lives nowhere
//! else: `--yes` is the confirmation, and the active slot is refused outright
//! so a `remove` can never leave the machine logged into an account swapd no
//! longer knows.
//!
//! Row, credential and run profile all go inside one `slots.json` lock cycle,
//! so a slot number cannot be handed to a new account (`add`) between freeing
//! the row and deleting what it pointed at.
//!
//! The slots above the removed one then move down to close the gap
//! (`core::compact`, deathemperor/swapd#22): "slots numbers must always
//! sequential when an account is removed." A slot with a live session cannot
//! move and stops the renumber there; the output says so and names `compact`.

use serde::Serialize;

use crate::core::compact::{self, Compacted};
use crate::core::settings;
use crate::core::slots::{self, LOCK_TIMEOUT};
use crate::core::store::FileLock;
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
    #[serde(flatten)]
    pub compacted: Compacted,
}

pub fn run(ctx: &Ctx, driver: &dyn Driver, ident: &str, yes: bool) -> Result<RemoveOutput> {
    let id = driver.id();
    if !yes {
        return Err(invalid(
            "removing an account deletes its stored login; pass --yes to confirm",
        ));
    }
    // Everything in ONE `slots::update` cycle, so the whole removal is fenced
    // by `slots.json`'s lock. Deleting the credential after the lock is
    // released is a check-then-act: a concurrent `add` whose `next_free()`
    // returns the slot just freed writes the NEW account's credential under
    // the lock, and the trailing delete then erases it, leaving a row that
    // cannot authenticate — exactly the state `slots::claim` writes the secret
    // inside the lock to prevent.
    //
    // A delete that fails therefore aborts the removal: the closure returns
    // `Err`, nothing is written, and the row still points at the credential
    // that is still there.
    let (slot, email, compacted) = slots::update(&ctx.home.slots_file(), |file| {
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
        // Under the slot's refresh lock: a refresh in flight would otherwise
        // persist its successor token under the key being deleted. Released
        // before the renumber, which fences every key it touches itself.
        {
            let _refresh =
                FileLock::acquire(&ctx.home.refresh_lock_base(id, target), LOCK_TIMEOUT)?;
            ctx.secrets.delete(&slot_key(id, target))?;
        }
        // A profile is not only its directory: the CLI may have migrated the
        // seeded credential into a keychain item named after the profile's
        // config dir, which `remove_dir_all` would never touch — leaving a live
        // login behind for an account swapd has forgotten. Only the driver
        // knows that item exists, so it is the driver that deletes it, and
        // first: a failure here aborts the removal like any other, rather than
        // orphaning the item under a slot that no longer names it.
        driver.forget_profile(&ctx.env, target)?;
        // The slot's run profile holds a copy of the credential (and whatever
        // Claude Code wrote beside it), so forgetting the account has to take
        // the profile with it. Already gone is fine.
        let profile = ctx.home.profiles_dir().join(id).join(target.to_string());
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
        // A pin by number named this account; after the renumber the number
        // would name whoever moved into it. The account is gone either way,
        // so a rewrite that fails is a warning.
        if let Err(e) = settings::renumber_preferred(&ctx.home, id, |n| (n != target).then_some(n))
        {
            eprintln!(
                "warning: autoswitch.preferred still names slot {target}: {}",
                e.message
            );
        }
        let compacted = compact::compact(ctx, driver, provider)?;
        Ok((true, (target, email, compacted)))
    })?;

    // The usage row is left: rows are identity-guarded (`UsageStore::entries`
    // matches email and org), so a slot number reused by another account never
    // serves the removed one's numbers.
    Ok(RemoveOutput {
        schema_version: output::SCHEMA_VERSION,
        ok: true,
        slot,
        email,
        compacted,
    })
}

pub fn print_human(out: &RemoveOutput) {
    println!("removed slot {} ({})", out.slot, out.email);
    for m in &out.compacted.moves {
        println!("slot {} is now slot {}", m.from, m.to);
    }
    if let Some(stop) = &out.compacted.stopped_at {
        println!("{}", compact::stopped_note(stop));
    }
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}
