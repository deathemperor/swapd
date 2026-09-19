//! The verbs. Each `run` returns the payload its `--json` form emits, so the
//! human renderer and the machine one describe exactly the same pass.

pub mod add;
pub mod add_oauth;
pub mod add_token;
pub mod alias;
pub mod auto;
pub mod auto_ignite;
pub mod compact;
pub mod config;
pub mod export;
pub mod history;
pub mod hold;
pub mod icon;
pub mod ignite;
pub mod import;
pub mod limit_hit;
pub mod list;
pub mod notify;
pub mod prefer;
pub mod refresh;
pub mod remove;
pub mod reorder;
pub mod rotate;
pub mod run;
pub mod switch;
pub mod unclaimed;

use std::time::Duration;

use crate::contract::ListPayload;
use crate::core::collect::{collect, record_slot_fingerprint, CollectOpts};
use crate::core::refresh::{refresh_slot, Refreshed};
use crate::core::slots::{self, ProviderSlots};
use crate::ctx::Ctx;
use crate::driver::{Driver, DriverError, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;
use crate::secrets::slot_key;

/// Edit one provider's slot table under `slots.json`'s lock, then report the
/// same payload `list` does — every slots.json editor (`alias`, `icon`,
/// `prefer`, `hold`, `unhold`, `reorder`) is this plus its own `mutate`.
///
/// `<ident>` is resolved *inside* `mutate`, against the table as it stands
/// under the lock: resolving outside and writing inside is a check-then-act a
/// concurrent `remove` or `reorder` invalidates. `mutate` answers `false` when
/// it changed nothing, which skips the write.
pub fn edit_slots(
    ctx: &Ctx,
    driver: &dyn Driver,
    mutate: impl FnOnce(&mut ProviderSlots) -> Result<bool>,
) -> Result<ListPayload> {
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry(driver.id().to_string()).or_default();
        Ok((mutate(provider)?, ()))
    })?;
    // The board `list` renders, served from the store: a flag flip fetches no
    // usage (the numbers did not change) and waits only `list`'s short beat for
    // `engine.lock`, so a daemon tick in flight degrades the reply instead of
    // stalling it — one press took 11 s and outlived the app's 10 s budget
    // (infinitus #1481).
    let view = collect(
        ctx,
        driver,
        &CollectOpts {
            only: Some(Vec::new()),
            lock_wait: Duration::from_secs(1),
            ..CollectOpts::default()
        },
    )?;
    Ok(ListPayload {
        schema_version: output::SCHEMA_VERSION,
        providers: vec![view],
    })
}

/// Slot `slot`'s stored login, ready to hand to a run of the provider's CLI
/// (`ignite`, `run`).
///
/// An access token that has already expired is refreshed here, and the rotation
/// persisted, because a driver never refreshes on its own: a Claude refresh
/// token is single-use, so a refresh whose result nobody stores burns the
/// lineage. A rejected refresh token is fatal to the run — the CLI would come
/// up logged out, and letting it try would spend the account's last generation
/// to learn what the error already said.
pub fn login_to_run(ctx: &Ctx, driver: &dyn Driver, slot: u32) -> Result<Login> {
    let id = driver.id();
    let login = ctx
        .secrets
        .get(&slot_key(id, slot))?
        .filter(|bytes| !bytes.trim().is_empty())
        .map(|bytes| Login { bytes })
        .ok_or_else(|| {
            SwapdError::new(
                ErrorCode::NoSuchSlot,
                format!("slot {slot} has no stored login; log in and run `swapd add`"),
            )
        })?;
    // The stated expiry, without `switch`'s buffer: a run refreshes its own
    // token when it needs to, and pre-empting that would rotate the lineage on
    // every invocation.
    if !driver
        .expires_at(&login)
        .is_some_and(|expires_at| expires_at < ctx.now())
    {
        return Ok(login);
    }
    // Under the slot's refresh lock: a `run` and a collector pass that both
    // find the same expired login would otherwise POST the same single-use
    // token, and the loser would read its own `invalid_grant` as a dead account.
    match refresh_slot(ctx, driver, slot, &login)? {
        // Another refresher spent this generation first; its successor is the
        // login to run with.
        Refreshed::Rotated(refreshed) | Refreshed::Adopted(refreshed) => Ok(refreshed),
        Refreshed::Failed(DriverError::TokenDead) => Err(SwapdError::new(
            ErrorCode::TokenDead,
            format!(
                "slot {slot}'s login is expired and its refresh token was rejected; \
                 log in again and run `swapd add`"
            ),
        )),
        Refreshed::Failed(e) => Err(e.into()),
    }
}

/// Store a login in its slot: the bytes first, then the fingerprint the board
/// and the dead-token quarantine key on.
///
/// The bytes lead because a row pointing at a credential that never landed is a
/// slot that cannot authenticate, while a stale fingerprint only mis-labels one.
/// No `clear_dead`: a quarantine is recorded against the fingerprint it was
/// earned by, and `collect::prepare` lifts the strikes a slot's current
/// credential does not answer for. Do not read that as `Entry::token_dead`
/// lifting it on its own — the fetch gate reads the strike COUNT, so until
/// `prepare` clears the row nothing fetches it (#42).
pub fn persist_login(ctx: &Ctx, provider: &str, slot: u32, login: &Login) -> Result<()> {
    ctx.secrets.set(&slot_key(provider, slot), &login.bytes)?;
    record_slot_fingerprint(ctx, provider, slot, Some(&login.fingerprint()))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::core::collect::tests::{login_for, one_slot, FakeDriver};
    use crate::core::store::FileLock;

    fn flip(ctx: &Ctx, driver: &FakeDriver) -> ListPayload {
        edit_slots(ctx, driver, |slots| {
            let slot = slots.slots.get_mut(&1).unwrap();
            slot.auto_ignite = !slot.auto_ignite;
            Ok(true)
        })
        .unwrap()
    }

    /// A flag flip answers with the stored board: no usage fetch, however
    /// stale the store is.
    #[test]
    fn an_edit_serves_the_board_from_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1")).usable("rt-1");
        let reply = flip(&ctx, &driver);
        assert!(reply.providers[0].accounts[0].auto_ignite);
        assert_eq!(*driver.usages.lock().unwrap(), 0, "an edit fetches nothing");
    }

    /// With `engine.lock` held (a switch or the daemon's tick) the edit still
    /// lands and answers within about a second, degraded like `list`, instead
    /// of waiting the writers' full timeout.
    #[test]
    fn an_edit_under_a_held_engine_lock_answers_within_a_beat() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1")).usable("rt-1");
        let _held =
            FileLock::acquire(&ctx.home.engine_lock_base(), Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        let reply = flip(&ctx, &driver);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "waited {:?}",
            started.elapsed()
        );
        assert!(
            reply.providers[0].accounts[0].auto_ignite,
            "the flag landed"
        );
        assert_eq!(
            reply.providers[0].active_unreadable.as_deref(),
            Some("switch-in-progress")
        );
    }
}
