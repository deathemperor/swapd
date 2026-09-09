//! One slot's token refresh, serialized against every other refresher of the
//! same slot.
//!
//! A Claude refresh token is single-use: two processes that POST the same one
//! produce one winner and one `invalid_grant`, and the loser reads that as a
//! dead account (a strike, a quarantine, a `token-dead` envelope) for a slot
//! whose successor the winner has just persisted. cswap closes the same race in
//! `consume_backup_grant` by re-reading under the slot's lock and comparing
//! fingerprints; this is that gate.
//!
//! The lock is per SLOT (`<home>/refresh-<provider>-<slot>.lock`) and nothing
//! else orders against it, so holding it across the network call breaks no lock
//! ordering: it is released before any caller takes `engine.lock` for a live
//! write.

use crate::cmd::persist_login;
use crate::core::slots::LOCK_TIMEOUT;
use crate::core::store::FileLock;
use crate::ctx::Ctx;
use crate::driver::{Driver, DriverError, Login};
use crate::errors::{ErrorCode, Result};
use crate::secrets::slot_key;

/// What `refresh_slot` did with the credential it was handed.
pub enum Refreshed {
    /// This process spent the refresh token and persisted the rotation.
    Rotated(Login),
    /// Another refresher got there first: this is the generation it stored,
    /// and no token was spent here.
    Adopted(Login),
    /// The POST failed. The slot still holds the login it held before; what
    /// the failure means is the caller's to decide (a dead lineage is a
    /// quarantine for the collector and a refused switch for `switch`).
    Failed(DriverError),
}

/// Refresh `login` for `slot` under the slot's refresh lock, persisting the
/// rotation before returning it.
///
/// The compare-and-swap is on the STORED fingerprint: whoever holds the lock
/// re-reads the slot's secret, and a secret that has moved on since the caller
/// read it is proof that another refresher already spent this generation — so
/// the stored successor is adopted instead of POSTing a token the endpoint has
/// consumed.
///
/// `Err` is a lock or store fault only; a refusal by the token endpoint is
/// `Failed`, so every caller keeps its own classification of one.
pub fn refresh_slot(ctx: &Ctx, driver: &dyn Driver, slot: u32, login: &Login) -> Result<Refreshed> {
    let id = driver.id();
    let lock = match FileLock::acquire(&ctx.home.refresh_lock_base(id, slot), LOCK_TIMEOUT) {
        Ok(lock) => lock,
        // Another refresher is mid-POST and outlasted the wait. Spending this
        // generation anyway is exactly the double-consume the lock exists to
        // prevent, so the caller is told the refresh did not happen.
        Err(e) if e.code == ErrorCode::Locked => {
            return Ok(Refreshed::Failed(DriverError::Locked(e.message)))
        }
        Err(e) => return Err(e),
    };

    let key = slot_key(id, slot);
    let stored = ctx
        .secrets
        .get(&key)?
        .filter(|bytes| !bytes.trim().is_empty())
        .map(|bytes| Login { bytes });
    if let Some(stored) = stored {
        if stored.fingerprint() != login.fingerprint() {
            return Ok(Refreshed::Adopted(stored));
        }
    }

    let outcome = match driver.refresh(login) {
        Ok(refreshed) => {
            persist_login(ctx, id, slot, &refreshed)?;
            Refreshed::Rotated(refreshed)
        }
        Err(e) => Refreshed::Failed(e),
    };
    drop(lock);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::core::collect::tests::{login_for, one_slot, FakeDriver};

    /// The M2 race: a `switch` and a collector pass that both find slot 1's
    /// login expired. The token is single-use, so the loser of a double POST
    /// gets `invalid_grant` and quarantines an account whose successor the
    /// winner just stored.
    #[test]
    fn two_refreshers_of_one_slot_spend_one_token() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
        // Slow enough that the loser is certainly waiting on the lock while the
        // winner is on the network.
        let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"))
            .slow_refresh(Duration::from_millis(200));
        let login = Login {
            bytes: login_for("one@example.com", "rt-1"),
        };

        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| scope.spawn(|| refresh_slot(&ctx, &driver, 1, &login).unwrap()))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            driver.refreshes.lock().unwrap().len(),
            1,
            "the second refresher must adopt the successor, not POST the spent token"
        );
        let successor = login_for("one@example.com", "rt-next-1");
        for outcome in outcomes {
            match outcome {
                Refreshed::Rotated(login) | Refreshed::Adopted(login) => {
                    assert_eq!(login.bytes, successor)
                }
                Refreshed::Failed(e) => panic!("neither refresher may fail: {e}"),
            }
        }
        assert_eq!(
            ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
            successor
        );
    }
}
