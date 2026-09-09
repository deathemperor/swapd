//! The collector's credential safety, driven a pass at a time.
//!
//! Everything here is in-process and hermetic: a fake `Driver` whose live store
//! is a `Mutex<String>`, a temp swapd home, an in-memory secret store. No
//! network, no keychain, no `~/.claude*`.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use super::*;
use crate::core::slots::Slot;
use crate::driver::{Caps, Identity, IgniteOutcome, RunProfile, Usage};

/// A driver whose live store is a string and whose token endpoint can be told
/// what to do while the POST is in flight.
pub struct FakeDriver {
    pub live: Mutex<Option<String>>,
    /// Every login handed to `write_live`, in order.
    pub writes: Mutex<Vec<String>>,
    /// Every login handed to `refresh`, in order — the endpoint's budget is
    /// per-token, so a double consume is only visible by counting.
    pub refreshes: Mutex<Vec<String>>,
    /// Refresh tokens whose access token still works: `usage()` answers
    /// `NeedsRefresh` for anything else, which is what drives the refresh path.
    usable: Mutex<BTreeSet<String>>,
    /// Written into the live store the moment `refresh` is called — a switch
    /// landing while this pass is on the network.
    pub switch_during_refresh: Mutex<Option<String>>,
    /// How long the token endpoint takes, so two refreshers really overlap.
    pub refresh_delay: Duration,
}

impl FakeDriver {
    pub fn new(live: &str) -> Self {
        FakeDriver {
            live: Mutex::new(Some(live.to_string())),
            writes: Mutex::new(Vec::new()),
            refreshes: Mutex::new(Vec::new()),
            usable: Mutex::new(BTreeSet::new()),
            switch_during_refresh: Mutex::new(None),
            refresh_delay: Duration::ZERO,
        }
    }

    /// Mark this refresh token's access token as good, so `usage()` answers.
    pub fn usable(self, token: &str) -> Self {
        self.usable.lock().unwrap().insert(token.to_string());
        self
    }

    /// Retire this refresh token's access token — the ordinary way a
    /// credential a pass measured needs refreshing by the time the next one
    /// uses it.
    pub fn unusable(&self, token: &str) {
        self.usable.lock().unwrap().remove(token);
    }

    pub fn slow_refresh(mut self, delay: Duration) -> Self {
        self.refresh_delay = delay;
        self
    }

    pub fn live_bytes(&self) -> Option<String> {
        self.live.lock().unwrap().clone()
    }

    fn token_of(login: &Login) -> String {
        serde_json::from_str::<serde_json::Value>(&login.bytes)
            .ok()
            .and_then(|v| {
                v.pointer("/claudeAiOauth/refreshToken")?
                    .as_str()
                    .map(str::to_string)
            })
            .unwrap_or_default()
    }
}

impl Driver for FakeDriver {
    fn id(&self) -> &'static str {
        "claude"
    }
    fn installed(&self, _env: &crate::driver::Env) -> Option<std::path::PathBuf> {
        None
    }
    fn read_live(&self, _env: &crate::driver::Env) -> std::result::Result<Login, DriverError> {
        match self.live.lock().unwrap().clone() {
            Some(bytes) => Ok(Login { bytes }),
            None => Err(DriverError::NoLogin),
        }
    }
    fn write_live(
        &self,
        _env: &crate::driver::Env,
        login: &Login,
    ) -> std::result::Result<(), DriverError> {
        self.writes.lock().unwrap().push(login.bytes.clone());
        *self.live.lock().unwrap() = Some(login.bytes.clone());
        Ok(())
    }
    fn identity(&self, login: &Login) -> std::result::Result<Identity, DriverError> {
        self.identity_offline(login)
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
    }
    fn identity_offline(&self, login: &Login) -> Option<Identity> {
        let value: serde_json::Value = serde_json::from_str(&login.bytes).ok()?;
        Some(Identity {
            email: value.get("email")?.as_str()?.to_string(),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            uuid: None,
        })
    }
    fn expires_at(&self, login: &Login) -> Option<f64> {
        serde_json::from_str::<serde_json::Value>(&login.bytes)
            .ok()?
            .pointer("/claudeAiOauth/expiresAt")?
            .as_f64()
    }
    fn refresh(&self, login: &Login) -> std::result::Result<Login, DriverError> {
        self.refreshes.lock().unwrap().push(login.bytes.clone());
        if let Some(bytes) = self.switch_during_refresh.lock().unwrap().take() {
            *self.live.lock().unwrap() = Some(bytes);
        }
        std::thread::sleep(self.refresh_delay);
        let next = Login {
            bytes: login.bytes.replace("rt-", "rt-next-"),
        };
        self.usable.lock().unwrap().insert(Self::token_of(&next));
        Ok(next)
    }
    fn usage(&self, login: &Login) -> std::result::Result<Usage, DriverError> {
        if !self.usable.lock().unwrap().contains(&Self::token_of(login)) {
            return Err(DriverError::NeedsRefresh);
        }
        Ok(Usage {
            windows: Vec::new(),
            fetched_at: 1_757_000_000.0,
        })
    }
    fn ignite(
        &self,
        _env: &crate::driver::Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<IgniteOutcome, DriverError> {
        Err(DriverError::Unsupported("ignite"))
    }
    fn run_profile(
        &self,
        _env: &crate::driver::Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<RunProfile, DriverError> {
        Err(DriverError::Unsupported("run"))
    }
    fn commit_profile(
        &self,
        _env: &crate::driver::Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<(), DriverError> {
        Ok(())
    }
    fn forget_profile(
        &self,
        _env: &crate::driver::Env,
        _slot: u32,
    ) -> std::result::Result<(), DriverError> {
        Ok(())
    }
    fn live_config_text(
        &self,
        _env: &crate::driver::Env,
    ) -> std::result::Result<Option<String>, DriverError> {
        Ok(None)
    }
    fn can_activate(&self, _login: &Login) -> std::result::Result<(), DriverError> {
        Ok(())
    }
    fn is_api_key(&self, login: &Login) -> bool {
        let text = login.bytes.trim();
        text.starts_with("sk-ant-api") && !text.starts_with('{')
    }
    fn capabilities(&self) -> Caps {
        Caps {
            ignite: true,
            add_token: true,
            prefer: true,
            refresh: true,
            run: true,
        }
    }
}

/// A `Ctx` over a temp home, an in-memory secret store and a fixed clock.
pub fn ctx_for(dir: &std::path::Path) -> Ctx {
    let home = crate::paths::Home {
        root: dir.to_path_buf(),
    };
    home.ensure().unwrap();
    let store = crate::core::usage_store::UsageStore::new(&home.usage_file());
    Ctx {
        env: crate::driver::Env {
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

/// A login for `email`, with `token` as its refresh token and an access token
/// that outlives every test.
pub fn login_for(email: &str, token: &str) -> String {
    login_expiring(email, token, 4_102_444_800_000_i64)
}

/// The same, with an explicit expiry — what tells two generations of one
/// lineage apart (`driver::live_is_older`).
pub fn login_expiring(email: &str, token: &str, expires_at: i64) -> String {
    format!(
        r#"{{"email":"{email}","claudeAiOauth":{{"refreshToken":"{token}","expiresAt":{expires_at}}}}}"#
    )
}

/// A login that names no account — the envelope a `~/.claude.json` with no
/// `oauthAccount` produces, which every identity match falls back to the
/// fingerprint for.
pub fn anonymous_login(token: &str, expires_at: i64) -> String {
    format!(r#"{{"claudeAiOauth":{{"refreshToken":"{token}","expiresAt":{expires_at}}}}}"#)
}

fn slot_row(email: &str) -> Slot {
    Slot {
        email: email.to_string(),
        organization_uuid: String::new(),
        organization_name: String::new(),
        plan: None,
        alias: None,
        icon: None,
        disabled: false,
        preferred: false,
        added: None,
        fingerprint: None,
    }
}

/// One slot, holding `token`, recorded as the provider's active one.
pub fn one_slot(dir: &std::path::Path, email: &str, token: &str) -> Ctx {
    let ctx = ctx_for(dir);
    ctx.secrets
        .set(&slot_key("claude", 1), &login_for(email, token))
        .unwrap();
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry("claude".to_string()).or_default();
        provider.insert(1, slot_row(email));
        provider.active_slot = Some(1);
        Ok((true, ()))
    })
    .unwrap();
    ctx
}

#[test]
fn a_switch_landing_during_the_refresh_is_not_reverted() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    // Slot 1 is live and its access token needs a refresh; while the POST is in
    // flight, a switch lands slot 2's login.
    let landed = login_for("two@example.com", "rt-2");
    let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"));
    *driver.switch_during_refresh.lock().unwrap() = Some(landed.clone());

    collect(&ctx, &driver, &CollectOpts::default()).unwrap();

    // The rotation was persisted — the token that produced it is spent — but
    // the live store still holds what the switch put there.
    assert_eq!(driver.refreshes.lock().unwrap().len(), 1);
    assert!(
        driver.writes.lock().unwrap().is_empty(),
        "the pass must not write over a switch that landed after its snapshot"
    );
    assert_eq!(driver.live_bytes().unwrap(), landed);
    assert_eq!(
        ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
        login_for("one@example.com", "rt-next-1"),
        "the successor belongs to the slot even when it cannot go live"
    );
}

#[test]
fn a_refresh_of_the_active_slot_lands_in_the_live_store() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"));

    collect(&ctx, &driver, &CollectOpts::default()).unwrap();

    // The unraced path still does what it always did: the live store follows
    // the rotation the pass persisted.
    let refreshed = login_for("one@example.com", "rt-next-1");
    assert_eq!(
        driver.writes.lock().unwrap().clone(),
        vec![refreshed.clone()]
    );
    assert_eq!(driver.live_bytes().unwrap(), refreshed);
}

#[test]
fn a_torn_live_login_is_not_adopted_while_a_switch_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    // A switch has written account two's credential and not yet spliced the
    // identity: the live store reads as slot 1's account holding slot 2's
    // token. Both tokens are usable, so only the fence stops the adopt.
    let torn = login_for("one@example.com", "rt-2");
    let driver = FakeDriver::new(&torn).usable("rt-2").usable("rt-1");

    let _held =
        crate::core::store::FileLock::acquire(&ctx.home.engine_lock_base(), Duration::from_secs(5))
            .unwrap();
    let view = collect(&ctx, &driver, &CollectOpts::default()).unwrap();

    assert_eq!(
        ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
        login_for("one@example.com", "rt-1"),
        "a pass that could not take the fence must not adopt the live login"
    );
    // The slot `slots.json` calls active is served from the store and marked
    // stale, exactly as it is when the keychain cannot be read.
    assert_eq!(view.active_slot, None);
    assert_eq!(view.accounts[0].usage_status, UsageStatus::Stale);
    assert!(driver.refreshes.lock().unwrap().is_empty());
}

#[test]
fn active_unreadable_reports_switch_in_progress_and_is_absent_on_a_normal_pass() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    let driver = FakeDriver::new(&login_for("one@example.com", "rt-1")).usable("rt-1");

    let held =
        crate::core::store::FileLock::acquire(&ctx.home.engine_lock_base(), Duration::from_secs(5))
            .unwrap();
    let view = collect(&ctx, &driver, &CollectOpts::default()).unwrap();
    assert_eq!(
        view.active_unreadable,
        Some("switch-in-progress".to_string())
    );
    drop(held);

    let view = collect(&ctx, &driver, &CollectOpts::default()).unwrap();
    assert_eq!(view.active_unreadable, None);
    let json = serde_json::to_string(&view).unwrap();
    assert!(
        !json.contains("activeUnreadable"),
        "an absent reason must not be serialised: {json}"
    );
}

#[test]
fn a_heal_then_a_refresh_leaves_the_successor_live() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_for(dir.path());
    // The state a `write_live` that failed leaves behind: the slot holds the
    // newer generation, the live store the spent one it was rotated from.
    let stored = login_expiring("one@example.com", "rt-1", 2_000_000_000_000);
    let live = login_expiring("one@example.com", "rt-0", 1_000_000_000_000);
    ctx.secrets.set(&slot_key("claude", 1), &stored).unwrap();
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry("claude".to_string()).or_default();
        provider.insert(1, slot_row("one@example.com"));
        provider.active_slot = Some(1);
        Ok((true, ()))
    })
    .unwrap();
    // Neither generation's access token works, so the heal is followed by a
    // refresh in the same fetch.
    let driver = FakeDriver::new(&live);

    collect(&ctx, &driver, &CollectOpts::default()).unwrap();

    let refreshed = stored.replace("rt-", "rt-next-");
    assert_eq!(
        driver.writes.lock().unwrap().clone(),
        vec![stored, refreshed.clone()],
        "the heal writes the stored login, then the refresh writes its successor"
    );
    assert_eq!(
        driver.live_bytes().unwrap(),
        refreshed,
        "a spent generation must never be the one left live"
    );
}

#[test]
fn a_fingerprint_matched_active_slot_still_gets_its_live_login_updated() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_for(dir.path());
    // A live login that names no account: `~/.claude.json` has no
    // `oauthAccount`, so the slot is matched by fingerprint alone — the
    // fallback `match_slot` and `export` have always had.
    let login = anonymous_login("rt-1", 4_102_444_800_000);
    ctx.secrets.set(&slot_key("claude", 1), &login).unwrap();
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry("claude".to_string()).or_default();
        provider.insert(1, slot_row("one@example.com"));
        Ok((true, ()))
    })
    .unwrap();
    let driver = FakeDriver::new(&login);

    let view = collect(&ctx, &driver, &CollectOpts::default()).unwrap();
    assert_eq!(view.active_slot, Some(1), "matched by fingerprint");

    // The rotation must reach the live store: refusing it there leaves the CLI
    // on the spent generation, and the next pass no longer recognises the slot
    // as active — nothing would ever heal it.
    let refreshed = anonymous_login("rt-next-1", 4_102_444_800_000);
    assert_eq!(
        driver.writes.lock().unwrap().clone(),
        vec![refreshed.clone()]
    );
    assert_eq!(driver.live_bytes().unwrap(), refreshed);
}

#[test]
fn a_contended_refresh_lock_is_stale_not_a_strike() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    // Another process is spending this slot's token: its refresh lock is held
    // for longer than the pass will wait.
    let _held = crate::core::store::FileLock::acquire(
        &ctx.home.refresh_lock_base("claude", 1),
        Duration::from_secs(5),
    )
    .unwrap();
    let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"));

    let view = collect(&ctx, &driver, &CollectOpts::default()).unwrap();

    assert!(driver.refreshes.lock().unwrap().is_empty());
    assert_eq!(view.accounts[0].usage_status, UsageStatus::Stale);
    // No strike, no backoff — and the claim is handed back, so the next pass
    // (by when the winner is done) fetches instead of skipping.
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ctx.home.usage_file()).unwrap()).unwrap();
    let row = &rows["rows"]["claude:1"];
    assert_eq!(row["consecutiveFailures"], 0);
    assert!(row["lastError"].is_null(), "{row}");
    assert!(row["backoffUntil"].is_null(), "{row}");
    assert!(row["claimUntil"].is_null(), "{row}");
}

#[test]
fn a_second_execute_uses_the_successor_token() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = one_slot(dir.path(), "one@example.com", "rt-1");
    let driver = FakeDriver::new(&login_for("one@example.com", "rt-1"));
    let mut prepared = prepare(&ctx, &driver, slots::LOCK_TIMEOUT).unwrap();
    let forced = || FetchOpts {
        force_slots: vec![1],
        ..FetchOpts::default()
    };

    // Pass 1: rt-1's access token is spent, so the fetch rotates the lineage
    // and persists rt-next-1 (secret, slot fingerprint and live store).
    let view = execute(&ctx, &driver, &mut prepared, &forced()).unwrap();
    assert_eq!(view.accounts[0].usage_status, UsageStatus::Ok);
    assert_eq!(
        ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
        login_for("one@example.com", "rt-next-1")
    );

    // By pass 2 the successor's own access token has expired too, so this pass
    // refreshes as well — with the successor, never with the generation pass 1
    // spent. Re-POSTing that one is a `RefreshDenied` and a dead-token strike
    // on a healthy account.
    driver.unusable("rt-next-1");
    let view = execute(&ctx, &driver, &mut prepared, &forced()).unwrap();

    let refreshes = driver.refreshes.lock().unwrap().clone();
    assert_eq!(refreshes.len(), 2, "{refreshes:?}");
    assert_eq!(
        refreshes[1],
        login_for("one@example.com", "rt-next-1"),
        "the second pass must POST the successor the first one left behind"
    );
    assert_eq!(
        ctx.secrets.get(&slot_key("claude", 1)).unwrap().unwrap(),
        login_for("one@example.com", "rt-next-next-1"),
        "and its own rotation is the one the slot ends on"
    );
    assert_eq!(view.accounts[0].usage_status, UsageStatus::Ok);
    assert_eq!(
        driver.live_bytes().unwrap(),
        login_for("one@example.com", "rt-next-next-1")
    );
}

#[test]
fn pass_marks_do_not_leak_between_executes() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_for(dir.path());
    // The active slot's access token expired long ago.
    let expired = login_expiring("one@example.com", "rt-1", 1_000_000);
    ctx.secrets.set(&slot_key("claude", 1), &expired).unwrap();
    slots::update(&ctx.home.slots_file(), |file| {
        let provider = file.providers.entry("claude".to_string()).or_default();
        provider.insert(1, slot_row("one@example.com"));
        provider.active_slot = Some(1);
        Ok((true, ()))
    })
    .unwrap();
    let driver = FakeDriver::new(&expired);
    let mut prepared = prepare(&ctx, &driver, slots::LOCK_TIMEOUT).unwrap();

    // Pass 1 fetches nothing, so the expired active credential surfaces as
    // expired rather than as a stale `ok`.
    let view = execute(
        &ctx,
        &driver,
        &mut prepared,
        &FetchOpts {
            only: Some(Vec::new()),
            ..FetchOpts::default()
        },
    )
    .unwrap();
    assert_eq!(view.accounts[0].usage_status, UsageStatus::TokenExpired);

    // That mark was about pass 1's fetch gate, not about the slot: pass 2
    // claims it, refreshes it, and reports what it measured.
    let view = execute(
        &ctx,
        &driver,
        &mut prepared,
        &FetchOpts {
            force_slots: vec![1],
            ..FetchOpts::default()
        },
    )
    .unwrap();
    assert_eq!(driver.refreshes.lock().unwrap().len(), 1);
    assert_eq!(view.accounts[0].usage_status, UsageStatus::Ok);
}
