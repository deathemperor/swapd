//! The auto engine's decisions, driven a tick at a time.
//!
//! Everything here is in-process and hermetic: a fake `Driver` whose live
//! store is a `Mutex<String>` and whose usage answers come from a table the
//! test writes, a temp swapd home, a file-backed secret store and one injected
//! clock shared by the context and the usage table. No network, no keychain,
//! no `~/.claude*`, no real `claude` binary.
//!
//! The clock is shared on purpose: the store computes each row's age against
//! its own clock, so a context frozen at 2026 with a store on wall time would
//! read every fresh measurement as hours stale, and every test below would
//! quietly become a failover test.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tempfile::TempDir;

use super::*;
use crate::contract::WindowKind;
use crate::core::slots::Slot;
use crate::core::store::read_json;
use crate::driver::{Caps, DriverError, Env, Identity, IgniteOutcome, RunProfile, Usage};
use crate::paths::Home;
use crate::secrets::{secrets_for, Secrets};

/// Fixed start of every test's clock (2026-09-04T14:13:20Z).
const T0: f64 = 1_757_000_000.0;

// -- the fake provider -------------------------------------------------------

/// A driver whose live store is a string, whose usage comes from a table and
/// whose refresh can be told to fail for a given credential.
struct FakeDriver {
    live: Mutex<Option<String>>,
    /// email → the windows `usage()` reports for it.
    usage: Mutex<BTreeMap<String, Vec<Window>>>,
    /// Refresh tokens whose lineage is dead: refreshing one is `TokenDead`.
    dead: Mutex<Vec<String>>,
    writes: Mutex<Vec<String>>,
    /// Every account `usage()` was called for, in order — the endpoint's
    /// budget is per-request, so the schedule is only testable by counting.
    usage_calls: Mutex<Vec<String>>,
    /// How many times the collector's preamble read the live login. One per
    /// `prepare`, which is what says how many preambles a tick ran.
    live_reads: Mutex<usize>,
}

impl FakeDriver {
    fn new(live: &str) -> Self {
        FakeDriver {
            live: Mutex::new(Some(live.to_string())),
            usage: Mutex::new(BTreeMap::new()),
            dead: Mutex::new(Vec::new()),
            writes: Mutex::new(Vec::new()),
            usage_calls: Mutex::new(Vec::new()),
            live_reads: Mutex::new(0),
        }
    }

    /// The preambles since the last call.
    fn take_live_reads(&self) -> usize {
        std::mem::take(&mut *self.live_reads.lock().unwrap())
    }

    /// Make this account's usage endpoint fail (an account with no row in the
    /// table answers the way the real one does when it errors).
    fn fail_usage(&self, email: &str) {
        self.usage.lock().unwrap().remove(email);
    }

    fn set_usage(&self, email: &str, windows: Vec<Window>) {
        self.usage
            .lock()
            .unwrap()
            .insert(email.to_string(), windows);
    }

    /// The accounts fetched since the last `take_usage_calls`.
    fn take_usage_calls(&self) -> Vec<String> {
        std::mem::take(&mut *self.usage_calls.lock().unwrap())
    }

    fn email_of(login: &Login) -> String {
        serde_json::from_str::<Value>(&login.bytes)
            .ok()
            .and_then(|v| v.get("email")?.as_str().map(str::to_string))
            .unwrap_or_default()
    }

    fn refresh_token(login: &Login) -> String {
        serde_json::from_str::<Value>(&login.bytes)
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
    fn installed(&self, _env: &Env) -> Option<std::path::PathBuf> {
        None
    }
    fn read_live(&self, _env: &Env) -> std::result::Result<Login, DriverError> {
        match self.live.lock().unwrap().clone() {
            Some(bytes) => Ok(Login { bytes }),
            None => Err(DriverError::NoLogin),
        }
    }
    fn read_live_locked(&self, env: &Env) -> std::result::Result<Login, DriverError> {
        *self.live_reads.lock().unwrap() += 1;
        self.read_live(env)
    }
    fn write_live(&self, _env: &Env, login: &Login) -> std::result::Result<(), DriverError> {
        self.writes.lock().unwrap().push(login.bytes.clone());
        *self.live.lock().unwrap() = Some(login.bytes.clone());
        Ok(())
    }
    fn identity(&self, login: &Login) -> std::result::Result<Identity, DriverError> {
        self.identity_offline(login)
            .ok_or_else(|| DriverError::Invalid("no identity".to_string()))
    }
    fn identity_offline(&self, login: &Login) -> Option<Identity> {
        Some(Identity {
            email: Self::email_of(login),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            uuid: None,
        })
    }
    fn expires_at(&self, login: &Login) -> Option<f64> {
        serde_json::from_str::<Value>(&login.bytes)
            .ok()?
            .pointer("/claudeAiOauth/expiresAt")?
            .as_f64()
    }
    fn refresh(&self, login: &Login) -> std::result::Result<Login, DriverError> {
        if self
            .dead
            .lock()
            .unwrap()
            .contains(&Self::refresh_token(login))
        {
            return Err(DriverError::TokenDead);
        }
        Ok(Login {
            bytes: login
                .bytes
                .replace("\"expiresAt\":", "\"refreshedAt\":0,\"expiresAt\":"),
        })
    }
    /// Usage never depends on the credential's expiry: the real endpoint
    /// answers `NeedsRefresh` there, and the collector would then refresh —
    /// which would quarantine a dead lineage in the STORE and hide it from the
    /// engine's own quarantine path, the one these tests are about.
    fn usage(&self, login: &Login) -> std::result::Result<Usage, DriverError> {
        let email = Self::email_of(login);
        self.usage_calls.lock().unwrap().push(email.clone());
        match self.usage.lock().unwrap().get(&email) {
            Some(windows) => Ok(Usage {
                windows: windows.clone(),
                fetched_at: 0.0,
            }),
            None => Err(DriverError::Http("usage: http-500".to_string())),
        }
    }
    fn ignite(
        &self,
        _env: &Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<IgniteOutcome, DriverError> {
        Err(DriverError::Unsupported("ignite"))
    }
    fn run_profile(
        &self,
        _env: &Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<RunProfile, DriverError> {
        Err(DriverError::Unsupported("run"))
    }

    fn commit_profile(
        &self,
        _env: &Env,
        _slot: u32,
        _login: &Login,
    ) -> std::result::Result<(), DriverError> {
        Ok(())
    }

    fn forget_profile(&self, _env: &Env, _slot: u32) -> std::result::Result<(), DriverError> {
        Ok(())
    }
    fn live_config_text(&self, _env: &Env) -> std::result::Result<Option<String>, DriverError> {
        Ok(None)
    }
    fn can_activate(&self, login: &Login) -> std::result::Result<(), DriverError> {
        if self.is_api_key(login) {
            return Err(DriverError::Invalid("api key login".to_string()));
        }
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

/// The board's secret store, counting every read.
///
/// What the preamble costs is not an implementation detail: on macOS each
/// `get` is one `/usr/bin/security` spawn, so a tick that reads every slot's
/// secret once per fetch pass costs several times what one that reads them
/// once does. The count is the behaviour.
struct CountingSecrets {
    inner: Box<dyn Secrets>,
    gets: Arc<Mutex<Vec<String>>>,
}

impl Secrets for CountingSecrets {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.gets.lock().unwrap().push(key.to_string());
        self.inner.get(key)
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.inner.set(key, value)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

// -- the board ---------------------------------------------------------------

/// A seeded fleet: a temp home, a fake provider, one clock and the event log.
struct Board {
    dir: TempDir,
    clock: Arc<Mutex<f64>>,
    driver: FakeDriver,
    events: Rc<RefCell<Vec<Value>>>,
    /// Every secret key the ticks read, in order.
    secret_gets: Arc<Mutex<Vec<String>>>,
}

impl Board {
    /// Two accounts, slot 1 live, both with usable credentials.
    fn new() -> Board {
        let board = Board {
            dir: TempDir::new().unwrap(),
            clock: Arc::new(Mutex::new(T0)),
            driver: FakeDriver::new(&login("one@example.com", "rt-1", T0 + 86_400.0)),
            events: Rc::new(RefCell::new(Vec::new())),
            secret_gets: Arc::new(Mutex::new(Vec::new())),
        };
        Home {
            root: board.dir.path().to_path_buf(),
        }
        .ensure()
        .unwrap();
        board.seed(1, "one@example.com", "rt-1", T0 + 86_400.0);
        board.seed(2, "two@example.com", "rt-2", T0 + 86_400.0);
        board
    }

    fn home(&self) -> Home {
        Home {
            root: self.dir.path().to_path_buf(),
        }
    }

    fn secrets(&self) -> Box<dyn Secrets> {
        secrets_for(&self.home(), Some("file")).unwrap()
    }

    /// Add a slot with a stored login.
    fn seed(&self, slot: u32, email: &str, refresh: &str, expires_at: f64) {
        self.secrets()
            .set(
                &slot_key("claude", slot),
                &login(email, refresh, expires_at),
            )
            .unwrap();
        slots::update(&self.home().slots_file(), |file| {
            file.providers
                .entry("claude".to_string())
                .or_default()
                .insert(
                    slot,
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
                    },
                );
            Ok((true, ()))
        })
        .unwrap();
    }

    /// Add a slot whose stored credential is a managed API key — an account
    /// the driver refuses to make the live login.
    fn seed_api_key(&self, slot: u32, email: &str) {
        self.seed(slot, email, &format!("rt-{slot}"), T0 + 86_400.0);
        self.secrets()
            .set(&slot_key("claude", slot), "sk-ant-api03-managed")
            .unwrap();
    }

    /// A context on this board's home, secrets and clock. Built per tick, the
    /// way a cron-driven `--once` run would: everything a tick must remember
    /// is in `auto-state.json`, and nothing here may depend on process memory.
    fn ctx(&self) -> Ctx {
        let home = self.home();
        let (a, b) = (self.clock.clone(), self.clock.clone());
        let store = crate::core::usage_store::UsageStore::with_clock(
            &home.usage_file(),
            Box::new(move || *a.lock().unwrap()),
            // A fixed midpoint: the planner's ±10% jitter becomes ×1.0, so a
            // seeded board schedules the same way every run.
            Box::new(|| 0.5),
        );
        Ctx {
            env: Env {
                home: home.root.clone(),
                vars: Default::default(),
            },
            home,
            secrets: Box::new(CountingSecrets {
                inner: self.secrets(),
                gets: self.secret_gets.clone(),
            }),
            clock: Box::new(move || *b.lock().unwrap()),
            settings: Default::default(),
            store,
        }
    }

    /// One engine over this board, ticking into the event log. Held across
    /// ticks by the tests whose point IS what one tick remembers of the last.
    fn engine(&self) -> AutoEngine<'_> {
        let sink = self.events.clone();
        AutoEngine::new(
            self.ctx(),
            &self.driver,
            Box::new(move |emit| sink.borrow_mut().push(emit.to_json())),
        )
    }

    /// One tick by a fresh engine — the shape a cron-driven single run has.
    fn tick(&self) -> TickOutcome {
        self.engine().tick()
    }

    /// One tick, plus the delay it asks to sleep for.
    fn tick_and_schedule(&self) -> (TickOutcome, f64) {
        let mut engine = self.engine();
        let outcome = engine.tick();
        let delay = engine.schedule(outcome, || 0.5);
        (outcome, delay)
    }

    /// The secret keys read since the last call.
    fn take_secret_gets(&self) -> Vec<String> {
        std::mem::take(&mut *self.secret_gets.lock().unwrap())
    }

    fn advance(&self, seconds: f64) {
        *self.clock.lock().unwrap() += seconds;
    }

    fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    /// Every event emitted so far, in order.
    fn kinds(&self) -> Vec<String> {
        self.events
            .borrow()
            .iter()
            .map(|e| e["event"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// The last event of a kind.
    fn last(&self, kind: &str) -> Option<Value> {
        self.events
            .borrow()
            .iter()
            .rfind(|e| e["event"] == kind)
            .cloned()
    }

    fn count(&self, kind: &str) -> usize {
        self.kinds().iter().filter(|k| *k == kind).count()
    }

    fn state(&self) -> AutoState {
        read_json(&self.home().auto_state_file()).unwrap()
    }

    fn live_email(&self) -> String {
        FakeDriver::email_of(&self.driver.read_live(&self.ctx().env).unwrap())
    }

    fn set_state(&self, state: &AutoState) {
        crate::core::store::write_json_atomic(&self.home().auto_state_file(), state).unwrap();
    }
}

fn login(email: &str, refresh: &str, expires_at: f64) -> String {
    serde_json::json!({
        "email": email,
        "claudeAiOauth": {
            "accessToken": format!("at-{refresh}"),
            "refreshToken": refresh,
            "expiresAt": expires_at,
        }
    })
    .to_string()
}

/// A 5-hour and a 7-day window at `pct`, both resetting `in_s` from now.
fn usage_at(pct: f64, now: f64, in_s: f64) -> Vec<Window> {
    vec![
        window(WindowKind::FiveHour, pct, now + in_s),
        window(WindowKind::SevenDay, pct / 2.0, now + in_s * 10.0),
    ]
}

fn window(kind: WindowKind, pct: f64, resets_at: f64) -> Window {
    Window {
        kind,
        name: None,
        pct,
        resets_at: format_ts(resets_at),
        pace: None,
        used: None,
        limit: None,
        currency: None,
    }
}

/// Write one policy knob, the way `swapd config set` does.
fn set(board: &Board, key: &str, value: Value) {
    settings::set(&board.home(), "claude", key, value).unwrap();
}

// -- the tests ---------------------------------------------------------------

#[test]
fn below_threshold_polls_and_no_switch() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);

    assert_eq!(board.kinds(), vec!["poll", "no-switch"]);
    let poll = board.last("poll").unwrap();
    assert_eq!(poll["active"]["number"], 1);
    assert_eq!(poll["active"]["slot"], 1);
    assert_eq!(poll["provider"], "claude");
    assert_eq!(poll["schemaVersion"], 1);
    assert_eq!(poll["headroomPct"]["1"], 50.0);
    assert_eq!(poll["headroomPct"]["2"], 90.0);
    assert_eq!(poll["threshold"], 90.0);
    // The binding pct alone hides which window binds, so both are reported.
    assert_eq!(poll["windows"]["1"]["5h"], 50.0);
    assert_eq!(poll["windows"]["1"]["7d"], 25.0);

    let no_switch = board.last("no-switch").unwrap();
    assert_eq!(no_switch["reason"], "below-threshold");
    // Nothing was written to the live store, and no cooldown was started.
    assert!(board.driver.writes.lock().unwrap().is_empty());
    assert_eq!(board.state(), AutoState::default());
}

/// The endpoint budgets usage requests per identity over a trailing hour, so
/// what a tick costs is policy, not an implementation detail: cswap's baseline
/// fetches the active account plus the ONE stalest due candidate and escalates
/// to the whole fleet only near the threshold. A five-slot fleet at 50% is
/// nowhere near it, so it must not cost five requests a minute.
#[test]
fn a_quiet_tick_fetches_the_active_account_and_one_candidate() {
    let board = Board::new();
    for slot in 3..=5 {
        let email = format!("slot{slot}@example.com");
        board.seed(slot, &email, &format!("rt-{slot}"), T0 + 86_400.0);
        board.driver.set_usage(&email, usage_at(10.0, T0, 3600.0));
    }
    // 50% used against a 90% threshold and a 15-point escalation margin: the
    // band opens at 75%, so this tick stays on the baseline.
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);
    let fetched = board.driver.take_usage_calls();
    assert_eq!(fetched.len(), 2, "{fetched:?}");
    assert!(
        fetched.contains(&"one@example.com".to_string()),
        "{fetched:?}"
    );
    let first_candidate = fetched
        .iter()
        .find(|email| *email != "one@example.com")
        .cloned()
        .unwrap();

    // The next tick is inside the active account's learned plan, and the
    // candidate it just measured is no longer the stalest — so it spends one
    // request, on a candidate it has never measured.
    board.advance(60.0);
    assert_eq!(board.tick(), TickOutcome::NoAction);
    let second = board.driver.take_usage_calls();
    assert_eq!(second.len(), 1, "{second:?}");
    assert_ne!(
        second[0], "one@example.com",
        "the active account is not due"
    );
    assert_ne!(
        second[0], first_candidate,
        "the candidate poll rotates: {second:?} after {fetched:?}"
    );
}

#[test]
fn at_threshold_switches_to_ranked_candidate() {
    let board = Board::new();
    board.seed(3, "three@example.com", "rt-3", T0 + 86_400.0);
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    // Slot 2 has the most headroom, so it is the one `best` must take.
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    board
        .driver
        .set_usage("three@example.com", usage_at(60.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::Switched);

    let switched = board.last("switch").unwrap();
    assert_eq!(switched["trigger"], "proactive");
    assert_eq!(switched["from"]["number"], 1);
    assert_eq!(switched["to"]["number"], 2);
    assert_eq!(switched["to"]["email"], "two@example.com");
    assert_eq!(switched["dryRun"], false);
    assert_eq!(board.live_email(), "two@example.com");

    // The cooldown starts, and the departure is recorded for the next tick's
    // no-return bar.
    let state = board.state();
    assert_eq!(state.schema_version, 1);
    assert_eq!(state.cooldown_until, Some(T0 + 300.0));
    let departure = state.left_at_limit.unwrap();
    assert_eq!((departure.from, departure.to), (1, 2));
    assert_eq!(departure.trigger, "proactive");
    assert_eq!(departure.headroom, Some(5.0));

    // And the switch is in the log every other verb writes to.
    let history = crate::core::history::read(&board.home(), None).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].trigger, "proactive");
    assert_eq!(history[0].to.slot, Some(2));
}

/// The live login changes inside `switch::perform`; the cooldown and the
/// no-return bar are written after it. If that write fails, the switch has
/// still happened — reporting it as a tick error would leave a supervisor
/// believing the old account is still active, and would hide the fact that the
/// cooldown is missing. It is a warning on the `switch` event instead.
#[test]
fn a_landed_switch_is_reported_when_its_bookkeeping_fails() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    // A directory where the state lock file belongs: the state write is the
    // only step of the tick that cannot succeed.
    std::fs::create_dir(board.home().root.join("auto-state.json.lock")).unwrap();

    assert_eq!(board.tick(), TickOutcome::Switched);

    let switched = board.last("switch").unwrap();
    assert_eq!(switched["to"]["number"], 2);
    assert_eq!(board.live_email(), "two@example.com");
    let warnings = switched["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("were not recorded")),
        "{switched}"
    );
    assert!(board.last("error").is_none());
}

#[test]
fn cooldown_blocks_proactive_switch() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    board.set_state(&AutoState {
        schema_version: 1,
        cooldown_until: Some(T0 + 300.0),
        ..AutoState::default()
    });

    assert_eq!(board.tick(), TickOutcome::NoAction);

    assert_eq!(board.last("no-switch").unwrap()["reason"], "cooldown");
    assert!(
        board.driver.writes.lock().unwrap().is_empty(),
        "a switch in cooldown must not touch the live store"
    );
    assert_eq!(board.live_email(), "one@example.com");

    // The same board once the cooldown has lapsed: the switch it was holding
    // back is exactly the one that now fires.
    board.advance(301.0);
    assert_eq!(board.tick(), TickOutcome::Switched);
    assert_eq!(board.live_email(), "two@example.com");
}

#[test]
fn dead_target_is_quarantined_and_skipped() {
    let board = Board::new();
    board.seed(3, "three@example.com", "rt-3", T0 + 86_400.0);
    // Slot 2 is the best candidate on paper, but its login is expired and its
    // refresh token is dead — the state a re-login is the only cure for.
    board.seed(2, "two@example.com", "rt-2", T0 - 60.0);
    board.driver.dead.lock().unwrap().push("rt-2".to_string());
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    board
        .driver
        .set_usage("three@example.com", usage_at(60.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::Switched);

    // Tried first, quarantined, and the rotation carried on to the next.
    let quarantined = board.last("account-quarantined").unwrap();
    assert_eq!(quarantined["number"], 2);
    assert_eq!(quarantined["slot"], 2);
    assert_eq!(quarantined["email"], "two@example.com");
    assert_eq!(quarantined["reason"], "invalid_grant");
    assert_eq!(board.last("switch").unwrap()["to"]["number"], 3);
    assert_eq!(board.live_email(), "three@example.com");

    let entry = board.state().quarantine["2"].clone();
    assert_eq!(entry.reason, "invalid_grant");
    // Bound to the credential generation that failed, so a re-login releases
    // it without anybody having to.
    assert_eq!(
        entry.fingerprint,
        Some(
            Login {
                bytes: login("two@example.com", "rt-2", T0 - 60.0)
            }
            .fingerprint()
        )
    );

    // Next tick: the account we just landed on is at its limit and slot 1 has
    // recovered, so the engine must move again — past slot 2 without trying it
    // a second time.
    board.advance(400.0);
    let now = board.now();
    board
        .driver
        .set_usage("three@example.com", usage_at(95.0, now, 3600.0));
    // Slot 2 would outrank slot 1 outright if it were still a candidate, so
    // landing on slot 1 is only possible if the quarantine kept it out.
    board
        .driver
        .set_usage("two@example.com", usage_at(0.0, now, 3600.0));
    board
        .driver
        .set_usage("one@example.com", usage_at(10.0, now, 3600.0));
    assert_eq!(board.tick(), TickOutcome::Switched);
    assert_eq!(board.live_email(), "one@example.com");
    assert_eq!(
        board.count("account-quarantined"),
        1,
        "a quarantined slot is not a candidate, so it is never tried again"
    );
    // And it is still out: nothing replaced its credential.
    assert!(board.state().quarantine.contains_key("2"));
}

#[test]
fn a_replaced_credential_releases_the_quarantine() {
    let board = Board::new();
    board.set_state(&AutoState {
        schema_version: 1,
        quarantine: BTreeMap::from([(
            "2".to_string(),
            Quarantine {
                reason: "invalid_grant".to_string(),
                since: format_ts(T0).unwrap(),
                fingerprint: Some("sha256:stale".to_string()),
            },
        )]),
        ..AutoState::default()
    });
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);

    let released = board.last("account-unquarantined").unwrap();
    assert_eq!(released["number"], 2);
    assert_eq!(released["reason"], "credentials-replaced");
    assert!(board.state().quarantine.is_empty());
}

#[test]
fn all_exhausted_emits_earliest_reset() {
    let board = Board::new();
    // Both accounts hard at their limit; slot 2's window comes back first.
    board.driver.set_usage(
        "one@example.com",
        vec![window(WindowKind::FiveHour, 100.0, T0 + 7200.0)],
    );
    board.driver.set_usage(
        "two@example.com",
        vec![window(WindowKind::FiveHour, 100.0, T0 + 3600.0)],
    );

    let (outcome, delay) = board.tick_and_schedule();
    assert_eq!(outcome, TickOutcome::Blocked);

    let exhausted = board.last("all-exhausted").unwrap();
    assert_eq!(
        exhausted["earliestResetAt"],
        format_ts(T0 + 3600.0).unwrap()
    );
    // Never switched onto an account that is itself spent.
    assert!(board.driver.writes.lock().unwrap().is_empty());

    // The sleep is reset-aware but bounded: quota can be granted before the
    // advertised time, so the engine re-checks long before then.
    assert_eq!(delay, MAX_SLEEP_S);
    let sleep = board.last("sleep").unwrap();
    assert_eq!(sleep["seconds"], MAX_SLEEP_S);
    assert_eq!(sleep["until"], format_ts(T0 + MAX_SLEEP_S).unwrap());
}

/// The two ways a tick can find nobody to watch: a live login no slot owns
/// (adding it is the fix), and no live login at all. Neither is acted on —
/// switching would overwrite a credential no slot holds a copy of.
#[test]
fn an_unmanaged_or_absent_live_login_is_reported_not_acted_on() {
    let board = Board::new();
    *board.driver.live.lock().unwrap() = Some(login("stranger@example.com", "rt-x", T0 + 86_400.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);
    let poll = board.last("poll").unwrap();
    assert_eq!(poll["active"], Value::Null);
    let said = board.last("no-switch").unwrap();
    assert_eq!(said["reason"], "unmanaged-active-account");
    assert!(said["detail"].as_str().unwrap().contains("swapd add"));
    assert!(
        board.driver.take_usage_calls().is_empty(),
        "with no account to schedule around, no request is spent"
    );

    *board.driver.live.lock().unwrap() = None;
    board.advance(60.0);
    assert_eq!(board.tick(), TickOutcome::NoAction);
    assert_eq!(
        board.last("no-switch").unwrap()["reason"],
        "no-active-account"
    );
}

/// A switch in flight fences the live store, but the account IS active — the
/// tick must say so (`no-switch{switch-in-progress}`), not claim there is no
/// active account, and it must not touch anything.
#[test]
fn a_switch_in_flight_is_reported_as_switch_in_progress() {
    let board = Board::new();
    slots::update(&board.home().slots_file(), |file| {
        file.providers
            .entry("claude".to_string())
            .or_default()
            .active_slot = Some(1);
        Ok((true, ()))
    })
    .unwrap();

    let _held = crate::core::store::FileLock::acquire(
        &board.home().engine_lock_base(),
        std::time::Duration::from_secs(5),
    )
    .unwrap();

    assert_eq!(board.tick(), TickOutcome::NoAction);
    let said = board.last("no-switch").unwrap();
    assert_eq!(said["reason"], "switch-in-progress");
    assert!(board.driver.writes.lock().unwrap().is_empty());
    assert!(
        board.driver.take_usage_calls().is_empty(),
        "a fenced store is served from the table, not fetched"
    );
}

/// Two ways the ranking can come back empty with the active account at its
/// threshold: nothing readable to compare against, and a candidate that is
/// readable but does not clear the hysteresis margin. Neither is
/// `all-exhausted`, so neither may take its long reset-aware sleep.
#[test]
fn an_empty_ranking_says_which_kind_of_empty_it_is() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    // Slot 2's usage endpoint fails, so nothing about it can be read.
    board.driver.fail_usage("two@example.com");

    let (outcome, delay) = board.tick_and_schedule();
    assert_eq!(outcome, TickOutcome::Blocked);
    assert_eq!(board.last("no-switch").unwrap()["reason"], "no-comparison");
    assert_eq!(delay, 60.0, "an unreadable candidate can become readable");

    // Now it reads — with room, but not enough of it to be worth the move.
    let board = Board::new();
    set(&board, "hysteresisPct", Value::from(20.0));
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(85.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::Blocked);
    assert_eq!(
        board.last("no-switch").unwrap()["reason"],
        "no-qualifying-candidate"
    );
    assert!(
        board.last("all-exhausted").is_none(),
        "10 points of headroom is not an exhausted fleet"
    );
}

/// A managed API-key slot has no usage to fetch/// A managed API-key slot has no usage to fetch, so it never gets a
/// `fetchedAt` — and a never-fetched account is the stalest thing in the fleet,
/// which is what the single alternate poll slot goes to. Nominating one would
/// therefore starve every OAuth peer of measurements for as long as the active
/// account stays out of the escalation band.
#[test]
fn an_api_key_slot_never_takes_the_one_candidate_poll() {
    let board = Board::new();
    board.seed_api_key(3, "keyed@example.com");
    // Well below the escalation band, so only the baseline runs.
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);
    board.driver.take_usage_calls();
    board.advance(400.0);
    assert_eq!(board.tick(), TickOutcome::NoAction);

    let fetched = board.driver.take_usage_calls();
    assert!(
        fetched.contains(&"two@example.com".to_string()),
        "the OAuth peer must still get the candidate slot: {fetched:?}"
    );
}

/// A managed API-key slot in the fleet is not a candidate at default settings,
/// and must not stand between the engine and the reason it is actually stuck:
/// with `unsupported` in the way, a fleet with one API-key slot could never
/// report `all-exhausted`, never take its bounded reset-aware sleep, and would
/// poll at full cadence through a whole reset window.
#[test]
fn an_api_key_peer_never_hides_all_exhausted() {
    let board = Board::new();
    board.seed_api_key(3, "keyed@example.com");
    for email in ["one@example.com", "two@example.com"] {
        board.driver.set_usage(
            email,
            vec![window(WindowKind::FiveHour, 100.0, T0 + 3600.0)],
        );
    }

    assert_eq!(board.tick(), TickOutcome::Blocked);

    let exhausted = board.last("all-exhausted").unwrap();
    assert_eq!(
        exhausted["earliestResetAt"],
        format_ts(T0 + 3600.0).unwrap()
    );
    assert!(
        board.last("no-switch").is_none(),
        "the API-key slot is not a candidate at all: {:?}",
        board.kinds()
    );
}

/// With no OAuth peer left, the API-key slot IS the whole story — and which
/// story depends on the flag. Off: it is not a candidate, so there are none.
/// On: it is the only candidate, and swapd cannot land on it, so it says so.
#[test]
fn an_api_key_slot_alone_is_no_candidates_until_it_is_opted_in() {
    let board = Board::new();
    // Slot 2 is the only peer, and it is a managed key.
    board.seed_api_key(2, "keyed@example.com");
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::Blocked);
    assert_eq!(board.last("no-switch").unwrap()["reason"], "no-candidates");

    set(&board, "includeApiKeyAccounts", Value::Bool(true));
    board.advance(400.0);
    board
        .driver
        .set_usage("one@example.com", usage_at(95.0, board.now(), 3600.0));
    assert_eq!(board.tick(), TickOutcome::Blocked);
    let refused = board.last("no-switch").unwrap();
    assert_eq!(refused["reason"], "unsupported");
    assert!(
        refused["detail"].as_str().unwrap().contains("slots 2"),
        "{refused}"
    );
}

/// When the active account and every peer are over the threshold there is no
/// "land somewhere healthy" left, and the goal becomes soonest back. The
/// account with the MOST headroom is deliberately not the one taken.
#[test]
fn with_everything_above_the_threshold_the_soonest_back_wins() {
    let board = Board::new();
    board.seed(3, "three@example.com", "rt-3", T0 + 86_400.0);
    // Active: 4% left, back in four hours.
    board
        .driver
        .set_usage("one@example.com", usage_at(96.0, T0, 4.0 * 3600.0));
    // Slot 2: less headroom than slot 3, but back in half an hour.
    board
        .driver
        .set_usage("two@example.com", usage_at(95.0, T0, 1800.0));
    // Slot 3: the most headroom of the three, and back last.
    board
        .driver
        .set_usage("three@example.com", usage_at(91.0, T0, 3.0 * 3600.0));

    assert_eq!(board.tick(), TickOutcome::Switched);
    let switched = board.last("switch").unwrap();
    assert_eq!(
        switched["to"]["number"], 2,
        "ranked by headroom this would be slot 3"
    );
}

/// A spent active account with only a near-spent peer: the ratio margin refuses
/// every candidate, and without the one-way fallback the engine would park in
/// that band reporting `no-qualifying-candidate` while a usable account sat
/// there resetting sooner.
#[test]
fn a_spent_active_falls_back_to_the_only_thing_left() {
    let board = Board::new();
    // 3% left, back in six hours — past the recovery horizon, so the ranking
    // is on headroom and 5% does not beat 3% by the 2x margin.
    board
        .driver
        .set_usage("one@example.com", usage_at(97.0, T0, 6.0 * 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(95.0, T0, 5.0 * 3600.0));

    assert_eq!(board.tick(), TickOutcome::Switched);
    assert_eq!(board.last("switch").unwrap()["to"]["number"], 2);
}

/// consume-first's three ways of doing nothing, in the order a user meets
/// them: an active account whose weekly reset nobody has reported, a fleet
/// where nothing resets sooner, and a target whose measurement is too old to
/// act on. The last one matters most — consume-first decides BELOW the
/// threshold, where a stored number can be a full candidate interval old.
#[test]
fn consume_first_holds_on_unknown_resets_later_resets_and_stale_usage() {
    let board = Board::new();
    set(&board, "strategy", Value::from("consume-first"));
    // No weekly reset reported for the active account.
    board.driver.set_usage(
        "one@example.com",
        vec![
            window(WindowKind::FiveHour, 50.0, T0 + 3600.0),
            Window {
                kind: WindowKind::SevenDay,
                name: None,
                pct: 25.0,
                resets_at: None,
                pace: None,
                used: None,
                limit: None,
                currency: None,
            },
        ],
    );
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    assert_eq!(board.tick(), TickOutcome::NoAction);
    assert_eq!(board.last("no-switch").unwrap()["reason"], "reset-unknown");

    // Now the active account's weekly window resets first: nothing to trade up
    // to, whatever the peer's headroom.
    board.advance(400.0);
    let now = board.now();
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, now, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, now, 7200.0));
    assert_eq!(board.tick(), TickOutcome::NoAction);
    assert_eq!(
        board.last("no-switch").unwrap()["reason"],
        "already-consuming-soonest"
    );

    assert_eq!(board.live_email(), "one@example.com");
}

/// A consume-first pick can have ridden a measurement a full candidate interval
/// old — the schedule only guarantees freshness for what it nominated, and
/// consume-first is the one trigger that decides outside the escalation band.
/// The commit is therefore two-phase: refetch the pair the decision turns on,
/// re-rank, and only then move.
#[test]
fn consume_first_refetches_a_stale_pick_before_it_commits() {
    let board = stale_consume_first_pick();

    assert_eq!(board.driver.take_usage_calls().len(), 0);
    assert_eq!(board.tick(), TickOutcome::Switched, "{:?}", board.kinds());

    let refetched = board.driver.take_usage_calls();
    assert!(
        refetched.contains(&"two@example.com".to_string()),
        "the pick must be measured again before it is landed on: {refetched:?}"
    );
    assert_eq!(board.live_email(), "two@example.com");
    assert_eq!(board.last("switch").unwrap()["trigger"], "consume-first");
}

/// The other half of the two-phase commit: when the account cannot be measured
/// after all, the engine holds rather than landing on a number it has stopped
/// trusting.
#[test]
fn consume_first_holds_when_the_refetch_fails() {
    let board = stale_consume_first_pick();
    board.driver.fail_usage("two@example.com");

    assert_eq!(board.tick(), TickOutcome::NoAction, "{:?}", board.kinds());

    // The re-measure spends a request on the pick, and none on the active
    // account: phase A measured it moments ago, and this hold repeats on every
    // tick for as long as the pick's endpoint is down.
    let calls = board.driver.take_usage_calls();
    assert_eq!(
        calls.iter().filter(|e| *e == "one@example.com").count(),
        1,
        "{calls:?}"
    );

    let held = board.last("no-switch").unwrap();
    assert_eq!(held["reason"], "stale-usage");
    assert!(
        held["detail"]
            .as_str()
            .unwrap()
            .contains("the fetch failed"),
        "{held}"
    );
    assert_eq!(board.live_email(), "one@example.com");
}

/// A board whose next tick is a consume-first switch onto slot 2, except that
/// slot 2's measurement is 400 s old (past the 180 s serve TTL) and its own
/// poll plan is not due — the exact state cswap's two-phase commit exists for.
fn stale_consume_first_pick() -> Board {
    let board = Board::new();
    // Slot 2's weekly window resets sooner, so it is the consume-first pick.
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 7200.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    // Two ticks under the default `best` strategy, which does nothing at 50%,
    // to give both accounts a learned plan: after them slot 2 is next due at
    // T0+850, so the tick at T0+800 cannot nominate it and it goes into the
    // decision 400 s old.
    assert_eq!(board.tick(), TickOutcome::NoAction);
    board.advance(400.0);
    assert_eq!(board.tick(), TickOutcome::NoAction);
    board.advance(400.0);
    let now = board.now();
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, now, 7200.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, now, 3600.0));
    set(&board, "strategy", Value::from("consume-first"));
    board.driver.take_usage_calls();
    board
}

/// An active token that expired while the CLI was idle is not a failing
/// account: Claude Code refreshes it on first use, so there is no quota burn
/// and nothing to switch for. The engine crawls instead of spending failover
/// ticks on it.
#[test]
fn an_expired_active_token_idle_holds_instead_of_failing_over() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(50.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));
    assert_eq!(board.tick(), TickOutcome::NoAction);

    // The CLI's live login expires while nobody is using it. The next tick is
    // inside the active account's plan, so nothing refreshes it: the collector
    // reports the expiry rather than a measurement.
    *board.driver.live.lock().unwrap() = Some(login("one@example.com", "rt-1", T0 - 1.0));
    board.advance(10.0);
    let (outcome, delay) = board.tick_and_schedule();
    assert_eq!(outcome, TickOutcome::NoAction);
    let held = board.last("no-switch").unwrap();
    assert_eq!(held["reason"], "active-idle", "{:?}", board.kinds());
    assert_eq!(delay, 300.0, "an idle hold crawls instead of polling");
    assert!(
        board.last("switch").is_none(),
        "an idle CLI is not a reason to move the user's account"
    );
}

/// Python's `max` keeps the FIRST maximal element and Rust's `max_by` the
/// last, and two windows at the same pct is routine the moment an account is
/// spent — so this one line decides whether the engine schedules around the 5h
/// reset (as cswap does) or the weekly one, and with it the recovery tier, the
/// recovery release and every hysteresis on that axis.
#[test]
fn a_tie_between_windows_binds_on_the_first_one() {
    let tied = vec![
        window(WindowKind::FiveHour, 100.0, T0 + 3600.0),
        window(WindowKind::SevenDay, 100.0, T0 + 86_400.0),
    ];
    assert_eq!(binding_recovery_ts(&tied, &[], T0), T0 + 3600.0);
}

#[test]
fn disabled_keeps_polling_and_never_switches() {
    let board = Board::new();
    set(&board, "enabled", Value::from(false));
    board
        .driver
        .set_usage("one@example.com", usage_at(99.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    assert_eq!(board.tick(), TickOutcome::NoAction);

    // The poll still happened — every display reads that stream.
    assert_eq!(board.kinds(), vec!["poll", "no-switch"]);
    assert_eq!(board.last("no-switch").unwrap()["reason"], "disabled");
    assert!(board.driver.writes.lock().unwrap().is_empty());
}

/// The policy file is re-read every tick, so `swapd config set` takes effect
/// without restarting the daemon — and the collector must decide on the same
/// values, not on the ones the process started with.
#[test]
fn a_threshold_change_takes_effect_without_a_restart() {
    let board = Board::new();
    board
        .driver
        .set_usage("one@example.com", usage_at(80.0, T0, 3600.0));
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    // One engine across both ticks: a fresh process would re-read the file on
    // its own, so only a held engine can prove the RE-read.
    let mut engine = board.engine();
    assert_eq!(engine.tick(), TickOutcome::NoAction);
    assert_eq!(
        board.last("no-switch").unwrap()["reason"],
        "below-threshold"
    );

    set(&board, "threshold", Value::from(75.0));
    board.advance(400.0);
    assert_eq!(engine.tick(), TickOutcome::Switched);
    assert_eq!(board.last("poll").unwrap()["threshold"], 75.0);
    assert_eq!(board.live_email(), "two@example.com");
}

/// The active account has no readable usage: the engine counts unhealthy ticks
/// before failing over, and says how far along it is.
#[test]
fn an_unreadable_active_account_fails_over_after_unhealthy_ticks() {
    let board = Board::new();
    set(&board, "unhealthyTicks", Value::from(2));
    // No usage table entry for slot 1 → the fetch fails, and nothing has ever
    // measured it, so its headroom is unknown.
    board
        .driver
        .set_usage("two@example.com", usage_at(10.0, T0, 3600.0));

    let mut engine = board.engine();
    assert_eq!(engine.tick(), TickOutcome::NoAction);
    let held = board.last("no-switch").unwrap();
    assert_eq!(held["reason"], "active-usage-unknown");
    assert_eq!(held["detail"], "1/2 before failover");
    // The cause is reported next to the unknown, not swallowed.
    assert_eq!(board.last("poll").unwrap()["fetchErrors"]["1"], "http-500");

    // The second consecutive unreadable tick is the one that fails over.
    board.advance(400.0);
    assert_eq!(engine.tick(), TickOutcome::Switched);
    assert_eq!(board.last("switch").unwrap()["trigger"], "failover");
    assert_eq!(board.live_email(), "two@example.com");
}

/// The bar that keeps the engine from undoing its own last move: the account
/// it just left is not a target again until it is provably a different
/// proposition than the one it was at departure (`_no_return_account`).
///
/// The numbers are the point. The barred account is the BEST candidate on the
/// board — without the bar the ranking takes it straight back, which is the
/// flap — and it clears none of the release legs: it does not dominate the
/// active (23 is not more than 10x2+3), it has not gained the spent margin on
/// its own departure baseline (23 against 23), and its binding window comes
/// back exactly when it did then.
#[test]
fn the_account_just_left_is_not_taken_straight_back() {
    // Slot 2 is live and at the threshold; slot 1 was left a moment ago and
    // still has more headroom than slot 3.
    let board = leaving_slot_one();
    board.set_state(&AutoState {
        schema_version: 1,
        cooldown_until: None,
        quarantine: BTreeMap::new(),
        left_at_limit: Some(Departure {
            from: 1,
            to: 2,
            trigger: "proactive".to_string(),
            headroom: Some(23.0),
            recovery_at: Some(T0 + 3600.0),
        }),
    });

    assert_eq!(board.tick(), TickOutcome::Switched);
    assert_eq!(
        board.last("switch").unwrap()["to"]["number"],
        3,
        "the barred account must not be taken back while an alternative exists"
    );

    // The counterfactual, so the assertion above is about the bar and not
    // about the ranking: with no departure on record, slot 1 wins outright.
    let board = leaving_slot_one();
    assert_eq!(board.tick(), TickOutcome::Switched);
    assert_eq!(board.last("switch").unwrap()["to"]["number"], 1);
}

/// The board both halves of the test above run on: slot 2 live at 90% (the
/// threshold, so a proactive switch fires), slot 1 at 77% and slot 3 at 80%.
fn leaving_slot_one() -> Board {
    let board = Board::new();
    board.seed(3, "three@example.com", "rt-3", T0 + 86_400.0);
    board
        .driver
        .write_live(
            &board.ctx().env,
            &Login {
                bytes: login("two@example.com", "rt-2", T0 + 86_400.0),
            },
        )
        .unwrap();
    board
        .driver
        .set_usage("two@example.com", usage_at(90.0, T0, 3600.0));
    board
        .driver
        .set_usage("one@example.com", usage_at(77.0, T0, 3600.0));
    board
        .driver
        .set_usage("three@example.com", usage_at(80.0, T0, 3600.0));
    board
}

/// The preamble is the expensive half of a collection pass — `engine.lock`,
/// the live login, one secret read per slot — and a tick runs up to three fetch
/// passes over numbers that cannot have changed between them. So it runs once,
/// no matter how many phases the schedule ends up spending.
#[test]
fn one_tick_prepares_once() {
    let board = Board::new();
    board.seed(3, "three@example.com", "rt-3", T0 + 86_400.0);
    board.seed(4, "four@example.com", "rt-4", T0 + 86_400.0);
    // 80% used against a 90% threshold and a 15-point escalation margin: inside
    // the band, so the tick escalates to the whole fleet — and still below it,
    // so nothing switches and the live login cannot move under the tick.
    board
        .driver
        .set_usage("one@example.com", usage_at(80.0, T0, 3600.0));
    for email in ["two@example.com", "three@example.com", "four@example.com"] {
        board.driver.set_usage(email, usage_at(10.0, T0, 3600.0));
    }
    board.driver.take_live_reads();
    board.take_secret_gets();

    assert_eq!(board.tick(), TickOutcome::NoAction, "{:?}", board.kinds());

    // Phase A serves from the store, phase B fetches the active account and the
    // stalest due candidate, and the escalation fetches the other two.
    assert_eq!(board.driver.take_usage_calls().len(), 4);
    assert_eq!(
        board.driver.take_live_reads(),
        1,
        "three fetch passes, one preamble"
    );
    let gets = board.take_secret_gets();
    for slot in 1..=4 {
        assert_eq!(
            gets.iter()
                .filter(|key| **key == slot_key("claude", slot))
                .count(),
            2,
            "slot {slot}: one preamble read, plus the successor re-read it \
             earned by being fetched: {gets:?}"
        );
    }
    assert_eq!(gets.len(), 8, "{gets:?}");
}

/// The one thing a `Prepared` may not outlive is a switch: it names the active
/// account, and after a consume-first commit that is somebody else. Every pass
/// on that path prepares again.
#[test]
fn a_switch_tick_re_prepares() {
    let board = stale_consume_first_pick();
    board.driver.take_live_reads();

    assert_eq!(board.tick(), TickOutcome::Switched, "{:?}", board.kinds());

    assert_eq!(
        board.driver.take_live_reads(),
        2,
        "the two-phase commit's re-measure reads the live login again"
    );
    assert_eq!(board.live_email(), "two@example.com");
}
