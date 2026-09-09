//! The one process-wide context the verbs run against: where swapd's data
//! lives, how it reads secrets, what time it is, and the usage table.
//!
//! Built once in `main` for the verbs that need it (`version` and `doctor` do
//! not), so a single `list` pass reads the environment once and every layer
//! below sees the same view of it.

use crate::core::settings::{self, Settings};
use crate::core::usage_store::UsageStore;
use crate::driver::Env;
use crate::errors::Result;
use crate::paths::Home;
use crate::secrets::{self, Secrets};

pub struct Ctx {
    pub home: Home,
    pub secrets: Box<dyn Secrets>,
    pub clock: Box<dyn Fn() -> f64 + Send + Sync>,
    pub settings: Settings,
    pub env: Env,
    pub store: UsageStore,
}

impl Ctx {
    pub fn from_env() -> Result<Ctx> {
        let home = Home::resolve()?;
        home.ensure()?;
        let secrets = secrets::default_secrets(&home);
        let env = Env::current(&home);
        let store = UsageStore::new(&home.usage_file());
        // One provider today, so one section is read. A multi-provider `list`
        // would want the policy of the provider it is collecting; that waits
        // for a per-provider view of the context.
        let settings = settings::load(&home, crate::DEFAULT_PROVIDER);
        Ok(Ctx {
            home,
            secrets,
            clock: Box::new(now_s),
            settings,
            env,
            store,
        })
    }

    pub fn now(&self) -> f64 {
        (self.clock)()
    }
}

fn now_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
