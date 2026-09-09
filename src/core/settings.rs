//! Placeholder for the settings file. Task 11 reads `settings.json` into this;
//! until then every field is its default.

/// The policy knobs the collector and the poll planner read.
pub struct Settings {
    /// Binding utilization at or above which an account stops being a rotation
    /// candidate (cswap `autoswitch.threshold`).
    pub threshold: f64,
    /// Scoped-window model names that gate the account, on top of the
    /// account-wide 5h/7d windows (cswap `AutoSwitchSettings.model`, default
    /// `None`). Empty means account-wide only; the sentinel `all` is an
    /// explicit opt-in to every scoped window the account reports.
    pub models: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            threshold: 90.0,
            models: Vec::new(),
        }
    }
}
