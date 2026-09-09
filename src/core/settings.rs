//! `settings.json` — the policy knobs, one section per provider.
//!
//! Port of cswap's `settings.py`, with its two readers kept apart: loading is
//! lenient (an out-of-range or mistyped value is clamped or dropped back to the
//! default with a warning on stderr, `_clamped` settings.py:238), while
//! `config set` is strict (`parse_setting_value` settings.py:368) so the user
//! learns about a bad value when they type it rather than by degraded behaviour
//! at rotate time.
//!
//! The file is `{"schemaVersion":1,"providers":{"<provider>":{…}}}` and keys
//! outside the specs below — a future field, another tool's experiment —
//! survive a write untouched.
//!
//! cswap's `resumeStoppedSessions`, `rearm*`, `limitScanIntervalSeconds` and
//! `ui.theme` are deliberately not ported: Infinitus owns the resume/nudge
//! mechanism and swapd has no TUI.

use std::path::Path;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::core::store::{write_json_atomic, FileLock};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::paths::Home;

/// The `settings.json` layout this build writes.
pub const SCHEMA_VERSION: u32 = 1;

/// How long to wait for `settings.json`'s lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// The policy knobs the collector, the ranking and (later) the auto loop read.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// Whether the auto loop may switch at all. Stored for the daemon; the
    /// one-shot verbs are what the user asked for and never consult it.
    pub enabled: bool,
    /// Binding utilization at or above which an account stops being a rotation
    /// candidate (cswap `autoswitch.threshold`).
    pub threshold: f64,
    /// The auto loop's poll interval, in seconds.
    pub interval_seconds: f64,
    /// Minimum seconds between two proactive switches.
    pub cooldown_seconds: f64,
    /// How far a candidate must beat the active account to be worth taking.
    pub hysteresis_pct: f64,
    /// The auto loop's ranking strategy (`core::switch::Strategy`).
    pub strategy: String,
    /// Whether managed API-key accounts may be rotated onto. Stored only: the
    /// Claude driver refuses to make a managed key the live login
    /// (`can_activate`), so nothing ranks them today.
    pub include_api_key_accounts: bool,
    /// Consecutive failed polls before the auto loop calls an account unhealthy.
    pub unhealthy_ticks: u32,
    /// Accounts to land on first, as lowercased emails, aliases or slot numbers
    /// (cswap `parse_preferred`).
    pub preferred: Vec<String>,
    /// Scoped-window model names that gate the account, on top of the
    /// account-wide 5h/7d windows (cswap `AutoSwitchSettings.model`, default
    /// `None`). Empty means account-wide only; the sentinel `all` is an
    /// explicit opt-in to every scoped window the account reports.
    ///
    /// The field keeps its plural name (the collector reads it) while the file
    /// key stays cswap's `model`.
    pub models: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 90.0,
            interval_seconds: 60.0,
            cooldown_seconds: 300.0,
            hysteresis_pct: 10.0,
            strategy: "best".to_string(),
            include_api_key_accounts: false,
            unhealthy_ticks: 3,
            preferred: Vec::new(),
            models: Vec::new(),
        }
    }
}

/// What one key accepts. The single source of truth for bounds and choices:
/// the lenient clamp on load and the strict parse in `config set` both read it,
/// so the two cannot drift (cswap `SettingSpec`, settings.py:107).
pub enum Kind {
    Bool,
    Float {
        lo: f64,
        hi: f64,
    },
    Int {
        lo: i64,
        hi: i64,
    },
    Choice(&'static [&'static str]),
    /// A list of names: comma-separated on the command line, a JSON array in
    /// the file. `lowercase` matches cswap's `parse_preferred`, which compares
    /// case-insensitively; `model` keeps the spelling it was given.
    List {
        lowercase: bool,
    },
}

pub struct Spec {
    /// The camelCase key inside the provider's section.
    pub key: &'static str,
    pub kind: Kind,
    pub help: &'static str,
}

pub const SPECS: &[Spec] = &[
    Spec {
        key: "enabled",
        kind: Kind::Bool,
        help: "Auto-switching on/off — off keeps polling usage, never switches",
    },
    Spec {
        key: "threshold",
        kind: Kind::Float { lo: 50.0, hi: 99.9 },
        help: "Switch when the binding 5h/7d window reaches this pct",
    },
    Spec {
        key: "intervalSeconds",
        kind: Kind::Float {
            lo: 15.0,
            hi: 3600.0,
        },
        help: "Poll interval for the auto loop, in seconds",
    },
    Spec {
        key: "cooldownSeconds",
        kind: Kind::Float {
            lo: 0.0,
            hi: 86400.0,
        },
        help: "Minimum seconds between proactive switches",
    },
    Spec {
        key: "hysteresisPct",
        kind: Kind::Float { lo: 0.0, hi: 50.0 },
        help: "A target must beat the active account by this many pct",
    },
    Spec {
        key: "strategy",
        kind: Kind::Choice(&["best", "consume-first", "next-available"]),
        help: "How the auto loop picks the target account",
    },
    Spec {
        key: "includeApiKeyAccounts",
        kind: Kind::Bool,
        help: "Allow rotating onto managed API-key accounts (bill per token) \
               — stored only in phase 1: a managed key cannot be made the live login",
    },
    Spec {
        key: "unhealthyTicks",
        kind: Kind::Int { lo: 1, hi: 100 },
        help: "Consecutive failed polls before an account is unhealthy",
    },
    Spec {
        key: "preferred",
        kind: Kind::List { lowercase: true },
        help: "Accounts to land on first (emails, aliases and/or slot numbers, comma-separated)",
    },
    Spec {
        key: "model",
        kind: Kind::List { lowercase: false },
        help: "Also switch on these models' weekly limits (e.g. Fable, Fable,Opus, or all)",
    },
];

/// The spec for a camelCase key, if it is one swapd knows.
pub fn spec(key: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.key == key)
}

impl Settings {
    /// This key's value as `settings.json` would write it.
    pub fn value(&self, key: &str) -> Value {
        match key {
            "enabled" => Value::from(self.enabled),
            "threshold" => Value::from(self.threshold),
            "intervalSeconds" => Value::from(self.interval_seconds),
            "cooldownSeconds" => Value::from(self.cooldown_seconds),
            "hysteresisPct" => Value::from(self.hysteresis_pct),
            "strategy" => Value::from(self.strategy.clone()),
            "includeApiKeyAccounts" => Value::from(self.include_api_key_accounts),
            "unhealthyTicks" => Value::from(self.unhealthy_ticks),
            "preferred" => Value::from(self.preferred.clone()),
            "model" => Value::from(self.models.clone()),
            _ => Value::Null,
        }
    }

    /// Take one stored value, leniently: clamp a number into range, drop a
    /// mistyped or unknown one back to the default, and say so on stderr.
    fn apply(&mut self, spec: &Spec, raw: &Value) {
        let key = spec.key;
        match &spec.kind {
            Kind::Bool => match raw.as_bool() {
                Some(v) => self.set_bool(key, v),
                None => warn_type(key, raw, "a boolean"),
            },
            Kind::Float { lo, hi } => match number(raw) {
                Some(v) => self.set_float(key, v.clamp(*lo, *hi)),
                None => warn_type(key, raw, "a number"),
            },
            Kind::Int { lo, hi } => match number(raw) {
                Some(v) => self.set_int(key, v.clamp(*lo as f64, *hi as f64) as u32),
                None => warn_type(key, raw, "an integer"),
            },
            Kind::Choice(choices) => match raw.as_str() {
                Some(v) if choices.contains(&v) => self.set_choice(key, v),
                _ => warn_type(key, raw, &format!("one of {}", choices.join(", "))),
            },
            Kind::List { lowercase } => match list(raw, *lowercase) {
                Some(v) => self.set_list(key, v),
                None => warn_type(key, raw, "a list of names"),
            },
        }
    }

    fn set_bool(&mut self, key: &str, v: bool) {
        match key {
            "enabled" => self.enabled = v,
            "includeApiKeyAccounts" => self.include_api_key_accounts = v,
            _ => {}
        }
    }

    fn set_float(&mut self, key: &str, v: f64) {
        match key {
            "threshold" => self.threshold = v,
            "intervalSeconds" => self.interval_seconds = v,
            "cooldownSeconds" => self.cooldown_seconds = v,
            "hysteresisPct" => self.hysteresis_pct = v,
            _ => {}
        }
    }

    fn set_choice(&mut self, key: &str, v: &str) {
        if key == "strategy" {
            self.strategy = v.to_string();
        }
    }

    fn set_int(&mut self, key: &str, v: u32) {
        if key == "unhealthyTicks" {
            self.unhealthy_ticks = v;
        }
    }

    fn set_list(&mut self, key: &str, v: Vec<String>) {
        match key {
            "preferred" => self.preferred = v,
            "model" => self.models = v,
            _ => {}
        }
    }
}

/// A stored number, never a boolean (cswap's `num`: `isinstance(value, bool)`
/// is rejected before the numeric check).
fn number(raw: &Value) -> Option<f64> {
    raw.as_f64()
}

/// A stored list: an array of names, or cswap's comma-separated string.
///
/// Trimmed, empties dropped, deduped case-insensitively with the first
/// spelling winning (`parse_model_names` settings.py:215); `lowercase` folds
/// the tokens as `parse_preferred` (settings.py:229) does.
fn list(raw: &Value, lowercase: bool) -> Option<Vec<String>> {
    let tokens: Vec<String> = match raw {
        Value::String(s) => s.split(',').map(str::to_string).collect(),
        Value::Array(items) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()?,
        Value::Null => return Some(Vec::new()),
        _ => return None,
    };
    Some(normalize(tokens, lowercase))
}

fn normalize(tokens: Vec<String>, lowercase: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in tokens {
        let name = token.trim();
        if name.is_empty() {
            continue;
        }
        let name = if lowercase {
            name.to_lowercase()
        } else {
            name.to_string()
        };
        if !out
            .iter()
            .any(|kept| kept.to_lowercase() == name.to_lowercase())
        {
            out.push(name);
        }
    }
    out
}

fn warn_type(key: &str, raw: &Value, expected: &str) {
    eprintln!("warning: settings.json: {key} expects {expected}, got {raw}; using the default");
}

/// One provider's settings, or the defaults when the file (or the section) is
/// not there. Never fails: a missing, corrupt or hand-mangled file degrades to
/// default behaviour with a warning (cswap `_read_raw`, settings.py:275) — and
/// that includes a `schemaVersion` this build does not know, whose keys are
/// still read for whatever they are worth. Refusing to *read* a newer file
/// would leave a policy verb with no policy at all; refusing to *write* one is
/// `edit`'s job.
pub fn load(home: &Home, provider: &str) -> Settings {
    let raw = read_lenient(&home.settings_file());
    if let Some(version) = foreign_version(&raw) {
        eprintln!(
            "warning: settings.json is schemaVersion {version}, not {SCHEMA_VERSION}; \
             reading it anyway"
        );
    }
    let mut settings = Settings::default();
    let Some(section) = section_of(&raw, provider) else {
        return settings;
    };
    for spec in SPECS {
        if let Some(raw) = section.get(spec.key) {
            settings.apply(spec, raw);
        }
    }
    settings
}

/// The same fold, over a section a caller already has (`config list`).
pub fn from_section(section: Option<&Map<String, Value>>) -> Settings {
    let mut settings = Settings::default();
    if let Some(section) = section {
        for spec in SPECS {
            if let Some(raw) = section.get(spec.key) {
                settings.apply(spec, raw);
            }
        }
    }
    settings
}

pub fn section_of<'a>(
    raw: &'a Map<String, Value>,
    provider: &str,
) -> Option<&'a Map<String, Value>> {
    raw.get("providers")?.get(provider)?.as_object()
}

/// The file as a JSON object, warning and yielding an empty one for anything
/// unreadable. The read every *policy* consumer uses.
fn read_lenient(path: &Path) -> Map<String, Value> {
    match read_strict(path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("warning: {}: {}; using defaults", path.display(), e.message);
            Map::new()
        }
    }
}

/// The file as a JSON object, or an error. A missing file is an empty object;
/// a corrupt one is an error, so `config set` refuses to overwrite settings it
/// could not read rather than silently resetting them.
pub fn read_strict(path: &Path) -> Result<Map<String, Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => return Err(e.into()),
    };
    match serde_json::from_slice(&bytes)? {
        Value::Object(map) => Ok(map),
        _ => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "settings.json is not a JSON object",
        )),
    }
}

/// The file's `schemaVersion` when it is present and is not the one this build
/// writes.
fn foreign_version(raw: &Map<String, Value>) -> Option<u64> {
    raw.get("schemaVersion")
        .and_then(Value::as_u64)
        .filter(|v| *v != SCHEMA_VERSION as u64)
}

/// Read-modify-write `settings.json` under `<settings.json>.lock`, preserving
/// every key the specs do not name.
///
/// A file stamped with another `schemaVersion` is refused rather than rewritten:
/// this build would write v1 semantics into it and leave the stamp lying about
/// what the file means.
fn edit<T>(
    home: &Home,
    mutate: impl FnOnce(&mut Map<String, Value>) -> Result<(bool, T)>,
) -> Result<T> {
    let path = home.settings_file();
    let _lock = FileLock::acquire(&path, LOCK_TIMEOUT)?;
    let mut raw = read_strict(&path)?;
    if let Some(version) = foreign_version(&raw) {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("settings.json is schemaVersion {version}; this build writes {SCHEMA_VERSION}"),
        ));
    }
    let (dirty, out) = mutate(&mut raw)?;
    if dirty {
        // Always stamped, as `slots::update` stamps `slots.json`: the file this
        // build wrote is a file this build's semantics describe.
        raw.insert("schemaVersion".to_string(), Value::from(SCHEMA_VERSION));
        write_json_atomic(&path, &Value::Object(raw))?;
    }
    Ok(out)
}

/// Store one key's already-validated value.
pub fn set(home: &Home, provider: &str, key: &str, value: Value) -> Result<()> {
    edit(home, |raw| {
        let providers = raw
            .entry("providers".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let providers = providers.as_object_mut().ok_or_else(|| {
            SwapdError::new(
                ErrorCode::InvalidInput,
                "settings.json: 'providers' is not a JSON object",
            )
        })?;
        let section = providers
            .entry(provider.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let section = section.as_object_mut().ok_or_else(|| {
            SwapdError::new(
                ErrorCode::InvalidInput,
                format!("settings.json: '{provider}' is not a JSON object"),
            )
        })?;
        section.insert(key.to_string(), value);
        Ok((true, ()))
    })
}

/// Drop one key, so the default applies again. Answers whether it was there.
pub fn unset(home: &Home, provider: &str, key: &str) -> Result<bool> {
    edit(home, |raw| {
        let removed = raw
            .get_mut("providers")
            .and_then(Value::as_object_mut)
            .and_then(|providers| providers.get_mut(provider))
            .and_then(Value::as_object_mut)
            .and_then(|section| section.remove(key))
            .is_some();
        Ok((removed, removed))
    })
}

/// Strictly parse a command-line string for `config set` (cswap
/// `parse_setting_value`, settings.py:368): out of range or mistyped is an
/// error naming the range or the choices, never a silent clamp.
pub fn parse_value(spec: &Spec, raw: &str) -> Result<Value> {
    let key = spec.key;
    match &spec.kind {
        Kind::Bool => match raw.trim().to_lowercase().as_str() {
            // Never `raw.parse::<bool>()` alone: cswap accepts 1/0 and yes/no.
            "true" | "1" | "yes" => Ok(Value::from(true)),
            "false" | "0" | "no" => Ok(Value::from(false)),
            _ => Err(invalid(format!(
                "{key} expects true or false (or 1/0, yes/no), got '{raw}'"
            ))),
        },
        Kind::Choice(choices) => {
            if choices.contains(&raw) {
                Ok(Value::from(raw))
            } else {
                Err(invalid(format!(
                    "{key} must be one of: {}",
                    choices.join(", ")
                )))
            }
        }
        Kind::Float { lo, hi } => {
            let value: f64 = raw
                .trim()
                .parse()
                .map_err(|_| invalid(format!("{key} expects a number, got '{raw}'")))?;
            if !(*lo..=*hi).contains(&value) {
                return Err(invalid(format!("{key} must be between {lo} and {hi}")));
            }
            Ok(Value::from(value))
        }
        Kind::Int { lo, hi } => {
            let value: i64 = raw
                .trim()
                .parse()
                .map_err(|_| invalid(format!("{key} expects an integer, got '{raw}'")))?;
            if !(*lo..=*hi).contains(&value) {
                return Err(invalid(format!("{key} must be between {lo} and {hi}")));
            }
            Ok(Value::from(value))
        }
        Kind::List { lowercase } => {
            let names = normalize(raw.split(',').map(str::to_string).collect(), *lowercase);
            if names.is_empty() {
                return Err(invalid(format!(
                    "{key} expects a non-empty value; use 'swapd config unset' to clear it"
                )));
            }
            Ok(Value::from(names))
        }
    }
}

fn invalid(message: impl Into<String>) -> SwapdError {
    SwapdError::new(ErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> Settings {
        from_section(value.as_object())
    }

    #[test]
    fn defaults_are_cswaps_autoswitch_defaults() {
        let s = Settings::default();
        assert!(s.enabled);
        assert_eq!(s.threshold, 90.0);
        assert_eq!(s.interval_seconds, 60.0);
        assert_eq!(s.cooldown_seconds, 300.0);
        assert_eq!(s.hysteresis_pct, 10.0);
        assert_eq!(s.strategy, "best");
        assert!(!s.include_api_key_accounts);
        assert_eq!(s.unhealthy_ticks, 3);
        assert!(s.preferred.is_empty());
        assert!(s.models.is_empty());
    }

    #[test]
    fn load_clamps_and_keeps_the_default_for_a_mistyped_value() {
        let s = section(json!({
            "threshold": 120.0,
            "unhealthyTicks": 0,
            "intervalSeconds": "soon",
            "strategy": "vibes",
        }));
        assert_eq!(s.threshold, 99.9, "clamped to the spec's ceiling");
        assert_eq!(s.unhealthy_ticks, 1, "clamped to the spec's floor");
        assert_eq!(s.interval_seconds, 60.0, "mistyped falls back");
        assert_eq!(s.strategy, "best", "unknown choice falls back");
    }

    #[test]
    fn lists_take_an_array_or_cswaps_comma_string() {
        let s = section(
            json!({"preferred": ["ONE@example.com", " 2 "], "model": "Fable, fable ,Opus"}),
        );
        assert_eq!(s.preferred, vec!["one@example.com", "2"]);
        assert_eq!(s.models, vec!["Fable", "Opus"], "first spelling wins");

        let s = section(json!({"preferred": "one@example.com, 2"}));
        assert_eq!(s.preferred, vec!["one@example.com", "2"]);
    }

    #[test]
    fn set_is_strict_where_load_is_lenient() {
        let threshold = spec("threshold").unwrap();
        assert!(parse_value(threshold, "120").is_err());
        assert_eq!(parse_value(threshold, "95").unwrap(), json!(95.0));

        let enabled = spec("enabled").unwrap();
        assert_eq!(parse_value(enabled, "no").unwrap(), json!(false));
        assert!(parse_value(enabled, "maybe").is_err());

        let strategy = spec("strategy").unwrap();
        assert!(parse_value(strategy, "vibes").is_err());
        assert_eq!(
            parse_value(strategy, "consume-first").unwrap(),
            json!("consume-first")
        );
    }
}
