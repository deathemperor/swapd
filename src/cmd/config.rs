//! `swapd config list|get|set|unset` — the `settings.json` knobs.
//!
//! Keys are `<provider>.<camelKey>` (`claude.threshold`), so one flat namespace
//! covers every provider's policy. `value` is what swapd would actually use —
//! the stored value after the lenient clamp — while `isSet` says whether the
//! file names the key at all, which is the difference between "90, because you
//! asked for 90" and "90, because that is the default".

use serde::Serialize;
use serde_json::Value;

use crate::core::settings::{self, Settings};
use crate::ctx::Ctx;
use crate::driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigOutput {
    pub schema_version: u32,
    pub settings: Vec<SettingView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingView {
    pub key: String,
    pub value: Value,
    /// Whether `settings.json` names this key, as opposed to swapd falling
    /// back to the default.
    pub is_set: bool,
    pub default: Value,
    /// One line describing the key, so a GUI can render its settings surface
    /// from this payload instead of hand-wiring a widget per key (cswap
    /// `spec_metadata`, settings.py:341).
    pub help: &'static str,
}

/// Every key of every provider (or of the one the caller named).
pub fn list(ctx: &Ctx, provider_filter: Option<&str>) -> Result<ConfigOutput> {
    let providers = providers_for(provider_filter)?;
    let raw = settings::read_strict(&ctx.home.settings_file())?;
    let mut out = Vec::new();
    for provider in providers {
        let section = settings::section_of(&raw, &provider);
        let effective = settings::from_section(section);
        for spec in settings::SPECS {
            out.push(view(
                &provider,
                spec.key,
                &effective,
                section.is_some_and(|s| s.contains_key(spec.key)),
            ));
        }
    }
    Ok(ConfigOutput {
        schema_version: output::SCHEMA_VERSION,
        settings: out,
    })
}

/// One key, in the same envelope `list` uses — so a caller parses one shape.
pub fn get(ctx: &Ctx, key: &str) -> Result<ConfigOutput> {
    let (provider, name) = split(key)?;
    let raw = settings::read_strict(&ctx.home.settings_file())?;
    let section = settings::section_of(&raw, &provider);
    Ok(one(view(
        &provider,
        name,
        &settings::from_section(section),
        section.is_some_and(|s| s.contains_key(name)),
    )))
}

pub fn set(ctx: &Ctx, key: &str, raw_value: &str) -> Result<ConfigOutput> {
    let (provider, name) = split(key)?;
    let spec = settings::spec(name).expect("split validated the key");
    settings::set(
        &ctx.home,
        &provider,
        name,
        settings::parse_value(spec, raw_value)?,
    )?;
    get(ctx, key)
}

pub fn unset(ctx: &Ctx, key: &str) -> Result<ConfigOutput> {
    let (provider, name) = split(key)?;
    settings::unset(&ctx.home, &provider, name)?;
    get(ctx, key)
}

fn one(setting: SettingView) -> ConfigOutput {
    ConfigOutput {
        schema_version: output::SCHEMA_VERSION,
        settings: vec![setting],
    }
}

fn view(provider: &str, key: &str, effective: &Settings, is_set: bool) -> SettingView {
    SettingView {
        key: format!("{provider}.{key}"),
        value: effective.value(key),
        is_set,
        default: Settings::default().value(key),
        help: settings::spec(key).map(|s| s.help).unwrap_or_default(),
    }
}

/// `<provider>.<key>`, both halves checked. An unknown key is reported with the
/// valid ones rather than silently stored: a typo that persisted would read as
/// a setting that has no effect.
fn split(key: &str) -> Result<(String, &str)> {
    let (provider, name) = key.split_once('.').ok_or_else(|| unknown_key(key))?;
    if !providers().iter().any(|p| p == provider) || settings::spec(name).is_none() {
        return Err(unknown_key(key));
    }
    Ok((provider.to_string(), name))
}

fn unknown_key(key: &str) -> SwapdError {
    let valid: Vec<String> = providers()
        .iter()
        .flat_map(|p| {
            settings::SPECS
                .iter()
                .map(move |s| format!("{p}.{}", s.key))
        })
        .collect();
    SwapdError::new(
        ErrorCode::InvalidInput,
        format!("unknown setting '{key}'; valid keys: {}", valid.join(", ")),
    )
}

fn providers() -> Vec<String> {
    driver::registry()
        .iter()
        .map(|d| d.id().to_string())
        .collect()
}

/// The registry, narrowed to the provider the caller named. An unknown one is
/// an error, as it is for `list`.
fn providers_for(filter: Option<&str>) -> Result<Vec<String>> {
    let all = providers();
    let Some(id) = filter else {
        return Ok(all);
    };
    if !all.iter().any(|p| p == id) {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown provider: {id}"),
        ));
    }
    Ok(vec![id.to_string()])
}

pub fn print_human(out: &ConfigOutput) {
    for setting in &out.settings {
        println!(
            "{} = {}{}",
            setting.key,
            render(&setting.value),
            if setting.is_set { "" } else { " (default)" }
        );
    }
}

/// Values the way a shell user reads them: a list as its comma-separated form,
/// a string bare, everything else as JSON.
fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(render).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}
