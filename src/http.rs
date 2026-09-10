//! Shared HTTP client helper for provider drivers.

use std::time::Duration;

pub fn agent(timeout_s: u64) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .user_agent("swapd/0.1")
        .timeout_global(Some(Duration::from_secs(timeout_s)))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Base URL for a named upstream, overridable via `SWAPD_URL_<NAME>` (with
/// `-` folded to `_`). The env lookup is injected rather than read from
/// `std::env` here: every driver is built from its own `Env`, never the
/// process environment, so callers pass a closure over `Env::vars`.
pub fn base_url_from(name: &str, get: impl Fn(&str) -> Option<String>) -> String {
    let env_key = format!("SWAPD_URL_{}", name.to_uppercase().replace('-', "_"));
    if let Some(v) = get(&env_key) {
        return v;
    }
    match env_key.as_str() {
        "SWAPD_URL_ANTHROPIC_API" => "https://api.anthropic.com".to_string(),
        "SWAPD_URL_PLATFORM" => "https://platform.claude.com".to_string(),
        "SWAPD_URL_GOOGLE_OAUTH" => "https://oauth2.googleapis.com".to_string(),
        "SWAPD_URL_CLOUDCODE" => "https://cloudcode-pa.googleapis.com".to_string(),
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_constructs_without_network() {
        let _ = agent(5);
    }

    #[test]
    fn base_url_defaults() {
        assert_eq!(
            base_url_from("anthropic-api", |_| None),
            "https://api.anthropic.com"
        );
        assert_eq!(
            base_url_from("platform", |_| None),
            "https://platform.claude.com"
        );
        assert_eq!(
            base_url_from("google-oauth", |_| None),
            "https://oauth2.googleapis.com"
        );
        assert_eq!(
            base_url_from("cloudcode", |_| None),
            "https://cloudcode-pa.googleapis.com"
        );
    }

    #[test]
    fn base_url_unknown_name_returns_unchanged() {
        assert_eq!(
            base_url_from("mystery-provider", |_| None),
            "mystery-provider"
        );
    }

    #[test]
    fn base_url_env_override() {
        let got = base_url_from("probe-only", |_| Some("http://127.0.0.1:9999".to_string()));
        assert_eq!(got, "http://127.0.0.1:9999");
    }

    #[test]
    fn base_url_env_override_looks_up_folded_key() {
        let got = base_url_from("probe-only", |k| {
            assert_eq!(k, "SWAPD_URL_PROBE_ONLY");
            None
        });
        assert_eq!(got, "probe-only");
    }
}
