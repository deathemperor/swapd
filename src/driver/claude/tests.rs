//! Shared test scaffolding for the Claude driver, plus the network-facing
//! suite.
//!
//! The crate is a binary, so an integration test under `tests/` cannot import
//! these modules; the httpmock suite therefore lives here, with its fixtures in
//! `fixtures/` next door (scrubbed: `rt-*`/`at-*` placeholder tokens,
//! `you@example.com`, `org-0000`). No test ever reaches the real network, reads
//! a real `~/.claude`, or touches the process environment.

use std::collections::HashMap;

use tempfile::TempDir;

use crate::driver::claude::oauth::Endpoints;
use crate::driver::Env;

/// A throwaway `$HOME` for one test.
pub fn temp_home() -> TempDir {
    TempDir::new().expect("temp home")
}

/// Endpoints for a test that must make no request at all: an unroutable
/// address, so an accidental one fails immediately instead of reaching
/// Anthropic.
pub fn endpoints() -> Endpoints {
    Endpoints {
        api: "http://127.0.0.1:1".to_string(),
        platform: "http://127.0.0.1:1".to_string(),
    }
}

/// An `Env` over `home` with `vars` on top of `HOME`. No test ever touches
/// the process environment: every path and variable this module reads
/// comes from here.
pub fn env_with<'a>(home: &TempDir, vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> Env {
    let mut map = HashMap::new();
    map.insert(
        "HOME".to_string(),
        home.path().to_str().expect("utf-8 temp path").to_string(),
    );
    for (key, value) in vars {
        map.insert(key.to_string(), value.to_string());
    }
    Env {
        // swapd's own home, deliberately NOT $HOME — nothing in this
        // module may read Claude Code's paths out of it.
        home: home.path().join("swapd"),
        vars: map,
    }
}

#[cfg(test)]
mod http_tests {
    use httpmock::prelude::*;
    use serde_json::Value;

    use super::*;
    use crate::contract::WindowKind;
    use crate::driver::claude::live::{ClaudeDriver, LiveStore};
    use crate::driver::claude::{oauth, usage};
    use crate::driver::{Driver, DriverError, Login};

    const USAGE: &str = include_str!("fixtures/usage.json");
    const TOKEN_REFRESH: &str = include_str!("fixtures/token_refresh.json");
    const TOKEN_INVALID_GRANT: &str = include_str!("fixtures/token_invalid_grant.json");
    const PROFILE: &str = include_str!("fixtures/profile.json");

    /// Both fixtures' weekly windows reset at this instant.
    const WEEK_RESET: &str = "2026-09-15T10:59:59Z";
    /// Three and a half days into that week — past the 24h pace suppression,
    /// and a fixed point, so the mapping never depends on the wall clock.
    fn fetched_at() -> f64 {
        use time::format_description::well_known::Rfc3339;
        let reset = time::OffsetDateTime::parse(WEEK_RESET, &Rfc3339)
            .unwrap()
            .unix_timestamp() as f64;
        reset - 3.5 * 86400.0
    }

    fn endpoints_at(server: &MockServer) -> Endpoints {
        Endpoints {
            api: server.base_url(),
            platform: server.base_url(),
        }
    }

    fn login(bytes: &str) -> Login {
        Login {
            bytes: bytes.to_string(),
        }
    }

    fn expect_err(result: Result<Login, DriverError>) -> DriverError {
        match result {
            Err(e) => e,
            // `Login` has no `Debug` on purpose (it holds the credential), so
            // `unwrap_err` is unavailable.
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn usage_maps_five_hour_seven_day_scoped_spend() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/usage")
                .header("authorization", "Bearer at-1")
                // cswap sends the beta header on the usage request (and only
                // there); without it the endpoint does not answer.
                .header("anthropic-beta", oauth::BETA_HEADER);
            then.status(200)
                .header("content-type", "application/json")
                .body(USAGE);
        });

        let raw = usage::fetch(&endpoints_at(&server), "at-1").unwrap();
        mock.assert();
        let windows = usage::windows_at(&raw, fetched_at());

        // Order is the shape of the response: 5h, 7d, spend, then each scoped
        // limit.
        let kinds: Vec<_> = windows.iter().map(|w| w.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WindowKind::FiveHour,
                WindowKind::SevenDay,
                WindowKind::Spend,
                WindowKind::Scoped,
                WindowKind::Scoped,
            ]
        );

        let five_hour = &windows[0];
        assert_eq!(five_hour.pct, 12.5);
        assert_eq!(five_hour.resets_at.as_deref(), Some("2026-09-09T15:59:59Z"));
        // Pace never lands on the 5h window: it resets too fast to mean
        // anything.
        assert_eq!(five_hour.pace, None);

        let seven_day = &windows[1];
        assert_eq!(seven_day.pct, 61.0);
        assert_eq!(seven_day.resets_at.as_deref(), Some(WEEK_RESET));
        let pace = seven_day.pace.as_ref().expect("7d carries pace");
        // Half the week gone, 61% used: 11 points over, under the 15-point
        // marker threshold but still not on track to last.
        assert_eq!(pace.expected_pct, 50.0);
        assert!(!pace.ahead);
        assert!(!pace.lasts_to_reset);
        assert!(pace.exhausts_at.is_some());

        let spend = &windows[2];
        // Credits are cents.
        assert_eq!(spend.used, Some(12.34));
        assert_eq!(spend.limit, Some(50.0));
        assert_eq!(spend.pct, 24.68);
        assert_eq!(spend.currency.as_deref(), Some("USD"));

        // Only `limits[]` entries naming a model become scoped windows; the
        // org-scoped entry has no `scope.model.display_name` and is dropped.
        assert_eq!(windows[3].name.as_deref(), Some("Fable"));
        assert_eq!(windows[3].pct, 29.0);
        assert_eq!(windows[4].name.as_deref(), Some("Sonnet"));
        assert_eq!(windows[4].pct, 4.0);
        // A scoped window well under pace is on track and shows no marker.
        let scoped_pace = windows[4].pace.as_ref().expect("scoped carries pace");
        assert!(!scoped_pace.ahead);
        assert!(scoped_pace.lasts_to_reset);
    }

    #[test]
    fn usage_429_is_throttled_with_retry_after() {
        let server = MockServer::start();
        let throttled = server.mock(|when, then| {
            when.method(GET).path("/api/oauth/usage");
            then.status(429)
                .header("Retry-After", "90")
                .body(r#"{"error":{"message":"rate limited"}}"#);
        });

        let err = usage::fetch(&endpoints_at(&server), "at-1").unwrap_err();
        throttled.assert();
        assert!(matches!(
            err,
            DriverError::Throttled {
                retry_after: Some(seconds)
            } if seconds == 90.0
        ));
    }

    #[test]
    fn usage_429_without_retry_after_carries_none() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/oauth/usage");
            then.status(429).body("{}");
        });

        // The header is optional; a missing one is None, never a guessed delay.
        let err = usage::fetch(&endpoints_at(&server), "at-1").unwrap_err();
        assert!(matches!(err, DriverError::Throttled { retry_after: None }));
    }

    #[test]
    fn refresh_invalid_grant_is_token_dead() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/oauth/token")
                .json_body_partial(format!(
                    r#"{{"grant_type":"refresh_token","refresh_token":"rt-1","client_id":"{}"}}"#,
                    oauth::CLIENT_ID
                ));
            then.status(400)
                .header("content-type", "application/json")
                .body(TOKEN_INVALID_GRANT);
        });

        let err = expect_err(oauth::refresh(
            &endpoints_at(&server),
            &login(r#"{"claudeAiOauth":{"refreshToken":"rt-1"}}"#),
        ));
        mock.assert();
        // This lineage is dead: only a re-login fixes it.
        assert!(matches!(err, DriverError::TokenDead));
    }

    #[test]
    fn refresh_invalid_client_is_not_token_dead() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/oauth/token");
            then.status(401).body(r#"{"error":"invalid_client"}"#);
        });

        let err = expect_err(oauth::refresh(
            &endpoints_at(&server),
            &login(r#"{"claudeAiOauth":{"refreshToken":"rt-1"}}"#),
        ));
        // *Our* client credential was rejected — systemic, and no evidence at
        // all about this slot, so it must not quarantine one.
        // Its own kind, and emphatically not the one that quarantines a slot.
        assert!(!matches!(err, DriverError::TokenDead));
        assert!(matches!(err, DriverError::Http(m) if m == "invalid_client"));
    }

    #[test]
    fn refresh_transient_on_500() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/oauth/token");
            // Even with the permanent marker in the body: outside 400/401/403
            // the server is not rejecting the grant.
            then.status(500).body(r#"{"error":"invalid_grant"}"#);
        });

        let err = expect_err(oauth::refresh(
            &endpoints_at(&server),
            &login(r#"{"claudeAiOauth":{"refreshToken":"rt-1"}}"#),
        ));
        assert!(matches!(err, DriverError::Http(m) if m == "refresh: http 500"));
    }

    #[test]
    fn refresh_rotates_the_credential_and_keeps_the_envelope() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/oauth/token");
            then.status(200).body(TOKEN_REFRESH);
        });

        let before = oauth::now_ms();
        let rotated = oauth::refresh(
            &endpoints_at(&server),
            &login(
                r#"{"claudeAiOauth":{"accessToken":"at-1","refreshToken":"rt-1"},"oauthAccount":{"emailAddress":"you@example.com"}}"#,
            ),
        )
        .unwrap();

        let value: Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(value["claudeAiOauth"]["accessToken"], "at-2");
        assert_eq!(value["claudeAiOauth"]["refreshToken"], "rt-2");
        assert_eq!(value["claudeAiOauth"]["scopes"][0], "user:inference");
        assert_eq!(value["claudeAiOauth"]["scopes"][1], "user:profile");
        let expires_at = value["claudeAiOauth"]["expiresAt"].as_i64().unwrap();
        assert!(expires_at >= before + 28800 * 1000);
        // Every sibling key rides through, the envelope's identity included.
        assert_eq!(value["oauthAccount"]["emailAddress"], "you@example.com");
    }

    #[test]
    fn profile_none_on_401() {
        let server = MockServer::start();
        let denied = server.mock(|when, then| {
            when.method(GET).path("/api/oauth/profile");
            then.status(401).body(r#"{"error":"unauthorized"}"#);
        });

        // Fail-open by contract: unresolvable, never an error.
        assert_eq!(oauth::profile(&endpoints_at(&server), "at-1"), None);
        denied.assert();
    }

    #[test]
    fn profile_resolves_the_account() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/profile")
                .header("authorization", "Bearer at-1");
            then.status(200).body(PROFILE);
        });

        let identity = oauth::profile(&endpoints_at(&server), "at-1").unwrap();
        assert_eq!(identity.email, "you@example.com");
        assert_eq!(identity.organization_uuid, "org-0000");
        assert_eq!(identity.uuid.as_deref(), Some("acc-0001"));
        // The endpoint reports neither, so a caller that needs them must use
        // the config identity instead.
        assert_eq!(identity.organization_name, "");
        assert_eq!(identity.plan, None);
    }

    #[test]
    fn expired_login_is_refreshed_before_usage() {
        let server = MockServer::start();
        let token = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/oauth/token")
                .json_body_partial(r#"{"refresh_token":"rt-1"}"#.to_string());
            then.status(200).body(TOKEN_REFRESH);
        });
        // The usage request must carry the ROTATED token: an expired one would
        // only earn a 401.
        let usage_call = server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/usage")
                .header("authorization", "Bearer at-2");
            then.status(200).body(USAGE);
        });

        let driver = ClaudeDriver::new(LiveStore::File, endpoints_at(&server));
        let expired = login(&format!(
            r#"{{"claudeAiOauth":{{"accessToken":"at-1","refreshToken":"rt-1","expiresAt":{}}}}}"#,
            oauth::now_ms() - 1000
        ));

        let usage = driver.usage(&expired).unwrap();
        token.assert();
        usage_call.assert();
        assert_eq!(usage.windows.len(), 5);
        assert!(usage.fetched_at > 0.0);
    }

    #[test]
    fn a_live_token_is_not_refreshed_before_usage() {
        let server = MockServer::start();
        let token = server.mock(|when, then| {
            when.method(POST).path("/v1/oauth/token");
            then.status(500).body("{}");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/oauth/usage")
                .header("authorization", "Bearer at-1");
            then.status(200).body(USAGE);
        });

        let driver = ClaudeDriver::new(LiveStore::File, endpoints_at(&server));
        let fresh = login(&format!(
            r#"{{"claudeAiOauth":{{"accessToken":"at-1","refreshToken":"rt-1","expiresAt":{}}}}}"#,
            oauth::now_ms() + 3_600_000
        ));

        assert!(driver.usage(&fresh).is_ok());
        // A single-use refresh token is not spent on a token that still works.
        assert_eq!(token.hits(), 0);
    }

    #[test]
    fn identity_prefers_the_envelope_over_the_network() {
        let server = MockServer::start();
        let profile = server.mock(|when, then| {
            when.method(GET).path("/api/oauth/profile");
            then.status(200).body(PROFILE);
        });
        let driver = ClaudeDriver::new(LiveStore::File, endpoints_at(&server));

        // With an `oauthAccount` in the envelope the profile endpoint is never
        // asked — and the answer is richer for it (org name, plan).
        let identity = driver
            .identity(&login(
                r#"{"claudeAiOauth":{"accessToken":"at-1"},"oauthAccount":{"emailAddress":"you@example.com","organizationName":"Example Org","organizationUuid":"org-0000","userRateLimitTier":"default_claude_max_20x"}}"#,
            ))
            .unwrap();
        assert_eq!(identity.email, "you@example.com");
        assert_eq!(identity.organization_name, "Example Org");
        assert_eq!(identity.plan.as_deref(), Some("Max 20x"));
        assert_eq!(profile.hits(), 0);

        // Without one, the endpoint is the fallback.
        let identity = driver
            .identity(&login(r#"{"claudeAiOauth":{"accessToken":"at-1"}}"#))
            .unwrap();
        assert_eq!(identity.uuid.as_deref(), Some("acc-0001"));
        assert_eq!(profile.hits(), 1);
    }

    #[test]
    fn identity_without_any_source_is_invalid() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/oauth/profile");
            then.status(401).body("{}");
        });
        let driver = ClaudeDriver::new(LiveStore::File, endpoints_at(&server));

        // Neither the envelope nor the endpoint can name this login: an error,
        // never a blank identity a caller might present as an account.
        let err = driver
            .identity(&login(r#"{"claudeAiOauth":{"accessToken":"at-1"}}"#))
            .unwrap_err();
        assert!(matches!(err, DriverError::Invalid(m) if m == "no identity"));
    }
}
