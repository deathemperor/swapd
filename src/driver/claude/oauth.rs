//! The OAuth half of the Claude driver: token refresh and the profile oracle.
//!
//! Port of cswap `oauth.py:16-19` (constants), `oauth.py:24-30`
//! (`extract_access_token`), `oauth.py:62-68` (`is_oauth_token_expired`),
//! `oauth.py:112-196` (`try_refresh_oauth_credentials`) and `oauth.py:232-300`
//! (`fetch_oauth_profile`).
//!
//! Every upstream URL comes from an `Endpoints` value the driver was built
//! with — never from the process environment — so the httpmock suite points the
//! driver at a local server by constructing one.

use serde_json::{Map, Value};

use crate::driver::{DriverError, Env, Identity, Login};
use crate::http;

/// The `anthropic-beta` value Claude Code's OAuth endpoints require
/// (`oauth.py:16`). The usage endpoint only; `fetch_oauth_profile` sends no
/// beta header, and we send exactly what cswap sends.
pub const BETA_HEADER: &str = "oauth-2025-04-20";

/// Treat a token as expired this long before its stated expiry
/// (`oauth.py:17`), so a refresh happens before a request can 401.
pub const EXPIRY_BUFFER_MS: i64 = 5 * 60 * 1000;

/// Claude Code's public OAuth client id (`oauth.py:19`).
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// The token grant is a lock-free network call, but callers may hold Claude
/// Code's credential locks around it, so it stays inside their acquire budget
/// (`try_refresh_oauth_credentials`'s `timeout_s=10.0`).
const REFRESH_TIMEOUT_S: u64 = 10;
/// `fetch_oauth_profile` / `request_usage_data` both use 5s.
pub const READ_TIMEOUT_S: u64 = 5;

/// The upstreams this driver talks to.
///
/// A value rather than a `base_url` call per request: the driver must not read
/// the process environment (the ruling), and the test suite builds one pointing
/// at an httpmock server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub api: String,
    pub platform: String,
}

impl Endpoints {
    /// The production endpoints, honouring the `SWAPD_URL_*` overrides — read
    /// from the driver's own `Env`, never the process environment, so the
    /// driver stays built from values instead of a hidden global.
    pub fn from_env(env: &Env) -> Self {
        Self {
            api: http::base_url_from("anthropic-api", |k| env.vars.get(k).cloned()),
            platform: http::base_url_from("platform", |k| env.vars.get(k).cloned()),
        }
    }
}

pub fn token_url(ep: &Endpoints) -> String {
    format!("{}/v1/oauth/token", ep.platform)
}

pub fn profile_url(ep: &Endpoints) -> String {
    format!("{}/api/oauth/profile", ep.api)
}

pub fn usage_url(ep: &Endpoints) -> String {
    format!("{}/api/oauth/usage", ep.api)
}

/// Milliseconds since the epoch, matching Python's
/// `int(datetime.now(timezone.utc).timestamp() * 1000)`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `claudeAiOauth.accessToken`, or None for anything that is not an OAuth
/// credential object (`oauth.py:24-30`).
pub fn access_token(login: &Login) -> Option<String> {
    serde_json::from_str::<Value>(&login.bytes)
        .ok()?
        .pointer("/claudeAiOauth/accessToken")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Whether the access token is expired or inside the refresh buffer
/// (`oauth.py:62-68`). A missing or non-numeric `expiresAt` is *not* expired:
/// an unknown expiry must not trigger a refresh that spends a single-use
/// refresh token on a guess.
pub fn is_expired(login: &Login, now_ms: i64) -> bool {
    let expires_at = serde_json::from_str::<Value>(&login.bytes)
        .ok()
        .and_then(|v| {
            v.pointer("/claudeAiOauth/expiresAt")
                .and_then(Value::as_f64)
        });
    match expires_at {
        Some(expires_at) => (now_ms + EXPIRY_BUFFER_MS) as f64 >= expires_at,
        None => false,
    }
}

/// Exchange the login's refresh token for a fresh access token
/// (`oauth.py:112-196`).
///
/// The whole envelope is returned rotated: cswap mutates `claudeAiOauth` inside
/// the parsed object and re-serializes it, so every sibling key — including the
/// envelope's `oauthAccount` — travels through untouched.
///
/// Classification is cswap's, and deliberately asymmetric: permanent only when
/// the server itself rejected the grant (a 4xx *and* an explicit RFC 6749 §5.2
/// `error` member). A misclassified transient costs one retry; a misclassified
/// permanent would quarantine a live account.
///
/// - structurally complete OAuth object with no refresh token -> `TokenDead`
///   (cswap's `no_refresh_token`, which strikes at 1 like `invalid_grant`)
/// - unparseable / non-object bytes -> transient `Http` (more likely a torn
///   read than a real credential shape)
/// - 400/401/403 + body `error == "invalid_grant"` -> `TokenDead`
/// - ... `error == "invalid_client"` -> `Http("invalid_client")`; *our* client
///   credential was rejected, which is systemic and says nothing about the slot
/// - anything else -> transient `Http`
///
/// No error ever carries the response body or any token: only the HTTP status
/// and, for the two known codes, the `error` string itself.
pub fn refresh(ep: &Endpoints, login: &Login) -> Result<Login, DriverError> {
    let Ok(Value::Object(mut data)) = serde_json::from_str::<Value>(&login.bytes) else {
        return Err(DriverError::Http(
            "refresh: malformed credential".to_string(),
        ));
    };
    // `oauth.py:139-141`: a parsed object whose `claudeAiOauth` is missing, not
    // an object, or carries no refresh token is `no_refresh_token` — permanent.
    let mut oauth = match data.get("claudeAiOauth").cloned() {
        Some(Value::Object(oauth)) => oauth,
        _ => return Err(DriverError::TokenDead),
    };
    let refresh_token = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or(DriverError::TokenDead)?
        .to_string();

    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    });

    let response = http::agent(REFRESH_TIMEOUT_S)
        .post(token_url(ep))
        .config()
        // Read the body ourselves: the `error` member is the whole verdict.
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .send_json(&body)
        // The transport error's own message can name the URL; it says nothing
        // useful about the grant either way.
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;

    let status = response.status().as_u16();
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;

    if status != 200 {
        return Err(classify_refresh_status(status, &text));
    }

    let Ok(Value::Object(resp)) = serde_json::from_str::<Value>(&text) else {
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };
    let (Some(access_token), Some(expires_in)) = (
        resp.get("access_token").and_then(Value::as_str),
        resp.get("expires_in").and_then(Value::as_f64),
    ) else {
        // cswap's `resp_data["access_token"]` KeyError lands in the catch-all
        // `except Exception` -> transient.
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };

    oauth.insert("accessToken".to_string(), Value::from(access_token));
    oauth.insert(
        "expiresAt".to_string(),
        Value::from(now_ms() + (expires_in * 1000.0) as i64),
    );
    if let Some(rotated) = resp
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    {
        oauth.insert("refreshToken".to_string(), Value::from(rotated));
    }
    if let Some(scope) = resp
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let scopes: Vec<Value> = scope.split_whitespace().map(Value::from).collect();
        oauth.insert("scopes".to_string(), Value::Array(scopes));
    }
    data.insert("claudeAiOauth".to_string(), Value::Object(oauth));
    merge_token_account(&mut data, &resp);

    Ok(Login {
        bytes: serde_json::to_string(&Value::Object(data))
            .map_err(|_| DriverError::Http("refresh: malformed response".to_string()))?,
    })
}

/// Fold the token response's optional account identity into the envelope's
/// `oauthAccount` (`oauth.py:198-228` `_parse_token_account`).
///
/// The refresh grant may carry `account` / `organization` objects naming who
/// the rotated token belongs to; some responses omit them. cswap's strict
/// boundary applies: usable only with a non-empty string `account.uuid`, every
/// other field str-or-nothing, and anything malformed ignored — this identity
/// is opportunistic and must never break the refresh that carried it.
///
/// cswap's keys (`uuid`, `email`, `organizationUuid`) are translated to the ones
/// Claude Code writes in `~/.claude.json`'s `oauthAccount` (`accountUuid`,
/// `emailAddress`, `organizationUuid`) — that is the shape this envelope's
/// `oauthAccount` has, and `identity()` reads it by those names. Merged, not
/// replaced: the response carries neither `organizationName` nor the rate-limit
/// tier, and dropping them would cost the plan label.
fn merge_token_account(data: &mut Map<String, Value>, resp: &Map<String, Value>) {
    let Some(account) = resp.get("account").and_then(Value::as_object) else {
        return;
    };
    let Some(uuid) = account
        .get("uuid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|u| !u.is_empty())
    else {
        return;
    };

    let mut oauth_account = match data.get("oauthAccount") {
        Some(Value::Object(existing)) => existing.clone(),
        _ => Map::new(),
    };
    oauth_account.insert("accountUuid".to_string(), Value::from(uuid));
    if let Some(email) = account.get("email_address").and_then(Value::as_str) {
        oauth_account.insert("emailAddress".to_string(), Value::from(email));
    }
    if let Some(org_uuid) = resp
        .get("organization")
        .and_then(Value::as_object)
        .and_then(|org| org.get("uuid"))
        .and_then(Value::as_str)
    {
        oauth_account.insert("organizationUuid".to_string(), Value::from(org_uuid));
    }
    data.insert("oauthAccount".to_string(), Value::Object(oauth_account));
}

/// `oauth.py:167-192`: the body's top-level `error` member decides, and only on
/// a 400/401/403. A substring scan would misclassify — the marker can appear
/// inside another envelope's detail text, and a dead-token verdict quarantines
/// the slot on the spot.
fn classify_refresh_status(status: u16, body: &str) -> DriverError {
    if matches!(status, 400 | 401 | 403) {
        let error = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string));
        match error.as_deref() {
            Some("invalid_grant") => return DriverError::TokenDead,
            Some("invalid_client") => return DriverError::Http("invalid_client".to_string()),
            _ => {}
        }
    }
    DriverError::Http(format!("refresh: http {status}"))
}

/// Resolve an access token to the account it belongs to, or `None`
/// (`oauth.py:232-300`).
///
/// Fail-open by contract: every failure — transport, non-200, schema drift — is
/// `None`, which callers read as "unresolvable", never as an error. The
/// boundary is strict the other way: a response resolves only when it carries a
/// non-empty string `account.uuid`, so a rename keeps drift on the fail-open
/// path instead of silently degrading a switch.
///
/// The profile response carries no organization *name* and no plan, so the
/// `Identity` it yields is thinner than the config-derived one — which is why
/// `identity()` prefers the envelope's `oauthAccount` and only falls back here.
pub fn profile(ep: &Endpoints, access_token: &str) -> Option<Identity> {
    // No `anthropic-beta` here: `fetch_oauth_profile` sends none (only
    // `request_usage_data` does), and we send exactly what cswap sends.
    let response = http::agent(READ_TIMEOUT_S)
        .get(profile_url(ep))
        .config()
        .http_status_as_error(false)
        .build()
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .call()
        .ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    let text = response.into_body().read_to_string().ok()?;
    identity_from_profile(&serde_json::from_str::<Value>(&text).ok()?)
}

/// The strict `account.uuid` boundary, split out so it is testable without a
/// server (`oauth.py:288-300`).
fn identity_from_profile(data: &Value) -> Option<Identity> {
    let account = data.get("account")?.as_object()?;
    let uuid = account.get("uuid").and_then(Value::as_str)?.trim();
    if uuid.is_empty() {
        return None;
    }
    let text = |map: &Map<String, Value>, key: &str| {
        map.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let organization_uuid = data
        .get("organization")
        .and_then(Value::as_object)
        .map(|org| text(org, "uuid"))
        .unwrap_or_default();
    Some(Identity {
        email: text(account, "email"),
        organization_uuid,
        // The profile endpoint reports neither; a caller that needs them reads
        // the config identity instead.
        organization_name: String::new(),
        plan: None,
        uuid: Some(uuid.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(bytes: &str) -> Login {
        Login {
            bytes: bytes.to_string(),
        }
    }

    /// `Result::unwrap_err` needs `T: Debug`, and `Login` deliberately has no
    /// `Debug` (it holds the credential).
    fn expect_err(result: Result<Login, DriverError>) -> DriverError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    /// `Endpoints::from_env` reads the override out of the driver's own
    /// `Env`, never `std::env` — so this never touches the real process
    /// environment (racy/unsound under parallel test threads) and still
    /// proves the override reaches `Endpoints`.
    #[test]
    fn endpoints_from_env_reads_the_overrides_from_env_not_the_process() {
        let env = crate::driver::Env {
            home: std::path::PathBuf::new(),
            vars: std::collections::HashMap::from([(
                "SWAPD_URL_PLATFORM".to_string(),
                "http://127.0.0.1:1".to_string(),
            )]),
        };
        assert_eq!(Endpoints::from_env(&env).platform, "http://127.0.0.1:1");
        assert!(std::env::var("SWAPD_URL_PLATFORM").is_err());
    }

    #[test]
    fn urls_hang_off_the_endpoints() {
        let ep = Endpoints {
            api: "http://api.test".to_string(),
            platform: "http://platform.test".to_string(),
        };
        assert_eq!(token_url(&ep), "http://platform.test/v1/oauth/token");
        assert_eq!(profile_url(&ep), "http://api.test/api/oauth/profile");
        assert_eq!(usage_url(&ep), "http://api.test/api/oauth/usage");
    }

    #[test]
    fn access_token_and_expiry() {
        let l = login(r#"{"claudeAiOauth":{"accessToken":"at-1","expiresAt":1000000}}"#);
        assert_eq!(access_token(&l).as_deref(), Some("at-1"));
        // Inside the 5-minute buffer counts as expired.
        assert!(is_expired(&l, 1000000 - EXPIRY_BUFFER_MS));
        assert!(!is_expired(&l, 1000000 - EXPIRY_BUFFER_MS - 1));

        // Unknown expiry is never "expired": refreshing on a guess would spend
        // a single-use refresh token for nothing.
        let l = login(r#"{"claudeAiOauth":{"accessToken":"at-1"}}"#);
        assert!(!is_expired(&l, i64::MAX / 2));
        assert!(!is_expired(&login("not json"), 0));
        assert_eq!(access_token(&login("not json")), None);
    }

    #[test]
    fn refresh_without_a_refresh_token_is_token_dead() {
        let ep = Endpoints {
            api: "http://127.0.0.1:1".to_string(),
            platform: "http://127.0.0.1:1".to_string(),
        };
        // Structurally complete OAuth object, genuinely missing the field:
        // cswap's `no_refresh_token`, permanent. No request is made.
        let err = expect_err(refresh(
            &ep,
            &login(r#"{"claudeAiOauth":{"accessToken":"at-1"}}"#),
        ));
        assert!(matches!(err, DriverError::TokenDead));
        let err = expect_err(refresh(
            &ep,
            &login(r#"{"claudeAiOauth":{"refreshToken":""}}"#),
        ));
        assert!(matches!(err, DriverError::TokenDead));
        // Missing or non-object `claudeAiOauth` in a parsed object is the same
        // permanent verdict (`oauth.py:139-141`).
        let err = expect_err(refresh(&ep, &login(r#"{"other":1}"#)));
        assert!(matches!(err, DriverError::TokenDead));
        let err = expect_err(refresh(&ep, &login(r#"{"claudeAiOauth":"nope"}"#)));
        assert!(matches!(err, DriverError::TokenDead));

        // A torn/unparseable blob is transient instead — it is more likely a
        // partial read than a credential shape.
        let err = expect_err(refresh(&ep, &login("not json")));
        assert!(matches!(err, DriverError::Http(m) if m == "refresh: malformed credential"));
        let err = expect_err(refresh(&ep, &login("[1,2]")));
        assert!(matches!(err, DriverError::Http(m) if m == "refresh: malformed credential"));
    }

    #[test]
    fn classify_refresh_status_only_trusts_the_error_member() {
        assert!(matches!(
            classify_refresh_status(400, r#"{"error":"invalid_grant"}"#),
            DriverError::TokenDead
        ));
        assert!(matches!(
            classify_refresh_status(403, r#"{"error":"invalid_client"}"#),
            DriverError::Http(m) if m == "invalid_client"
        ));
        // The marker inside detail text is not the verdict.
        assert!(matches!(
            classify_refresh_status(400, r#"{"detail":"the invalid_grant was bad"}"#),
            DriverError::Http(m) if m == "refresh: http 400"
        ));
        // Right marker, wrong status class: transient.
        assert!(matches!(
            classify_refresh_status(500, r#"{"error":"invalid_grant"}"#),
            DriverError::Http(m) if m == "refresh: http 500"
        ));
        // Unparseable body stays transient.
        assert!(matches!(
            classify_refresh_status(401, "<html>nope</html>"),
            DriverError::Http(m) if m == "refresh: http 401"
        ));
    }

    #[test]
    fn identity_from_profile_requires_a_non_empty_uuid() {
        let ok = serde_json::json!({
            "account": {"uuid": " acc-1 ", "email": "you@example.com"},
            "organization": {"uuid": "org-1"},
        });
        assert_eq!(
            identity_from_profile(&ok),
            Some(Identity {
                email: "you@example.com".to_string(),
                organization_uuid: "org-1".to_string(),
                organization_name: String::new(),
                plan: None,
                uuid: Some("acc-1".to_string()),
            })
        );
        assert_eq!(
            identity_from_profile(&serde_json::json!({"account": {"uuid": "  "}})),
            None
        );
        assert_eq!(
            identity_from_profile(&serde_json::json!({"account": {"email": "you@example.com"}})),
            None
        );
        assert_eq!(identity_from_profile(&serde_json::json!({})), None);
    }
}
