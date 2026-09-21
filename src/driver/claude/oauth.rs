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
    /// Where the human signs in. A different host from `platform`, which is
    /// the console: this one is claude.ai, where a subscription lives.
    pub web: String,
}

impl Endpoints {
    /// The production endpoints, honouring the `SWAPD_URL_*` overrides — read
    /// from the driver's own `Env`, never the process environment, so the
    /// driver stays built from values instead of a hidden global.
    pub fn from_env(env: &Env) -> Self {
        Self {
            api: http::base_url_from("anthropic-api", |k| env.vars.get(k).cloned()),
            platform: http::base_url_from("platform", |k| env.vars.get(k).cloned()),
            web: http::base_url_from("claude-web", |k| env.vars.get(k).cloned()),
        }
    }
}

pub fn token_url(ep: &Endpoints) -> String {
    format!("{}/v1/oauth/token", ep.platform)
}

pub fn authorize_url_base(ep: &Endpoints) -> String {
    format!("{}/cai/oauth/authorize", ep.web)
}

pub fn profile_url(ep: &Endpoints) -> String {
    format!("{}/api/oauth/profile", ep.api)
}

pub fn usage_url(ep: &Endpoints) -> String {
    format!("{}/api/oauth/usage", ep.api)
}

/// The loopback port the OAuth client is registered to redirect to.
///
/// Not a choice: the authorization server refuses a `redirect_uri` the client
/// registration does not name, so this is read off Claude Code's own flow
/// rather than picked. One fixed port also means a second sign-in cannot start
/// while one is in flight, which is the behaviour we want anyway.
pub const REDIRECT_PORT: u16 = 54545;

/// What a real Claude Code login asks for today: the list its own `/login`
/// sends (Claude Code 2.1.278, the same set for the claude.ai and console
/// hosts), in its order. The authorization server refuses a set that is not
/// the registered one — a five-scope subset that was accepted until 2026-09-20
/// now fails with "Invalid request format" (#50) — so this list is copied
/// rather than composed.
const REQUESTED_SCOPES: [&str; 7] = [
    "org:create_api_key",
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
    "user:plugins",
];

/// What a claude.ai grant carries: the request minus `org:create_api_key`,
/// which only a console grant gives. Claude Code stores and refreshes with
/// this set, so a token response that names no scope is recorded as this
/// rather than as the request (#51).
const SCOPES: [&str; 6] = [
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
    "user:plugins",
];

/// The exchange is a person's browser round trip away and may land on a cold
/// path; `refresh`'s 10s budget exists because callers hold credential locks
/// around it, and this one holds nothing.
const EXCHANGE_TIMEOUT_S: u64 = 30;

/// The port this sign-in will listen on.
///
/// `REDIRECT_PORT` unless the driver's `Env` names another. Not a user knob:
/// the authorization server refuses a `redirect_uri` the client registration
/// does not name, so an override only ever points at a mock upstream — which
/// is what makes the round trip testable without taking one global socket.
pub fn redirect_port(env: &Env) -> u16 {
    env.vars
        .get("SWAPD_OAUTH_PORT")
        .and_then(|value| value.parse().ok())
        .unwrap_or(REDIRECT_PORT)
}

pub fn redirect_uri(port: u16) -> String {
    format!("http://localhost:{port}/callback")
}

/// A PKCE pair: the verifier to keep, and the S256 challenge to publish.
///
/// 32 bytes of randomness, base64url without padding — RFC 7636's own shape,
/// and what Claude Code sends.
pub fn pkce() -> (String, String) {
    use base64::Engine as _;
    use sha2::Digest as _;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_le_bytes());
    }
    let verifier = b64.encode(bytes);
    let challenge = b64.encode(sha2::Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// An opaque value the callback must echo, so a request that lands on the
/// listener from anywhere else is refused rather than redeemed.
///
/// 32 bytes, like the verifier and like Claude Code's own: the authorization
/// server refuses a 16-byte one with "Invalid request format" (#52, bisected
/// in the browser 2026-09-21 — the same request with a 32-byte state went
/// through).
pub fn state() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_le_bytes());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The page to open in the browser.
///
/// `code=true` is Claude Code's own parameter: it asks the success page to
/// display the `code#state` pair for a manual paste. We send it because the
/// upstream flow does, and it costs nothing — the loopback redirect is what
/// actually carries the code back here.
pub fn authorize_url(ep: &Endpoints, port: u16, challenge: &str, state: &str) -> String {
    let params = [
        ("code", "true"),
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", &redirect_uri(port)),
        ("scope", &REQUESTED_SCOPES.join(" ")),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", urlencode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{}?{params}", authorize_url_base(ep))
}

/// Percent-encode for a query value: everything but RFC 3986's unreserved set.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Redeem an authorization code for the credential envelope Claude Code keeps.
///
/// The result is a complete `Login`: `claudeAiOauth` from the grant, and
/// whatever identity the response carried folded into `oauthAccount` by the
/// same rule a refresh uses — so the account has an offline identity from the
/// moment it is signed in, and `add-oauth` need not go to the profile endpoint.
pub fn exchange(
    ep: &Endpoints,
    port: u16,
    code: &str,
    verifier: &str,
    state: &str,
) -> Result<Login, DriverError> {
    let body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(port),
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
        "state": state,
    });
    let response = http::agent(EXCHANGE_TIMEOUT_S)
        .post(token_url(ep))
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|_| DriverError::Http("sign-in: the token request failed".to_string()))?;

    let status = response.status().as_u16();
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http("sign-in: the token response was unreadable".to_string()))?;
    if status != 200 {
        // A code is single-use and short-lived, so a 4xx here is almost always
        // "that code is spent or stale" — say so rather than print a number.
        return Err(DriverError::Http(match status {
            400 | 401 => "sign-in: the authorization code was rejected; sign in again".to_string(),
            _ => format!("sign-in: http {status}"),
        }));
    }

    let Ok(Value::Object(resp)) = serde_json::from_str::<Value>(&text) else {
        return Err(DriverError::Http(
            "sign-in: malformed token response".to_string(),
        ));
    };
    let (Some(access_token), Some(refresh_token), Some(expires_in)) = (
        resp.get("access_token").and_then(Value::as_str),
        resp.get("refresh_token").and_then(Value::as_str),
        resp.get("expires_in").and_then(Value::as_f64),
    ) else {
        return Err(DriverError::Http(
            "sign-in: malformed token response".to_string(),
        ));
    };

    let scopes: Vec<Value> = match resp.get("scope").and_then(Value::as_str) {
        Some(scope) if !scope.is_empty() => scope.split_whitespace().map(Value::from).collect(),
        _ => SCOPES.iter().map(|s| Value::from(*s)).collect(),
    };
    let mut oauth = Map::new();
    oauth.insert("accessToken".to_string(), Value::from(access_token));
    oauth.insert("refreshToken".to_string(), Value::from(refresh_token));
    oauth.insert(
        "expiresAt".to_string(),
        Value::from(now_ms() + (expires_in * 1000.0) as i64),
    );
    oauth.insert("scopes".to_string(), Value::Array(scopes));

    let mut data = Map::new();
    data.insert("claudeAiOauth".to_string(), Value::Object(oauth));
    merge_token_account(&mut data, &resp);

    Ok(Login {
        bytes: serde_json::to_string(&Value::Object(data))
            .map_err(|_| DriverError::Http("sign-in: malformed token response".to_string()))?,
    })
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
            web: "http://web.test".to_string(),
        };
        assert_eq!(token_url(&ep), "http://platform.test/v1/oauth/token");
        assert_eq!(
            authorize_url_base(&ep),
            "http://web.test/cai/oauth/authorize"
        );
        assert_eq!(profile_url(&ep), "http://api.test/api/oauth/profile");
        assert_eq!(usage_url(&ep), "http://api.test/api/oauth/usage");
    }

    #[test]
    fn a_pkce_pair_is_a_verifier_and_its_sha256() {
        use base64::Engine as _;
        use sha2::Digest as _;

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (verifier, challenge) = pkce();
        // 32 bytes, base64url without padding.
        assert_eq!(b64.decode(&verifier).unwrap().len(), 32);
        assert!(!verifier.contains('=') && !verifier.contains('+') && !verifier.contains('/'));
        assert_eq!(
            challenge,
            b64.encode(sha2::Sha256::digest(verifier.as_bytes()))
        );
        // The state is the same 32 bytes, base64url.
        assert_eq!(b64.decode(state()).unwrap().len(), 32);
        // Two calls are two sign-ins.
        assert_ne!(pkce().0, verifier);
        assert_ne!(state(), state());
    }

    #[test]
    fn the_authorize_url_carries_the_challenge_the_redirect_and_the_scopes() {
        let ep = Endpoints {
            api: "http://api.test".to_string(),
            platform: "http://platform.test".to_string(),
            web: "http://web.test".to_string(),
        };
        let url = authorize_url(&ep, 54545, "chal-1", "st/1");
        assert!(url.starts_with("http://web.test/cai/oauth/authorize?"));
        assert!(url.contains(&format!("client_id={CLIENT_ID}")));
        assert!(url.contains("code_challenge=chal-1"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("response_type=code"));
        // Reserved characters are encoded, in the value and in the redirect.
        assert!(url.contains("state=st%2F1"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A54545%2Fcallback"));
        // Space-joined, so every scope arrives as one parameter, and the set
        // is Claude Code's own, whole and in its order.
        assert!(url.contains(
            "scope=org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20\
             user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload%20user%3Aplugins&"
        ));
    }

    #[test]
    fn the_port_is_fixed_unless_the_env_names_another() {
        let env = |vars: &[(&str, &str)]| Env {
            home: std::path::PathBuf::new(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        assert_eq!(redirect_port(&env(&[])), REDIRECT_PORT);
        assert_eq!(redirect_port(&env(&[("SWAPD_OAUTH_PORT", "1234")])), 1234);
        // Anything unparseable is the default, not a panic.
        assert_eq!(
            redirect_port(&env(&[("SWAPD_OAUTH_PORT", "nope")])),
            REDIRECT_PORT
        );
        assert_eq!(redirect_uri(1234), "http://localhost:1234/callback");
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
            web: "http://127.0.0.1:1".to_string(),
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
