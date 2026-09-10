//! Google OAuth for the Gemini CLI's "oauth-personal" login: the token
//! endpoint the CLI's `google-auth-library` client uses, with the CLI's own
//! installed-app client (gemini-cli v0.46.0 `code_assist/oauth2.ts:76-92`).
//! The client secret is public by Google's installed-app model; it is still
//! never logged, printed or exported.

use serde_json::Value;

use crate::driver::gemini::live::Envelope;
use crate::driver::{DriverError, Env, Login};
use crate::http;

/// `OAUTH_CLIENT_ID` from oauth2.ts:76-77 at the pinned commit.
const CLIENT_ID: &str = "REDACTED-CLIENT-ID.apps.googleusercontent.com";
/// `OAUTH_CLIENT_SECRET` from oauth2.ts:85 at the pinned commit.
const CLIENT_SECRET: &str = "GOCSPX-REDACTED";

pub const REFRESH_TIMEOUT_S: u64 = 20;
pub const READ_TIMEOUT_S: u64 = 15;
/// google-auth-library's `CLOCK_SKEW_SECS_ = 300`: a token this close to
/// expiry is treated as expired.
pub const REFRESH_BUFFER_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct GeminiEndpoints {
    pub oauth: String,
    pub cloudcode: String,
}

impl GeminiEndpoints {
    pub fn from_env(env: &Env) -> Self {
        Self {
            oauth: http::base_url_from("google-oauth", |k| env.vars.get(k).cloned()),
            cloudcode: http::base_url_from("cloudcode", |k| env.vars.get(k).cloned()),
        }
    }
}

pub fn token_url(ep: &GeminiEndpoints) -> String {
    format!("{}/token", ep.oauth.trim_end_matches('/'))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn access_token(login: &Login) -> Option<String> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    envelope
        .oauth_creds
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Expired, or within the CLI's own skew buffer of it; a missing
/// `expiry_date` counts as expired (the CLI would refresh too).
pub fn is_expired(login: &Login, now_ms: i64) -> bool {
    let Ok(envelope) = Envelope::parse(&login.bytes) else {
        return true;
    };
    match envelope
        .oauth_creds
        .get("expiry_date")
        .and_then(Value::as_i64)
    {
        Some(expiry) => expiry - REFRESH_BUFFER_MS <= now_ms,
        None => true,
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `POST {oauth}/token`, form-encoded, as `refreshTokenNoCache` does.
/// `invalid_grant` → `TokenDead`; 429 → `Throttled`; other non-200 → `Http`.
/// A reply without `refresh_token` keeps the stored one (rotation is not
/// guaranteed — gemini-cli PR #26924). Untouched members of `oauth_creds`
/// survive; `google_account` is carried over.
pub fn refresh(ep: &GeminiEndpoints, login: &Login) -> Result<Login, DriverError> {
    let mut envelope = Envelope::parse(&login.bytes)
        .map_err(|_| DriverError::Http("refresh: malformed credential".to_string()))?;
    let refresh_token = envelope
        .oauth_creds
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or(DriverError::TokenDead)?
        .to_string();
    let body = form_encode(&[
        ("refresh_token", refresh_token.as_str()),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
        ("grant_type", "refresh_token"),
    ]);
    let response = http::agent(REFRESH_TIMEOUT_S)
        .post(token_url(ep))
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;
    let status = response.status().as_u16();
    if status == 429 {
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v.max(0.0));
        return Err(DriverError::Throttled { retry_after });
    }
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http("refresh: request failed".to_string()))?;
    if status != 200 {
        let error = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        return Err(match (status, error.as_str()) {
            (400 | 401, "invalid_grant") => DriverError::TokenDead,
            _ => DriverError::Http(format!("refresh: http {status}")),
        });
    }
    let Ok(Value::Object(resp)) = serde_json::from_str::<Value>(&text) else {
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };
    let (Some(access_token), Some(expires_in)) = (
        resp.get("access_token").and_then(Value::as_str),
        resp.get("expires_in").and_then(Value::as_f64),
    ) else {
        return Err(DriverError::Http("refresh: malformed response".to_string()));
    };
    envelope
        .oauth_creds
        .insert("access_token".to_string(), Value::from(access_token));
    envelope.oauth_creds.insert(
        "expiry_date".to_string(),
        Value::from(now_ms() + (expires_in * 1000.0) as i64),
    );
    for key in ["refresh_token", "id_token", "token_type"] {
        if let Some(v) = resp
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            envelope.oauth_creds.insert(key.to_string(), Value::from(v));
        }
    }
    Ok(envelope.to_login())
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn endpoints(server: &MockServer) -> GeminiEndpoints {
        GeminiEndpoints {
            oauth: server.base_url(),
            cloudcode: server.base_url(),
        }
    }

    fn login() -> Login {
        Login { bytes: r#"{"oauth_creds":{"access_token":"at-1","refresh_token":"rt-1","expiry_date":1000,"scope":"openid","token_type":"Bearer"},"google_account":"you@example.com"}"#.to_string() }
    }

    #[test]
    fn refresh_posts_the_form_and_keeps_the_old_refresh_token_when_the_reply_omits_it() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body_contains("grant_type=refresh_token")
                .body_contains("refresh_token=rt-1")
                .body_contains("client_id=");
            then.status(200)
                .body(include_str!("fixtures/token_refresh.json"));
        });
        let before = now_ms();
        let rotated = refresh(&endpoints(&server), &login()).unwrap();
        mock.assert();
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["access_token"], "at-2");
        assert_eq!(
            v["oauth_creds"]["refresh_token"], "rt-1",
            "kept from the input"
        );
        assert_eq!(v["oauth_creds"]["id_token"], "h.e30.s");
        assert_eq!(
            v["oauth_creds"]["scope"], "openid",
            "untouched members survive"
        );
        assert_eq!(v["google_account"], "you@example.com");
        let expiry = v["oauth_creds"]["expiry_date"].as_i64().unwrap();
        assert!(expiry >= before + 3_599_000 && expiry <= now_ms() + 3_599_000);
    }

    #[test]
    fn refresh_adopts_a_rotated_refresh_token() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .body(r#"{"access_token":"at-2","expires_in":10,"refresh_token":"rt-2"}"#);
        });
        let rotated = refresh(&endpoints(&server), &login()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["refresh_token"], "rt-2");
    }

    #[test]
    fn invalid_grant_is_token_dead() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400)
                .body(include_str!("fixtures/token_invalid_grant.json"));
        });
        assert!(matches!(
            refresh(&endpoints(&server), &login()),
            Err(DriverError::TokenDead)
        ));
    }

    #[test]
    fn a_429_is_throttled_and_a_500_is_transient() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(429).header("Retry-After", "7");
        });
        match refresh(&endpoints(&server), &login()) {
            Err(DriverError::Throttled { retry_after }) => assert_eq!(retry_after, Some(7.0)),
            other => panic!("{:?}", other.err()),
        }
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(500);
        });
        assert!(matches!(
            refresh(&endpoints(&server), &login()),
            Err(DriverError::Http(_))
        ));
    }

    #[test]
    fn a_login_without_a_refresh_token_is_token_dead_without_a_request() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200);
        });
        let login = Login {
            bytes: r#"{"oauth_creds":{"access_token":"a"},"google_account":null}"#.to_string(),
        };
        assert!(matches!(
            refresh(&endpoints(&server), &login),
            Err(DriverError::TokenDead)
        ));
        mock.assert_hits(0);
    }

    #[test]
    fn expiry_uses_the_five_minute_buffer() {
        let l = |ms: i64| Login {
            bytes: format!(r#"{{"oauth_creds":{{"expiry_date":{ms}}},"google_account":null}}"#),
        };
        assert!(is_expired(&l(1_000_000), 1_000_000 - REFRESH_BUFFER_MS + 1));
        assert!(!is_expired(
            &l(1_000_000),
            1_000_000 - REFRESH_BUFFER_MS - 1
        ));
        assert!(is_expired(
            &Login {
                bytes: r#"{"oauth_creds":{},"google_account":null}"#.to_string()
            },
            0
        ));
    }

    #[test]
    fn endpoints_from_env_honour_the_overrides() {
        let home = crate::driver::gemini::tests::temp_home();
        let env = crate::driver::gemini::tests::env_with(
            &home,
            [
                ("SWAPD_URL_GOOGLE_OAUTH", "http://127.0.0.1:1"),
                ("SWAPD_URL_CLOUDCODE", "http://127.0.0.1:2"),
            ],
        );
        let ep = GeminiEndpoints::from_env(&env);
        assert_eq!(ep.oauth, "http://127.0.0.1:1");
        assert_eq!(ep.cloudcode, "http://127.0.0.1:2");
        let plain = GeminiEndpoints::from_env(&crate::driver::gemini::tests::env_with(&home, []));
        assert_eq!(plain.oauth, "https://oauth2.googleapis.com");
        assert_eq!(plain.cloudcode, "https://cloudcode-pa.googleapis.com");
    }
}
