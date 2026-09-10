//! Quota for a Gemini login: Code Assist's `retrieveUserQuota`, one bucket
//! per model with a server-chosen `resetTime` (gemini-cli v0.46.0
//! `code_assist/server.ts:363-370`, `types.ts:250-265`). The project the
//! call needs comes from `loadCodeAssist` (`setup.ts:177-183`), memoised per
//! account for the process. Never refreshes: an expired token is
//! `NeedsRefresh`, the caller's to fix.

use serde_json::{json, Value};

use crate::contract::{Window, WindowKind};
use crate::driver::gemini::oauth::{self, GeminiEndpoints};
use crate::driver::gemini::{identity, GeminiDriver};
use crate::driver::{DriverError, Login, Usage};
use crate::http;

/// What swapd calls itself to Code Assist, and on the wire (`http::agent`).
pub const USER_AGENT: &str = concat!("swapd/", env!("CARGO_PKG_VERSION"));

pub fn load_url(ep: &GeminiEndpoints) -> String {
    format!(
        "{}/v1internal:loadCodeAssist",
        ep.cloudcode.trim_end_matches('/')
    )
}

pub fn quota_url(ep: &GeminiEndpoints) -> String {
    format!(
        "{}/v1internal:retrieveUserQuota",
        ep.cloudcode.trim_end_matches('/')
    )
}

/// One authenticated POST; non-2xx classified here. 401/403 → `NeedsRefresh`
/// (the caller refreshes and retries), 429 → `Throttled` with the
/// `RetryInfo.retryDelay` seconds when the body carries one.
fn post(url: String, access_token: &str, body: &Value, what: &str) -> Result<Value, DriverError> {
    let response = http::agent(oauth::READ_TIMEOUT_S)
        .post(url)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => DriverError::Http(format!("{what}: timeout")),
            _ => DriverError::Http(format!("{what}: network")),
        })?;
    let status = response.status().as_u16();
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http(format!("{what}: network")))?;
    match status {
        200..=299 => serde_json::from_str::<Value>(&text)
            .map_err(|_| DriverError::Http(format!("{what}: malformed response"))),
        401 | 403 => Err(DriverError::NeedsRefresh),
        429 => Err(DriverError::Throttled {
            retry_after: retry_delay_seconds(&text),
        }),
        _ => Err(DriverError::Http(format!("{what}: http {status}"))),
    }
}

/// `error.details[].retryDelay` like `"40s"` (google.rpc.RetryInfo).
fn retry_delay_seconds(body: &str) -> Option<f64> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .pointer("/error/details")?
        .as_array()?
        .iter()
        .find_map(|d| d.get("retryDelay").and_then(Value::as_str))
        .and_then(|s| s.trim_end_matches('s').parse::<f64>().ok())
}

pub fn load_project(ep: &GeminiEndpoints, access_token: &str) -> Result<String, DriverError> {
    let body = json!({"metadata": {"ideType": "IDE_UNSPECIFIED", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"}});
    let reply = post(load_url(ep), access_token, &body, "loadCodeAssist")?;
    reply
        .get("cloudaicompanionProject")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            DriverError::Invalid("gemini: no code assist project for this account".to_string())
        })
}

pub fn fetch_quota(
    ep: &GeminiEndpoints,
    access_token: &str,
    project: &str,
) -> Result<Value, DriverError> {
    post(
        quota_url(ep),
        access_token,
        // Both this and the HTTP `User-Agent` (`http::agent`) carry the crate
        // version: the release workflow bumps `Cargo.toml`, and a literal here
        // would go stale at the first bump without anything noticing.
        &json!({"project": project, "userAgent": USER_AGENT}),
        "retrieveUserQuota",
    )
}

/// One `Scoped` window per named bucket. `pct` is used, not remaining;
/// `used`/`limit` only when the server sent an amount to derive them from;
/// no pace (a bucket has no start). A named bucket the server sent no
/// remaining figures for at all reads as exhausted, not as absent.
pub fn windows_at(raw: &Value) -> Vec<Window> {
    let mut out = Vec::new();
    let Some(buckets) = raw.get("buckets").and_then(Value::as_array) else {
        return out;
    };
    for bucket in buckets {
        let name = bucket
            .get("modelId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                bucket
                    .get("tokenType")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            });
        let Some(name) = name else { continue };
        let fraction = bucket.get("remainingFraction").and_then(Value::as_f64);
        let amount = bucket
            .get("remainingAmount")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<f64>().ok());
        // `retrieveUserQuota` is a protobuf-JSON endpoint, and proto3 JSON
        // omits default-valued fields: the bucket with NO `remainingFraction`
        // is the one that has none left, not one to be silently dropped —
        // dropping it reports an exhausted account as having fewer windows.
        // A positive `remainingAmount` with no fraction still cannot be
        // placed (there is no limit to divide by), so that one is skipped.
        let remaining = match (fraction, amount) {
            (Some(fraction), _) => fraction,
            (None, Some(amount)) if amount > 0.0 => continue,
            (None, _) => 0.0,
        };
        let pct = ((1.0 - remaining.clamp(0.0, 1.0)) * 100.0).clamp(0.0, 100.0);
        let (used, limit) = match amount {
            Some(amount) if remaining > 0.0 => {
                let limit = (amount / remaining).round();
                (Some(limit - amount), Some(limit))
            }
            _ => (None, None),
        };
        out.push(Window {
            kind: WindowKind::Scoped,
            name: Some(name.to_string()),
            pct,
            resets_at: bucket
                .get("resetTime")
                .and_then(Value::as_str)
                .map(str::to_string),
            pace: None,
            used,
            limit,
            currency: None,
        });
    }
    out
}

pub fn usage(driver: &GeminiDriver, login: &Login) -> Result<Usage, DriverError> {
    if oauth::is_expired(login, oauth::now_ms()) {
        return Err(DriverError::NeedsRefresh);
    }
    let access_token = oauth::access_token(login)
        .ok_or_else(|| DriverError::Invalid("no access token".to_string()))?;
    let key = identity::identity_offline(login)
        .map(|i| i.email)
        .unwrap_or_default();
    let memoised = driver
        .project_memo
        .lock()
        .ok()
        .and_then(|m| m.get(&key).cloned());
    let project = match memoised {
        Some(p) => p,
        None => {
            let p = load_project(&driver.endpoints, &access_token)?;
            if let Ok(mut m) = driver.project_memo.lock() {
                m.insert(key, p.clone());
            }
            p
        }
    };
    let raw = fetch_quota(&driver.endpoints, &access_token, &project)?;
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    Ok(Usage {
        windows: windows_at(&raw),
        fetched_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::WindowKind;
    use crate::driver::gemini::oauth::GeminiEndpoints;
    use httpmock::prelude::*;

    fn driver(server: &MockServer) -> GeminiDriver {
        GeminiDriver::new(
            GeminiEndpoints {
                oauth: server.base_url(),
                cloudcode: server.base_url(),
            },
            crate::driver::gemini::oauth::ClientSource::for_tests(),
        )
    }

    fn login(expiry_ms: i64) -> Login {
        Login {
            bytes: format!(
                r#"{{"oauth_creds":{{"access_token":"at-1","refresh_token":"rt-1","expiry_date":{expiry_ms}}},"google_account":"you@example.com"}}"#
            ),
        }
    }
    const FRESH: i64 = 4_102_444_800_000;

    #[test]
    fn buckets_become_scoped_windows_named_by_model() {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/quota.json")).unwrap();
        let windows = windows_at(&raw);
        assert_eq!(windows.len(), 3, "the unnamed bucket is dropped");
        let pro = &windows[0];
        assert_eq!(pro.kind, WindowKind::Scoped);
        assert_eq!(pro.name.as_deref(), Some("gemini-2.5-pro"));
        assert!((pro.pct - 75.0).abs() < 1e-9);
        assert_eq!(pro.resets_at.as_deref(), Some("2026-09-11T00:00:00Z"));
        assert_eq!(pro.pace, None);
        assert_eq!(pro.used, None);
        let flash = &windows[1];
        assert!((flash.pct - 10.0).abs() < 1e-9);
        assert_eq!(
            flash.limit,
            Some(200.0),
            "remainingAmount / remainingFraction"
        );
        assert_eq!(flash.used, Some(20.0));
        assert_eq!(
            windows[2].name.as_deref(),
            Some("CREDITS"),
            "tokenType names an unnamed-model bucket"
        );
        assert!((windows[2].pct - 0.0).abs() < 1e-9);
    }

    #[test]
    fn a_bucket_without_a_fraction_is_exhausted() {
        let raw = serde_json::json!({"buckets": [
            {"modelId": "gemini-2.5-pro", "resetTime": "2026-09-11T00:00:00Z"},
            {"modelId": "x", "remainingAmount": "5"},
        ]});
        let windows = windows_at(&raw);
        assert_eq!(windows.len(), 1, "the unplaceable bucket is dropped");
        assert_eq!(windows[0].name.as_deref(), Some("gemini-2.5-pro"));
        assert!((windows[0].pct - 100.0).abs() < 1e-9);
        assert_eq!(windows[0].used, None);
        assert_eq!(windows[0].limit, None);
        assert_eq!(
            windows[0].resets_at.as_deref(),
            Some("2026-09-11T00:00:00Z")
        );
    }

    #[test]
    fn usage_loads_the_project_once_then_asks_for_quota() {
        let server = MockServer::start();
        let load = server.mock(|when, then| {
            when.method(POST)
                .path("/v1internal:loadCodeAssist")
                .header("authorization", "Bearer at-1")
                .json_body_partial(r#"{"metadata":{"pluginType":"GEMINI"}}"#);
            then.status(200)
                .body(include_str!("fixtures/load_code_assist.json"));
        });
        let quota = server.mock(|when, then| {
            when.method(POST)
                .path("/v1internal:retrieveUserQuota")
                .header("authorization", "Bearer at-1")
                .header("user-agent", USER_AGENT)
                .json_body_partial(
                    serde_json::json!({"project": "projects-123", "userAgent": USER_AGENT})
                        .to_string(),
                );
            then.status(200).body(include_str!("fixtures/quota.json"));
        });
        let driver = driver(&server);
        let result = usage(&driver, &login(FRESH)).unwrap();
        assert_eq!(result.windows.len(), 3);
        assert!(result.fetched_at > 0.0);
        let _ = usage(&driver, &login(FRESH)).unwrap();
        load.assert_hits(1);
        quota.assert_hits(2);
    }

    #[test]
    fn an_expired_token_needs_a_refresh_without_a_request() {
        let server = MockServer::start();
        let any = server.mock(|when, then| {
            when.method(POST);
            then.status(200);
        });
        assert!(matches!(
            usage(&driver(&server), &login(1_000)),
            Err(DriverError::NeedsRefresh)
        ));
        any.assert_hits(0);
    }

    #[test]
    fn a_401_needs_a_refresh_and_a_429_is_throttled_from_retry_info() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(401);
        });
        assert!(matches!(
            usage(&driver(&server), &login(FRESH)),
            Err(DriverError::NeedsRefresh)
        ));

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(429).body(r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"40s"}]}}"#);
        });
        match usage(&driver(&server), &login(FRESH)) {
            Err(DriverError::Throttled { retry_after }) => assert_eq!(retry_after, Some(40.0)),
            other => panic!("{:?}", other.err()),
        }
    }

    #[test]
    fn a_reply_without_a_project_is_invalid() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1internal:loadCodeAssist");
            then.status(200)
                .body(r#"{"currentTier":{"id":"free-tier"}}"#);
        });
        assert!(matches!(
            usage(&driver(&server), &login(FRESH)),
            Err(DriverError::Invalid(_))
        ));
    }
}
