//! One authenticated round trip, shared by the drivers' usage endpoints.
//!
//! Transport and body only: the status is **returned, not classified**. Which
//! statuses mean "refresh and retry", where a throttle's delay is carried, and
//! how a failure is spelled are all provider policy — and the spellings are
//! load-bearing (`core::collect::failure_kind` keys on them), so they stay at
//! the call sites rather than moving behind a parameter here.

use serde_json::Value;

use crate::driver::DriverError;
use crate::http;

/// A completed round trip, before anyone has judged it.
pub struct Reply {
    pub status: u16,
    /// The `Retry-After` header verbatim, when the server sent one. Read here
    /// because it must come off the response before the body consumes it;
    /// interpreting it is the caller's (the two providers disagree about
    /// whether the delay even lives in the header).
    pub retry_after: Option<String>,
    pub body: String,
}

/// An authenticated GET.
pub fn get(
    url: String,
    timeout_s: u64,
    access_token: &str,
    label: &str,
    headers: &[(&str, &str)],
) -> Result<Reply, DriverError> {
    let mut request = http::agent(timeout_s)
        .get(url)
        .config()
        // Non-2xx is a value, not a throw: the caller classifies it.
        .http_status_as_error(false)
        .build()
        .header("Authorization", format!("Bearer {access_token}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    finish(request.call(), label)
}

/// An authenticated POST of a JSON body.
pub fn post_json(
    url: String,
    timeout_s: u64,
    access_token: &str,
    label: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> Result<Reply, DriverError> {
    let mut request = http::agent(timeout_s)
        .post(url)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Authorization", format!("Bearer {access_token}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    finish(request.send_json(body), label)
}

/// The half both verbs share: classify the transport failure, read the body.
///
/// `label` prefixes both messages (`"usage: timeout"`, `"retrieveUserQuota:
/// network"`) — the caller's own wording, since the store keys on it.
fn finish(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    label: &str,
) -> Result<Reply, DriverError> {
    let response = result.map_err(|e| match e {
        ureq::Error::Timeout(_) => DriverError::Http(format!("{label}: timeout")),
        _ => DriverError::Http(format!("{label}: network")),
    })?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response
        .into_body()
        .read_to_string()
        .map_err(|_| DriverError::Http(format!("{label}: network")))?;
    Ok(Reply {
        status,
        retry_after,
        body,
    })
}
