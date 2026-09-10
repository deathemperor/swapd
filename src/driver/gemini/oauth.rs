//! The OAuth half of the Gemini driver: token refresh. Stub — replaced by
//! Task 4, which also gives `cloudcode` and `oauth` their real default URLs.

use crate::driver::{DriverError, Env, Login};
use crate::http;

/// The upstreams this driver talks to: Google's OAuth token endpoint and the
/// Cloud Code Assist API. A value rather than a `base_url` call per request,
/// so the driver never reads the process environment and a test suite can
/// point it at a local server.
#[derive(Clone, Debug)]
pub struct GeminiEndpoints {
    pub oauth: String,
    pub cloudcode: String,
}

impl GeminiEndpoints {
    /// The production endpoints, honouring the `SWAPD_URL_*` overrides. Until
    /// Task 4 adds their real defaults, `base_url_from` falls back to the
    /// name itself as the URL.
    pub fn from_env(env: &Env) -> Self {
        Self {
            oauth: http::base_url_from("google-oauth", |k| env.vars.get(k).cloned()),
            cloudcode: http::base_url_from("cloudcode", |k| env.vars.get(k).cloned()),
        }
    }
}

pub fn refresh(_ep: &GeminiEndpoints, _login: &Login) -> Result<Login, DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}
