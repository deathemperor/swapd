//! Google OAuth for the Gemini CLI's "oauth-personal" login: the token
//! endpoint the CLI's `google-auth-library` client uses, as the CLI's own
//! installed-app OAuth client.
//!
//! The client id and secret are NOT compiled in. Google's installed-app model
//! makes them public (they ship in every gemini-cli bundle), but a public
//! repository must not carry another product's OAuth client, and GitHub's
//! push protection refuses one. swapd reads them from the installed CLI's
//! bundle instead — the bytes the CLI itself would send — or from
//! `SWAPD_GEMINI_OAUTH_CLIENT_ID` / `SWAPD_GEMINI_OAUTH_CLIENT_SECRET`. They
//! are never logged, printed or exported.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::driver::gemini::live::Envelope;
use crate::driver::gemini::run;
use crate::driver::{DriverError, Env, Login};
use crate::http;

/// The CLI's OAuth client: what `client_id` / `client_secret` the token
/// endpoint expects. No `Debug`: it holds the secret.
#[derive(Clone)]
pub struct OauthClient {
    pub id: String,
    pub secret: String,
}

/// Where a driver looks for its OAuth client, captured at construction
/// (values, never a hidden environment read): an explicit pair from the
/// environment wins; else the CLI's bundle directory, scanned on first use.
#[derive(Clone, Default)]
pub struct ClientSource {
    pub explicit: Option<OauthClient>,
    pub bundle_dir: Option<PathBuf>,
}

pub const CLIENT_ID_ENV: &str = "SWAPD_GEMINI_OAUTH_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "SWAPD_GEMINI_OAUTH_CLIENT_SECRET";
/// Points at a directory of `*.js` to scan instead of the installed CLI's.
pub const BUNDLE_DIR_ENV: &str = "SWAPD_GEMINI_BUNDLE_DIR";

impl ClientSource {
    pub fn from_env(env: &Env) -> Self {
        let explicit = match (env.vars.get(CLIENT_ID_ENV), env.vars.get(CLIENT_SECRET_ENV)) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => Some(OauthClient {
                id: id.clone(),
                secret: secret.clone(),
            }),
            _ => None,
        };
        let bundle_dir = env
            .vars
            .get(BUNDLE_DIR_ENV)
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| bundle_dir_of(&run::resolve_cli(env)?));
        Self {
            explicit,
            bundle_dir,
        }
    }

    /// A synthetic client for tests: no bundle is ever scanned.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            explicit: Some(OauthClient {
                id: "id-1.apps.googleusercontent.com".to_string(),
                secret: "GOCSPX-test".to_string(),
            }),
            bundle_dir: None,
        }
    }

    /// The client this source yields, scanning the bundle when it has to.
    pub fn resolve(&self) -> Result<OauthClient, DriverError> {
        if let Some(client) = &self.explicit {
            return Ok(client.clone());
        }
        match &self.bundle_dir {
            Some(dir) => client_from_bundle(dir),
            None => Err(DriverError::Unsupported(NOT_FOUND)),
        }
    }
}

/// What every "no client" path reports; `doctor` prints the same words.
pub const NOT_FOUND: &str =
    "gemini oauth client not found: install the Gemini CLI, or set SWAPD_GEMINI_OAUTH_CLIENT_ID and SWAPD_GEMINI_OAUTH_CLIENT_SECRET";

/// The directory holding the CLI's JavaScript bundle, from the `gemini`
/// executable: npm's `bin/gemini` is a symlink into
/// `…/@google/gemini-cli/bundle/gemini.js`, so the resolved file's parent is
/// the bundle. Windows' `gemini.cmd` shim is a file next to
/// `node_modules/`, so that layout is tried second.
pub fn bundle_dir_of(cli: &Path) -> Option<PathBuf> {
    let resolved = fs::canonicalize(cli).ok()?;
    if resolved.extension().is_some_and(|e| e == "js") {
        return resolved.parent().map(Path::to_path_buf);
    }
    let dir = resolved.parent()?;
    let candidates = [
        dir.join("node_modules")
            .join("@google")
            .join("gemini-cli")
            .join("bundle"),
        dir.join("..")
            .join("lib")
            .join("node_modules")
            .join("@google")
            .join("gemini-cli")
            .join("bundle"),
    ];
    candidates.into_iter().find(|c| c.is_dir())
}

/// A `doctor` note when the installed CLI's bundle yields no client.
pub fn client_note(env: &Env) -> Option<String> {
    let source = ClientSource::from_env(env);
    match source.resolve() {
        Ok(_) => None,
        Err(_) if source.bundle_dir.is_some() => Some(
            "no oauth client found in the Gemini CLI's bundle; refresh needs SWAPD_GEMINI_OAUTH_CLIENT_ID and SWAPD_GEMINI_OAUTH_CLIENT_SECRET"
                .to_string(),
        ),
        Err(_) => None,
    }
}

/// Scan the bundle's `*.js` files (largest first) for the CLI's OAuth client:
/// the one `GOCSPX-…` installed-app secret, and the
/// `….apps.googleusercontent.com` client id nearest to it in the same file
/// (the source declares them together; a second id in the bundle belongs
/// to another flow). Ambiguity — two distinct secrets — is an error, not a
/// guess.
pub fn client_from_bundle(dir: &Path) -> Result<OauthClient, DriverError> {
    let mut files: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .map_err(|_| DriverError::Unsupported(NOT_FOUND))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "js"))
        .filter_map(|p| Some((fs::metadata(&p).ok()?.len(), p)))
        .collect();
    files.sort_by_key(|(len, _)| std::cmp::Reverse(*len));
    for (_, path) in files {
        let Ok(bytes) = fs::read(&path) else { continue };
        if let Some(client) = client_in(&bytes)? {
            return Ok(client);
        }
    }
    Err(DriverError::Unsupported(NOT_FOUND))
}

const SECRET_PREFIX: &[u8] = b"GOCSPX-";
const ID_SUFFIX: &[u8] = b".apps.googleusercontent.com";

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while from + needle.len() <= hay.len() {
        match hay[from..].windows(needle.len()).position(|w| w == needle) {
            Some(i) => {
                out.push(from + i);
                from += i + 1;
            }
            None => break,
        }
    }
    out
}

/// `Ok(None)` when the file carries no secret; `Err` when it carries two.
fn client_in(bytes: &[u8]) -> Result<Option<OauthClient>, DriverError> {
    let mut secrets: Vec<(usize, String)> = Vec::new();
    for start in find_all(bytes, SECRET_PREFIX) {
        let mut end = start + SECRET_PREFIX.len();
        while end < bytes.len() && is_token_byte(bytes[end]) {
            end += 1;
        }
        if end > start + SECRET_PREFIX.len() {
            let value = String::from_utf8_lossy(&bytes[start..end]).into_owned();
            if !secrets.iter().any(|(_, s)| *s == value) {
                secrets.push((start, value));
            }
        }
    }
    let (secret_at, secret) = match secrets.len() {
        0 => return Ok(None),
        1 => secrets.remove(0),
        _ => {
            return Err(DriverError::Invalid(
                "gemini bundle carries more than one oauth client secret".to_string(),
            ))
        }
    };
    let mut nearest: Option<(usize, String)> = None;
    for suffix_at in find_all(bytes, ID_SUFFIX) {
        let mut start = suffix_at;
        while start > 0 && is_token_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start == suffix_at {
            continue;
        }
        let id = String::from_utf8_lossy(&bytes[start..suffix_at + ID_SUFFIX.len()]).into_owned();
        let distance = start.abs_diff(secret_at);
        if nearest.as_ref().is_none_or(|(d, _)| distance < *d) {
            nearest = Some((distance, id));
        }
    }
    match nearest {
        Some((_, id)) => Ok(Some(OauthClient { id, secret })),
        None => Err(DriverError::Invalid(
            "gemini bundle carries a secret but no client id".to_string(),
        )),
    }
}

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
pub fn refresh(
    ep: &GeminiEndpoints,
    client: &OauthClient,
    login: &Login,
) -> Result<Login, DriverError> {
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
        ("client_id", client.id.as_str()),
        ("client_secret", client.secret.as_str()),
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
    for key in ["refresh_token", "id_token", "scope", "token_type"] {
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

    fn client() -> OauthClient {
        ClientSource::for_tests().explicit.unwrap()
    }

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
                .body_contains("client_id=id-1.apps.googleusercontent.com")
                .body_contains("client_secret=GOCSPX-test");
            then.status(200)
                .body(include_str!("fixtures/token_refresh.json"));
        });
        let before = now_ms();
        let rotated = refresh(&endpoints(&server), &client(), &login()).unwrap();
        mock.assert();
        let v: serde_json::Value = serde_json::from_str(&rotated.bytes).unwrap();
        assert_eq!(v["oauth_creds"]["access_token"], "at-2");
        assert_eq!(
            v["oauth_creds"]["refresh_token"], "rt-1",
            "kept from the input"
        );
        assert_eq!(v["oauth_creds"]["id_token"], "h.e30.s");
        assert_eq!(
            v["oauth_creds"]["scope"], "openid https://www.googleapis.com/auth/userinfo.email",
            "the reply's scope is adopted"
        );
        assert_eq!(
            v["oauth_creds"]["token_type"], "Bearer",
            "untouched member survives (the reply omits it)"
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
        let rotated = refresh(&endpoints(&server), &client(), &login()).unwrap();
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
            refresh(&endpoints(&server), &client(), &login()),
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
        match refresh(&endpoints(&server), &client(), &login()) {
            Err(DriverError::Throttled { retry_after }) => assert_eq!(retry_after, Some(7.0)),
            other => panic!("{:?}", other.err()),
        }
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(500);
        });
        assert!(matches!(
            refresh(&endpoints(&server), &client(), &login()),
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
            refresh(&endpoints(&server), &client(), &login),
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

    #[test]
    fn the_bundle_scan_pairs_the_secret_with_its_nearest_id() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("decoy.js"),
            "x=\"1111-aaaa.apps.googleusercontent.com\";",
        )
        .unwrap();
        let mut big = String::from("y=\"2222-bbbb.apps.googleusercontent.com\";");
        big.push_str(&"/* filler */".repeat(2000));
        big.push_str("z=\"3333-cccc.apps.googleusercontent.com\";s=\"GOCSPX-abc_DEF-123\";");
        std::fs::write(dir.path().join("chunk.js"), big).unwrap();
        let client = client_from_bundle(dir.path()).unwrap();
        assert_eq!(client.id, "3333-cccc.apps.googleusercontent.com");
        assert_eq!(client.secret, "GOCSPX-abc_DEF-123");
    }

    #[test]
    fn a_bundle_without_a_secret_or_with_two_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("a.js"),
            "x=\"1111-aaaa.apps.googleusercontent.com\";",
        )
        .unwrap();
        assert!(matches!(
            client_from_bundle(dir.path()),
            Err(DriverError::Unsupported(_))
        ));
        std::fs::write(
            dir.path().join("b.js"),
            "s=\"GOCSPX-one\";t=\"GOCSPX-two\";i=\"1-a.apps.googleusercontent.com\";",
        )
        .unwrap();
        assert!(matches!(
            client_from_bundle(dir.path()),
            Err(DriverError::Invalid(_))
        ));
        assert!(matches!(
            client_from_bundle(&dir.path().join("missing")),
            Err(DriverError::Unsupported(_))
        ));
    }

    #[test]
    fn the_explicit_pair_wins_and_an_empty_source_is_unsupported() {
        let home = crate::driver::gemini::tests::temp_home();
        let env = crate::driver::gemini::tests::env_with(
            &home,
            [
                (CLIENT_ID_ENV, "id-9.apps.googleusercontent.com"),
                (CLIENT_SECRET_ENV, "GOCSPX-nine"),
            ],
        );
        let client = ClientSource::from_env(&env).resolve().unwrap();
        assert_eq!(client.id, "id-9.apps.googleusercontent.com");
        assert!(matches!(
            ClientSource::default().resolve(),
            Err(DriverError::Unsupported(_))
        ));
        // SWAPD_GEMINI_BUNDLE_DIR names the directory to scan.
        let dir = home.path().join("bundle");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("c.js"),
            "i=\"5-e.apps.googleusercontent.com\";s=\"GOCSPX-five\";",
        )
        .unwrap();
        let env = crate::driver::gemini::tests::env_with(
            &home,
            [(BUNDLE_DIR_ENV, dir.to_str().unwrap())],
        );
        assert_eq!(
            ClientSource::from_env(&env).resolve().unwrap().secret,
            "GOCSPX-five"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_bundle_dir_follows_the_cli_symlink_into_the_package() {
        let home = crate::driver::gemini::tests::temp_home();
        let bundle = home
            .path()
            .join("lib")
            .join("node_modules")
            .join("@google")
            .join("gemini-cli")
            .join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("gemini.js"), "").unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(bundle.join("gemini.js"), bin.join("gemini")).unwrap();
        assert_eq!(
            bundle_dir_of(&bin.join("gemini")).unwrap(),
            std::fs::canonicalize(&bundle).unwrap()
        );
    }
}
