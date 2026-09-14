//! `swapd add-oauth` — sign an account in through the browser and register it,
//! with no prior login on this machine.
//!
//! The difference from `add` is who holds the OAuth client. `add` captures what
//! the provider's own CLI wrote; here swapd *is* the client: it holds the PKCE
//! verifier, listens on the loopback port the client registration names, and
//! redeems the code itself. Nothing is pasted, and the code never reaches argv,
//! a log or another process.
//!
//! The verb blocks and prints two lines: the URL to open, flushed the moment
//! the listener is up, and then the usual `add` envelope once the sign-in has
//! been redeemed and stored. Cancelling is killing the process — the listener
//! dies with it.

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cmd::add::{check_alias, compose, place, AddOutput};
use crate::core::slots::{self};
use crate::ctx::Ctx;
use crate::driver::{Driver, OauthStart};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// How long a browser round trip is given before the listener gives up.
pub const DEFAULT_TIMEOUT_S: u64 = 300;

/// How often the loopback listeners are polled while waiting. Short enough that
/// the redirect feels instant, long enough to cost nothing.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A callback request's own read budget: the browser has already connected, so
/// anything slower than this is not a browser.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Enough for the request line of any real redirect; a client sending more is
/// refused rather than read.
const MAX_REQUEST_LINE: u64 = 8 * 1024;

pub struct AddOauthOpts {
    pub slot: Option<u32>,
    pub alias: Option<String>,
    pub force: bool,
    pub timeout_s: u64,
}

/// The first line the verb prints: what to open, and where the answer will
/// land. Emitted before the wait, so a caller can open the URL while the
/// command still holds the socket.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthUrlOutput {
    pub schema_version: u32,
    pub url: String,
    pub port: u16,
}

pub fn run(
    ctx: &Ctx,
    provider: &dyn Driver,
    opts: &AddOauthOpts,
    announce: impl FnOnce(&OauthUrlOutput),
) -> Result<AddOutput> {
    if !provider.capabilities().add_oauth {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{} has no browser sign-in", provider.id()),
        ));
    }
    let id = provider.id();

    let OauthStart {
        port,
        url,
        state,
        redeem,
    } = provider.oauth_begin(&ctx.env)?;

    // The socket is taken before the URL is printed: a port already held is a
    // refusal the user should get instead of a browser window whose answer has
    // nowhere to land.
    let listeners = bind(port)?;
    announce(&OauthUrlOutput {
        schema_version: output::SCHEMA_VERSION,
        url,
        port,
    });

    let deadline = Instant::now() + Duration::from_secs(opts.timeout_s);
    let code = wait_for_code(&listeners, &state, deadline)?;
    let login = redeem(&code)?;

    // The grant response carries the account, so this is offline; the profile
    // endpoint is only reached for a provider whose grant does not.
    let identity = match provider.identity_offline(&login) {
        Some(identity) => identity,
        None => provider.identity(&login)?,
    };
    if identity.email.is_empty() {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the sign-in did not name an account; try again",
        ));
    }

    // Not activated: a credential minted here is not the login the CLI is
    // holding, and making it live is `switch`'s job (`add-token`'s rule).
    let (slot, moved_from, created) = slots::claim(ctx, id, false, |existing| {
        let owner = existing
            .slots
            .iter()
            .find(|(_, s)| slots::same_account(&identity, s))
            .map(|(n, s)| (*n, s.clone()));

        if let Some(alias) = &opts.alias {
            check_alias(existing, alias, owner.as_ref().map(|(n, _)| *n))?;
        }

        let (slot, created, prior, moved_from) = place(existing, owner, opts.slot, opts.force)?;
        let meta = compose(&identity, prior.as_ref(), opts.alias.as_deref(), ctx.now());
        Ok((slot, meta, login, moved_from, created))
    })?;

    Ok(AddOutput {
        schema_version: output::SCHEMA_VERSION,
        slot,
        email: identity.email,
        created,
        moved_from,
    })
}

/// The loopback sockets the redirect may land on.
///
/// 127.0.0.1 is required; `::1` is best-effort because a browser resolving
/// `localhost` may pick either, and a machine with IPv6 turned off has no `::1`
/// to bind. Never `[::]` or `0.0.0.0`: an authorization code must not be
/// reachable from outside this machine.
fn bind(port: u16) -> Result<Vec<TcpListener>> {
    let v4 = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
        SwapdError::new(
            ErrorCode::InvalidInput,
            format!(
                "port {port} is not free ({e}); the sign-in can only land there, \
                 so close whatever holds it (another sign-in, or a proxy) and try again"
            ),
        )
    })?;
    v4.set_nonblocking(true)?;
    let mut listeners = vec![v4];
    if let Ok(v6) = TcpListener::bind(("::1", port)) {
        if v6.set_nonblocking(true).is_ok() {
            listeners.push(v6);
        }
    }
    Ok(listeners)
}

/// Wait for the browser's redirect and answer with the code it carried.
fn wait_for_code(listeners: &[TcpListener], state: &str, deadline: Instant) -> Result<String> {
    loop {
        for listener in listeners {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Some(code) = serve(stream, state)? {
                        return Ok(code);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        if Instant::now() >= deadline {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                "the sign-in was not completed in time; run `swapd add-oauth` again",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// One connection. `None` means it was not the callback — a favicon probe, a
/// stray connection — and the wait goes on.
fn serve(stream: TcpStream, state: &str) -> Result<Option<String>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT))?;
    // Only the request line is read: everything the redirect carries is in it,
    // and the headers after it are none of swapd's business.
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST_LINE);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return Ok(None);
    }
    let mut stream = stream;

    let Some(target) = line.split_whitespace().nth(1) else {
        respond(&mut stream, "400 Bad Request", "Bad request.");
        return Ok(None);
    };
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    if path != "/callback" {
        respond(&mut stream, "404 Not Found", "Not found.");
        return Ok(None);
    }

    let params = parse_query(query);
    let param = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    if let Some(error) = param("error") {
        respond(
            &mut stream,
            "200 OK",
            "Sign-in failed. You can close this window.",
        );
        // The provider's own word for what went wrong, nothing else from the
        // query: it is attacker-supplied text on an open port.
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("the sign-in was refused ({})", sanitize(error)),
        ));
    }
    // The state proves the callback belongs to THIS attempt; anything else
    // reaching an open loopback port is not an answer to it.
    if param("state") != Some(state) {
        respond(&mut stream, "400 Bad Request", "Not this sign-in.");
        return Ok(None);
    }
    let Some(code) = param("code").filter(|c| !c.is_empty()) else {
        respond(&mut stream, "400 Bad Request", "No code.");
        return Ok(None);
    };
    let code = code.to_string();
    respond(
        &mut stream,
        "200 OK",
        "Signed in. You can close this window.",
    );
    Ok(Some(code))
}

/// A one-line HTML page and the connection closed. A failure to write it is not
/// a failure of the sign-in: the code is already in hand.
fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let body = format!("<!doctype html><meta charset=utf-8><p>{body}</p>");
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

/// `a=1&b=2` into pairs, percent-decoded. Not a general parser: a query with a
/// repeated key keeps the first, which is what a callback ever has.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (urldecode(k), urldecode(v)),
            None => (urldecode(pair), String::new()),
        })
        .collect()
}

fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A query value on its way into an error message: printable ASCII, bounded.
/// The port is open to anything on the machine, so nothing from it reaches a
/// terminal unedited.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect()
}

pub fn print_human(out: &OauthUrlOutput) {
    println!("Open this page to sign in:\n{}", out.url);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_pairs_are_decoded() {
        let params = parse_query("code=ac%2F1&state=s-1&empty=");
        assert_eq!(params[0], ("code".to_string(), "ac/1".to_string()));
        assert_eq!(params[1], ("state".to_string(), "s-1".to_string()));
        assert_eq!(params[2], ("empty".to_string(), String::new()));
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn a_stray_percent_is_kept_rather_than_eating_the_value() {
        assert_eq!(urldecode("100%"), "100%");
        assert_eq!(urldecode("a%zz"), "a%zz");
        assert_eq!(urldecode("a+b"), "a b");
    }

    #[test]
    fn an_error_from_the_query_cannot_carry_control_characters() {
        assert_eq!(sanitize("access_denied"), "access_denied");
        assert_eq!(sanitize("bad\r\nSet-Cookie: x"), "badSet-Cookie: x");
        assert_eq!(sanitize(&"x".repeat(200)).len(), 80);
    }
}
