use std::io::Read;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::process::Child;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::errors::{ErrorCode, Result, SwapdError};

// Not wired into a verb yet; `RealSecurity` (macOS only, below) uses this.
#[allow(dead_code)]
const TIMEOUT: Duration = Duration::from_secs(15);

// Not wired into a verb yet; `RealSecurity` (macOS only, below) uses this.
#[allow(dead_code)]
fn keychain_unavailable() -> SwapdError {
    // Never echo `security`'s stderr here: it can contain the account name.
    SwapdError::new(ErrorCode::KeychainUnavailable, "keychain unavailable")
}

// security_cli.rs — shared by Task 6's Claude driver (it reads Claude Code's own item through the same trait)
// Not wired into a verb yet.
#[allow(dead_code)]
pub trait SecurityCli: Send + Sync {
    /// `security find-generic-password -s S [-a A] -g`; exit 44 (not found) -> `Ok(None)`.
    /// Reads via `-g`, not `-w`: `-w` prints the raw value only when every byte is
    /// printable ASCII and otherwise prints its hex encoding, indistinguishably from a
    /// secret that legitimately looks like hex (e.g. a 64-char API key) — `-g`'s
    /// `password:` line format (`"…"` vs `0x<hex>  "…"`) is unambiguous instead.
    fn find(&self, service: &str, account: Option<&str>) -> Result<Option<String>>;
    /// Never puts `value` on argv (visible in `ps`): runs `security -i` and writes
    /// `add-generic-password -U -s "S" -a "A" -X <hex>` to its stdin, `value` hex-encoded
    /// so spaces, quotes, newlines and non-ASCII bytes in it can't break the one-line
    /// command syntax.
    fn add(&self, service: &str, account: &str, value: &str) -> Result<()>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
}

/// Reads a pipe to completion on a background thread, so it never blocks the
/// `try_wait` poll loop below on a full pipe buffer.
fn read_to_string_in_background(
    pipe: Option<impl Read + Send + 'static>,
) -> std::thread::JoinHandle<String> {
    let mut pipe = pipe;
    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(p) = pipe.as_mut() {
            let _ = p.read_to_string(&mut buf);
        }
        buf
    })
}

/// Runs `child` to completion, polling `try_wait` and sleeping between polls; kills it
/// (and reports `KeychainUnavailable`) if `TIMEOUT` elapses first. Returns the exit
/// code, captured stdout and captured stderr — `security find-generic-password -g`
/// puts the `password:` line on stderr, so both are captured, though neither is ever
/// put in an error message (it can contain the account, or the encoded secret).
// Not wired into a verb yet; `RealSecurity` (macOS only, below) uses this.
#[allow(dead_code)]
fn wait_for(mut child: Child) -> Result<(i32, String, String)> {
    let stdout_reader = read_to_string_in_background(child.stdout.take());
    let stderr_reader = read_to_string_in_background(child.stderr.take());

    let start = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|_| keychain_unavailable())? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(keychain_unavailable());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok((status.code().unwrap_or(-1), stdout, stderr))
}

/// Quotes `service`/`account` for `security -i`'s command line: wraps in double quotes,
/// escaping embedded backslashes. Callers must reject embedded `"`/`\n`/`\r` first
/// (`validate_component` below) — this only protects against a stray backslash.
// Not wired into a verb yet; `RealSecurity::add` (macOS only, below) uses this.
#[allow(dead_code)]
fn quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\");
    format!("\"{escaped}\"")
}

/// Rejects a keychain `service`/`account` component that would break the `security -i`
/// one-line command syntax. The secret value itself needs no such check: it goes over
/// `-X <hex>`, which tolerates any byte.
// Not wired into a verb yet; `RealSecurity` (macOS only, below) uses this.
#[allow(dead_code)]
fn validate_component(s: &str) -> Result<()> {
    if s.contains('"') || s.contains('\n') || s.contains('\r') {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "invalid keychain service or account",
        ));
    }
    Ok(())
}

/// Parses the `password: …` line `security find-generic-password -g` writes to
/// stderr. Verified against `/usr/bin/security` on Darwin 25.6 (macOS 26): the line is
/// `password: "<content>"` when every byte of the value is printable ASCII with no
/// backslash, `password: 0x<HEX>  "<preview>"` otherwise (the preview is discarded —
/// only the hex is decoded), or `password: ` with nothing after it for an empty value.
/// Never echoes `stderr` on a parse failure: it can contain the account name.
// Not wired into a verb yet; `find_outcome` (below) uses this.
#[allow(dead_code)]
fn parse_password_line(stderr: &str) -> Result<String> {
    let line = stderr
        .lines()
        .find(|l| l.starts_with("password: "))
        .ok_or_else(keychain_unavailable)?;
    let rest = &line["password: ".len()..];
    if rest.is_empty() {
        return Ok(String::new());
    }
    if let Some(hex_token) = rest.strip_prefix("0x") {
        let hex_digits = hex_token.split_whitespace().next().unwrap_or("");
        let bytes = hex::decode(hex_digits).map_err(|_| keychain_unavailable())?;
        return String::from_utf8(bytes).map_err(|_| keychain_unavailable());
    }
    if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
        return Ok(rest[1..rest.len() - 1].to_string());
    }
    Err(keychain_unavailable())
}

/// Maps a `security find-generic-password -g` exit code + captured stderr to a result:
/// 44 (not found) -> `Ok(None)`; 0 -> the parsed `password:` line; anything else ->
/// `KeychainUnavailable`. Pure and platform-independent so it's unit-testable without
/// spawning `security`.
// Not wired into a verb yet; `RealSecurity::find` (macOS only, below) uses this.
#[allow(dead_code)]
fn find_outcome(code: i32, stderr: &str) -> Result<Option<String>> {
    match code {
        44 => Ok(None),
        0 => parse_password_line(stderr).map(Some),
        _ => Err(keychain_unavailable()),
    }
}

/// Maps a `security delete-generic-password` exit code to a result: 0 (deleted) or 44
/// (already absent) -> `Ok(())`; anything else -> `KeychainUnavailable`. An absent item
/// is not a failure — treating it as one would (under `StickySecrets`) permanently
/// degrade the process to the file backend on a plain delete-of-nonexistent.
// Not wired into a verb yet; `RealSecurity::delete` (macOS only, below) uses this.
#[allow(dead_code)]
fn delete_outcome(code: i32) -> Result<()> {
    match code {
        0 | 44 => Ok(()),
        _ => Err(keychain_unavailable()),
    }
}

// Not wired into a verb yet; Task 6's Claude driver constructs this to read/write the
// real keychain.
#[allow(dead_code)]
#[cfg(target_os = "macos")]
pub struct RealSecurity;

// Not wired into a verb yet; Task 6's Claude driver constructs `RealSecurity` and calls it.
#[allow(dead_code)]
#[cfg(target_os = "macos")]
impl RealSecurity {
    fn run(cmd: &mut Command, stdin_data: Option<&str>) -> Result<(i32, String, String)> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = cmd.spawn().map_err(|_| keychain_unavailable())?;
        if let Some(data) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(data.as_bytes())
                    .map_err(|_| keychain_unavailable())?;
                // `stdin` drops here, closing the pipe so `security -i` processes the line.
            }
        }
        wait_for(child)
    }
}

#[cfg(target_os = "macos")]
impl SecurityCli for RealSecurity {
    fn find(&self, service: &str, account: Option<&str>) -> Result<Option<String>> {
        validate_component(service)?;
        if let Some(account) = account {
            validate_component(account)?;
        }
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("find-generic-password").arg("-s").arg(service);
        if let Some(account) = account {
            cmd.arg("-a").arg(account);
        }
        cmd.arg("-g");
        let (code, _stdout, stderr) = Self::run(&mut cmd, None)?;
        find_outcome(code, &stderr)
    }

    fn add(&self, service: &str, account: &str, value: &str) -> Result<()> {
        validate_component(service)?;
        validate_component(account)?;
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("-i");
        let line = format!(
            "add-generic-password -U -s {} -a {} -X {}\n",
            quote(service),
            quote(account),
            hex::encode(value.as_bytes())
        );
        let (code, _, _) = Self::run(&mut cmd, Some(&line))?;
        if code != 0 {
            return Err(keychain_unavailable());
        }
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        validate_component(service)?;
        validate_component(account)?;
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("delete-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account);
        let (code, _, _) = Self::run(&mut cmd, None)?;
        delete_outcome(code)
    }
}

// Not wired into a verb yet; unit tests (this file) and Task 6's Claude driver tests
// exercise `SecuritySecrets` against this instead of the real keychain.
#[allow(dead_code)]
pub struct FakeSecurity(std::sync::Mutex<std::collections::HashMap<(String, String), String>>);

// Not wired into a verb yet; unit tests (this file, secrets.rs) construct this directly.
#[allow(dead_code)]
impl FakeSecurity {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(std::collections::HashMap::new()))
    }
}

impl Default for FakeSecurity {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityCli for FakeSecurity {
    fn find(&self, service: &str, account: Option<&str>) -> Result<Option<String>> {
        let map = self.0.lock().unwrap();
        // Mirrors the real `security find-generic-password` without `-a`: matches any
        // account for the service.
        match account {
            Some(account) => Ok(map
                .get(&(service.to_string(), account.to_string()))
                .cloned()),
            None => Ok(map
                .iter()
                .find(|((s, _), _)| s == service)
                .map(|(_, v)| v.clone())),
        }
    }

    fn add(&self, service: &str, account: &str, value: &str) -> Result<()> {
        let mut map = self.0.lock().unwrap();
        map.insert(
            (service.to_string(), account.to_string()),
            value.to_string(),
        );
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        let mut map = self.0.lock().unwrap();
        map.remove(&(service.to_string(), account.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_roundtrip() {
        let fake = FakeSecurity::new();
        fake.add("swapd", "claude:1", "tok-1").unwrap();
        assert_eq!(
            fake.find("swapd", Some("claude:1")).unwrap(),
            Some("tok-1".to_string())
        );
        fake.delete("swapd", "claude:1").unwrap();
        assert_eq!(fake.find("swapd", Some("claude:1")).unwrap(), None);
    }

    // Exercises the real macOS keychain by hand: `cargo test -- --ignored security_real`.
    // Uses a service containing a space and deletes its item at the end (even on
    // panic) so it never leaves a trace. Round-trips three values byte-exact to lock in
    // both `security -g` `password:` line shapes and the ambiguity between them:
    // a JSON blob (forces the `0x<hex>` branch: has a newline and a non-ASCII byte),
    // a value that looks like hex (`deadbeef`: printable-ASCII branch — the case a
    // `-w`-based read would have silently corrupted by re-decoding it as hex), and a
    // value with a backslash and a quote (printable-ASCII branch; backslash is the only
    // byte the `-i` line quoting has to escape).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn security_real() {
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                RealSecurity
                    .delete("swapd test", "swapd-test-account")
                    .expect("cleanup delete must succeed (0 or already-absent 44)");
            }
        }
        let _cleanup = Cleanup;

        let cli = RealSecurity;
        let service = "swapd test";
        let account = "swapd-test-account";

        for value in [
            "{\"a\": \"b c\",\n\"e\": \"🩸\"}",
            "deadbeef",
            "back\\slash \"quote\"",
        ] {
            cli.add(service, account, value).unwrap();
            assert_eq!(
                cli.find(service, Some(account)).unwrap(),
                Some(value.to_string()),
                "roundtrip failed for {value:?}"
            );
        }
        cli.delete(service, account).unwrap();
        assert_eq!(cli.find(service, Some(account)).unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn add_rejects_quote_in_service() {
        let err = RealSecurity
            .add("swapd\"evil", "account", "value")
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn parse_password_line_printable_branch() {
        let stderr = "keychain: \"x\"\npassword: \"has \"quotes\" and space\"\nattributes:\n";
        assert_eq!(
            parse_password_line(stderr).unwrap(),
            "has \"quotes\" and space"
        );
    }

    #[test]
    fn parse_password_line_hex_branch_ignores_preview() {
        let stderr = "password: 0x68656c6c6f  \"hello\"\n";
        assert_eq!(parse_password_line(stderr).unwrap(), "hello");
    }

    #[test]
    fn parse_password_line_empty_value() {
        let stderr = "password: \n";
        assert_eq!(parse_password_line(stderr).unwrap(), "");
    }

    #[test]
    fn parse_password_line_missing_line_is_keychain_unavailable() {
        let err = parse_password_line("no password here\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::KeychainUnavailable);
    }

    #[test]
    fn find_outcome_not_found() {
        assert_eq!(find_outcome(44, "").unwrap(), None);
    }

    #[test]
    fn find_outcome_success_printable_line() {
        let stderr = "password: \"hello\"\n";
        assert_eq!(find_outcome(0, stderr).unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn find_outcome_success_hex_line() {
        let stderr = "password: 0x68656c6c6f  \"hello\"\n";
        assert_eq!(find_outcome(0, stderr).unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn find_outcome_other_code_is_keychain_unavailable() {
        let err = find_outcome(1, "").unwrap_err();
        assert_eq!(err.code, ErrorCode::KeychainUnavailable);
    }

    #[test]
    fn delete_outcome_success_and_not_found_are_ok() {
        assert!(delete_outcome(0).is_ok());
        assert!(delete_outcome(44).is_ok());
    }

    #[test]
    fn delete_outcome_other_code_is_keychain_unavailable() {
        let err = delete_outcome(1).unwrap_err();
        assert_eq!(err.code, ErrorCode::KeychainUnavailable);
    }
}
