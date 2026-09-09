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
    /// `security find-generic-password -s S [-a A] -w`; exit 44 (not found) -> `Ok(None)`.
    fn find(&self, service: &str, account: Option<&str>) -> Result<Option<String>>;
    /// Never puts `value` on argv (visible in `ps`): runs `security -i` and writes the
    /// command line to its stdin.
    fn add(&self, service: &str, account: &str, value: &str) -> Result<()>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
}

/// Runs `child` to completion, polling `try_wait` and sleeping between polls; kills it
/// (and reports `KeychainUnavailable`) if `TIMEOUT` elapses first. Returns the exit code
/// and captured stdout.
// Not wired into a verb yet; `RealSecurity` (macOS only, below) uses this.
#[allow(dead_code)]
fn wait_for(mut child: Child) -> Result<(i32, String)> {
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(s) = stdout.as_mut() {
            let _ = s.read_to_string(&mut buf);
        }
        buf
    });

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
    let stdout = reader.join().unwrap_or_default();
    Ok((status.code().unwrap_or(-1), stdout))
}

/// Quotes `s` for `security -i`'s command line: wraps it in double quotes, escaping
/// embedded backslashes and quotes.
// Not wired into a verb yet; `RealSecurity::add` (macOS only, below) uses this.
#[allow(dead_code)]
fn quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
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
    fn run(cmd: &mut Command, stdin_data: Option<&str>) -> Result<(i32, String)> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
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
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("find-generic-password").arg("-s").arg(service);
        if let Some(account) = account {
            cmd.arg("-a").arg(account);
        }
        cmd.arg("-w");
        let (code, stdout) = Self::run(&mut cmd, None)?;
        match code {
            44 => Ok(None),
            0 => Ok(Some(stdout.trim_end_matches('\n').to_string())),
            _ => Err(keychain_unavailable()),
        }
    }

    fn add(&self, service: &str, account: &str, value: &str) -> Result<()> {
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("-i");
        let line = format!(
            "add-generic-password -U -s {} -a {} -w {}\n",
            quote(service),
            quote(account),
            quote(value)
        );
        let (code, _) = Self::run(&mut cmd, Some(&line))?;
        if code != 0 {
            return Err(keychain_unavailable());
        }
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        let mut cmd = Command::new("/usr/bin/security");
        cmd.arg("delete-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account);
        let (code, _) = Self::run(&mut cmd, None)?;
        if code != 0 {
            return Err(keychain_unavailable());
        }
        Ok(())
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

    // Exercises the real macOS keychain by hand: `cargo test -- --ignored real_security_roundtrip`.
    // Uses service "swapd-test" and deletes its item at the end (even on panic) so it
    // never leaves a trace.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn real_security_roundtrip() {
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = RealSecurity.delete("swapd-test", "swapd-test-account");
            }
        }
        let _cleanup = Cleanup;

        let cli = RealSecurity;
        let service = "swapd-test";
        let account = "swapd-test-account";
        // Stresses the `security -i` quoting: an embedded space and double quote.
        let value = r#"tok real "1""#;

        cli.add(service, account, value).unwrap();
        assert_eq!(
            cli.find(service, Some(account)).unwrap(),
            Some(value.to_string())
        );
        cli.delete(service, account).unwrap();
        assert_eq!(cli.find(service, Some(account)).unwrap(), None);
    }
}
