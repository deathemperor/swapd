mod cmd;
mod contract;
mod core;
mod ctx;
mod driver;
mod errors;
mod http;
mod output;
mod paths;
mod secrets;
mod security_cli;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use errors::{ErrorCode, Result, SwapdError};
use paths::Home;
use serde::Serialize;

#[derive(Parser)]
#[command(name = "swapd", version)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Provider to operate on. Unset lists every known provider.
    #[arg(long, global = true)]
    provider: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the swapd version.
    Version,
    /// Check the local environment for problems.
    Doctor,
    /// List every account, its usage and the rotation.
    List,
    /// Fetch usage now, then list.
    Refresh {
        /// Fetch this slot past the serve TTL and its poll plan.
        #[arg(long)]
        slot: Option<u32>,
    },
    /// Capture the login the CLI is holding right now into a slot.
    Add {
        /// Store it in this slot instead of the account's own (or the next free one).
        #[arg(long)]
        slot: Option<u32>,
        /// Short name to reach this account by.
        #[arg(long)]
        alias: Option<String>,
        /// Overwrite a slot that holds a different account.
        #[arg(long)]
        force: bool,
    },
    /// Register a raw OAuth setup token or API key read from stdin.
    AddToken {
        /// Must be `-`: the token is read from stdin, never from argv.
        source: String,
        #[arg(long)]
        slot: Option<u32>,
        /// Address to file the account under, instead of `<kind>-<slot>@token.local`.
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        alias: Option<String>,
        /// Overwrite a slot that holds a different account.
        #[arg(long)]
        force: bool,
    },
    /// Import accounts from an export file (`-` for stdin).
    Import {
        path: String,
        /// Overwrite slots that hold a different account.
        #[arg(long)]
        force: bool,
    },
    /// Make an account the live login, by slot number, alias or email.
    Switch { ident: String },
    /// Run the switching daemon: poll usage, switch when policy says to.
    Auto,
    /// Start an account's usage window: one short run in its own profile.
    Ignite { ident: String },
    /// Run the provider's CLI as one account, without touching the live login.
    Run {
        ident: String,
        /// Everything after `--`, passed to the CLI untouched.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Switch to the next account a strategy picks.
    Rotate {
        /// `consume-first`, `best` or `next-available`.
        #[arg(long)]
        strategy: Option<String>,
    },
    /// Set or clear a slot's short name.
    Alias {
        ident: String,
        name: Option<String>,
        /// Clear the alias instead of setting one.
        #[arg(long)]
        unset: bool,
    },
    /// Set or clear a slot's icon.
    Icon {
        ident: String,
        icon: Option<String>,
        /// Clear the icon instead of setting one.
        #[arg(long)]
        unset: bool,
    },
    /// Pin (`on`) or unpin (`off`) an account the rotation lands on first.
    Prefer { ident: String, state: String },
    /// Take an account out of the rotation, keeping its login.
    Hold { ident: String },
    /// Put a held account back into the rotation.
    Unhold { ident: String },
    /// Set the rotation order: every slot, exactly once.
    Reorder { idents: Vec<String> },
    /// Renumber the slots 1…n, closing any gap (a `remove` stopped by a live
    /// session, an import of a sparse roster).
    Compact,
    /// Forget an account: its stored login, its run profile and its slot.
    Remove {
        ident: String,
        /// Confirm the deletion. Without it nothing is touched.
        #[arg(long)]
        yes: bool,
    },
    /// Write an export envelope to a file (`-` for stdout).
    Export {
        path: String,
        /// Export this slot alone.
        #[arg(long)]
        slot: Option<u32>,
        /// Same-machine backup: also carry the CLI's config snapshot.
        #[arg(long)]
        full: bool,
    },
    /// Which push channels are configured, masked.
    Notify,
    /// Read or change the `settings.json` knobs.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// The switch log, newest last.
    History {
        /// Show only the most recent `n`.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// List logins a switch stashed because they matched no slot.
    Unclaimed {
        /// Delete one entry's bytes for good — recovery is a fresh login +
        /// `swapd add`.
        #[arg(long)]
        purge: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Every key: its value, whether it is set, and its default.
    List,
    /// One key, as `<provider>.<key>`.
    Get { key: String },
    /// Set one key. Out-of-range and mistyped values are refused, never clamped.
    Set { key: String, value: String },
    /// Drop one key, so its default applies again.
    Unset { key: String },
}

/// The provider a single-provider verb operates on.
pub const DEFAULT_PROVIDER: &str = "claude";

#[derive(Serialize)]
struct VersionOutput {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    version: &'static str,
}

#[derive(Serialize)]
struct DoctorOutput {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    home: String,
    #[serde(rename = "liveStore")]
    live_store: &'static str,
    secrets: &'static str,
    locks: LocksOutput,
    profiles: Vec<ProfileEntry>,
    providers: Vec<ProviderStatus>,
}

#[derive(Serialize)]
struct LocksOutput {
    engine: LockStatus,
    auto: LockStatus,
}

#[derive(Serialize)]
struct LockStatus {
    held: bool,
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
}

#[derive(Serialize)]
struct ProfileEntry {
    provider: String,
    slot: u32,
    path: String,
}

#[derive(Serialize)]
struct ProviderStatus {
    provider: String,
    installed: bool,
    path: Option<String>,
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                e.exit();
            }
            let json = std::env::args().any(|a| a == "--json");
            let message = if matches!(
                e.kind(),
                ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                "missing subcommand".to_string()
            } else {
                let first_line = e.to_string().lines().next().unwrap_or_default().to_string();
                first_line
                    .strip_prefix("error: ")
                    .unwrap_or(&first_line)
                    .to_string()
            };
            output::emit_error(&SwapdError::new(ErrorCode::InvalidInput, message), json);
            std::process::exit(1);
        }
    };
    let json = cli.json;
    let result = run(&cli);
    match result {
        Ok(()) => {}
        Err(err) => {
            output::emit_error(&err, json);
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Version => version(cli.json),
        Command::Doctor => doctor(cli.json),
        Command::List => {
            // Resolved before `Ctx::from_env()`, which creates the data dir: a
            // rejected command must not leave one behind.
            let drivers = cmd::list::drivers_for(cli.provider.as_deref(), &env_snapshot()?)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(&cmd::list::run(&ctx, &drivers)?, cli.json)
        }
        Command::Refresh { slot } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(&cmd::refresh::run(&ctx, driver.as_ref(), *slot)?, cli.json)
        }
        Command::Add { slot, alias, force } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let opts = cmd::add::AddOpts {
                slot: *slot,
                alias: alias.clone(),
                force: *force,
            };
            let out = cmd::add::run(&ctx, driver.as_ref(), &opts)?;
            emit(&out, cli.json, || cmd::add::print_human(&out))
        }
        Command::AddToken {
            source,
            slot,
            email,
            alias,
            force,
        } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let opts = cmd::add_token::AddTokenOpts {
                slot: *slot,
                email: email.clone(),
                alias: alias.clone(),
                force: *force,
            };
            let out = cmd::add_token::run(&ctx, driver.as_ref(), source, &opts)?;
            emit(&out, cli.json, || cmd::add::print_human(&out))
        }
        Command::Import { path, force } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::import::run(&ctx, driver.as_ref(), path, *force)?;
            emit(&out, cli.json, || cmd::import::print_human(&out))
        }
        Command::Switch { ident } => {
            refuse_in_shadow("switch")?;
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::switch::run(&ctx, driver.as_ref(), ident)?;
            emit(&out, cli.json, || cmd::switch::print_human(&out))
        }
        Command::Auto => {
            refuse_in_shadow("auto")?;
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            // The refusal is an EVENT on the stream, not an error envelope: a
            // supervisor reading the stream must not have to parse two shapes.
            let code = cmd::auto::run(ctx, driver.as_ref(), cli.json)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Command::Ignite { ident } => {
            refuse_in_shadow("ignite")?;
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::ignite::run(&ctx, driver.as_ref(), ident, &std::thread::sleep)?;
            emit(&out, cli.json, || cmd::ignite::print_human(&out))
        }
        Command::Run { ident, args } => {
            refuse_in_shadow("run")?;
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            // The child's code is the verb's: `swapd run` is a wrapper, and a
            // wrapper that flattens exit codes breaks every script around it.
            let code = cmd::run::run(&ctx, driver.as_ref(), ident, args, cli.json)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Command::Rotate { strategy } => {
            refuse_in_shadow("rotate")?;
            // Parsed before the data dir is created: a bad strategy is a
            // rejected command, and a rejected command leaves nothing behind.
            let named = strategy
                .as_deref()
                .map(core::switch::Strategy::parse)
                .transpose()?;
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            // `--strategy` overrides; without it the answer is the policy file's
            // (`<provider>.strategy`), which the lenient load has already
            // narrowed to one of the three choices.
            let strategy = match named {
                Some(strategy) => strategy,
                None => core::switch::Strategy::parse(&ctx.settings.strategy)?,
            };
            let out = cmd::rotate::run(&ctx, driver.as_ref(), strategy)?;
            emit(&out, cli.json, || cmd::switch::print_human(&out))
        }
        Command::Alias { ident, name, unset } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(
                &cmd::alias::run(&ctx, driver.as_ref(), ident, name.as_deref(), *unset)?,
                cli.json,
            )
        }
        Command::Icon { ident, icon, unset } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(
                &cmd::icon::run(&ctx, driver.as_ref(), ident, icon.as_deref(), *unset)?,
                cli.json,
            )
        }
        Command::Prefer { ident, state } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(
                &cmd::prefer::run(&ctx, driver.as_ref(), ident, state)?,
                cli.json,
            )
        }
        Command::Hold { ident } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(
                &cmd::hold::run(&ctx, driver.as_ref(), ident, true)?,
                cli.json,
            )
        }
        Command::Unhold { ident } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(
                &cmd::hold::run(&ctx, driver.as_ref(), ident, false)?,
                cli.json,
            )
        }
        Command::Reorder { idents } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            emit_list(&cmd::reorder::run(&ctx, driver.as_ref(), idents)?, cli.json)
        }
        Command::Compact => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::compact::run(&ctx, driver.as_ref())?;
            emit(&out, cli.json, || cmd::compact::print_human(&out))
        }
        Command::Remove { ident, yes } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::remove::run(&ctx, driver.as_ref(), ident, *yes)?;
            emit(&out, cli.json, || cmd::remove::print_human(&out))
        }
        Command::Export { path, slot, full } => {
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let opts = cmd::export::ExportOpts {
                slot: *slot,
                full: *full,
            };
            // A `-` export IS the output: the envelope has already gone to
            // stdout, and a second document after it would break every reader.
            match cmd::export::run(&ctx, driver.as_ref(), path, &opts)? {
                Some(out) => emit(&out, cli.json, || cmd::export::print_human(&out)),
                None => Ok(()),
            }
        }
        Command::Notify => {
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::notify::run(&ctx)?;
            emit(&out, cli.json, || cmd::notify::print_human(&out))
        }
        Command::Config { action } => {
            let ctx = ctx::Ctx::from_env()?;
            let out = match action {
                ConfigAction::List => cmd::config::list(&ctx, cli.provider.as_deref())?,
                ConfigAction::Get { key } => cmd::config::get(&ctx, key)?,
                ConfigAction::Set { key, value } => cmd::config::set(&ctx, key, value)?,
                ConfigAction::Unset { key } => cmd::config::unset(&ctx, key)?,
            };
            emit(&out, cli.json, || cmd::config::print_human(&out))
        }
        Command::History { limit } => {
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::history::run(&ctx, *limit)?;
            emit(&out, cli.json, || cmd::history::print_human(&out))
        }
        Command::Unclaimed { purge } => {
            let ctx = ctx::Ctx::from_env()?;
            match purge {
                Some(id) => {
                    let out = cmd::unclaimed::purge(&ctx, id)?;
                    emit(&out, cli.json, || cmd::unclaimed::print_purged(&out))
                }
                None => {
                    let out = cmd::unclaimed::list(&ctx)?;
                    emit(&out, cli.json, || cmd::unclaimed::print_human(&out))
                }
            }
        }
    }
}

/// The driver a single-provider verb runs against. Resolved before
/// `Ctx::from_env()`, which creates the data dir: a rejected command must not
/// leave one behind — which is why the driver is built from an `Env` captured
/// here rather than from the one `Ctx` will hold. Same process, same variables;
/// what matters is that the driver holds VALUES and never reads the
/// environment again.
fn single_driver(cli: &Cli) -> Result<Box<dyn driver::Driver>> {
    let provider = cli.provider.as_deref().unwrap_or(DEFAULT_PROVIDER);
    driver::by_id(provider, &env_snapshot()?).ok_or_else(|| {
        SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown provider: {provider}"),
        )
    })
}

/// The environment a driver is built from: swapd's home (resolved, not
/// created) plus this process's variables, captured once.
/// The verbs that write the live login are refused while `SWAPD_SHADOW` is
/// set (`driver::Env::shadow`): the login belongs to another tool.
fn refuse_in_shadow(verb: &str) -> Result<()> {
    let value = std::env::var("SWAPD_SHADOW").ok();
    if driver::shadow_flag(value.as_deref()) {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{verb}` is refused while SWAPD_SHADOW is set: another tool owns the live login; unset it first"
            ),
        ));
    }
    Ok(())
}

fn env_snapshot() -> Result<driver::Env> {
    Ok(driver::Env::current(&Home::resolve()?))
}

fn emit<T: Serialize>(payload: &T, json: bool, human: impl FnOnce()) -> Result<()> {
    if json {
        output::emit_json(payload);
    } else {
        human();
    }
    Ok(())
}

fn emit_list(payload: &contract::ListPayload, json: bool) -> Result<()> {
    if json {
        output::emit_json(payload);
    } else {
        cmd::list::print_human(payload);
    }
    Ok(())
}

fn version(json: bool) -> Result<()> {
    let out = VersionOutput {
        schema_version: output::SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION"),
    };
    if json {
        output::emit_json(&out);
    } else {
        println!("swapd {}", out.version);
    }
    Ok(())
}

fn doctor(json: bool) -> Result<()> {
    let home = Home::resolve()?;
    let env = driver::Env::current(&home);

    let live_store = driver::claude::live::live_store_name(&env);
    let secrets =
        secrets::secrets_for(&home, std::env::var("SWAPD_SECRETS").ok().as_deref())?.name();

    let engine = lock_status(&home.engine_lock_base(), false)?;
    let auto = lock_status(&home.auto_lock_base(), true)?;

    let profiles = list_profiles(&home);

    let providers = driver::registry(&env)
        .iter()
        .map(|d| {
            let path = d.installed(&env).map(|p| p.to_string_lossy().into_owned());
            let version = path.as_deref().and_then(cli_version);
            // Both Gemini notes explain the same symptom — `list` shows the
            // provider with no login — which `read_live` reports as a plain
            // `NoLogin` so it cannot take the other providers down with it.
            let note = match d.id() {
                "gemini"
                    if env
                        .vars
                        .get("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE")
                        .is_some_and(|v| !v.is_empty()) =>
                {
                    Some(
                        "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE is set; encrypted credential storage is not supported"
                            .to_string(),
                    )
                }
                "gemini" => driver::gemini::live::selected_auth_type(&env)
                    .ok()
                    .flatten()
                    .filter(|kind| kind != driver::gemini::live::OAUTH_PERSONAL)
                    .map(|kind| {
                        format!("gemini is configured for {kind} auth; only oauth-personal is managed")
                    })
                    .or_else(|| path.as_ref().and_then(|_| driver::gemini::oauth::client_note(&env))),
                _ => None,
            };
            ProviderStatus {
                provider: d.id().to_string(),
                installed: path.is_some(),
                path,
                version,
                note,
            }
        })
        .collect();

    let out = DoctorOutput {
        schema_version: output::SCHEMA_VERSION,
        home: home.root.to_string_lossy().into_owned(),
        live_store,
        secrets,
        locks: LocksOutput { engine, auto },
        profiles,
        providers,
    };
    if json {
        output::emit_json(&out);
    } else {
        println!("home: {}", out.home);
        println!("live store: {}", out.live_store);
        println!("secrets: {}", out.secrets);
        println!("engine.lock: {}", lock_line(&out.locks.engine));
        println!("auto.lock: {}", lock_line(&out.locks.auto));
        if out.profiles.is_empty() {
            println!("profiles: none");
        } else {
            let list = out
                .profiles
                .iter()
                .map(|p| format!("{}/{}", p.provider, p.slot))
                .collect::<Vec<_>>()
                .join(", ");
            println!("profiles: {list}");
        }
        for p in &out.providers {
            match (&p.path, &p.version) {
                (Some(path), Some(version)) => {
                    println!("{}: installed ({}) {}", p.provider, path, version)
                }
                (Some(path), None) => println!("{}: installed ({})", p.provider, path),
                (None, _) => println!("{}: not installed", p.provider),
            }
            if let Some(note) = &p.note {
                println!("  note: {note}");
            }
        }
    }
    Ok(())
}

/// `held`/`note` for a lock's `.lock` sibling. `want_pid` is only true for
/// `auto.lock`: `engine.lock` has no pid concept, so it never even tries to
/// parse one out of its note.
fn lock_status(base: &std::path::Path, want_pid: bool) -> Result<LockStatus> {
    let probe = core::store::FileLock::probe(base)?;
    let pid = if want_pid {
        probe.note.as_deref().and_then(parse_pid)
    } else {
        None
    };
    Ok(LockStatus {
        held: probe.held,
        note: probe.note,
        pid,
    })
}

/// The daemon's breadcrumb is `{"pid":N}` (`FileLock::note`, `cmd/auto.rs`);
/// anything else — no note, malformed JSON, a non-u32 value — reports no pid
/// rather than failing doctor over it.
fn parse_pid(note: &str) -> Option<u32> {
    let value: serde_json::Value = serde_json::from_str(note).ok()?;
    value
        .get("pid")?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
}

fn lock_line(status: &LockStatus) -> String {
    if !status.held {
        "free".to_string()
    } else if let Some(pid) = status.pid {
        format!("held by pid {pid}")
    } else {
        "held".to_string()
    }
}

/// Every `profiles/<provider>/<slot>` directory that exists, sorted by
/// (provider, slot). A missing `profiles/` dir or a slot name that doesn't
/// parse as `u32` is skipped, not an error.
fn list_profiles(home: &Home) -> Vec<ProfileEntry> {
    let mut entries = Vec::new();
    let Ok(provider_dirs) = std::fs::read_dir(home.profiles_dir()) else {
        return entries;
    };
    for provider_entry in provider_dirs.flatten() {
        if !provider_entry.path().is_dir() {
            continue;
        }
        let Some(provider) = provider_entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(slot_dirs) = std::fs::read_dir(provider_entry.path()) else {
            continue;
        };
        for slot_entry in slot_dirs.flatten() {
            let slot_path = slot_entry.path();
            if !slot_path.is_dir() {
                continue;
            }
            let Some(slot) = slot_entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            entries.push(ProfileEntry {
                provider: provider.clone(),
                slot,
                path: slot_path.to_string_lossy().into_owned(),
            });
        }
    }
    entries.sort_by(|a, b| (&a.provider, a.slot).cmp(&(&b.provider, b.slot)));
    entries
}

/// The CLI's own version, from `<path> --version`'s first stdout line,
/// trimmed. `None` on anything short of a clean, prompt exit — not installed,
/// a timeout, a non-zero exit, empty output — so a broken binary never fails
/// `doctor` itself.
fn cli_version(path: &str) -> Option<String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let start = Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= VERSION_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    if !status.success() {
        return None;
    }

    let mut stdout = child.stdout.take()?;
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).ok()?;
    let first_line = buf.lines().next()?.trim();
    (!first_line.is_empty()).then(|| first_line.to_string())
}
