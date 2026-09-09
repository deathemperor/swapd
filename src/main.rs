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
use std::path::Path;

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
    providers: Vec<ProviderStatus>,
}

#[derive(Serialize)]
struct ProviderStatus {
    provider: String,
    installed: bool,
    path: Option<String>,
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
            let drivers = cmd::list::drivers_for(cli.provider.as_deref())?;
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
            let driver = single_driver(cli)?;
            let ctx = ctx::Ctx::from_env()?;
            let out = cmd::switch::run(&ctx, driver.as_ref(), ident)?;
            emit(&out, cli.json, || cmd::switch::print_human(&out))
        }
        Command::Rotate { strategy } => {
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
    }
}

/// The driver a single-provider verb runs against. Resolved before
/// `Ctx::from_env()`, which creates the data dir: a rejected command must not
/// leave one behind.
fn single_driver(cli: &Cli) -> Result<Box<dyn driver::Driver>> {
    let provider = cli.provider.as_deref().unwrap_or(DEFAULT_PROVIDER);
    driver::by_id(provider).ok_or_else(|| {
        SwapdError::new(
            ErrorCode::InvalidInput,
            format!("unknown provider: {provider}"),
        )
    })
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
    let (installed, path) = locate_claude();
    let providers = vec![ProviderStatus {
        provider: "claude".to_string(),
        installed,
        path,
    }];
    let out = DoctorOutput {
        schema_version: output::SCHEMA_VERSION,
        home: home.root.to_string_lossy().into_owned(),
        providers,
    };
    if json {
        output::emit_json(&out);
    } else {
        println!("home: {}", out.home);
        for p in &out.providers {
            match &p.path {
                Some(path) => println!("{}: installed ({})", p.provider, path),
                None => println!("{}: not installed", p.provider),
            }
        }
    }
    Ok(())
}

/// Find the `claude` binary on PATH or in a set of well-known install locations.
///
/// One lookup, shared with the Claude driver's `installed()` and its igniter
/// (`driver::claude::run::find_claude`), so doctor cannot disagree with what a
/// run would actually execute.
fn locate_claude() -> (bool, Option<String>) {
    let home = std::env::var("HOME").unwrap_or_default();
    match driver::claude::run::find_claude(std::env::var("PATH").ok().as_deref(), Path::new(&home))
    {
        Some(path) => (true, Some(path.to_string_lossy().into_owned())),
        None => (false, None),
    }
}
