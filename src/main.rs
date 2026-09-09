mod errors;
mod output;
mod paths;

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

    /// Provider to operate on.
    #[arg(long, global = true, default_value = "claude")]
    provider: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the swapd version.
    Version,
    /// Check the local environment for problems.
    Doctor,
}

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
    }
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
fn locate_claude() -> (bool, Option<String>) {
    if let Some(path) = find_on_path("claude") {
        return (true, Some(path));
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        format!("{home}/.claude/local/claude"),
        format!("{home}/.local/bin/claude"),
        "/opt/homebrew/bin/claude".to_string(),
        "/usr/local/bin/claude".to_string(),
    ];
    for candidate in candidates {
        if Path::new(&candidate).is_file() {
            return (true, Some(candidate));
        }
    }
    (false, None)
}

fn find_on_path(bin: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}
