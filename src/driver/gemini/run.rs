//! Per-slot `GEMINI_CLI_HOME` profiles and the igniter. Stub — replaced by
//! Task 6.

use std::path::PathBuf;

use crate::driver::gemini::GeminiDriver;
use crate::driver::{DriverError, Env, IgniteOutcome, Login, RunProfile};

pub fn resolve_cli(_env: &Env) -> Option<PathBuf> {
    None
}

pub fn run_profile(_env: &Env, _slot: u32, _login: &Login) -> Result<RunProfile, DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}

pub fn commit_profile(_env: &Env, _slot: u32, _login: &Login) -> Result<(), DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}

pub fn forget_profile(_env: &Env, _slot: u32) -> Result<(), DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}

pub fn ignite(
    _driver: &GeminiDriver,
    _env: &Env,
    _slot: u32,
    _login: &Login,
) -> Result<IgniteOutcome, DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}
