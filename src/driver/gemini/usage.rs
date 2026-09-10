//! Usage → windows for the Gemini driver, and the igniter's data source.
//! Stub — replaced by Task 5.

use crate::driver::gemini::GeminiDriver;
use crate::driver::{DriverError, Login, Usage};

pub fn usage(_driver: &GeminiDriver, _login: &Login) -> Result<Usage, DriverError> {
    Err(DriverError::Unsupported("gemini: not yet implemented"))
}
