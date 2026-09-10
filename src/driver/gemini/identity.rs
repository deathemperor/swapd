//! Offline identity from a Gemini login. Stub — replaced by Task 3.

use crate::driver::{Identity, Login};

pub fn identity_offline(_login: &Login) -> Option<Identity> {
    None
}

pub fn expires_at(_login: &Login) -> Option<f64> {
    None
}
