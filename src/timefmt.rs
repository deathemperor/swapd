//! The one timestamp spelling every surface writes.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A POSIX timestamp as `2026-09-15T10:59:59Z` — cswap's
/// `isoformat(timespec="seconds").replace("+00:00", "Z")`.
pub fn format_ts(ts: f64) -> Option<String> {
    let seconds = if ts.is_finite() { ts.floor() as i64 } else { 0 };
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
        .map(|s| s.replace("+00:00", "Z"))
}
