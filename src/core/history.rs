//! The switch log: one JSON object per line, appended, newest last.
//!
//! JSONL rather than a JSON document because it is only ever appended to and
//! only ever read whole: an append is one `write` on an `O_APPEND` handle, so a
//! crash mid-write can cost the last line but can never tear the lines before
//! it — which a rewritten array would.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::Result;
use crate::paths::Home;

/// One end of a switch: the slot and the account that was on it. `slot` is
/// `None` for a live login no managed slot claims (cswap's unnumbered
/// `account_ref`), which is a real thing to switch *away from*.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SlotRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u32>,
    pub email: String,
}

impl SlotRef {
    pub fn numbered(slot: u32, email: impl Into<String>) -> Self {
        Self {
            slot: Some(slot),
            email: email.into(),
        }
    }

    pub fn unmanaged(email: impl Into<String>) -> Self {
        Self {
            slot: None,
            email: email.into(),
        }
    }
}

/// One line of the log.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SwitchRecord {
    /// RFC 3339, UTC.
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<SlotRef>,
    pub to: SlotRef,
    /// What asked for this switch: `manual`, `rotate`, later the auto loop.
    pub trigger: String,
}

/// Append one record. The write is a single `O_APPEND` line, so concurrent
/// switches interleave whole lines rather than tearing one.
pub fn append(home: &Home, record: &SwitchRecord) -> Result<()> {
    let path = home.history_file();
    let mut line = serde_json::to_string(record)?;
    line.push('\n');

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// The log newest last, at most `limit` records (the *last* `limit`, so a limit
/// answers "what happened recently" rather than "what happened first").
///
/// A line that does not parse is skipped rather than fatal: the log is
/// append-only history, and one torn tail must not make the verb unusable.
pub fn read(home: &Home, limit: Option<usize>) -> Result<Vec<SwitchRecord>> {
    let path = home.history_file();
    let records = read_all(&path)?;
    match limit {
        Some(limit) if records.len() > limit => Ok(records[records.len() - limit..].to_vec()),
        _ => Ok(records),
    }
}

fn read_all(path: &Path) -> Result<Vec<SwitchRecord>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<SwitchRecord>(&line) {
            out.push(record);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ts: &str, to: u32) -> SwitchRecord {
        SwitchRecord {
            ts: ts.to_string(),
            from: Some(SlotRef::numbered(1, "one@example.com")),
            to: SlotRef::numbered(to, "two@example.com"),
            trigger: "manual".to_string(),
        }
    }

    #[test]
    fn append_then_read_is_newest_last() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        append(&home, &record("2026-09-09T00:00:00Z", 2)).unwrap();
        append(&home, &record("2026-09-09T00:01:00Z", 3)).unwrap();

        let all = read(&home, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].to.slot, Some(3));
    }

    #[test]
    fn limit_keeps_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        for (i, ts) in ["a", "b", "c"].iter().enumerate() {
            append(&home, &record(ts, i as u32 + 2)).unwrap();
        }
        let last_two = read(&home, Some(2)).unwrap();
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[0].ts, "b");
        assert_eq!(last_two[1].ts, "c");
    }

    #[test]
    fn missing_log_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        assert!(read(&home, None).unwrap().is_empty());
    }

    #[test]
    fn a_torn_line_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            root: dir.path().to_path_buf(),
        };
        append(&home, &record("2026-09-09T00:00:00Z", 2)).unwrap();
        std::fs::write(
            home.history_file(),
            "{\"ts\":\"a\",\"to\":{\"slot\":2,\"email\":\"x\"},\"trigger\":\"manual\"}\n\
             {\"ts\":\"torn\",\n",
        )
        .unwrap();

        let all = read(&home, None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ts, "a");
    }
}
