//! `swapd notify` — which push channels are configured, masked.
//!
//! Port of cswap's `away_notify` config surface (`cli.py:1240`): the channel
//! secrets live in `<home>/notify.json`, 0600, deliberately outside
//! `settings.json` (which `config list` prints freely) and outside every export
//! bundle. A webhook URL or a bot token is a capability — anyone holding it can
//! post as the user — so this verb reports only that one is set, never its
//! value (`masked`, away_notify.py:71). Sending is out of scope here.

use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::core::store::read_json;
use crate::ctx::Ctx;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyOutput {
    pub schema_version: u32,
    pub slack_webhook_url: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

pub fn run(ctx: &Ctx) -> Result<NotifyOutput> {
    let raw = read_object(&ctx.home.root.join("notify.json"))?;
    let masked_of = |key: &str| raw.get(key).and_then(Value::as_str).and_then(masked);
    Ok(NotifyOutput {
        schema_version: output::SCHEMA_VERSION,
        slack_webhook_url: masked_of("slackWebhookUrl"),
        telegram_bot_token: masked_of("telegramBotToken"),
        // Masked too, unlike cswap, which prints the chat id whole: it is a
        // durable identifier of where the user's alerts land, and nothing here
        // needs its value to report that the channel is configured.
        telegram_chat_id: masked_of("telegramChatId"),
    })
}

/// The file as a JSON object; missing is empty, malformed is an error — a
/// channel silently dropped because the file would not parse is exactly the
/// kind of quiet failure this verb exists to rule out.
fn read_object(path: &Path) -> Result<Map<String, Value>> {
    match read_json::<Value>(path)? {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        _ => Err(SwapdError::new(
            ErrorCode::InvalidInput,
            format!("{}: not a JSON object", path.display()),
        )),
    }
}

/// A displayable stand-in: the host (for URLs) plus the last four characters
/// (`masked`, away_notify.py:71). `None` for an empty value, which is how an
/// unset channel reads.
fn masked(secret: &str) -> Option<String> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    let tail: String = {
        let chars: Vec<char> = secret.chars().collect();
        chars[chars.len().saturating_sub(4)..].iter().collect()
    };
    match host(secret) {
        Some(host) => Some(format!("{host}…{tail}")),
        None => Some(format!("…{tail}")),
    }
}

/// The `netloc` of a URL-shaped value, as `urlsplit` reports it.
fn host(secret: &str) -> Option<&str> {
    let rest = secret.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    (!host.is_empty()).then_some(host)
}

pub fn print_human(out: &NotifyOutput) {
    for (name, value) in [
        ("slackWebhookUrl", &out.slack_webhook_url),
        ("telegramBotToken", &out.telegram_bot_token),
        ("telegramChatId", &out.telegram_chat_id),
    ] {
        println!("{name}: {}", value.as_deref().unwrap_or("(unset)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_keeps_its_host_and_four_characters() {
        assert_eq!(
            masked("https://hooks.slack.com/services/T00/B00/abcd1234"),
            Some("hooks.slack.com…1234".to_string())
        );
        assert_eq!(masked("12345:AAbbCCddEEff"), Some("…EEff".to_string()));
        assert_eq!(masked("  "), None);
    }
}
