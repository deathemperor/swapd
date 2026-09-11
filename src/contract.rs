//! JSON contract types for `list --json`, consumed by the Infinitus app and
//! other external readers. Field order mirrors the emitted JSON.
//!
//! `ProviderView.active_unreadable` was added additively (issue #8), and so was
//! `last_known_active_slot` beside it; `schemaVersion` stays 1.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListPayload {
    pub schema_version: u32,
    pub providers: Vec<ProviderView>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderView {
    pub provider: String,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_slot: Option<u32>,
    /// Why `active_slot` is absent although the store may hold an active account:
    /// `switch-in-progress` (engine.lock held by a switch), `keychain-unavailable`,
    /// `cli-busy` (the CLI is mid-write of its own login). Absent when `active_slot`
    /// is present or when there is genuinely no live login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_unreadable: Option<String>,
    /// The slot the store records as active while `active_unreadable` explains
    /// why this pass could not confirm it. Present only beside `active_unreadable`;
    /// a reader carries it forward instead of treating the provider as having no
    /// active account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_active_slot: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_candidate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_recovery: Option<NextRecovery>,
    pub accounts: Vec<AccountView>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NextRecovery {
    pub slot: u32,
    pub at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub slot: u32,
    pub email: String,
    pub organization_name: String,
    pub organization_uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub active: bool,
    pub disabled: bool,
    pub preferred: bool,
    pub usage_status: UsageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<f64>,
    pub windows: Vec<Window>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_good: Option<LastGood>,
    /// The store's classified kind of the most recent failed fetch
    /// (`http-429`, `timeout`, `locked`, …); absent once a fetch succeeds.
    /// Why a `stale` row is stale, without opening the store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the failure backoff lifts, RFC 3339; absent when none is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoff_until: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LastGood {
    pub fetched_at: String,
    pub age_seconds: f64,
    pub windows: Vec<Window>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UsageStatus {
    Ok,
    Stale,
    ReloginRequired,
    TokenExpired,
    NoCredentials,
    ApiKey,
    Unsupported,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub kind: WindowKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pace: Option<Pace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WindowKind {
    #[serde(rename = "5h")]
    FiveHour,
    #[serde(rename = "7d")]
    SevenDay,
    Daily,
    Monthly,
    Scoped,
    Spend,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Pace {
    pub expected_pct: f64,
    pub ahead: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exhausts_at: Option<String>,
    pub lasts_to_reset: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_payload_snapshot() {
        let payload = ListPayload {
            schema_version: 1,
            providers: vec![ProviderView {
                provider: "claude".to_string(),
                installed: true,
                active_slot: Some(2),
                active_unreadable: None,
                last_known_active_slot: None,
                next_candidate: Some(1),
                next_recovery: Some(NextRecovery {
                    slot: 8,
                    at: "2026-09-09T03:29:59Z".to_string(),
                }),
                accounts: vec![AccountView {
                    slot: 1,
                    email: "you@example.com".to_string(),
                    organization_name: "Example Org".to_string(),
                    organization_uuid: "org-0000".to_string(),
                    plan: Some("Max 20x".to_string()),
                    alias: Some("death2".to_string()),
                    icon: Some("🩸".to_string()),
                    active: false,
                    disabled: false,
                    preferred: false,
                    usage_status: UsageStatus::Ok,
                    fetched_at: Some("2026-09-09T01:11:03Z".to_string()),
                    age_seconds: Some(7.6),
                    windows: vec![
                        Window {
                            kind: WindowKind::FiveHour,
                            name: None,
                            pct: 0.0,
                            resets_at: Some("2026-09-09T05:59:59Z".to_string()),
                            pace: None,
                            used: None,
                            limit: None,
                            currency: None,
                        },
                        Window {
                            kind: WindowKind::SevenDay,
                            name: None,
                            pct: 19.0,
                            resets_at: Some("2026-09-15T10:59:59Z".to_string()),
                            pace: Some(Pace {
                                expected_pct: 20.3,
                                ahead: true,
                                exhausts_at: None,
                                lasts_to_reset: true,
                            }),
                            used: None,
                            limit: None,
                            currency: None,
                        },
                        Window {
                            kind: WindowKind::Scoped,
                            name: Some("Fable".to_string()),
                            pct: 29.0,
                            resets_at: Some("2026-09-15T10:59:59Z".to_string()),
                            pace: None,
                            used: None,
                            limit: None,
                            currency: None,
                        },
                    ],
                    last_good: Some(LastGood {
                        fetched_at: "2026-09-09T01:11:03Z".to_string(),
                        age_seconds: 0.0,
                        windows: vec![],
                    }),
                    last_error: None,
                    backoff_until: None,
                }],
            }],
        };

        insta::assert_json_snapshot!("list_payload", payload);
    }
}
